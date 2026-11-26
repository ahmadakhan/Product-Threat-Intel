import { correlationPreflight } from './correlation/preflight.ts';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  DEFAULT_NEWS_EMAIL_CUSTOMIZATION,
  compileDailyDigestTemplate,
  compileNewsTemplate,
} from '../src/utils/templateCompiler.ts';
import { DEFAULT_ADVISORY_EMAIL_TEMPLATE } from '../src/utils/defaultAdvisoryEmailTemplate.ts';
import pg, { type PoolClient } from 'pg';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

export type { PoolClient };
import { randomUUID } from 'node:crypto';
import {
  emptyState,
  type AppState,
  type CollectionKind,
  type HeavyCollectionKind,
  COLLECTION_KINDS,
} from '../shared/state.ts';
import { chainAuditLogs, hashAuditLog, SortedMerkleAccumulator } from '../src/utils/cryptoChain.ts';
import type { AuditLog } from '../src/types/index.ts';
import { orderWatchlist } from '../src/utils/watchlist.ts';
import { auditContext, auditText } from './audit.ts';
import { loadPoolSettings } from './config.ts';
export type Db = pg.Pool | PoolClient;

/**
 * TTL cache for state_metrics reads. `state()` is called on every `/api/state`
 * poll and every pipeline run; the summary table rarely changes between polls,
 * so caching avoids a full-table scan on every request.
 */
const STATE_METRICS_CACHE_TTL_MS = 10_000;
let stateMetricsCache: { metrics: Map<string, number>; expiresAt: number } | null = null;

/**
 * Template compilation cache. Compiled Handlebars templates are deterministic
 * given the same customization input, so caching by input string avoids
 * re-parsing on every state() / pipelineState() call. Bounded at 1,000 entries
 * to prevent unbounded growth.
 */
const TEMPLATE_CACHE_TTL_MS = 300_000;
const templateCompileCache = new Map<string, { template: string; expiresAt: number }>();
const evictTemplateCache = () => {
  if (templateCompileCache.size <= 1_000) return;
  const oldest = templateCompileCache.keys().next().value;
  if (oldest !== undefined) templateCompileCache.delete(oldest);
};

function cachedCompileTemplate(key: string, compile: () => string): string {
  const now = Date.now();
  const entry = templateCompileCache.get(key);
  if (entry && now < entry.expiresAt) return entry.template;
  const template = compile();
  templateCompileCache.set(key, { template, expiresAt: now + TEMPLATE_CACHE_TTL_MS });
  evictTemplateCache();
  return template;
}

/**
 * Merge libpq options into a connection string without discarding the ones the
 * caller already set.
 *
 * pg replaces a URL connection string's `options` with the pool-level `options`
 * rather than combining them, so passing `search_path` via `?options=` and the
 * statement timeout via the pool silently dropped the search_path
 * (per-schema test suites and any multi-schema deployment). Appending with a
 * space is exactly how libpq combines repeated `-c key=value` settings.
 */
const withLibpqOption = (url: string, option: string): string => {
  try {
    const parsed = new URL(url);
    const existing = parsed.searchParams.get('options')?.trim();
    parsed.searchParams.set('options', existing ? `${existing} ${option}` : option);
    return parsed.toString();
  } catch {
    // Keyword/value connection strings are not URLs; keep them untouched. They
    // rarely carry libpq options, and rewriting them risks corrupting a value.
    return url;
  }
};

export const createPool = (url: string) => {
  // Validated at the environment boundary (server/config.ts) so malformed
  // values fail startup instead of reaching pg as NaN. The statement timeout is
  // applied through libpq because a pool property named `statement_timeout` is
  // not supported by pg and is silently dropped, which left every query
  // unbounded.
  const settings = loadPoolSettings();
  // `pg` reads `maxLifetime`, `keepAlive` and `keepAliveInitialDelayMillis` at
  // runtime but its published `PoolOptions` type omits them, so they are
  // declared here rather than hidden behind an `as any` that also suppressed
  // checking of every real option above.
  type PoolOptionsWithLifecycle = pg.PoolConfig & {
    maxLifetime?: number;
    keepAlive?: boolean;
    keepAliveInitialDelayMillis?: number;
    timezone?: string;
  };
  const poolOptions: PoolOptionsWithLifecycle = {
    connectionString: withLibpqOption(url, `-c statement_timeout=${settings.statementTimeoutMs}`),
    max: settings.maxConnections,
    connectionTimeoutMillis: settings.connectionTimeoutMs,
    idleTimeoutMillis: settings.idleTimeoutMs,
    application_name: 'vulnstream',
    timezone: 'LOCAL',
    // Production optimizations
    allowExitOnIdle: true,
    // Connection lifecycle management
    maxLifetime: settings.maxLifetimeMs,
    // A pooled connection can sit idle inside one transaction, or between the
    // client's and the server's view of a quiet period, long enough for a
    // NAT/firewall or cloud LB to silently reap it. Without keepalive the next
    // query on that socket fails with ECONNRESET instead of being detected. pg
    // reads `keepAlive` and `keepAliveInitialDelayMillis`; the previous
    // `keepAliveDelay` was never read by pg or pg-pool and so did nothing.
    keepAlive: true,
    keepAliveInitialDelayMillis: settings.keepAliveDelayMs,
  };
  const pool = new pg.Pool(poolOptions);

  // Monitor connection pool health
  pool.on('connect', () => {
    console.log(
      JSON.stringify({
        level: 'info',
        event: 'database-pool-connected',
        timestamp: new Date().toISOString(),
        totalCount: pool.totalCount,
      }),
    );
  });

  // 'acquire' fires once per query checkout, so logging it at standard level
  // wrote one structured line per query and dominated log volume on a busy
  // deployment. Keep it behind the verbose log level used for per-operation
  // diagnostics; pool health is already visible through connect/remove/error.
  if (process.env.LOG_LEVEL === 'verbose') {
    pool.on('acquire', () => {
      console.log(
        JSON.stringify({
          level: 'info',
          event: 'database-pool-acquired',
          timestamp: new Date().toISOString(),
          idleCount: pool.idleCount,
        }),
      );
    });
  }

  // The 'remove' event is emitted when the pool disposes a client (for
  // example on timeout or when forced to shrink).  Logging this gives deeper
  // operational visibility than the generic `pg` error handler and preserves
  // the same structured JSON format used elsewhere.
  pool.on('remove', () => {
    console.log(
      JSON.stringify({
        level: 'warn',
        event: 'database-pool-connection-removed',
        timestamp: new Date().toISOString(),
        totalCount: pool.totalCount,
        idleCount: pool.idleCount,
        activeCount: pool.totalCount - pool.idleCount,
      }),
    );
  });

  pool.on('error', (error) => {
    console.error(
      JSON.stringify({
        level: 'error',
        event: 'database-pool-error',
        error: error.message,
        code: (error as { code?: string }).code,
        timestamp: new Date().toISOString(),
      }),
    );
  });

  return pool;
};
/**
 * Advisory locks are scoped to the database, not to the active schema. Mixing
 * in the schema keeps independent deployments (and isolated per-schema test
 * databases) that share one PostgreSQL database from blocking each other.
 * COALESCE covers a search_path whose first schema does not exist yet.
 */
export const schemaLockKey = 'hashtext(COALESCE(current_schema(), current_database()))';

/**
 * Renders a lock class for interpolation into an advisory-lock statement.
 *
 * Advisory locks are addressed as `(class, key)` where both are integers; the
 * SQL helper accepts either a bare number or a hashtext expression. Lock classes
 * in this codebase are always numeric constants, but the value is interpolated
 * (it cannot be bound, because the sibling argument is an expression), so it is
 * restricted to a safe numeric form rather than trusted.
 */
const advisoryLockClassArgument = (lockClass: number | string): string => {
  if (typeof lockClass === 'number' && Number.isSafeInteger(lockClass)) return String(lockClass);
  if (typeof lockClass === 'string' && /^\d{1,18}$/.test(lockClass)) return lockClass;
  throw new Error('Invalid advisory lock class');
};

/**
 * The newest migration this build depends on. Production startup refuses to
 * run against an older schema instead of failing later on a missing column.
 *
 * Bump this whenever a migration is added: `tests/migrations.test.ts` asserts
 * it matches the highest `NNN_*.sql` file, so a forgotten bump fails the suite
 * rather than shipping a build that boots against an un-migrated database.
 */
export const REQUIRED_SCHEMA_VERSION = 47;

/**
 * Migration files sorted by numeric prefix. Only plain `NNN_name.sql` entries
 * participate; anything else (README, retired migrations, editor backups) is
 * ignored rather than accidentally executed.
 */
async function migrationFiles(): Promise<{ version: number; name: string }[]> {
  const directory = fileURLToPath(new URL('./migrations/', import.meta.url));
  const entries = await readdir(directory);
  return entries
    .filter((name) => /^\d{3}_.*\.sql$/.test(name))
    .map((name) => ({ version: Number(name.slice(0, 3)), name }))
    .sort((a, b) => a.version - b.version);
}

/**
 * Non-transactional index builds.
 *
 * PostgreSQL refuses CREATE INDEX CONCURRENTLY inside a transaction block, and a
 * plain CREATE INDEX takes SHARE on the table for the entire build. On a large
 * live installation that blocks every INSERT/UPDATE for the duration, and ingest
 * workers run under a 3500ms statement timeout, so each one rolls back, burns
 * its retry ladder and is dead-lettered. A maintenance window is therefore not
 * an acceptable workaround: it converts an ordinary deploy into a loss window.
 *
 * So index DDL lives in ./migrations/indexes/*.sql and is applied here, one
 * statement at a time, on an autocommit connection. A concurrent build that
 * fails leaves an INVALID index behind (the catalogue row outlives the abort);
 * the retry path drops it before rebuilding. `preflight.ts` rejects any unique
 * index whose `indisvalid` is false, so an interrupted build cannot masquerade
 * as a satisfied ON CONFLICT target.
 */
async function indexMigrationFiles(): Promise<{ name: string; sql: string }[]> {
  const directory = fileURLToPath(new URL('./migrations/indexes/', import.meta.url));
  const entries = (await readdir(directory)).filter((name) => /^\d{3}_.*\.sql$/.test(name)).sort();
  return Promise.all(
    entries.map(async (name) => ({
      name,
      sql: await readFile(new URL(`./migrations/indexes/${name}`, import.meta.url), 'utf8'),
    })),
  );
}

/**
 * Strip comments and split on semicolons outside string literals.
 *
 * A `--` comment is consumed as a unit before quote tracking runs, so a
 * semicolon or an apostrophe inside it can neither split the statement nor open
 * a string literal. Index files are heavily commented prose, and both occur.
 */
export function indexStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = '';
  let quoted = false;
  for (let index = 0; index < sql.length; index++) {
    const char = sql[index];
    if (!quoted && char === '-' && sql[index + 1] === '-') {
      while (index < sql.length && sql[index] !== '\n') index++;
      current += '\n';
      continue;
    }
    if (char === "'") quoted = !quoted;
    if (!quoted && char === ';') {
      if (current.trim()) statements.push(current.trim());
      current = '';
      continue;
    }
    current += char;
  }
  if (current.trim()) statements.push(current.trim());
  return statements;
}

const indexName = (statement: string): string | null =>
  // Names are interpolated into `DROP INDEX ... "${name}"`, so the capture is
  // deliberately restricted to safe identifier characters — the regex doubles
  // as the injection guard for anything parsed out of a migration file.
  /^[\s\S]*?CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\s+IF\s+NOT\s+EXISTS\s+"?([A-Za-z_][A-Za-z0-9_$]*)"?/.exec(
    statement,
  )?.[1] ?? null;

/**
 * Unlock helper with observability.
 *
 * Session advisory locks acquired outside `transaction()` (the pipeline run
 * lock, the digest locks, the index-build lock) must be released on their own
 * connection; this wraps that unlock with structured logging so a failed release
 * — which can pin the lock until the connection dies — is visible in the process
 * log.
 *
 * CRITICAL: `pg_advisory_unlock` reports whether this session actually held the
 * lock via its `unlocked` result, and returns false (without erroring) when it
 * did not. Treating a successful round-trip as a successful release is what
 * hands a lock-holding connection back to the pool: the next request to check
 * that client out then believes it owns the lock, while the real owner is gone.
 * The boolean result is therefore inspected, not just awaited, and a `false`
 * result is reported as a failure so the caller destroys the connection.
 */
export async function safeAdvisoryUnlock(
  client: pg.PoolClient,
  lockClass: number | string,
  schemaKey: string,
  lockKey: string,
): Promise<boolean> {
  try {
    const result = await client.query<{ released: boolean }>(
      // `schemaKey` is a SQL *expression* (`schemaLockKey` is the literal text
      // `hashtext(COALESCE(current_schema(), current_database()))`), not a value.
      // Binding it as a parameter sent that text as the key, so the unlock looked
      // up an advisory key literally named "hashtext(...)" and never matched the
      // lock it was acquired under. It has always been interpolated at every other
      // call site for this reason. `lockClass` is a caller-supplied constant; it is
      // validated below because it is interpolated too.
      `SELECT pg_advisory_unlock(${advisoryLockClassArgument(lockClass)}, ${schemaKey}) AS released`,
    );
    if (result.rows[0]?.released !== true) {
      console.error(
        JSON.stringify({
          level: 'error',
          event: 'advisory_unlock_not_held',
          lockClass,
          lockKey,
          timestamp: new Date().toISOString(),
        }),
      );
      return false;
    }
    console.log(
      JSON.stringify({
        level: 'info',
        event: 'advisory_unlock_success',
        lockClass,
        lockKey,
        timestamp: new Date().toISOString(),
      }),
    );
    return true;
  } catch (error) {
    console.error(
      JSON.stringify({
        level: 'error',
        event: 'advisory_unlock_failed',
        lockClass,
        lockKey,
        error: (error as Error).message,
        timestamp: new Date().toISOString(),
      }),
    );
    return false;
  }
}

/**
 * Build the correlation indexes concurrently. Runs on its own connection, in
 * autocommit mode, after the transactional migrations have committed: the
 * relations must exist first, and the tables must not be locked by this run.
 */
export async function applyIndexMigrations(pool: pg.Pool): Promise<void> {
  const client = await pool.connect();
  let failed = false;
  try {
    // A concurrent build waits for every transaction that already holds a
    // conflicting lock. Ingest transactions are short (3500ms statement / 5000ms
    // idle), so a generous lock timeout retries rather than aborting; the
    // statement timeout is the real ceiling for a multi-million-row build.
    await client.query("SET statement_timeout = '900000ms'");
    await client.query("SET lock_timeout = '30000ms'");
    await client.query('SELECT set_config($1, current_schema(), false)', ['search_path']);
    // Serialize concurrent deploys of the same schema. Separate from the
    // migration lock because this runs outside that transaction.
    //
    // Routed through the documented order guard rather than inline SQL: this is
    // the highest-ranked class (800005), so a caller that already holds a lower
    // class on this connection must be rejected here instead of deadlocking with
    // `40P01` once two deployers acquire the same classes in opposite orders.
    await acquireSessionClassLock(
      client,
      800005,
      'hashtext(COALESCE(current_schema(), current_database()))',
      { wait: true },
    );
    try {
      for (const file of await indexMigrationFiles()) {
        for (const statement of indexStatements(file.sql)) {
          await buildIndex(client, statement, file.name);
        }
      }
    } finally {
      try {
        // A `false` result means the lock was not held by this session and was
        // therefore NOT released; like a thrown error it leaves the connection
        // suspect, so it takes the same destroy path.
        const unlocked = await client.query<{ released: boolean }>(
          'SELECT pg_advisory_unlock(800005, hashtext(COALESCE(current_schema(), current_database()))) AS released',
        );
        if (unlocked.rows[0]?.released !== true) failed = true;
      } catch {
        // If the release fails the session advisory lock stays pinned on this
        // connection. Destroying it prevents a recycled connection from handing
        // a held lock to the next migration and blocking every concurrent deploy.
        failed = true;
      }
    }
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    client.release(failed);
  }
}

/**
 * One CREATE INDEX CONCURRENTLY with the failure handling that statement class
 * actually needs. Returns false when the index is permanently unavailable in
 * this deployment (pg_trgm absent) rather than throwing, so an optimisation
 * cannot block a deploy.
 */
// Enhanced buildIndex function with improved error handling and logging
async function buildIndex(client: pg.PoolClient, statement: string, file: string): Promise<void> {
  const name = indexName(statement);
  // A cancelled or failed concurrent build leaves an INVALID index behind.
  // DROP INDEX CONCURRENTLY also runs outside a transaction, and the retry
  // must not trip over the stale catalogue entry.
  if (name) {
    const invalid = await client
      .query<{ invalid: boolean }>(
        `SELECT NOT i.indisvalid AS invalid
           FROM pg_index i
           JOIN pg_class c ON c.oid = i.indexrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE c.relname = $1 AND n.nspname = ANY(current_schemas(true))`,
        [name],
      )
      .catch(() => ({ rows: [] as { invalid: boolean }[] }));
    if (invalid.rows[0]?.invalid) {
      if (!/^[A-Za-z_][A-Za-z0-9_$]*$/.test(name)) throw new Error(`Unsafe migration index name: ${name}`);
      await client.query(`DROP INDEX CONCURRENTLY IF EXISTS "${name}"`);
      console.log(
        JSON.stringify({
          level: 'warn',
          event: 'index.invalid_rebuilt',
          index: name,
          file,
          timestamp: new Date().toISOString(),
        }),
      );
    }
  }
  // pg_trgm is optional, and migration 019 revoked the fuzzy helpers from
  // PUBLIC. Building a trigram index is therefore an optimisation that a
  // deployment may legitimately be unable to perform — a failed build must
  // never block the release. Probe resolution exactly as PostgreSQL will:
  // `gin_trgm_ops` must be an opclass name in the session's search_path
  // namespace set and its access method. A global catalogue lookup answers the
  // wrong question: in a multi-tenant database the extension is typically
  // installed once, in one schema, and remains invisible to every other
  // tenant's session.
  if (statement.includes('gin_trgm_ops')) {
    const available = await client
      .query<{ available: boolean }>(
        `SELECT EXISTS (
           SELECT 1 FROM pg_opclass o
           JOIN pg_namespace n ON n.oid = o.opcnamespace
           JOIN pg_am a ON a.oid = o.opcmethod
           WHERE o.opcname = 'gin_trgm_ops' AND a.amname = 'gin'
             AND n.nspname = ANY(current_schemas(true))
         ) AS available`,
      )
      .catch(() => ({ rows: [{ available: false }] }));
    if (!available.rows[0]?.available) {
      console.warn(
        JSON.stringify({
          level: 'warn',
          event: 'index.skipped',
          index: name,
          file,
          reason: 'gin_trgm_ops-unavailable',
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }
  }
  for (let attempt = 0; attempt <= 2; attempt++) {
    try {
      await client.query(statement);
      console.log(
        JSON.stringify({
          level: 'info',
          event: 'index.build_success',
          index: name,
          file,
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    } catch (error) {
      const code = String((error as { code?: string }).code ?? '');
      // A cancelled or failed concurrent build leaves an INVALID index behind.
      // DROP INDEX CONCURRENTLY also runs outside a transaction, and the retry
      // must not trip over the stale catalogue entry.
      if (name) await client.query(`DROP INDEX CONCURRENTLY IF EXISTS "${name}"`).catch(() => {});
      // Lock timeout and deadlock are transient: a live writer held the table.
      if ((code === '55P03' || code === '40P01') && attempt < 2) {
        await new Promise((resolve) => setTimeout(resolve, 2000 * (attempt + 1)));
        continue;
      }
      // An owner-managed table that does not exist in this schema is not an
      // install defect. The correlation index set covers `assets`,
      // `unstructured_advisories` and `vendor_product_aliases`, which the
      // platform operator may provision separately (a fresh isolated schema —
      // including every per-suite test schema — legitimately has none of them).
      // Failing migration here aborted deploy/startup for an optional
      // integration. Record the miss and let the preflight report the absent
      // relation when a code path that needs it actually runs.
      if (code === '42P01') {
        console.warn(
          JSON.stringify({
            level: 'warn',
            event: 'index.skipped',
            index: name,
            file,
            reason: 'relation-absent',
            timestamp: new Date().toISOString(),
          }),
        );
        return;
      }
      throw Object.assign(new Error(`Index build failed (${file}, ${name ?? 'unnamed'}): ${code}`), {
        cause: error,
      });
    }
  }
}

export async function migrate(pool: pg.Pool) {
  const client = await pool.connect();
  let failed = false;
  try {
    await client.query('BEGIN');
    // Fail fast instead of queueing behind long-running worker transactions and
    // stalling the application behind an AccessExclusive DDL lock.
    await client.query("SET LOCAL lock_timeout = '10000ms'");
    // Migrations may include index builds; do not inherit the 15-second API
    // statement timeout. Configurable: a large data migration that legitimately
    // needs longer than the 5-minute default would otherwise be cancelled
    // mid-transaction and roll back, which on a big table can take as long again
    // and fails the deploy for no defect. The default stays conservative; raise
    // MIGRATION_STATEMENT_TIMEOUT_MS for a one-off heavy migration.
    const migrationTimeoutMs = migrationStatementTimeoutMs();
    await client.query(`SET LOCAL statement_timeout = '${migrationTimeoutMs}ms'`);
    // Extensions live in the database-global `pg_extension` catalog, not in the
    // per-schema search path. Two schemas migrating at the same time can both
    // see `pg_trgm` as absent and race on `CREATE EXTENSION`, failing with
    // `pg_extension_name_index`. Serialize migration transactions across
    // schemas; the per-schema lock below still allows independent operation
    // once migrations have completed.
    assertClassLockOrder(800004, []);
    await client.query('SELECT pg_advisory_xact_lock(800004)');
    assertClassLockOrder(800001, [800004]);
    await client.query(`SELECT pg_advisory_xact_lock(800001, ${schemaLockKey})`);
    const nativeContract = await correlationPreflight(client);
    if (!nativeContract.compatible)
      throw new Error('Protected correlation schema incompatible: ' + nativeContract.issues.join('; '));
    // Apply every migration file in the directory, in version order. A
    // hard-coded list silently skipped files whenever two shared a version
    // number (014 and 015 each did) and had to be edited for every new
    // migration. Reading the directory makes the file the source of truth.
    // On a brand-new database schema_migrations does not exist yet; 001 creates
    // it. Probe the CURRENT schema only: `to_regclass('schema_migrations')`
    // resolves through the whole search_path, so on a multi-tenant database a
    // leftover row set in `public` made every tenant probe see "already at the
    // latest version" and commit an empty schema — every later statement then
    // failed with 42P01 and the tenant looked broken with no migration error.
    const exists = await client.query(
      "SELECT to_regclass(format('%I.schema_migrations', current_schema())) AS name",
    );
    const appliedVersions = new Set<number>(
      exists.rows[0].name
        ? (await client.query<{ version: number }>(`SELECT version FROM ${exists.rows[0].name}`)).rows.map(
            (row) => Number(row.version),
          )
        : [],
    );
    for (const { version, name } of await migrationFiles()) {
      if (appliedVersions.has(version)) continue;
      await client.query(await readFile(new URL(`./migrations/${name}`, import.meta.url), 'utf8'));
    }
    await client.query('COMMIT');
  } catch (e) {
    failed = true;
    // A failure here may mean the connection itself is broken (e.g. the BEGIN
    // never completed); do not let a secondary ROLLBACK error mask the real cause.
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    // Passing the failure tells the pool to destroy a possibly-broken connection
    // instead of recycling it back into the pool for the next caller.
    client.release(failed);
  }
  // Only after the schema transaction commits: the relations exist, and the
  // CREATE INDEX CONCURRENTLY statements must not run inside a transaction.
  await applyIndexMigrations(pool);
}
/**
 * Total acquisition order for every transaction-scoped advisory lock.
 *
 * `transaction()` sorts the *names* it is handed, which prevents a single
 * transaction from self-deadlocking but says nothing about two different call
 * sites that take different names in different orders. That cross-caller cycle
 * is the one PostgreSQL reports as `40P01`, and it was only ever guarded by a
 * comment asking developers to keep the order alphabetical.
 *
 * The order below is the executable form of that invariant. A name absent from
 * the table sorts after every listed one, keeping unknown locks at the tail
 * where they cannot be interleaved into an existing cycle.
 *
 * LOCK_ORDER must stay consistent with LOCK_CLASS_RANK: a lock acquired by hand
 * (the session-scoped run, leadership and index-build locks) has to rank after
 * anything its holder already took, or two holders that take the same classes in
 * opposite orders cycle and PostgreSQL reports `40P01`.
 */
export const LOCK_ORDER: readonly string[] = Object.freeze([
  // Coarsest scope first: migration/schema, then the domains a long run holds.
  'schema',
  'match-index',
  'pipeline-queue',
  'audit-chain',
  // Operator-managed identity domains. These are always leaves: their holders
  // never take a pipeline or index lock afterwards.
  'watchlist-identity',
  'feed-source',
  'recipients-unique',
  'digest-buffer',
]);

const LOCK_RANK: ReadonlyMap<string, number> = new Map(LOCK_ORDER.map((name, index) => [name, index]));

/**
 * Rank used to order named locks. Unknown names rank last, preserving their
 * relative order among themselves so the sort stays total and stable.
 */
export const lockRank = (name: string): number => LOCK_RANK.get(name) ?? LOCK_ORDER.length;

/**
 * Sorts lock names into the global acquisition order.
 *
 * Exported so call sites and tests can assert the order rather than trusting a
 * comment. Sorting is stable by name for equal ranks, so two callers that hold
 * the same set always acquire it in the same sequence.
 */
export const orderLocks = (names: readonly string[]): string[] =>
  [...names].sort((a, b) => lockRank(a) - lockRank(b) || (a < b ? -1 : a > b ? 1 : 0));

/**
 * Rank of the session- and transaction-scoped lock *classes* (the first
 * `pg_advisory_lock` argument).
 *
 * A holder of a class lock may open a `transaction()` afterwards and take a
 * named lock there, so the two orderings must agree. Every class below is
 * declared in increasing order of "how much the holder is entitled to take
 * afterwards": leadership and schema/migration locks rank lowest, then the
 * pipeline run lock, then the index-build lock.
 *
 * Keeping this table next to LOCK_ORDER is what makes the invariant checkable:
 * two independent numeric namespaces with no declared relationship are exactly
 * how the `match-index` / `watchlist-identity` cycle was introduced.
 *
 * The table only prevents a deadlock if every raw acquisition consults it, so
 * class locks are taken through `acquireSessionClassLock` (which calls
 * `assertClassLockOrder`) rather than inline `SELECT pg_try_advisory_lock(...)`
 * SQL. 800004, 800003 and 800005 each rank after everything a concurrent holder
 * of a lower-ranked class can take, which is what makes "acquire in increasing
 * rank" a total order across the deployment.
 */
export const LOCK_CLASS_RANK: ReadonlyMap<number, number> = new Map([
  [800004, 0], // migration transaction; also used by daily digest and ML training
  [800001, 1], // migration schema lock
  [800003, 2], // pipeline run / burst digest
  [784921, 3], // worker leadership
  [800005, 4], // concurrent index build
]);

/** Default statement budget for one migration transaction: five minutes. */
const DEFAULT_MIGRATION_STATEMENT_TIMEOUT_MS = 300_000;
/**
 * Statement budget for migrations, overridable with
 * MIGRATION_STATEMENT_TIMEOUT_MS.
 *
 * Validated rather than trusted: PostgreSQL is sent this value as SQL text, so a
 * non-numeric or absurd value must not reach it. Out-of-range falls back to the
 * default instead of failing a deploy on a typo in an optional knob.
 */
function migrationStatementTimeoutMs(): number {
  const raw = process.env.MIGRATION_STATEMENT_TIMEOUT_MS;
  if (raw === undefined || raw.trim() === '') return DEFAULT_MIGRATION_STATEMENT_TIMEOUT_MS;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1_000 || parsed > 3_600_000)
    return DEFAULT_MIGRATION_STATEMENT_TIMEOUT_MS;
  return parsed;
}

/**
 * Assert that session class locks are taken in LOCK_CLASS_RANK order.
 *
 * Named transaction locks are sorted by `orderLocks`, but the class locks are
 * acquired by hand on a dedicated connection. `LOCK_CLASS_RANK` on its own is
 * documentation: a call site that took two classes out of order would deadlock
 * with `40P01` and the table would not have prevented it. Every acquisition goes
 * through `acquireSessionClassLock`, which calls this first.
 *
 * Every holder here takes exactly one class lock, so today this is a guard
 * rather than a re-ordering. It is checked at acquisition so that a future
 * caller which takes a second class lock in the wrong order fails fast with a
 * clear message instead of deadlocking in production. Acquiring is NOT reordered
 * behind the caller's back: the order a lock is actually taken in must match the
 * order this function asserts, or the assertion would be a lie.
 */
export function assertClassLockOrder( lockClass: number, held: readonly number[]): void {
  const rank = LOCK_CLASS_RANK.get(lockClass);
  if (rank === undefined) return; // unranked classes keep their historical freedom
  for (const heldClass of held) {
    const heldRank = LOCK_CLASS_RANK.get(heldClass);
    if (heldRank === undefined) continue;
    if (heldRank > rank)
      throw new Error(
        `Advisory lock class order violated: ${lockClass} (rank ${rank}) acquired while holding ${heldClass} (rank ${heldRank})`,
      );
  }
}

/**
 * Acquire a session-scoped advisory lock through the documented order check.
 *
 * `held` is the set of class locks the caller already owns on this connection.
 * Returns the `pg_try_advisory_lock` boolean so callers keep their existing
 * "somebody else owns this run" control flow; `wait: true` uses the blocking
 * form instead.
 */
export async function acquireSessionClassLock(
  client: pg.PoolClient,
  lockClass: number,
  schemaKey: string,
  options: { held?: readonly number[]; wait?: boolean } = {},
): Promise<boolean> {
  assertClassLockOrder(lockClass, options.held ?? []);
  const fn = options.wait ? 'pg_advisory_lock' : 'pg_try_advisory_lock';
  const result = await client.query<{ locked: boolean }>(
    `SELECT ${fn}(${advisoryLockClassArgument(lockClass)}, ${schemaKey}) AS locked`,
  );
  // `pg_advisory_lock` returns void (a null `locked`); holding it is the success
  // signal, so a null result is reported as acquired rather than as `false`.
  return options.wait ? true : result.rows[0]?.locked === true;
}

export interface TransactionOptions {
  /**
   * Optional named advisory locks acquired for the duration of the transaction.
   * Locks are sorted before acquisition to prevent deadlocks between callers.
   * The previous single global 800002 lock serialized every write in the
   * installation; scoped locks let independent domains proceed concurrently.
   */
  locks?: string[];
  /**
   * Locks the caller already owns on another connection, in the same
   * `hashtext(name), schemaLockKey` namespace as `locks`.
   *
   * Some transactions have to acquire an advisory lock before opening the
   * transaction and then keep it while the transaction reads rows that other
   * holders lock in the opposite order (the pipeline stop path). Re-acquiring
   * them here would deadlock; declaring them is what keeps the documented
   * "acquire locks in alphabetical order" invariant true for every lock the
   * transaction depends on.
   */
  lockAcquired?: string[];
  /**
   * Cancels the work at the database rather than only abandoning the promise.
   *
   * A caller that stops waiting on a hung query still holds its pool connection
   * until the statement finishes, so a wedged statement can pin a connection
   * indefinitely and starve the pool of every other job. Aborting requests a
   * PostgreSQL cancel (and drops the connection as a backstop), so the timeout
   * releases the resource it exists to protect.
   */
  signal?: AbortSignal;
  /**
   * Override the pool-level statement timeout for this transaction, in
   * milliseconds. Set locally via `SET LOCAL` so it reverts when the
   * transaction commits or rolls back. Used by the correlation candidate-index
   * refresh, whose GIN join can exceed the default 15s statement timeout on
   * large installations.
   */
  statementTimeoutMs?: number;
  /**
   * Override the pool-level `lock_timeout` for this transaction, in
   * milliseconds, via `SET LOCAL`.
   *
   * A parked-in-catalogue/row lock wait is bounded only by `statement_timeout`
   * (15s by default, but minutes for a transaction that raised it), so a commit
   * transaction that collides with an operator write can hold a pool connection
   * and its advisory locks for the whole statement budget. Setting a lock
   * timeout makes the collision fail fast as `55P03` instead, which the callers'
   * existing retry/recovery paths already handle.
   */
  lockTimeoutMs?: number;
}

/**
 * Requests cancellation on a live backend.
 *
 * `pg` exposes no cancel API, so the cancel request is sent on the *same*
 * connection. If the connection is stuck that request cannot be delivered and
 * the backend keeps running, so the connection is destroyed once the socket no
 * longer responds. Destroying it returns it to the pool as broken and the
 * server terminates the orphaned backend when it notices the dropped socket.
 */
const CANCEL_REQUEST_TIMEOUT_MS = 2000;
/**
 * Cancels the running statement on a live backend.
 *
 * The cancel request must not share the connection whose statement is stuck: a
 * `pg` client serialises queries per connection, so `SELECT pg_cancel_backend()`
 * issued on that connection is queued behind the very statement it is meant to
 * cancel and is only sent once the statement finishes. It is therefore sent from
 * a second connection, which is available because the stuck one is still held.
 */
async function cancelBackend(pool: pg.Pool, db: PoolClient): Promise<void> {
  const pid = (db as unknown as { processID?: number }).processID;
  // `destroy` exists at runtime but is absent from the public typings.
  const destroy = () => {
    const client = db as unknown as { destroy?: () => void };
    if (typeof client.destroy === 'function') client.destroy();
  };
  if (!pid) {
    // No backend pid is visible yet (the connection has not been checked out or
    // the driver did not populate `processID`), so a cancel request cannot be
    // sent. Deliver the destroy-only backstop so the connection is not returned
    // to the pool in a half-open state, and make the unsent cancel observable.
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'cancelBackend.no_pid',
        reason: 'pg processID unavailable; delivering destroy-only backstop',
      }),
    );
    destroy();
    return;
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    // A reachable database answers immediately. An unreachable one never
    // answers, so race the cancel against a short deadline: a request that
    // cannot be delivered is exactly the case where the socket must be dropped.
    await Promise.race([
      pool.query(`SELECT pg_cancel_backend(${Number(pid)})`), // integer pid from the driver
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('CANCEL_TIMEOUT')), CANCEL_REQUEST_TIMEOUT_MS);
        timer.unref?.();
      }),
    ]);
  } catch {
    // The cancel could not be delivered (timeout or transport failure): drop
    // the socket so the pool surfaces the broken connection and PostgreSQL
    // terminates the orphaned backend when it notices the dropped socket.
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'cancelBackend.timeout',
        pid,
        reason: 'cancel request not delivered within deadline; destroying connection',
      }),
    );
    destroy();
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function transaction<T>(
  pool: pg.Pool,
  fn: (db: PoolClient) => Promise<T>,
  client?: PoolClient,
  options: TransactionOptions = {},
): Promise<T> {
  const db = client || (await pool.connect());
  let failed = false;
  let connectionError: Error | undefined;
  const onError = (error: Error) => {
    connectionError = error;
    failed = true;
  };
  db.on('error', onError);
  const onAbort = () => {
    connectionError = new Error('Transaction cancelled: operation exceeded its deadline');
    failed = true;
    void cancelBackend(pool, db);
  };
  if (options.signal?.aborted) {
    db.removeListener('error', onError);
    if (!client) db.release(true);
    throw new Error('Transaction cancelled: operation exceeded its deadline');
  }
  options.signal?.addEventListener('abort', onAbort, { once: true });
  try {
    await db.query('BEGIN');
    // Override the pool-level statement timeout for long-running transaction
    // work (e.g. correlation candidate-index refresh). Reverts on COMMIT/ROLLBACK.
    if (typeof options.statementTimeoutMs === 'number' && Number.isFinite(options.statementTimeoutMs))
      await db.query(`SET LOCAL statement_timeout = '${options.statementTimeoutMs}ms'`);
    // Bound lock waits independently of the statement budget. A transaction that
    // raised its statement timeout for expensive work must still fail fast when
    // it merely collides with a concurrent writer, otherwise it parks on a pool
    // connection (and its advisory locks) for the whole extended budget.
    if (typeof options.lockTimeoutMs === 'number' && Number.isFinite(options.lockTimeoutMs))
      await db.query(`SET LOCAL lock_timeout = '${Math.max(1, Math.floor(options.lockTimeoutMs))}ms'`);
    // Named, transaction-scoped locks replace the former global mutation lock.
    // Row-level locks on the records being mutated provide the per-record
    // serialization that operators actually need. Locks are acquired in the
    // global order declared by LOCK_ORDER, not merely alphabetically: an
    // alphabetical sort is only total within one call, while LOCK_ORDER is the
    // single sequence every caller observes, which is what prevents the
    // cross-caller cycle PostgreSQL reports as 40P01.
    for (const lock of orderLocks(
      (options.locks ?? []).filter((name) => !options.lockAcquired?.includes(name)),
    ))
      await db.query(`SELECT pg_advisory_xact_lock(hashtext($1), ${schemaLockKey})`, [lock]);
    const result = await fn(db);
    if (connectionError) throw connectionError;
    await db.query('COMMIT');
    return result;
  } catch (error) {
    failed = true;
    // `connectionError` is set by two paths that are NOT statement failures:
    // the client's `error` listener (fired for an idle or socket-level fault
    // while `fn` may still be running) and `onAbort`. When either is the reason
    // we got here, the transaction is already unusable or was deliberately
    // cancelled, so a ROLLBACK is pointless or will race the cancel; the
    // connection is destroyed below anyway.
    //
    // When, instead, a statement threw, always attempt ROLLBACK so server-side
    // transaction resources (locks, snapshots, tuple locks) are unwound before
    // the connection is reused. Swallow a secondary ROLLBACK failure so the
    // caller sees the original, more useful error.
    if (!connectionError) await db.query('ROLLBACK').catch(() => {});
    throw connectionError ?? error;
  } finally {
    // Release with the failure flag so a connection left in a bad state by a
    // transport-level error is destroyed rather than returned to the pool,
    // where a future caller would otherwise inherit an unusable connection.
    if (!client) db.release(failed);
    db.removeListener('error', onError);
    options.signal?.removeEventListener('abort', onAbort);
  }
}
export async function put(db: Db, kind: string, id: string, data: unknown) {
  await db.query(
    'INSERT INTO records(kind,id,data) VALUES($1,$2,$3) ON CONFLICT(kind,id) DO UPDATE SET data=EXCLUDED.data,updated_at=now()',
    [kind, id, JSON.stringify(data)],
  );
}
export async function putMany(db: Db, kind: string, items: { id: string; data: unknown }[]) {
  // PostgreSQL permits at most 65,535 bind parameters. Bound statement size as
  // well, and coalesce repeated IDs so a batch never updates one row twice.
  // Sort by id to guarantee deterministic row lock acquisition order across concurrent transactions.
  const unique = [...new Map(items.map((item) => [item.id, item])).values()].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  );
  for (let offset = 0; offset < unique.length; offset += 1000) {
    const values: unknown[] = [];
    const params = unique.slice(offset, offset + 1000).map((item, index) => {
      values.push(kind, item.id, JSON.stringify(item.data));
      const first = index * 3 + 1;
      return `($${first},$${first + 1},$${first + 2})`;
    });
    await db.query(
      `INSERT INTO records(kind,id,data) VALUES${params.join(',')} ON CONFLICT(kind,id) DO UPDATE SET data=EXCLUDED.data,updated_at=now() WHERE records.data IS DISTINCT FROM EXCLUDED.data`,
      values,
    );
  }
}
export async function get<T>(db: Db, kind: string, id: string): Promise<T | undefined> {
  return (await db.query('SELECT data FROM records WHERE kind=$1 AND id=$2', [kind, id])).rows[0]?.data;
}
/**
 * Fetch multiple records of the same kind in a single query. Returns a map of
 * id -> data for all ids that exist. Used to collapse N+1 read patterns.
 */
export async function getMany<T>(db: Db, kind: string, ids: readonly string[]): Promise<Map<string, T>> {
  if (!ids.length) return new Map();
  const rows = await db.query<{ id: string; data: T }>(
    'SELECT id,data FROM records WHERE kind=$1 AND id = ANY($2::text[])',
    [kind, [...ids]],
  );
  return new Map(rows.rows.map((row) => [row.id, row.data]));
}
/**
 * Reads a record while holding a row-level lock. Command handlers use this for
 * read-modify-write sequences so two concurrent operators cannot overwrite each
 * other's changes without taking the installation-wide lock.
 */
export async function getForUpdate<T>(db: Db, kind: string, id: string): Promise<T | undefined> {
  return (await db.query('SELECT data FROM records WHERE kind=$1 AND id=$2 FOR UPDATE', [kind, id])).rows[0]
    ?.data;
}
/**
 * `getMany` with a row lock on every returned record.
 *
 * The batch counterpart of `getForUpdate`, for a read-modify-write that touches
 * several records of one kind. The caller must be inside a transaction (a lock
 * taken on a pooled connection is released when the statement ends).
 *
 * Rows are locked in a fixed `id` order. PostgreSQL locks rows in the order the
 * executor visits them, so two processes that lock the same set through a
 * different plan or order can deadlock (`40P01`); pinning the order here makes
 * every caller traverse them identically. The caller must also deduplicate the
 * requested ids, since `= ANY` visits each id once but a duplicate in the
 * returned map is meaningless.
 */
export async function getManyForUpdate<T>(
  db: Db,
  kind: string,
  ids: readonly string[],
): Promise<Map<string, T>> {
  if (!ids.length) return new Map();
  const rows = await db.query<{ id: string; data: T }>(
    'SELECT id,data FROM records WHERE kind=$1 AND id = ANY($2::text[]) ORDER BY id FOR UPDATE',
    [kind, [...ids]],
  );
  return new Map(rows.rows.map((row) => [row.id, row.data]));
}
export async function list<T>(db: Db, kind: string, limit?: number): Promise<T[]> {
  const safeLimit =
    typeof limit === 'number' && Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : null;
  return (
    await db.query(
      safeLimit !== null
        ? `SELECT data FROM records WHERE kind=$1 ${recordOrder} LIMIT $2`
        : `SELECT data FROM records WHERE kind=$1 ${recordOrder}`,
      safeLimit !== null ? [kind, safeLimit] : [kind],
    )
  ).rows.map((row) => row.data);
}
export async function remove(db: Db, kind: string, id: string) {
  return (await db.query('DELETE FROM records WHERE kind=$1 AND id=$2', [kind, id])).rowCount;
}
/** Batch delete of many records of one kind, in one parameterised statement
 * (audit finding #10). One round trip for N ids instead of N round trips;
 * used for the alias-reconciliation sweep, which can remove hundreds of rows
 * per run. An empty input is a no-op. */
export async function removeMany(db: Db, kind: string, ids: readonly string[]): Promise<number> {
  if (!ids.length) return 0;
  return (
    (await db.query('DELETE FROM records WHERE kind=$1 AND id = ANY($2::text[])', [kind, [...ids]]))
      .rowCount ?? 0
  );
}
export async function appendAudit(
  db: Db,
  event: string,
  details: string,
  actor: string,
  category: AuditLog['category'] = 'SECURITY',
  level: AuditLog['level'] = 'INFO',
  ipAddress: string = '',
  context?: Partial<NonNullable<AuditLog['context']>>,
): Promise<void> {
  // Outside a transaction, wrap the read/insert pair so the audit lock is held
  // for the whole operation instead of being released after the lock statement.
  if (db instanceof pg.Pool)
    return transaction(db, (tx) =>
      appendAudit(tx, event, details, actor, category, level, ipAddress, context),
    );
  // The audit chain is a single linked list; a dedicated named lock serializes
  // only audit appends instead of every state mutation in the installation.
  await db.query(`SELECT pg_advisory_xact_lock(hashtext($1), ${schemaLockKey})`, ['audit-chain']);
  // Plain SELECT (no row lock). pg_advisory_xact_lock above already serializes
  // all audit-append calls per schema, so a row lock here was redundant; dropping
  // it lets the least-privilege runtime role read the chain head with table SELECT
  // only and never requires UPDATE on the tamper-sensitive audit table.
  const previous = (await db.query('SELECT data FROM audit ORDER BY seq DESC LIMIT 1')).rows[0]?.data;
  const entry = chainAuditLogs(
    [
      {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        category,
        level,
        event: auditText(event, 200),
        details: auditText(details, 12000),
        actor: auditText(actor, 160) || 'system',
        ipAddress: auditText(ipAddress, 128),
        context: auditContext(context, level),
        prevHash: '',
        hash: '',
      },
    ],
    previous?.hash,
  )[0];
  await db.query('INSERT INTO audit(data) VALUES($1)', [JSON.stringify(entry)]);
}
export interface StateOptions {
  /**
   * Maximum rows returned for a heavy collection. Omit a kind to return all of
   * its rows (internal callers only). `/api/state` always supplies limits.
   */
  limits?: Partial<Record<HeavyCollectionKind, number>>;
}

export async function verifyStoredAudit(pool: pg.Pool, signal?: AbortSignal) {
  return transaction(
    pool,
    async (db) => {
      await db.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
      await db.query(
        'DECLARE audit_chain_cursor NO SCROLL CURSOR FOR SELECT data FROM audit ORDER BY seq ASC',
      );
      let previousHash: string | undefined;
      let verified = true;
      let logCount = 0;
      while (true) {
        signal?.throwIfAborted();
        const batch = await db.query<{ data: AuditLog }>('FETCH FORWARD 256 FROM audit_chain_cursor');
        if (!batch.rowCount) break;
        for (const { data: log } of batch.rows) {
          verified =
            /^[a-f0-9]{64}$/.test(log.hash) &&
            log.hash === hashAuditLog(log) &&
            (previousHash === undefined || log.prevHash === previousHash) &&
            verified;
          previousHash = log.hash;
          logCount++;
        }
      }
      await db.query('CLOSE audit_chain_cursor');
      await db.query(`DECLARE audit_hash_cursor NO SCROLL CURSOR FOR
      SELECT data->>'hash' AS hash FROM audit ORDER BY (data->>'hash') COLLATE "C",seq`);
      const root = new SortedMerkleAccumulator();
      while (true) {
        signal?.throwIfAborted();
        const batch = await db.query<{ hash: string }>('FETCH FORWARD 256 FROM audit_hash_cursor');
        if (!batch.rowCount) break;
        for (const row of batch.rows) root.add(String(row.hash ?? ''));
      }
      await db.query('CLOSE audit_hash_cursor');
      return { verified, merkleRoot: root.root(), logCount };
    },
    undefined,
    { signal },
  );
}

const recordOrder = "ORDER BY CASE WHEN kind='feeds' THEN created_at ELSE updated_at END DESC,id";

export async function state(db: Db, options: StateOptions = {}): Promise<AppState> {
  const snapshot = emptyState();
  const arrayKinds = Object.entries(snapshot)
    .filter(([, value]) => Array.isArray(value))
    .map(([kind]) => kind)
    .filter((kind) => kind !== 'auditLogs');
  const limits = options.limits ?? {};
  const bounded = Object.entries(limits)
    .filter(([, limit]) => typeof limit === 'number' && limit >= 0)
    .map(([kind]) => kind)
    .filter((kind) => kind !== 'auditLogs') as HeavyCollectionKind[];
  const boundedSet = new Set<string>(bounded);
  const rows: { kind: string; data: unknown }[] = [];
  const unbounded = arrayKinds.filter((kind) => !boundedSet.has(kind));
  if (unbounded.length)
    rows.push(
      ...(
        await db.query(`SELECT kind,data FROM records WHERE kind=ANY($1::text[]) ${recordOrder}`, [unbounded])
      ).rows,
    );
  // Batch all bounded heavy-collection fetches into a single query using a
  // ROW_NUMBER() window. Per-kind limits are applied via a CASE expression so
  // each collection respects its own bound without a separate query.
  if (bounded.length) {
    const kinds = bounded;
    const limitValues = kinds.map((kind) => Math.max(0, Math.floor(limits[kind]!)));
    const limitCase = kinds
      .map((kind, i) => `WHEN '${kind.replace(/'/g, "''")}' THEN $${i + 2}::int`)
      .join(' ');
    rows.push(
      ...(
        await db.query<{ kind: string; data: unknown }>(
          `SELECT kind,data FROM (
            SELECT kind,data,ROW_NUMBER() OVER (PARTITION BY kind ORDER BY ${recordOrder.slice(9)}) AS rn
            FROM records WHERE kind=ANY($1::text[])
          ) ranked WHERE rn <= CASE kind ${limitCase} ELSE 0 END`,
          [kinds, ...limitValues],
        )
      ).rows,
    );
  }
  // Audit rows live in their own append-only table. Keep the historical 500-row
  // default for internal snapshots; the browser always supplies an explicit limit.
  const auditLimit = limits.auditLogs === undefined ? 500 : Math.max(0, Math.floor(limits.auditLogs));
  if (auditLimit)
    rows.push(
      ...(await db.query('SELECT data FROM audit ORDER BY seq DESC LIMIT $1', [auditLimit])).rows.map(
        (row) => ({ kind: 'auditLogs', data: row.data }),
      ),
    );
  rows.push(
    ...(
      await db.query('SELECT kind,data FROM records WHERE kind=ANY($1::text[])', [
        ['settings', 'emailConfig', 'template'],
      ])
    ).rows,
  );
  for (const row of rows) {
    if (Array.isArray(snapshot[row.kind as keyof AppState]))
      (snapshot[row.kind as keyof AppState] as unknown[]).push(row.data);
    else if (row.kind === 'settings') snapshot.settings = row.data as AppState['settings'];
    else if (row.kind === 'emailConfig') snapshot.emailConfig = row.data as AppState['emailConfig'];
    else if (row.kind === 'template') Object.assign(snapshot, row.data);
  }
  // Keep inventory position tied to original creation time. PostgreSQL record
  // updates change updated_at, so using the generic query order made edits jump
  // to the top of the monitored-products table.
  snapshot.watchlist = orderWatchlist(snapshot.watchlist);
  // Keep a hand-authored template authoritative; installations without one use
  // the canonical product HTML shared with Template Studio.
  snapshot.advisoryTemplate = snapshot.customAdvisoryTemplate || DEFAULT_ADVISORY_EMAIL_TEMPLATE;
  snapshot.dailyDigestTemplate =
    snapshot.dailyDigestCustomTemplate ||
    cachedCompileTemplate(
      `dailyDigest:${JSON.stringify(snapshot.dailyDigestCustomization || DEFAULT_DAILY_DIGEST_CUSTOMIZATION)}`,
      () => compileDailyDigestTemplate(snapshot.dailyDigestCustomization || DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
    );
  snapshot.newsDigestTemplate =
    snapshot.newsDigestCustomTemplate ||
    cachedCompileTemplate(
      `newsDigest:${JSON.stringify(snapshot.newsDigestCustomization || DEFAULT_NEWS_EMAIL_CUSTOMIZATION)}`,
      () => compileNewsTemplate(snapshot.newsDigestCustomization || DEFAULT_NEWS_EMAIL_CUSTOMIZATION),
    );
  await attachCounts(db, snapshot);
  return snapshot;
}

/**
 * Exact collection sizes and KPI aggregates. They are computed independently of
 * the bounded arrays so a large installation still shows truthful totals.
 */
async function attachCounts(db: Db, snapshot: AppState) {
  const now = Date.now();
  let metrics: Map<string, number>;
  if (stateMetricsCache && now < stateMetricsCache.expiresAt) {
    metrics = stateMetricsCache.metrics;
  } else {
    const rows = await db.query<{ name: string; value: string }>('SELECT name,value FROM state_metrics');
    metrics = new Map(rows.rows.map((row) => [row.name, Number(row.value)]));
    stateMetricsCache = { metrics, expiresAt: now + STATE_METRICS_CACHE_TTL_MS };
  }
  for (const kind of COLLECTION_KINDS) snapshot.counts[kind] = metrics.get(`collection:${kind}`) ?? 0;
  snapshot.summary = {
    activeFindings: metrics.get('summary:activeFindings') ?? 0,
    criticalFindings: metrics.get('summary:criticalFindings') ?? 0,
    kevFindings: metrics.get('summary:kevFindings') ?? 0,
    deliveredEmails: metrics.get('summary:deliveredEmails') ?? 0,
  };
}

/** Pipeline-only snapshot avoids loading executions, delivery logs, recipients and audit history.
 *
 * The pipeline already holds the full corpus in memory (loaded once outside the
 * commit), so re-materializing the identical rows inside the commit doubled peak
 * memory and re-parsed every record. Other callers keep the unfiltered snapshot. */
export async function pipelineState(db: Db): Promise<AppState> {
  const snapshot = emptyState();
  const kinds: string[] = [
    'settings',
    'watchlist',
    'cveData',
    'findings',
    'alertedCves',
    'intelligenceArticles',
    'template',
  ];
  const rows = await db.query(
    'SELECT kind,data FROM records WHERE kind=ANY($1::text[]) ORDER BY updated_at DESC,id',
    [kinds],
  );
  for (const row of rows.rows) {
    if (Array.isArray(snapshot[row.kind as keyof AppState]))
      (snapshot[row.kind as keyof AppState] as unknown[]).push(row.data);
    else if (row.kind === 'settings') snapshot.settings = row.data;
    else if (row.kind === 'template') Object.assign(snapshot, row.data);
  }
  snapshot.advisoryTemplate = snapshot.customAdvisoryTemplate || DEFAULT_ADVISORY_EMAIL_TEMPLATE;
  snapshot.dailyDigestTemplate =
    snapshot.dailyDigestCustomTemplate ||
    cachedCompileTemplate(
      `dailyDigest:${JSON.stringify(snapshot.dailyDigestCustomization || DEFAULT_DAILY_DIGEST_CUSTOMIZATION)}`,
      () => compileDailyDigestTemplate(snapshot.dailyDigestCustomization || DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
    );
  snapshot.newsDigestTemplate =
    snapshot.newsDigestCustomTemplate ||
    cachedCompileTemplate(
      `newsDigest:${JSON.stringify(snapshot.newsDigestCustomization || DEFAULT_NEWS_EMAIL_CUSTOMIZATION)}`,
      () => compileNewsTemplate(snapshot.newsDigestCustomization || DEFAULT_NEWS_EMAIL_CUSTOMIZATION),
    );
  return snapshot;
}
