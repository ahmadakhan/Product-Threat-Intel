import type { Db } from './db.ts';
import type { NormalizedCVE, WatchListItem } from '../src/types/index.ts';
import type { NvdVersionRange } from '../src/utils/versionComparator.ts';
import type { QueryResult } from 'pg';
import {
  DEFAULT_PRODUCT_ALIASES,
  DEFAULT_VENDOR_ALIASES,
  aliasGroupKeys,
  normalizeAliasToken,
  parseCPE23,
  purlIdentity,
} from '../src/utils/cpeMatcher.ts';
import { cpePreFilter } from './ml/integration.ts';

/**
 * Typed version ordinal used by the PostgreSQL candidate index.
 *
 * Only plain dotted numeric versions are encoded. Anything else (prereleases,
 * distribution revisions, wildcards, non-numeric vendor tags) returns `null`,
 * which the index treats as "cannot exclude" so the authoritative JS matcher
 * still evaluates the pair. This keeps the index a conservative superset.
 *
 * Four components of at most four digits each are packed base-10000 into an
 * int8, preserving numeric ordering for the overwhelmingly common version
 * shapes without ever overflowing.
 */
const ORDINAL_BASE = 10_000n;
const ORDINAL_COMPONENTS = 4;
const ORDINAL_LIMIT = ORDINAL_BASE ** BigInt(ORDINAL_COMPONENTS);

export function versionOrdinal(version: string | undefined): bigint | null {
  if (!version) return null;
  const trimmed = version.trim().toLowerCase();
  if (!trimmed || trimmed === '*' || trimmed === '-') return null;
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$/.exec(trimmed);
  if (!match) return null;
  const parts: bigint[] = [];
  for (let index = 1; index <= ORDINAL_COMPONENTS; index++)
    parts.push(match[index] === undefined ? 0n : BigInt(match[index]));
  if (parts.some((part) => part >= ORDINAL_BASE)) return null;
  const ordinal = parts.reduce((acc, part) => acc * ORDINAL_BASE + part, 0n);
  return ordinal < ORDINAL_LIMIT ? ordinal : null;
}

const identityKey = (vendor: string, product: string) =>
  `cpe:${vendor.toLowerCase()}\u001f${product.toLowerCase()}`;

/** Package identity (`npm/express`) used to index PURL inventory. */
const purlKey = (purl: string): string | null => {
  // Canonical parser shared with the matcher and the JS engine (audit H-2):
  // the three copies could drift on scoped npm packages, which silently
  // excluded pairs from this pushdown that the matcher would have accepted.
  const identity = purlIdentity(purl);
  return identity ? `purl:${identity}` : null;
};

export interface MatchIndexOptions {
  vendorAliases?: Record<string, string[]>;
  productAliases?: Record<string, string[]>;
}

/**
 * Mirrors the pipeline's alias-expanded inventory index. Both built-in and
 * operator-managed aliases must participate; otherwise the index would exclude
 * a pair that the authoritative matcher accepts (for example
 * `microsoft`/`msft`).
 */
const aliasKeys = (
  value: string,
  base: Record<string, string[]>,
  aliases: Record<string, string[]> = {},
): string[] => [
  ...new Set([
    value.toLowerCase(),
    // The matcher's alias path ignores punctuation, so `widget_pro` joins
    // `widget-pro`. Index the normalized token or the pushdown drops the pair.
    normalizeAliasToken(value),
    ...aliasGroupKeys(value, base, aliases),
  ]),
];

function cpeIdentities(cpe: string, options: MatchIndexOptions): string[] {
  // The trained gate may skip full parsing for obviously malformed criteria;
  // if it is uncertain or untrained it always defers to the authoritative parser.
  if (!cpePreFilter(cpe)) return [];
  const parsed = parseCPE23(cpe);
  if (!parsed.isValid) return [];
  if (/[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) return [];
  const vendors = aliasKeys(parsed.vendor, DEFAULT_VENDOR_ALIASES, options.vendorAliases);
  const products = aliasKeys(parsed.product, DEFAULT_PRODUCT_ALIASES, options.productAliases);
  const identities = new Set<string>();
  for (const vendor of vendors)
    for (const product of products) identities.add(identityKey(vendor, product));
  return [...identities];
}

function declaredIdentityKeys(
  vendor: string,
  product: string,
  options: MatchIndexOptions,
): string[] {
  if (!vendor || !product) return [];
  const vendors = aliasKeys(vendor, DEFAULT_VENDOR_ALIASES, options.vendorAliases);
  const products = aliasKeys(product, DEFAULT_PRODUCT_ALIASES, options.productAliases);
  const identities = new Set<string>();
  for (const vendorKey of vendors)
    for (const productKey of products) identities.add(identityKey(vendorKey, productKey));
  return [...identities];
}

function assetIdentities(asset: WatchListItem, options: MatchIndexOptions): string[] {
  const identities = new Set<string>();
  // The operator-declared vendor/product is an authoritative identity in the
  // matcher's alias and prose paths. Index it alongside the CPE/PURL identities;
  // otherwise the SQL pushdown excludes an asset whose CPEs are stale, more
  // specific, or absent, and the worker never evaluates the pair.
  for (const identity of declaredIdentityKeys(asset.vendor, asset.product, options))
    identities.add(identity);
  for (const cpe of asset.cpes) for (const identity of cpeIdentities(cpe, options)) identities.add(identity);
  for (const purl of asset.purls ?? []) {
    const identity = purlKey(purl);
    if (identity) identities.add(identity);
  }
  return [...identities];
}

interface VersionBounds {
  unbounded: boolean;
  start: bigint | null;
  startInclusive: boolean;
  end: bigint | null;
  endInclusive: boolean;
}

const UNBOUNDED: VersionBounds = {
  unbounded: true,
  start: null,
  startInclusive: true,
  end: null,
  endInclusive: true,
};

/**
 * Derives the numeric bounds PostgreSQL can enforce. A declared bound that
 * cannot be encoded makes the whole criterion unbounded: dropping a pair is
 * only safe when every bound in play is provably ordered.
 */
function boundsFor(range: NvdVersionRange | undefined, criterionVersion?: string): VersionBounds {
  const hasRange = Boolean(
    range &&
      (range.versionStartIncluding ||
        range.versionStartExcluding ||
        range.versionEndIncluding ||
        range.versionEndExcluding),
  );
  if (hasRange && range) {
    const startText = range.versionStartIncluding ?? range.versionStartExcluding;
    const endText = range.versionEndIncluding ?? range.versionEndExcluding;
    const start = versionOrdinal(startText);
    const end = versionOrdinal(endText);
    if ((startText && start === null) || (endText && end === null)) return UNBOUNDED;
    return {
      unbounded: false,
      start,
      startInclusive: Boolean(range.versionStartIncluding),
      end,
      endInclusive: Boolean(range.versionEndIncluding),
    };
  }
  // No interval: the criterion's version token must match exactly. Wildcards
  // and unparseable tokens stay unbounded so the matcher decides.
  const exact = versionOrdinal(criterionVersion);
  if (exact === null) return UNBOUNDED;
  return { unbounded: false, start: exact, startInclusive: true, end: exact, endInclusive: true };
}

interface CveIndexRow {
  criterionId: string;
  identities: string[];
  bounds: VersionBounds;
}

function cveIndexRows(cve: NormalizedCVE, options: MatchIndexOptions): CveIndexRow[] | null {
  const rows: CveIndexRow[] = [];
  const details = cve.cpeMatchDetails?.length
    ? [
        ...cve.cpeMatchDetails.map((detail, index) => ({
          id: `cpe-${index}`,
          criteria: detail.criteria,
          // A per-detail criterion without bounds means "any version of this
          // product"; the product-level range must not leak onto it. This mirrors
          // the pipeline's applicabilitySets, so the index cannot exclude a pair
          // the matcher would accept.
          range:
            detail.range && Object.values(detail.range).some(Boolean) ? detail.range : undefined,
        })),
        // `cpeMatches` can carry criteria that `cpeMatchDetails` does not list.
        // They are still affected products, matched with the product-level range
        // by the engine, so the pushdown must index them too or the SQL join
        // would drop the pair before the matcher sees it.
        ...cve.cpeMatches
          .filter((criteria) => !cve.cpeMatchDetails!.some((detail) => detail.criteria === criteria))
          .map((criteria, index) => ({
            id: `cpe-extra-${index}`,
            criteria,
            range: cve.versionRange,
          })),
      ]
    : cve.cpeMatches.map((criteria, index) => ({
        id: `cpe-${index}`,
        criteria,
        range: cve.versionRange,
      }));
  for (const detail of details) {
    const identities = cpeIdentities(detail.criteria, options);
    // A wildcard or invalid criterion can match any inventory item; the worker
    // must fall back to its full candidate set for this CVE.
    if (!identities.length) return null;
    const parsed = parseCPE23(detail.criteria);
    rows.push({
      criterionId: detail.id,
      identities,
      bounds: boundsFor(detail.range, parsed.isValid ? parsed.version : undefined),
    });
  }
  if (cve.purls?.length) {
    const identities = cve.purls.map(purlKey).filter((identity): identity is string => !!identity);
    if (identities.length)
      rows.push({
        criterionId: 'purl',
        identities,
        bounds: boundsFor(cve.versionRange),
      });
  }
  return rows.length ? rows : null;
}

interface AssetIndexRow {
  assetId: string;
  identities: string[];
  version: bigint | null;
}

function purlVersion(purl: string): string | null {
  const match = /^pkg:([a-z][a-z0-9.+-]*)\/([^?#]+)/.exec(purl.trim());
  if (!match) return null;
  const path = match[2];
  const at = path.lastIndexOf('@');
  const versionAt = at > path.indexOf('/') + 1 ? at : -1;
  return versionAt > 0 ? path.slice(versionAt + 1) : null;
}

/**
 * Derives one conservative version ordinal for an asset row.
 *
 * The asset index has a single ordinal, but an inventory entry can carry
 * several CPEs and PURLs with different versions. Using the declared
 * `asset.version` blindly would let the SQL pushdown drop a pair whose matching
 * CPE or package is inside the advisory range but whose declared version
 * differs. Only a version every concrete identifier agrees on is safe to use
 * for exclusion; anything ambiguous becomes NULL, which the query treats as
 * "cannot exclude".
 */
function assetVersionOrdinal(asset: WatchListItem): bigint | null {
  const declared = versionOrdinal(asset.version);
  const ordinals: bigint[] = [];
  for (const cpe of asset.cpes) {
    const parsed = parseCPE23(cpe);
    if (!parsed.isValid) continue;
    if (/[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) return null;
    if (!parsed.version || parsed.version === '*' || parsed.version === '-') return null;
    const ordinal = versionOrdinal(parsed.version);
    if (ordinal === null) return null;
    ordinals.push(ordinal);
  }
  for (const purl of asset.purls ?? []) {
    const version = purlVersion(purl);
    if (!version) return null;
    const ordinal = versionOrdinal(version);
    if (ordinal === null) return null;
    ordinals.push(ordinal);
  }
  if (!ordinals.length) return declared;
  const first = ordinals[0];
  if (ordinals.some((ordinal) => ordinal !== first)) return null;
  if (declared !== null && declared !== first) return null;
  return first;
}

function assetIndexRows(assets: WatchListItem[], options: MatchIndexOptions): AssetIndexRow[] {
  return assets
    .filter((asset) => asset.active)
    .map((asset) => ({
      assetId: asset.id,
      identities: assetIdentities(asset, options),
      version: assetVersionOrdinal(asset),
    }));
}

/**
 * Retry policy for index maintenance.
 *
 * Both values are operator-configurable because the correct budget depends on
 * deployment size: a 15,000-CVE corpus under contention needs far more attempts
 * than a 200-CVE one. Defaults are deliberately generous; the per-attempt work
 * is idempotent, so a longer budget can only delay a run, never duplicate it.
 *
 * `MATCH_INDEX_RETRIES` counts retries AFTER the first attempt.
 * `MATCH_INDEX_RETRY_BASE_MS` is the first backoff; it doubles per attempt.
 * `MATCH_INDEX_RETRY_MAX_MS` caps a single backoff.
 */
const STATEMENT_TIMEOUT_CODE = '57014';
const LOCK_TIMEOUT_CODE = '55P03';
const ABORTED_TX_CODE = '25P02';
const SERIALIZATION_CODE = '40001';
const DEADLOCK_CODE = '40P01';

/** Codes where retrying can succeed: the statement, not the data, was rejected. */
const RETRYABLE_CODES = new Set([
  STATEMENT_TIMEOUT_CODE,
  LOCK_TIMEOUT_CODE,
  SERIALIZATION_CODE,
  DEADLOCK_CODE,
]);

const boundedInt = (raw: string | undefined, fallback: number, min: number, max: number): number => {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
};

const MAX_STATEMENT_RETRIES = boundedInt(process.env.MATCH_INDEX_RETRIES, 8, 0, 50);
const STATEMENT_RETRY_BASE_MS = boundedInt(process.env.MATCH_INDEX_RETRY_BASE_MS, 250, 10, 30_000);
const STATEMENT_RETRY_MAX_MS = boundedInt(process.env.MATCH_INDEX_RETRY_MAX_MS, 10_000, 100, 300_000);

/**
 * Runs one idempotent statement with bounded, jittered retries.
 *
 * Retried: statement timeout (57014), lock timeout (55P03), serialization
 * failure (40001) and deadlock (40P01). Every one of these means *this attempt*
 * was rejected, not that the data is wrong, and every statement this helper
 * guards is an idempotent upsert or a set-based delete, so re-running it cannot
 * duplicate or lose work.
 *
 * Not retried: anything else. In particular `25P02` (aborted transaction) is a
 * programming fault - the transaction was already dead before this statement -
 * and retrying it would only spin. A permission error likewise cannot resolve
 * itself and must surface immediately.
 *
 * A statement timeout aborts the enclosing transaction, so each attempt runs
 * under its own SAVEPOINT and a failure rolls back to it before the retry. A
 * pool connection is in autocommit mode and needs none of this.
 *
 * Jitter is mandatory, not cosmetic: without it, every chunk of every replica
 * retries on the same schedule against the same contended rows and reproduces
 * the contention that caused the timeout. Backoff is capped so a large budget
 * still converges within the run budget.
 */
let statementSavepointSequence = 0;

async function withStatementTimeoutRetry(
  db: Db,
  query: string,
  values: unknown[] = [],
  maxRetries: number = MAX_STATEMENT_RETRIES,
): Promise<QueryResult<Record<string, unknown>>> {
  const inTransaction = typeof (db as { release?: unknown }).release === 'function';
  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const savepoint = `stmt_retry_${statementSavepointSequence++}`;
    try {
      if (inTransaction) await db.query(`SAVEPOINT ${savepoint}`);
      const result = await db.query(query, values);
      if (inTransaction) await db.query(`RELEASE SAVEPOINT ${savepoint}`);
      return result;
    } catch (error) {
      const code = (error as { code?: string })?.code;
      if (inTransaction) {
        // Restore a usable transaction before deciding whether to retry. If the
        // rollback itself fails the connection is unusable, so surface the
        // original error rather than masking it.
        try {
          await db.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
          await db.query(`RELEASE SAVEPOINT ${savepoint}`);
        } catch {
          throw error;
        }
      }
      if (!code || !RETRYABLE_CODES.has(code) || attempt === maxRetries) {
        lastError = error;
        break;
      }
      // Exponential with full jitter, capped: `base * 2^n` scaled by a random
      // factor in [0.5, 1.5] so concurrent writers de-synchronize.
      const exponential = Math.min(STATEMENT_RETRY_MAX_MS, STATEMENT_RETRY_BASE_MS * 2 ** attempt);
      const backoffMs = Math.round(exponential * (0.5 + Math.random()));
      await new Promise((resolve) => setTimeout(resolve, backoffMs));
    }
  }
  throw lastError;
}

/**
 * Refreshes the candidate index from the current corpus and inventory. The
 * pipeline already loads both in full, so a scoped refresh is cheaper and more
 * predictable than wiring index maintenance into every generic record write.
 */
export async function syncMatchIndex(
  db: Db,
  cves: NormalizedCVE[],
  assets: WatchListItem[],
  options: MatchIndexOptions = {},
): Promise<void> {
  const assetRows = assetIndexRows(assets, options);
  const cveRows: {
    cveId: string;
    criterionId: string;
    identities: string[];
    bounds: VersionBounds;
  }[] = [];
  for (const cve of cves) {
    const rows = cveIndexRows(cve, options);
    if (!rows) continue;
    for (const row of rows)
      cveRows.push({
        cveId: cve.cveId,
        criterionId: row.criterionId,
        identities: row.identities,
        bounds: row.bounds,
      });
  }

  // Set-based refresh, not per-row chunks.
  //
  // The previous version issued ceil(rows/100) separate statements per table
  // (~150 round trips for a 15,000-CVE corpus) inside one transaction. Each
  // statement re-dirtied the GIN index and re-took tuple locks, so cost grew
  // with corpus size AND contention: measured 3-32ms per chunk when idle and
  // 100+ seconds under a concurrent run, which blew the statement budget on
  // every run and rolled the run back. Two statements per table now do the same
  // work in one plan.
  //
  // Rows travel as one JSON payload rather than parallel arrays: node-pg cannot
  // serialise an array-of-arrays literal (identities is text[]), which made the
  // naive `unnest($2::text[])` form either lose the inner dimension or raise
  // "malformed array literal". `jsonb_to_recordset` carries the nested value
  // faithfully and PostgreSQL casts it once, server-side.
  //
  // Upsert + set-based delete (never TRUNCATE): the application role holds
  // INSERT/UPDATE/DELETE but not TRUNCATE on these tables. Both statements are
  // idempotent, so the retry helper can safely re-run them.
  await withStatementTimeoutRetry(
    db,
    `INSERT INTO match_asset_index(asset_id,identities,version_ordinal)
     SELECT asset_id, identities, version_ordinal
       FROM jsonb_to_recordset($1::jsonb)
         AS t(asset_id text, identities text[], version_ordinal bigint)
     ON CONFLICT(asset_id) DO UPDATE SET identities=EXCLUDED.identities,
       version_ordinal=EXCLUDED.version_ordinal,updated_at=now()`,
    [
      JSON.stringify(
        assetRows.map((row) => ({
          asset_id: row.assetId,
          identities: row.identities,
          version_ordinal: row.version === null ? null : row.version.toString(),
        })),
      ),
    ],
  );
  await withStatementTimeoutRetry(
    db,
    'DELETE FROM match_asset_index WHERE NOT (asset_id = ANY($1::text[]))',
    [assetRows.map((row) => row.assetId)],
  );

  await withStatementTimeoutRetry(
    db,
    `INSERT INTO match_cve_index(cve_id,criterion_id,identities,start_ordinal,start_inclusive,end_ordinal,end_inclusive,unbounded)
     SELECT cve_id, criterion_id, identities, start_ordinal, start_inclusive, end_ordinal, end_inclusive, unbounded
       FROM jsonb_to_recordset($1::jsonb)
         AS t(cve_id text, criterion_id text, identities text[], start_ordinal bigint,
              start_inclusive boolean, end_ordinal bigint, end_inclusive boolean, unbounded boolean)
     ON CONFLICT(cve_id,criterion_id) DO UPDATE SET identities=EXCLUDED.identities,
       start_ordinal=EXCLUDED.start_ordinal,start_inclusive=EXCLUDED.start_inclusive,
       end_ordinal=EXCLUDED.end_ordinal,end_inclusive=EXCLUDED.end_inclusive,
       unbounded=EXCLUDED.unbounded,updated_at=now()`,
    [
      JSON.stringify(
        cveRows.map((row) => ({
          cve_id: row.cveId,
          criterion_id: row.criterionId,
          identities: row.identities,
          start_ordinal: row.bounds.start === null ? null : row.bounds.start.toString(),
          start_inclusive: row.bounds.startInclusive,
          end_ordinal: row.bounds.end === null ? null : row.bounds.end.toString(),
          end_inclusive: row.bounds.endInclusive,
          unbounded: row.bounds.unbounded,
        })),
      ),
    ],
  );
  await withStatementTimeoutRetry(
    db,
    `DELETE FROM match_cve_index
      WHERE NOT (cve_id = ANY($1::text[]))
         OR NOT ((cve_id, criterion_id) IN (
              SELECT cve_id, criterion_id
                FROM unnest($1::text[], $2::text[]) AS t(cve_id, criterion_id)
            ))`,
    // Both arrays must be positionally aligned. De-duplicating the CVE ids here
    // would zip them against a longer criterion array and delete every criterion
    // after the first one for a multi-criterion CVE.
    [cveRows.map((row) => row.cveId), cveRows.map((row) => row.criterionId)],
  );
}

/**
 * Returns the plausible `(cveId, assetId)` pairs for the current index. The
 * query is the pushdown: identity arrays are joined with GIN, and the typed
 * ordinals exclude only pairs whose version is provably outside the interval.
 */
export async function buildCandidatePairs(
  db: Db,
): Promise<Map<string, Set<string>>> {
  const result = await withStatementTimeoutRetry(
    db,
    `SELECT DISTINCT c.cve_id, a.asset_id
       FROM match_cve_index c
       JOIN match_asset_index a ON a.identities && c.identities
      WHERE c.unbounded
         OR a.version_ordinal IS NULL
         OR (
              (c.start_ordinal IS NULL
                OR a.version_ordinal > c.start_ordinal
                OR (c.start_inclusive AND a.version_ordinal = c.start_ordinal))
              AND
              (c.end_ordinal IS NULL
                OR a.version_ordinal < c.end_ordinal
                OR (c.end_inclusive AND a.version_ordinal = c.end_ordinal))
            )`,
  );
  const pairs = new Map<string, Set<string>>();
  for (const row of result.rows as { cve_id: string; asset_id: string }[]) {
    const bucket = pairs.get(row.cve_id) || new Set<string>();
    bucket.add(row.asset_id);
    pairs.set(row.cve_id, bucket);
  }
  return pairs;
}

/** Refresh the index and return the candidate pairs in one call. */
export async function refreshCandidatePairs(
  db: Db,
  cves: NormalizedCVE[],
  assets: WatchListItem[],
  options: MatchIndexOptions = {},
): Promise<Map<string, Set<string>>> {
  await syncMatchIndex(db, cves, assets, options);
  return buildCandidatePairs(db);
}
