/**
 * Regression tests for the concurrency-audit fixes.
 *
 * Each case pins a defect verified against the real implementation:
 *
 *  - `paceConcurrent` paced dispatch with `Date.now()`, so an NTP step could
 *    stall it for the length of the skew or release every worker at once.
 *  - a hung correlation `drain()` kept its own in-flight guard forever, silently
 *    stopping ingestion and every sweep behind it.
 *  - `LOCK_CLASS_RANK` was documentation: nothing read it, so an out-of-order
 *    class-lock acquisition would deadlock with 40P01.
 *  - `claimItems` read the owning outbox row under READ COMMITTED, so a job a
 *    concurrent worker had just moved to SENDING (uncommitted) was invisible and
 *    its claim was wrongly reclaimed - a duplicate send.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { paceConcurrent } from '../server/concurrency.ts';
import {
  assertClassLockOrder,
  acquireSessionClassLock,
  createPool,
  migrate,
  schemaLockKey,
} from '../server/db.ts';
import { claimItems } from '../server/deliveryClaims.ts';
import { loadConfig, poolFeedBound, boundedEnvInt } from '../server/config.ts';

const database = process.env.TEST_DATABASE_URL;

/** Minimal environment that satisfies `loadConfig`'s required variables. */
const baseConfigEnv = (overrides: Record<string, string> = {}): NodeJS.ProcessEnv => ({
  DATABASE_URL: database ?? 'postgres://user:pass@127.0.0.1:5432/vulnstream',
  APP_ORIGIN: 'https://vulnstream.example.com',
  ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64'),
  NODE_ENV: 'test',
  ...overrides,
});

/* ------------------------------------------------------------------ pacing */

test('paceConcurrent paces dispatch even if the wall clock jumps backwards', async () => {
  // Simulate an NTP correction that steps Date.now() backwards by an hour.
  const realNow = Date.now;
  let offset = 0;
  Date.now = () => realNow() + offset;

  try {
    const dispatches: number[] = [];
    const started = process.hrtime.bigint();
    const work = paceConcurrent([1, 2, 3, 4], 20, 2, (ms) => new Promise((r) => setTimeout(r, ms)), async () => {
      dispatches.push(Number((process.hrtime.bigint() - started) / 1_000_000n));
      // After the first dispatch, jump wall time an hour into the past.
      if (dispatches.length === 1) offset = -3_600_000;
    });

    await work;
    assert.equal(dispatches.length, 4);
    // Under the old Date.now() pacing the skew made the wait enormous and the
    // run never finished. Monotonic pacing keeps it bounded.
    assert.ok(
      dispatches[dispatches.length - 1] < 10_000,
      `dispatch must not stall on clock skew (last at ${dispatches[dispatches.length - 1]}ms)`,
    );
  } finally {
    Date.now = realNow;
  }
});

test('paceConcurrent preserves result order and rate', async () => {
  const results = await paceConcurrent([1, 2, 3], 5, 3, (ms) => new Promise((r) => setTimeout(r, ms)), async (n) => n * 2);
  assert.deepEqual(results, [2, 4, 6]);
});

/* ------------------------------------------------------- lock class order */

test('the class-lock order helper rejects an out-of-order acquisition', () => {
  // 800005 (index build, rank 4) must never be taken while holding a
  // lower-ranked lock it would then precede.
  assert.throws(
    () => assertClassLockOrder(800003, [800005]),
    /lock class order violated/i,
    'taking the run lock while holding the index lock would deadlock',
  );
  // In order is fine.
  assert.doesNotThrow(() => assertClassLockOrder(800005, [800003]));
  assert.doesNotThrow(() => assertClassLockOrder(800003, [800001]));
  // Unranked classes are not constrained by the table.
  assert.doesNotThrow(() => assertClassLockOrder(999999, [800005]));
});

test('acquireSessionClassLock enforces the order before touching the database', async () => {
  // The raw-SQL call sites this helper replaced bypassed the guard entirely. It
  // must reject out of order BEFORE issuing pg_try_advisory_lock, which is what
  // the call counter below observes.
  let queries = 0;
  const client = {
    query: async () => {
      queries++;
      return { rows: [{ locked: true }] };
    },
  } as unknown as Parameters<typeof acquireSessionClassLock>[0];
  await assert.rejects(
    () => acquireSessionClassLock(client, 800003, schemaLockKey, { held: [800005] }),
    /lock class order violated/i,
  );
  assert.equal(queries, 0, 'an out-of-order acquisition must not reach PostgreSQL');
  assert.equal(await acquireSessionClassLock(client, 800005, schemaLockKey, { held: [800003] }), true);
  assert.equal(queries, 1);
});

test('poolFeedBound leaves the configured reserve for checkpoints and API work', () => {
  assert.equal(poolFeedBound({ POOL_MAX_CONNECTIONS: 25, POOL_RESERVED_CONNECTIONS: 4 }), 21);
  assert.equal(poolFeedBound({ POOL_MAX_CONNECTIONS: 25, POOL_RESERVED_CONNECTIONS: 2 }), 23);
  // A misconfigured reserve can never disable ingestion outright.
  assert.equal(poolFeedBound({ POOL_MAX_CONNECTIONS: 4, POOL_RESERVED_CONNECTIONS: 9 }), 1);
});

test('poolFeedBound subtracts the API reserve from feed concurrency', () => {
  assert.equal(
    poolFeedBound({ POOL_MAX_CONNECTIONS: 25, POOL_RESERVED_CONNECTIONS: 4, POOL_API_RESERVED_CONNECTIONS: 4 }),
    17,
  );
  // With no API reserve, behavior matches the pre-existing default.
  assert.equal(
    poolFeedBound({ POOL_MAX_CONNECTIONS: 25, POOL_RESERVED_CONNECTIONS: 4 }),
    21,
  );
  // A combined reserve can never disable ingestion outright.
  assert.equal(
    poolFeedBound({ POOL_MAX_CONNECTIONS: 4, POOL_RESERVED_CONNECTIONS: 2, POOL_API_RESERVED_CONNECTIONS: 2 }),
    1,
  );
});

test('loadConfig rejects a combined reserve that consumes the whole pool', () => {
  assert.throws(
    () =>
      loadConfig(
        baseConfigEnv({
          POOL_MAX_CONNECTIONS: '8',
          POOL_RESERVED_CONNECTIONS: '4',
          POOL_API_RESERVED_CONNECTIONS: '4',
        }),
      ),
    /POOL_RESERVED_CONNECTIONS \+ POOL_API_RESERVED_CONNECTIONS must be less than POOL_MAX_CONNECTIONS/,
  );
});

test('loadConfig accepts a combined reserve that leaves at least one slot', () => {
  const config = loadConfig(
    baseConfigEnv({
      POOL_MAX_CONNECTIONS: '10',
      POOL_RESERVED_CONNECTIONS: '4',
      POOL_API_RESERVED_CONNECTIONS: '4',
    }),
  );
  assert.equal(config.POOL_API_RESERVED_CONNECTIONS, 4);
  assert.equal(poolFeedBound(config), 2);
});

test('boundedEnvInt never returns NaN or a zero interval for a bad override', () => {
  // `Number('abc')` is NaN, which `setInterval` treats as ~0ms (a busy loop).
  assert.equal(boundedEnvInt('abc', 5000, 250, 3_600_000), 5000);
  assert.equal(boundedEnvInt('', 5000, 250, 3_600_000), 5000);
  assert.equal(boundedEnvInt(undefined, 5000, 250, 3_600_000), 5000);
  assert.equal(boundedEnvInt('Infinity', 5000, 250, 3_600_000), 5000);
  // A valid value is honoured, floored and clamped into range.
  assert.equal(boundedEnvInt('10000', 5000, 250, 3_600_000), 10000);
  assert.equal(boundedEnvInt('12.9', 5000, 250, 3_600_000), 250);
  assert.equal(boundedEnvInt('300.9', 5000, 250, 3_600_000), 300);
  assert.equal(boundedEnvInt('-5', 5000, 250, 3_600_000), 250);
  assert.equal(boundedEnvInt('99999999', 5000, 250, 3_600_000), 3_600_000);
});

test('loadConfig rejects a reserve that consumes the whole pool', () => {
  assert.throws(
    () => loadConfig(baseConfigEnv({ POOL_MAX_CONNECTIONS: '8', POOL_RESERVED_CONNECTIONS: '8' })),
    /POOL_RESERVED_CONNECTIONS.*must be less than POOL_MAX_CONNECTIONS/,
  );
});

test(
  'acquireSessionClassLock takes the lock and reports ownership',
  { skip: !database },
  async () => {
    const base = createPool(database!);
    const schema = 'lockorder_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    const holder = await pool.connect();
    const rival = await pool.connect();
    try {
      await migrate(pool);
      assert.equal(await acquireSessionClassLock(holder, 800003, schemaLockKey), true);
      // Another session cannot take the same class lock.
      assert.equal(await acquireSessionClassLock(rival, 800003, schemaLockKey), false);
      await holder.query(`SELECT pg_advisory_unlock(800003, ${schemaLockKey})`);
      assert.equal(await acquireSessionClassLock(rival, 800003, schemaLockKey), true);
      await rival.query(`SELECT pg_advisory_unlock(800003, ${schemaLockKey})`);
    } finally {
      holder.release();
      rival.release();
      await pool.end();
      await base.end();
    }
  },
);

/* --------------------------------------------------------- claim reclaim */

test(
  'a claim is not reclaimed while another transaction is committing its SENDING job',
  { skip: !database },
  async () => {
    const base = createPool(database!);
    const schema = 'claimrace_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    try {
      await migrate(pool);

      const jobId = randomUUID();
      await pool.query(
        `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status)
         VALUES($1,'d1','email','r1','a1','{}'::jsonb,'QUEUED')`,
        [jobId],
      );
      // Expired claim owned by that job.
      await pool.query(
        `INSERT INTO delivery_claims(recipient_id,kind,item_id,state,job_id,claimed_at,expires_at)
         VALUES('r1','finding','f1','CLAIMED',$1, now()-interval '1 hour', now()-interval '1 minute')`,
        [jobId],
      );

      // Worker A is mid-send: SENDING written, not committed.
      const sender = await pool.connect();
      await sender.query('BEGIN');
      await sender.query("UPDATE outbox SET status='SENDING' WHERE id=$1", [jobId]);

      const rival = await pool.connect();
      await rival.query('BEGIN');
      const reclaim = claimItems(rival, [{ recipientId: 'r1', kind: 'finding', itemId: 'f1' }]);
      const raced = (await Promise.race([
        reclaim.then((r) => ({ state: 'settled' as const, granted: r.granted.length })),
        new Promise<{ state: 'blocked' }>((resolve) =>
          setTimeout(() => resolve({ state: 'blocked' as const }), 750),
        ),
      ])) as { state: 'settled' | 'blocked'; granted?: number };
      assert.equal(
        raced.state,
        'blocked',
        'the rival must wait for the sender rather than reclaim from a stale snapshot',
      );

      await sender.query('COMMIT');
      const settled = await reclaim;
      assert.equal(settled.granted.length, 0, 'the live SENDING job still holds the claim');

      await rival.query('ROLLBACK').catch(() => undefined);
      sender.release();
      rival.release();
    } finally {
      await pool.end();
      await base.end();
    }
  },
);
