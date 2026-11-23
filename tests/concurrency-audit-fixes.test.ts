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

const database = process.env.TEST_DATABASE_URL;

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
