/**
 * Regression tests for the "executions keep running and stop does nothing" defect.
 *
 * Two failures compounded:
 *
 *  1. Cancelling a RUNNING execution only wrote `stopRequestedAt`. That works
 *     only when a live worker reaches a checkpoint and notices it. When the
 *     worker crashed, was detached by the stall watchdog, or lost its lock
 *     connection, nothing ever rewrote the row.
 *
 *  2. `queueRun()` treats ANY RUNNING row as the active run and returns it, so a
 *     single orphaned row wedged the pipeline permanently - and the crash
 *     recovery that would clear it lives inside `processPipeline`, which the
 *     stuck row prevented from starting. A cycle.
 *
 * The fix keys ownership off the run's own advisory lock (`pg_locks`), which
 * cannot be stale: the lock is released only when the holding session ends.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createPool, migrate, put, get } from '../server/db.ts';
import {
  stopRun,
  queueRun,
  releaseOrphanedRunningExecutions,
} from '../server/pipeline.ts';

const database = process.env.TEST_DATABASE_URL;

const RUN_LOCK_KEY = 'hashtext(COALESCE(current_schema(), current_database()))';

async function withSchema(fn: (pool: ReturnType<typeof createPool>) => Promise<void>) {
  const base = createPool(database!);
  const schema = 'pipeline_stop_' + randomBytes(8).toString('hex');
  await base.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema},public`);
  const pool = createPool(url.href);
  try {
    await migrate(pool);
    await fn(pool);
  } finally {
    await pool.end();
    await base.end();
  }
}

async function seedRunning(pool: ReturnType<typeof createPool>, name: string): Promise<string> {
  const id = randomUUID();
  await put(pool, 'executions', id, {
    id,
    name,
    startTime: new Date().toISOString(),
    endTime: null,
    status: 'RUNNING',
    scopeHours: 24,
    incrementalFeeds: true,
    phases: [{ name: 'Feed ingestion', status: 'RUNNING', durationMs: 0, details: '' }],
    stats: {},
    logs: [],
  });
  return id;
}

/** Hold the run lock, as a live worker would for the whole run. */
async function holdRunLock(pool: ReturnType<typeof createPool>) {
  const holder = await pool.connect();
  await holder.query(`SELECT pg_advisory_lock(800003, ${RUN_LOCK_KEY})`);
  return async () => {
    await holder.query(`SELECT pg_advisory_unlock(800003, ${RUN_LOCK_KEY})`).catch(() => undefined);
    holder.release();
  };
}

test(
  'stopping an orphaned RUNNING execution cancels it and unblocks the queue',
  { skip: !database },
  async () => {
    await withSchema(async (pool) => {
      const id = await seedRunning(pool, 'orphan');
      // No worker holds the run lock: this row has no owner.
      const stopped = await stopRun(pool, id, 'operator');

      assert.equal(stopped.status, 'CANCELLED', 'an ownerless run must be cancelled, not left RUNNING');
      assert.ok(stopped.endTime, 'a cancelled run must record its end time');
      assert.ok(stopped.stopRequestedAt, 'the stop must be recorded');
      assert.equal(
        stopped.phases[0].status,
        'CANCELLED',
        'in-flight phases must not be left RUNNING on a cancelled execution',
      );

      const persisted = await get<{ status: string }>(pool, 'executions', id);
      assert.equal(persisted?.status, 'CANCELLED');

      // The whole point: the queue must accept new work again.
      const next = await queueRun(pool, undefined, 'operator');
      assert.notEqual(next.id, id, 'queueRun must not return the cancelled execution');
      assert.equal(next.status, 'QUEUED', 'a fresh run must be queued');
    });
  },
);

test(
  'stopping a RUNNING execution owned by a live worker requests the stop instead of forcing it',
  { skip: !database },
  async () => {
    await withSchema(async (pool) => {
      const id = await seedRunning(pool, 'live');
      const release = await holdRunLock(pool);
      try {
        const stopped = await stopRun(pool, id, 'operator');
        assert.equal(
          stopped.status,
          'RUNNING',
          'a live run must be left for its worker to stop at the next checkpoint',
        );
        assert.ok(stopped.stopRequestedAt, 'the stop request must be persisted for the worker');
      } finally {
        await release();
      }
    });
  },
);

test(
  'the self-heal sweep clears orphans and never touches a run a live worker owns',
  { skip: !database },
  async () => {
    await withSchema(async (pool) => {
      const orphanA = await seedRunning(pool, 'orphan-a');
      const orphanB = await seedRunning(pool, 'orphan-b');
      const cleared = await releaseOrphanedRunningExecutions(pool, 'test sweep');
      assert.deepEqual(cleared.sort(), [orphanA, orphanB].sort());
      const remaining = await pool.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM records WHERE kind='executions' AND data->>'status'='RUNNING'",
      );
      assert.equal(remaining.rows[0].count, 0);

      // With a live worker holding the lock, the sweep must do nothing.
      const live = await seedRunning(pool, 'live');
      const release = await holdRunLock(pool);
      try {
        assert.deepEqual(await releaseOrphanedRunningExecutions(pool, 'test sweep'), []);
        assert.equal((await get<{ status: string }>(pool, 'executions', live))?.status, 'RUNNING');
      } finally {
        await release();
      }
    });
  },
);

test(
  'a crash-recovery sweep is idempotent and leaves terminal executions alone',
  { skip: !database },
  async () => {
    await withSchema(async (pool) => {
      const completedId = randomUUID();
      await put(pool, 'executions', completedId, {
        id: completedId,
        name: 'done',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        status: 'COMPLETED',
        scopeHours: 24,
        incrementalFeeds: true,
        phases: [],
        stats: {},
        logs: [],
      });

      assert.deepEqual(await releaseOrphanedRunningExecutions(pool, 'first'), []);
      assert.deepEqual(await releaseOrphanedRunningExecutions(pool, 'second'), []);
      assert.equal(
        (await get<{ status: string }>(pool, 'executions', completedId))?.status,
        'COMPLETED',
        'a terminal execution must never be rewritten by the sweep',
      );
    });
  },
);

test(
  'a queued run is cancelled immediately by a stop when no worker has picked it up',
  { skip: !database },
  async () => {
    await withSchema(async (pool) => {
      const queued = await queueRun(pool, 24, 'operator');
      assert.equal(queued.status, 'QUEUED');
      // No worker holds the run lock, so nothing will ever promote or finish it.
      const stopped = await stopRun(pool, queued.id, 'operator');
      assert.equal(stopped.status, 'CANCELLED');
      assert.ok(stopped.endTime);
      // A second stop is a no-op, not an error.
      assert.equal((await stopRun(pool, queued.id, 'operator')).status, 'CANCELLED');
    });
  },
);

test(
  'a queued run already claimed by a worker is left for that worker to stop',
  { skip: !database },
  async () => {
    await withSchema(async (pool) => {
      const queued = await queueRun(pool, 24, 'operator');
      // A worker has taken the run lock and is about to promote the row.
      const release = await holdRunLock(pool);
      try {
        const stopped = await stopRun(pool, queued.id, 'operator');
        assert.equal(stopped.status, 'QUEUED', 'a claimed run must not be yanked from under its worker');
        assert.ok(stopped.stopRequestedAt, 'the stop request must be waiting for the worker');
      } finally {
        await release();
      }
    });
  },
);
