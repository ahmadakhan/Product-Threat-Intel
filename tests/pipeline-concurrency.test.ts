import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { createPool, get, migrate, put } from '../server/db.ts';
import { queueRun, stopRun } from '../server/pipeline.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';

/**
 * Operator-stop serialization.
 *
 * `stopRun` writes the execution row. It must take the same `pipeline-queue`
 * advisory lock a worker transaction takes, or it can interleave with a live run
 * and have its CANCELLED overwritten by the worker's own commit.
 */

const database = process.env.TEST_DATABASE_URL;

const SCHEMA_KEY = 'hashtext(COALESCE(current_schema(), current_database()))';

test(
  'an operator stop waits for the pipeline-queue lock instead of writing unsynchronised',
  { skip: !database },
  async () => {
    const admin = createPool(database!);
    const schema = `stoplock_${randomBytes(6).toString('hex')}`;
    await admin.query(`CREATE SCHEMA ${schema}`);
    const pool = new pg.Pool({ connectionString: database, options: `-c search_path=${schema}`, max: 4 });
    const holder = await (pool as pg.Pool).connect();
    try {
      await migrate(pool as never);
      await put(pool as never, 'settings', 'main', { ...DEFAULT_SETTINGS });
      const run = await queueRun(pool as never, 24, 'test');

      // Hold `pipeline-queue` the way a worker transaction does.
      await holder.query('BEGIN');
      await holder.query(`SELECT pg_advisory_xact_lock(hashtext($1), ${SCHEMA_KEY})`, ['pipeline-queue']);

      const outcome = await Promise.race([
        stopRun(pool as never, run.id, 'operator').then(() => 'completed'),
        new Promise((resolve) => setTimeout(() => resolve('blocked'), 1500)),
      ]);
      assert.equal(outcome, 'blocked', 'the stop must not write while the queue lock is held');

      // It also must not have written anything yet.
      const during = await get<{ status: string; stopRequestedAt?: string }>(pool as never, 'executions', run.id);
      assert.equal(during?.stopRequestedAt, undefined);

      await holder.query('ROLLBACK');

      // With the lock free it proceeds normally.
      await stopRun(pool as never, run.id, 'operator');
      const after = await get<{ status: string; stopRequestedAt?: string }>(pool as never, 'executions', run.id);
      assert.ok(after?.stopRequestedAt, 'the stop is recorded once the lock is available');
      assert.equal(after?.status, 'CANCELLED');
    } finally {
      await holder.query('ROLLBACK').catch(() => undefined);
      holder.release();
      await (pool as pg.Pool).end();
      await admin.query(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    }
  },
);
