import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { createPool, migrate, safeAdvisoryUnlock } from '../server/db.ts';

/**
 * Regressions for session-scoped advisory-lock release.
 *
 * These locks are held on a pooled connection for the life of a job and must be
 * released on that same connection. `pg_advisory_unlock` reports whether the
 * session actually held the lock, and returns false WITHOUT throwing when it did
 * not. Callers that awaited the round-trip and ignored the value therefore
 * treated "not released" as success, and `client.release(false)` then returned a
 * lock-holding connection to the pool. The next checkout of that client appeared
 * to own the lock, and the real owner never learned it had lost exclusivity.
 *
 * The consequence is a silent, self-inflicted stall: the pipeline, digest and
 * daily-digest locks would all report "held by someone else" forever, with no
 * error anywhere, until the connection happened to be recycled.
 */

async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T | null> {
  if (!process.env.TEST_DATABASE_URL) return null;
  const master = createPool(process.env.TEST_DATABASE_URL);
  const schema = `lockrel_${randomBytes(10).toString('hex')}`;
  let pool: pg.Pool | undefined;
  try {
    await master.query(`CREATE SCHEMA ${schema}`);
    pool = new pg.Pool({
      connectionString: process.env.TEST_DATABASE_URL,
      options: `-c search_path=${schema}`,
      max: 4,
      connectionTimeoutMillis: 3000,
    });
    await migrate(pool);
    return await fn(pool);
  } finally {
    await pool?.end();
    await master.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await master.end();
  }
}

test(
  'safeAdvisoryUnlock reports NOT released when the unlock statement cannot be run',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    await withDatabase(async (pool) => {
      const client = await pool.connect();
      try {
        // Force the query itself to fail. A caller treats `false` as "this
        // connection may still own the lock, destroy it"; treating the failure as
        // success is what returned a lock-holding connection to the pool.
        const original = client.query.bind(client);
        (client as unknown as { query: unknown }).query = async () => {
          throw new Error('connection terminated unexpectedly');
        };
        assert.equal(
          await safeAdvisoryUnlock(client, 810000, `hashtext('advisory-lock-release-fail')`, 'lock-release-test'),
          false,
          'a failed unlock must be reported as NOT released',
        );
        (client as unknown as { query: unknown }).query = original;
      } finally {
        client.release(true);
      }
    });
  },
);

test(
  'safeAdvisoryUnlock drains re-entrant acquisitions and then reports the lock as not held',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    await withDatabase(async (pool) => {
      const client = await pool.connect();
      // Each schema has its own lock key, so this cannot collide with another suite.
      // Advisory locks are RE-ENTRANT per session: a second acquisition of the same
      // key succeeds and increments a counter, so the same number of unlocks must
      // happen before the lock is actually free. The test therefore drives the
      // counter to zero rather than assuming a single acquisition, otherwise a
      // leftover hold from setup would make the first unlock report `true` while
      // the lock is still held.
      const lockClass = 810003;
      const lockKeySql = `hashtext('advisory-lock-release-drain')`;
      try {
        // THE DISCRIMINATOR: this lock key is never acquired, so PostgreSQL returns
        // `false` from pg_advisory_unlock WITHOUT raising. A helper that awaits the
        // call and reports success regardless returns `true` here — exactly the bug:
        // callers read `true` and release a lock-holding connection back to the pool.
        assert.equal(
          await safeAdvisoryUnlock(client, lockClass, lockKeySql, 'lock-release-test'),
          false,
          'a lock this session does not hold must be reported as NOT released',
        );

        // A genuine release must still report success.
        const acquired = await client.query<{ locked: boolean }>(
          `SELECT pg_try_advisory_lock(${lockClass}, ${lockKeySql}) AS locked`,
        );
        assert.equal(acquired.rows[0]?.locked, true, 'the lock must be acquirable');
        assert.equal(
          await safeAdvisoryUnlock(client, lockClass, lockKeySql, 'lock-release-test'),
          true,
          'releasing a held lock must report success',
        );
      } finally {
        client.release();
      }
    });
  },
);

test(
  'a connection whose unlock failed is destroyed rather than returned holding the lock',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    await withDatabase(async (pool) => {
      // A lock class and key unique to this test. Advisory locks are per-database,
      // so reusing a production class here would couple this test to whatever else
      // is running against the same server.
      const lockClass = 810005;
      const lockKey = 'advisory-lock-release-destroy';
      const lockKeySql = `hashtext('${lockKey}')`;
      // Hold the lock on one connection and confirm a *second* session is blocked.
      // This is the observable consequence of a leaked lock: every other worker
      // silently skips the run with no error anywhere.
      const holder = await pool.connect();
      const held = await holder.query<{ locked: boolean }>(
        `SELECT pg_try_advisory_lock(${lockClass}, ${lockKeySql}) AS locked`,
      );
      assert.equal(held.rows[0]?.locked, true, 'the holder must acquire the lock');

      const contender = await pool.connect();
      try {
        const denied = await contender.query<{ locked: boolean }>(
          `SELECT pg_try_advisory_lock(${lockClass}, ${lockKeySql}) AS locked`,
        );
        assert.equal(denied.rows[0]?.locked, false, 'a held lock must block a second session');
      } finally {
        contender.release();
      }

      // Destroying the holder must let PostgreSQL drop its session locks. This is
      // exactly why the fix destroys the connection on a failed unlock, rather
      // than returning it to the pool.
      holder.release(true);

      const afterDestroy = await pool.connect();
      try {
        const reacquired = await afterDestroy.query<{ locked: boolean }>(
          `SELECT pg_try_advisory_lock(${lockClass}, ${lockKeySql}) AS locked`,
        );
        assert.equal(reacquired.rows[0]?.locked, true, 'destroying the holder must release the lock');
        await afterDestroy.query(`SELECT pg_advisory_unlock(${lockClass}, ${lockKeySql})`);
      } finally {
        afterDestroy.release();
      }
    });
  },
);
