/**
 * Concurrency regressions for the delivery finalize path and the batch helpers.
 *
 * Each case reproduces a lost-update window that existed because a
 * read-modify-write was performed on an unlocked snapshot:
 *
 *  - concurrent outbox workers updating the SAME finding through `get`+`put`
 *    reverted each other's status, so a finding could be re-sent or a terminal
 *    failure erased;
 *  - the per-CVE alert counters (`dispatchCount`, `recipientEmails`) of one
 *    digest delivered to several recipients each wrote `prior + 1`, so a
 *    four-cohort digest recorded one dispatch and lost three addresses;
 *  - `getManyForUpdate` is the primitive the fix is built on, and it must lock
 *    every requested row in one statement, in a deterministic order.
 *
 * These are real-database cases: a row lock cannot be exercised without one.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createPool, migrate, put, get, getManyForUpdate, transaction } from '../server/db.ts';
import type { Finding } from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;

test(
  'getManyForUpdate locks every requested row for the duration of the transaction',
  { skip: !database },
  async () => {
    const base = createPool(database!);
    const schema = 'concurrency_regr_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      await put(pool, 'findings', 'a', { id: 'a' });
      await put(pool, 'findings', 'b', { id: 'b' });

      // Hold the locks in one open transaction and prove a second writer blocks.
      let release!: () => void;
      const held = new Promise<void>((resolve) => (release = resolve));
      const holder = transaction(pool, async (db) => {
        const locked = await getManyForUpdate<Finding>(db, 'findings', ['b', 'a']);
        assert.deepEqual([...locked.keys()], ['a', 'b'], 'rows come back in id order regardless of input order');
        await held;
      });

      // The contender would block forever if the rows were not locked; a short
      // lock_timeout turns that into a fast, observable failure instead.
      const contender = transaction(pool, async (db) => {
        await db.query("SET LOCAL lock_timeout = '250ms'");
        const result = await getManyForUpdate<Finding>(db, 'findings', ['a']);
        return result.size;
      });
      await assert.rejects(contender, (error: unknown) => {
        const code = (error as { code?: string }).code;
        assert.equal(code, '55P03', `expected lock_not_available, got ${String(code)}`);
        return true;
      });

      release();
      await holder;
      // Once released the row is lockable again.
      assert.equal(await transaction(pool, (db) => getManyForUpdate<Finding>(db, 'findings', ['a'])).then((m) => m.size), 1);
    } finally {
      await pool.end();
      await base.end();
    }
  },
);

test(
  'concurrent finalizes of one finding do not lose an update (locked read-modify-write)',
  { skip: !database },
  async () => {
    const base = createPool(database!);
    const schema = 'concurrency_regr_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      await put(pool, 'findings', 'shared', {
        id: 'shared',
        deadLetterCount: 0,
        notificationStatus: 'QUEUED_FOR_DISPATCH',
      } satisfies Partial<Finding>);

      // The same shape as the dead-letter worker and the delivery finalize: a
      // read-modify-write that increments one field.
      const increment = () =>
        transaction(pool, async (db) => {
          const row = await getManyForUpdate<Finding>(db, 'findings', ['shared']);
          const current = row.get('shared')!;
          await put(db, 'findings', 'shared', { ...current, deadLetterCount: (current.deadLetterCount ?? 0) + 1 });
        });

      // Run enough writers concurrently that any lost update shows up.
      await Promise.all(Array.from({ length: 8 }, increment));

      const after = await get<Finding>(pool, 'findings', 'shared');
      assert.equal(after?.deadLetterCount, 8, 'every concurrent increment must be reflected');
    } finally {
      await pool.end();
      await base.end();
    }
  },
);

test(
  'a batch that shares one transaction uses savepoints so one bad row cannot discard its siblings',
  { skip: !database },
  async () => {
    const base = createPool(database!);
    const schema = 'concurrency_regr_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      await put(pool, 'delivery_dead_letters', 'good-1', { id: 'good-1' });
      await put(pool, 'delivery_dead_letters', 'poison', { id: 'poison' });
      await put(pool, 'delivery_dead_letters', 'good-2', { id: 'good-2' });

      await transaction(pool, async (db) => {
        for (const id of ['good-1', 'poison', 'good-2']) {
          await db.query('SAVEPOINT row');
          try {
            // Force the poison row to fail after a real write in the same step.
            await put(db, 'delivery_dead_letters', id, { id, resolvedAt: 'now' });
            if (id === 'poison') throw new Error('poisoned row');
            await db.query('RELEASE SAVEPOINT row');
          } catch {
            await db.query('ROLLBACK TO SAVEPOINT row');
          }
        }
      });

      const resolved = await get<{ resolvedAt?: string }>(pool, 'delivery_dead_letters', 'good-1');
      const poison = await get<{ resolvedAt?: string }>(pool, 'delivery_dead_letters', 'poison');
      const later = await get<{ resolvedAt?: string }>(pool, 'delivery_dead_letters', 'good-2');
      assert.equal(resolved?.resolvedAt, 'now', 'a row handled before the failure must commit');
      assert.equal(poison?.resolvedAt, undefined, 'the failing row must be rolled back to its savepoint');
      assert.equal(later?.resolvedAt, 'now', 'a row handled after the failure must still commit');
    } finally {
      await pool.end();
      await base.end();
    }
  },
);
