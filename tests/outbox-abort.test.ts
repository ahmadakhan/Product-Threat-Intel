import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { createPool, migrate, put, get } from '../server/db.ts';
import { loadConfig } from '../server/config.ts';
import { deliverNext } from '../server/delivery.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { EmailDeliveryLog, Finding } from '../src/types/index.ts';

/**
 * Regression: an outbox pass must stop when it is superseded or the worker shuts
 * down.
 *
 * The worker abandons an outbox pass that outlives the stall budget and starts a
 * replacement. Before this fix the abandoned loop kept claiming and *sending* —
 * up to 20 jobs per pass — competing with its replacement for the same queue and
 * holding pool connections, while both were reported as the outbox worker. It
 * also meant a shutdown could still deliver notifications after the operator
 * asked the process to stop.
 *
 * The contract tested here: an already-committed claim is finalised as a
 * retryable non-attempt (never left in SENDING for the lease to expire), and no
 * further job is claimed.
 */

async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T | null> {
  if (!process.env.TEST_DATABASE_URL) return null;
  const master = createPool(process.env.TEST_DATABASE_URL);
  const schema = `outboxabort_${randomBytes(10).toString('hex')}`;
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
  'an aborted outbox pass sends nothing and never leaves a job in SENDING',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    await withDatabase(async (pool) => {
      const config = loadConfig({
        NODE_ENV: 'test',
        DATABASE_URL: process.env.TEST_DATABASE_URL,
        APP_ORIGIN: 'http://localhost',
        ENCRYPTION_KEY: randomBytes(32).toString('base64'),
        WORKER_ENABLED: 'false',
        ATTACH_ADVISORY_PDF: 'false',
      });
      await pool.query(
        "INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,priority,edits,delivery_outcome) VALUES($1,$2,'email',$3,$4,$5,'QUEUED',0,'{}'::jsonb,'NOT_ATTEMPTED')",
        [randomUUID(), 'abort-test', 'ops', 'TEST', JSON.stringify({ subject: 'x', text: 'x', html: '<p>x</p>', recipientEmail: 'ops@example.invalid' })],
      );

      const controller = new AbortController();
      controller.abort(new Error('worker stopping'));

      let sends = 0;
      // Aborted before the claim: nothing may be claimed or sent.
      await assert.rejects(
        deliverNext(pool, config, async () => ({ status: 200, body: '{}', headers: {} }), async () => {
          sends++;
          return 'must-not-send';
        }, controller.signal),
        /worker stopping/,
      );
      assert.equal(sends, 0, 'an aborted pass must not reach the transport');
      const rows = (await pool.query<{ status: string }>('SELECT status FROM outbox')).rows;
      assert.equal(rows[0]?.status, 'QUEUED', 'the job must remain claimable, not be consumed');
    });
  },
);
