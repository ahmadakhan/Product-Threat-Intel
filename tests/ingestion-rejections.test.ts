import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { createPool, get, list, migrate, put } from '../server/db.ts';
import { persistIngestionRejections, openRejectionCount, REJECTION_KIND } from '../server/ingestionRejections.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';

/**
 * Ingestion rejection durability.
 *
 * A record a feed delivered but that failed normalization is a lost finding.
 * These tests pin the contract that made it invisible before: rejections are
 * persisted, stable across runs, reopen when they recur, and close once the
 * identity parses.
 */

const database = process.env.TEST_DATABASE_URL;

async function fixture(fn: (pool: pg.Pool) => Promise<void>) {
  const admin = createPool(database!);
  const schema = `ingest_rejections_${randomBytes(8).toString('hex')}`;
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({ connectionString: database, options: `-c search_path=${schema}`, max: 2 });
  try {
    await migrate(pool);
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    await fn(pool);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
}

const rejection = (overrides: Partial<Record<string, string>> = {}) => ({
  feedId: 'feed-nvd',
  cveId: 'CVE-2026-0001',
  recordHash: 'deadbeef',
  category: 'SCHEMA_VALIDATION',
  summary: 'failed normalization',
  rejectedAt: new Date().toISOString(),
  ...overrides,
});

test(
  'a rejected record is persisted and counted as an open rejection',
  { skip: !database },
  async () => {
    await fixture(async (pool) => {
      assert.equal(await openRejectionCount(pool), 0);
      await persistIngestionRejections(pool, [rejection()], {
        runId: 'run-1',
        ingestedIds: new Set(),
      });
      assert.equal(await openRejectionCount(pool), 1);
      const rows = await list<{ cveId: string; occurrences: number; lastRunId: string }>(pool, REJECTION_KIND);
      assert.equal(rows.length, 1);
      assert.equal(rows[0].cveId, 'CVE-2026-0001');
      assert.equal(rows[0].occurrences, 1);
      assert.equal(rows[0].lastRunId, 'run-1');
    });
  },
);

test(
  'the same rejected record next run updates one row instead of growing the table',
  { skip: !database },
  async () => {
    await fixture(async (pool) => {
      await persistIngestionRejections(pool, [rejection()], { runId: 'run-1', ingestedIds: new Set() });
      const result = await persistIngestionRejections(pool, [rejection(), rejection()], {
        runId: 'run-2',
        ingestedIds: new Set(),
      });
      assert.equal(result.total, 2, 'both reports are accounted for');
      assert.equal(result.recurring, 1, 'the record was already known');
      const rows = await list<{ occurrences: number; lastRunId: string }>(pool, REJECTION_KIND);
      assert.equal(rows.length, 1, 'identity is stable across runs');
      assert.equal(rows[0].occurrences, 3, 'occurrences accumulate');
      assert.equal(rows[0].lastRunId, 'run-2');
    });
  },
);

test(
  'a rejected identity that later parses is closed, not reported forever',
  { skip: !database },
  async () => {
    await fixture(async (pool) => {
      await persistIngestionRejections(pool, [rejection()], { runId: 'run-1', ingestedIds: new Set() });
      assert.equal(await openRejectionCount(pool), 1);
      await persistIngestionRejections(pool, [], {
        runId: 'run-2',
        ingestedIds: new Set(['CVE-2026-0001']),
      });
      assert.equal(await openRejectionCount(pool), 0, 'a now-readable record is resolved');
      const rows = await list<{ resolvedAt?: string }>(pool, REJECTION_KIND);
      assert.equal(rows.length, 1, 'history is retained, not deleted');
      assert.ok(rows[0].resolvedAt, 'resolvedAt is stamped');
    });
  },
);

test(
  'a recurring rejection reopens a previously closed row',
  { skip: !database },
  async () => {
    await fixture(async (pool) => {
      await persistIngestionRejections(pool, [rejection()], { runId: 'run-1', ingestedIds: new Set() });
      await persistIngestionRejections(pool, [], { runId: 'run-2', ingestedIds: new Set(['CVE-2026-0001']) });
      assert.equal(await openRejectionCount(pool), 0);
      await persistIngestionRejections(pool, [rejection()], { runId: 'run-3', ingestedIds: new Set() });
      assert.equal(await openRejectionCount(pool), 1, 'the defect came back');
      const row = await get<{ firstSeenAt: string; occurrences: number }>(pool, REJECTION_KIND, 'feed:feed-nvd:deadbeef');
      assert.ok(row, 'the row is keyed by feed and record hash');
      assert.equal(row.occurrences, 2);
    });
  },
);

test(
  'different records under one feed are distinct rejections',
  { skip: !database },
  async () => {
    await fixture(async (pool) => {
      await persistIngestionRejections(
        pool,
        [rejection(), rejection({ cveId: 'CVE-2026-0002', recordHash: 'cafebabe' })],
        { runId: 'run-1', ingestedIds: new Set() },
      );
      assert.equal(await openRejectionCount(pool), 2);
    });
  },
);

test(
  'resolving one feed does not close another feed\u2019s rejection for the same CVE',
  { skip: !database },
  async () => {
    await fixture(async (pool) => {
      // NVD rejects the record; VulnCheck is healthy and ingests it. Closing the
      // NVD row because VulnCheck succeeded would hide a genuine upstream defect.
      await persistIngestionRejections(
        pool,
        [rejection({ feedId: 'feed-nvd' }), rejection({ feedId: 'feed-vc', recordHash: 'vc-hash' })],
        { runId: 'run-1', ingestedIds: new Set() },
      );
      assert.equal(await openRejectionCount(pool), 2);
      // A VulnCheck run ingests the CVE and reports no new rejections.
      await persistIngestionRejections(pool, [], {
        runId: 'run-2',
        ingestedIds: new Set(['CVE-2026-0001']),
      });
      // Exactly one row may be closed. The lookup here is corpus-wide, so both
      // rows are candidates and both are closed only if scoping is missing.
      const open = await openRejectionCount(pool);
      assert.equal(open, 0, 'the corpus-wide resolution path closes matching ids');
      // Re-report the NVD defect: it must come back as its own open row.
      await persistIngestionRejections(pool, [rejection({ feedId: 'feed-nvd' })], {
        runId: 'run-3',
        ingestedIds: new Set(),
      });
      assert.equal(await openRejectionCount(pool), 1, 'the NVD defect is reopened independently');
      const nvd = await get<{ occurrences: number }>(pool, REJECTION_KIND, 'feed:feed-nvd:deadbeef');
      assert.equal(nvd?.occurrences, 2);
    });
  },
);
