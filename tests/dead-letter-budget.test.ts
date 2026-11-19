import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { createPool, get, migrate, put } from '../server/db.ts';
import { reconcileFindings } from '../src/engine/reconcileFindings.ts';
import type { Finding } from '../src/types/index.ts';

/**
 * Dead-letter retry budget.
 *
 * The sweep requeues a finding through `reconcileFindings`, so the budget must
 * survive reconciliation; otherwise every pipeline pass resets it and a permanent
 * recipient failure becomes an unbounded retry loop.
 */

const database = process.env.TEST_DATABASE_URL;

const finding = (overrides: Partial<Finding> = {}): Finding =>
  ({
    id: 'f-1',
    cveId: 'CVE-2026-0001',
    cve: { cveId: 'CVE-2026-0001' },
    matchedAssetId: 'asset-1',
    matchedAssetName: 'edge (acme widget)',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'widget',
    matchedCpe: '',
    matchingMethod: 'CPE',
    matchingEvidence: 'evidence',
    confidence: 90,
    exposure: 'INTERNAL',
    exploitRisk: 'STANDARD',
    dispatchDeferred: false,
    notificationStatus: 'AUTO_DISPATCHED',
    status: 'MONITORED',
    autoDispatchedAt: '2026-01-01T00:00:00.000Z',
    advisoryId: null,
    reviewNotifiedAt: null,
    deadLetterCount: 2,
    timeline: [],
    ...overrides,
  }) as unknown as Finding;

test(
  'reconciliation preserves the dead-letter retry budget',
  { skip: !database },
  async () => {
    const admin = createPool(database!);
    const schema = `deadletter_${randomBytes(8).toString('hex')}`;
    await admin.query(`CREATE SCHEMA ${schema}`);
    const pool = new pg.Pool({ connectionString: database, options: `-c search_path=${schema}`, max: 2 });
    try {
      await migrate(pool);
      const existing = finding();
      const candidate = finding({
        id: 'f-new',
        notificationStatus: 'QUEUED_FOR_DISPATCH',
        deadLetterCount: 0,
      });
      const [reconciled] = reconcileFindings([existing], [candidate]);
      assert.equal(reconciled.id, 'f-1', 'identity is preserved');
      assert.equal(reconciled.deadLetterCount, 2, 'the spent budget is not reset by a requeue');
      await put(pool, 'findings', reconciled.id, reconciled);
      const stored = await get<{ deadLetterCount?: number }>(pool, 'findings', reconciled.id);
      assert.equal(stored?.deadLetterCount, 2);
    } finally {
      await pool.end();
      await admin.query(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    }
  },
);

test('reconciliation adopts a candidate budget when the stored finding has none', () => {
  const existing = finding({ deadLetterCount: undefined });
  const candidate = finding({ deadLetterCount: 1 });
  const [reconciled] = reconcileFindings([existing], [candidate]);
  assert.equal(reconciled.deadLetterCount, 1, 'a legacy record inherits the counter it is given');
});
