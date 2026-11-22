import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { putMany, createPool, migrate, put, get, list } from '../server/db.ts';
import {
  claimItems,
  markClaimsDelivered,
  releaseClaims,
  attachClaimsToJob,
  type ClaimRequest,
} from '../server/deliveryClaims.ts';
import {
  queueConsolidatedFindingNotifications,
  queueEveryoneDeliveryJobs,
  type Job,
} from '../server/delivery.ts';
import { rebuildFromCurrentInventory, regroupStaleAdvisory } from '../server/pipeline.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { Finding, EmailRecipient, Advisory } from '../src/types/index.ts';

test('deliveryClaims: claimItems, markClaimsDelivered, releaseClaims sort parameters deterministically', async () => {
  const captured: Record<string, unknown[]> = {};
  const mockDb = {
    query: async (sql: string, params?: unknown[]) => {
      if (sql.includes('INSERT INTO delivery_claims')) {
        captured.insertParams = params ?? [];
        return {
          rows: [
            { recipient_id: 'r2', kind: 'finding', item_id: 'f1' },
            { recipient_id: 'r1', kind: 'finding', item_id: 'f2' },
          ],
        };
      }
      if (sql.includes('UPDATE delivery_claims')) {
        captured.updateParams = params ?? [];
        return { rowCount: 2 };
      }
      if (sql.includes('DELETE FROM delivery_claims')) {
        captured.deleteParams = params ?? [];
        return { rowCount: 2 };
      }
      return { rows: [] };
    },
  } as unknown as pg.PoolClient;

  // Unordered requests
  const requests: ClaimRequest[] = [
    { recipientId: 'r2', kind: 'finding', itemId: 'f2' },
    { recipientId: 'r1', kind: 'finding', itemId: 'f1' },
    { recipientId: 'r2', kind: 'finding', itemId: 'f1' },
    { recipientId: 'r1', kind: 'finding', itemId: 'f2' },
  ];

  await claimItems(mockDb, requests);
  // Expect sorted by recipientId, kind, itemId:
  // r1:finding:f1, r1:finding:f2, r2:finding:f1, r2:finding:f2
  const insertRecipients = captured.insertParams?.[0] as string[];
  const insertItemIds = captured.insertParams?.[4] as string[];
  assert.deepEqual(insertRecipients, ['r1', 'r1', 'r2', 'r2']);
  assert.deepEqual(insertItemIds, ['f1', 'f2', 'f1', 'f2']);

  await markClaimsDelivered(mockDb, requests, { jobId: '00000000-0000-0000-0000-000000000001' });
  const updateRecipients = captured.updateParams?.[0] as string[];
  const updateItemIds = captured.updateParams?.[2] as string[];
  assert.deepEqual(updateRecipients, ['r1', 'r1', 'r2', 'r2']);
  assert.deepEqual(updateItemIds, ['f1', 'f2', 'f1', 'f2']);

  await releaseClaims(mockDb, requests, { jobId: '00000000-0000-0000-0000-000000000001' });
  const deleteRecipients = captured.deleteParams?.[0] as string[];
  const deleteItemIds = captured.deleteParams?.[2] as string[];
  assert.deepEqual(deleteRecipients, ['r1', 'r1', 'r2', 'r2']);
  assert.deepEqual(deleteItemIds, ['f1', 'f2', 'f1', 'f2']);

  await attachClaimsToJob(mockDb, '00000000-0000-0000-0000-000000000001', requests);
  const attachRecipients = captured.updateParams?.[0] as string[];
  const attachItemIds = captured.updateParams?.[2] as string[];
  assert.deepEqual(attachRecipients, ['r1', 'r1', 'r2', 'r2']);
  assert.deepEqual(attachItemIds, ['f1', 'f2', 'f1', 'f2']);
});

test('db.putMany sorts unique items by id before insertion', async () => {
  let capturedValues: unknown[] = [];
  const mockDb = {
    query: async (_sql: string, values?: unknown[]) => {
      capturedValues = values ?? [];
      return { rowCount: 3 };
    },
  } as unknown as pg.Pool;

  const items = [
    { id: 'zeta', data: { val: 1 } },
    { id: 'alpha', data: { val: 2 } },
    { id: 'beta', data: { val: 3 } },
    { id: 'alpha', data: { val: 2 } }, // Duplicate to test dedup + sort
  ];

  await putMany(mockDb, 'findings', items);
  // Format is (kind, id, data) triplets in values
  // values = ['findings', 'alpha', '{"val":2}', 'findings', 'beta', '{"val":3}', 'findings', 'zeta', '{"val":1}']
  assert.equal(capturedValues[1], 'alpha');
  assert.equal(capturedValues[4], 'beta');
  assert.equal(capturedValues[7], 'zeta');
});

const database = process.env.TEST_DATABASE_URL;

async function setupTestDb(fn: (pool: pg.Pool) => Promise<void>) {
  const admin = createPool(database!);
  const schema = `pipeline_rel_${randomBytes(8).toString('hex')}`;
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({ connectionString: database, options: `-c search_path=${schema}`, max: 4 });
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

const sampleFinding = (id: string, cveId: string, severity: 'CRITICAL' | 'HIGH' | 'LOW' = 'HIGH'): Finding =>
  ({
    id,
    cveId,
    status: 'MONITORED',
    notificationStatus: 'QUEUED_FOR_DISPATCH',
    matchedAssetId: 'asset-1',
    matchedAssetName: 'srv-1',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'widget',
    matchedCpe: 'cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*',
    confidence: 90,
    matchingEvidence: 'Direct CPE match',
    matchingMethod: 'STRICT_CPE_INTERVAL',
    exploitRisk: 'HIGH',
    advisoryId: null,
    reviewNotifiedAt: null,
    autoDispatchedAt: null,
    timeline: [],
    cve: {
      cveId,
      title: 'Vulnerability ' + cveId,
      description: 'Test vulnerability',
      publishedDate: new Date().toISOString(),
      modifiedDate: new Date().toISOString(),
      cvss: {
        severity,
        score: severity === 'CRITICAL' ? 9.8 : severity === 'HIGH' ? 8.0 : 3.0,
        version: '3.1',
        vector: '',
      },
      cwe: ['CWE-79'],
      cpeMatches: ['cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*'],
      remediation: { vendorAdvisoryRef: 'https://example.com', immediateActions: [], workarounds: [] },
      epss: { score: 0.1, percentile: 0.5 },
      sourceFeeds: ['NVD'],
      cisaKev: { isKev: false },
    },
  }) as unknown as Finding;

test(
  'rebuildFromCurrentInventory releases CLAIMED claims and marks jobs NOT_ATTEMPTED',
  { skip: !database },
  async () => {
    await setupTestDb(async (pool) => {
      const f1 = sampleFinding('f-stale-1', 'CVE-2026-90001');
      await put(pool, 'findings', f1.id, f1);

      const recipient: EmailRecipient = {
        id: 'rec-1',
        name: 'SecOps',
        email: 'secops@example.com',
        role: 'Security lead',
        enabled: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
        deliverySuccessRate: 1,
      };
      await put(pool, 'recipients', recipient.id, recipient);

      // Queue consolidated notification
      const queuedCount = await queueConsolidatedFindingNotifications(pool, [f1]);
      assert.equal(queuedCount, 1);

      const outboxRows = (
        await pool.query<{ id: string; advisory_id: string }>(
          "SELECT id, advisory_id FROM outbox WHERE channel='email'",
        )
      ).rows;
      assert.equal(outboxRows.length, 1);
      const advisoryId = outboxRows[0].advisory_id;

      // Claims must exist
      const claimsBefore = (await pool.query("SELECT * FROM delivery_claims WHERE state='CLAIMED'")).rows;
      assert.equal(claimsBefore.length, 1);

      // Simulate stale advisory invalidation
      await rebuildFromCurrentInventory(pool, advisoryId, 'Findings no longer applicable');

      // Job must be FAILED with delivery_outcome NOT_ATTEMPTED
      const jobAfter = (
        await pool.query<{ status: string; delivery_outcome: string }>(
          'SELECT status, delivery_outcome FROM outbox WHERE id=$1',
          [outboxRows[0].id],
        )
      ).rows[0];
      assert.equal(jobAfter.status, 'FAILED');
      assert.equal(jobAfter.delivery_outcome, 'NOT_ATTEMPTED');

      // Claims for the invalidated job must be deleted/freed
      const claimsAfter = (await pool.query("SELECT * FROM delivery_claims WHERE state='CLAIMED'")).rows;
      assert.equal(claimsAfter.length, 0, 'Invalidated job must release its CLAIMED claims');
    });
  },
);

test(
  'queueEveryoneDeliveryJobs respects subscription tiers for Everyone recipients',
  { skip: !database },
  async () => {
    await setupTestDb(async (pool) => {
      const fHigh = sampleFinding('f-high', 'CVE-2026-90010', 'HIGH');
      const fCrit = sampleFinding('f-crit', 'CVE-2026-90011', 'CRITICAL');
      await put(pool, 'findings', fHigh.id, fHigh);
      await put(pool, 'findings', fCrit.id, fCrit);

      // Recipient who only allows CISA_KEV_ONLY findings
      const recCriticalOnly: EmailRecipient = {
        id: 'rec-crit-only',
        name: 'Manager',
        email: 'manager@example.com',
        role: 'Manager',
        enabled: true,
        deliveryGroup: 'EVERYONE',
        subscriptionTier: 'CISA_KEV_ONLY',
        deliverySuccessRate: 1,
      };
      await put(pool, 'recipients', recCriticalOnly.id, recCriticalOnly);

      // Mock an accepted security job carrying non-KEV findings
      const acceptedJob = {
        id: '00000000-0000-0000-0000-000000000099',
        advisory_id: 'ADV-TEST-001',
        dedupe_key: 'adv:test:001:email:sec',
        priority: 0,
        payload: {
          subject: 'Security Alert',
          text: 'Alert text',
          includedFindingIds: [fHigh.id, fCrit.id],
        },
      } as unknown as Job;

      const queued = await queueEveryoneDeliveryJobs(pool, acceptedJob, DEFAULT_SETTINGS);
      // Because recCriticalOnly subscribes only to CISA_KEV_ONLY and neither finding is KEV, 0 jobs should be queued
      assert.equal(
        queued,
        0,
        'Must not queue advisory if recipient subscription permits none of the findings',
      );
    });
  },
);
