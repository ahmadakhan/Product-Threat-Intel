import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import os from 'node:os';
import fs from 'node:fs';

import { CronDataProvider, runScheduledTraining } from '../server/ml/train/cron.ts';
import type { Db } from '../server/db.ts';
import type { Pool as pgPool } from 'pg';

const tmpDir = () => join(os.tmpdir(), `ml-cron-test-${Math.random().toString(36).slice(2)}`);

/** Minimal mock Db that matches SQL against patterns and returns canned rows. */
function createMockDb(rowsByQuery: Record<string, { rows: unknown[] }>): Db {
  const query = async (sql: string, _params?: unknown[]) => {
    for (const [pattern, result] of Object.entries(rowsByQuery)) {
      if (sql.includes(pattern)) return result;
    }
    return { rows: [] };
  };
  return { query, release: () => undefined } as unknown as Db;
}

/** Mock pool that returns our mock client on connect(). */
function createMockPool(client: ReturnType<typeof createMockDb>) {
  return {
    connect: async () => client,
    end: async () => undefined,
    query: client.query,
  };
}

const cpe = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
const sampleFinding = (status = 'PATCH_APPLIED') => ({
  id: 'finding',
  cveId: 'CVE-2026-10001',
  matchedCpe: cpe,
  matchingMethod: 'VENDOR_PRODUCT_ALIAS',
  confidence: 85,
  status,
  notificationStatus: 'DELIVERED',
  autoDispatchedAt: '2026-10-31T00:00:00Z',
  timeline: [{ timestamp: '2026-10-30T00:00:00Z' }, { timestamp: '2026-10-31T00:00:00Z' }],
  cve: {
    cvss: { score: 8 },
    epss: { score: 0.5 },
    cisaKev: { isKev: true },
    exploitStatus: 'Active Weaponized',
    publishedDate: new Date().toISOString(),
    remediation: {
      patchUrl: 'https://example.com/patch',
      immediateActions: ['Upgrade'],
      vendorAdvisoryRef: '',
      workarounds: [],
      rollbackPlan: '',
      stepByStep: [],
    },
  },
});

describe('CronDataProvider', () => {
  it('reads and deduplicates CPEs from JSON findings and watchlist records', async () => {
    const db = createMockDb({
      'SELECT kind,data FROM records': {
        rows: [
          { kind: 'findings', data: { matchedCpe: cpe } },
          { kind: 'watchlist', data: { cpes: [cpe, 'widget', 'invalid'] } },
        ],
      },
    });
    assert.deepEqual(await new CronDataProvider().collectCpeStrings(db), [cpe]);
  });
  it('uses adjudicated finding outcomes, never email acceptance as a relevance label', async () => {
    const db = createMockDb({
      "kind='findings'": {
        rows: [
          { data: sampleFinding() },
          { data: sampleFinding('FALSE_POSITIVE') },
          { data: sampleFinding('MONITORED') },
          { data: sampleFinding('RESOLVED') },
        ],
      },
    });
    const outcomes = await new CronDataProvider().collectDispatchOutcomes(db);
    assert.equal(outcomes.length, 2);
    assert.equal(outcomes[0].foundTruePositive, true);
    assert.equal(outcomes[1].wasFalsePositive, true);
  });
  it('maps real finding features and camelCase remediation without placeholder content', async () => {
    const db = createMockDb({ "kind='findings'": { rows: [{ data: sampleFinding() }] } });
    const provider = new CronDataProvider();
    const [review] = await provider.collectReviewOutcomeHistory(db);
    assert.equal(review.features.hasVersionEvidence, true);
    assert.equal(review.features.cisaKev, true);
    assert.equal(review.features.exploitStatus, 3);
    assert.equal(review.daysToAction, 1);
    const [remediation] = await provider.collectRemediationFindings(db);
    assert.equal(remediation.playbook.patchUrl, 'https://example.com/patch');
    assert.deepEqual(remediation.playbook.immediateActions, ['Upgrade']);
  });
  it('classifies provider HTTP errors without calling retry exhaustion a permanent rejection', async () => {
    const db = createMockDb({
      'FROM outbox o LEFT JOIN records': {
        rows: [
          {
            channel: 'email',
            attempts: 2,
            error: 'Provider HTTP 429',
            updated_at: '2026-10-31T14:00:00Z',
            log: { provider: 'SendGrid' },
          },
          {
            channel: 'email',
            attempts: 6,
            error: 'Connection failed',
            updated_at: '2026-10-31T14:00:00Z',
            log: { provider: 'SMTP_Relay' },
          },
          {
            channel: 'email',
            attempts: 1,
            error: 'Provider HTTP 401',
            updated_at: '2026-10-31T14:00:00Z',
            log: { provider: 'SendGrid' },
          },
        ],
      },
    });
    const errors = await new CronDataProvider().collectDeliveryErrorSamples(db);
    assert.deepEqual(
      errors.map((e) => e.isPermanent),
      [false, false, true],
    );
    assert.equal(errors[0].provider, 'SendGrid');
    assert.equal(errors[0].hourOfDay, 14);
  });
  it('skips models whose histories are not persisted without querying imaginary tables', async () => {
    const db = {
      query: async () => {
        throw new Error('Unexpected query');
      },
    } as unknown as Db;
    const provider = new CronDataProvider();
    for (const collect of [
      provider.collectTelemetry,
      provider.collectCalibrationPairs,
      provider.collectDeliveryOutcomes,
      provider.collectExploitRiskSamples,
      provider.collectCredibilityWeightSamples,
      provider.collectZeroDayRateLimitSamples,
      provider.collectDigestSelectionSamples,
      provider.collectSeverityTierSamples,
      provider.collectFeedRecoverySamples,
    ]) {
      assert.deepEqual(await (collect as (db: Db) => Promise<unknown[]>).call(provider, db), []);
    }
  });
  it('shares findings within a cycle and refreshes them on the next cycle', async () => {
    let calls = 0;
    const db = {
      query: async (sql: string) => {
        if (sql.includes("kind='findings'")) {
          calls++;
          return { rows: [{ data: sampleFinding() }] };
        }
        return { rows: [] };
      },
    } as unknown as Db;
    const provider = new CronDataProvider();
    const first = await provider.collectAll(db);
    assert.equal(Object.keys(first).length, 18);
    assert.equal(calls, 1);
    await provider.collectAll(db);
    assert.equal(calls, 2);
  });
});

describe('runScheduledTraining', () => {
  it('skips models when database has no training data', async () => {
    const mockDb = createMockDb({});
    const mockPool = createMockPool(mockDb);
    const dir = tmpDir();

    const summary = await runScheduledTraining(mockPool as unknown as pgPool, {
      directory: dir,
      lookbackDays: 1,
    });

    assert.equal(summary.summary.total, 18);
    assert.equal(summary.summary.skipped, 18);
    assert.equal(summary.summary.trained, 0);
    assert.equal(summary.summary.failed, 0);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('trains CPE validity gate with real data', async () => {
    const mockDb = createMockDb({
      'SELECT kind,data FROM records': {
        rows: Array.from({ length: 200 }, (_, i) => ({
          kind: 'watchlist',
          data: { cpes: [`cpe:2.3:a:vendor${i}:product${i}:1.0:*:*:*:*:*:*:*`] },
        })),
      },
    });
    const mockPool = createMockPool(mockDb);
    const dir = tmpDir();

    const summary = await runScheduledTraining(mockPool as unknown as pgPool, {
      directory: dir,
      lookbackDays: 30,
    });

    const cpeResult = summary.results.find((r) => r.modelId === 'cpe-validity-gate')!;
    assert.equal(cpeResult.status, 'trained');
    assert.ok(cpeResult.validation.passed);
    assert.ok(cpeResult.saved);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('handles training failures gracefully (does not throw)', async () => {
    const mockDb = createMockDb({});
    const mockPool = createMockPool(mockDb);
    const dir = tmpDir();

    const summary = await runScheduledTraining(mockPool as unknown as pgPool, { directory: dir });

    assert.equal(summary.summary.total, 18);
    assert.equal(summary.summary.failed, 0);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('logs results to console', async () => {
    const mockDb = createMockDb({});
    const mockPool = createMockPool(mockDb);
    const dir = tmpDir();

    const logs: string[] = [];
    const origLog = console.log;
    console.log = (...args: unknown[]) => {
      logs.push(args.join(' '));
    };

    try {
      await runScheduledTraining(mockPool as unknown as pgPool, { directory: dir });
      assert.ok(logs.length > 0, 'Expected console.log to be called');
      assert.ok(
        logs.some((l) => l.includes('[ML Training]')),
        'Expected ML Training log line',
      );
    } finally {
      console.log = origLog;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
