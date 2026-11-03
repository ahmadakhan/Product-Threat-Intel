import { test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { randomBytes, randomUUID } from 'node:crypto';
import { createPool, migrate, put, get } from '../server/db.ts';
import {
  queueUnverifiableMatchNotification,
  queueZeroDayDigestNotification,
  deliverNext,
  type ZeroDayDigestPayload,
} from '../server/delivery.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { loadConfig } from '../server/config.ts';
import type { Requester } from '../server/network.ts';
import type { Finding, EmailRecipient } from '../src/types/index.ts';

interface OutboxRow {
  id: string;
  dedupe_key: string;
  advisory_id: string;
  payload: Record<string, unknown>;
}

const url = process.env.TEST_DATABASE_URL ?? '';
async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T | null> {
  if (!url) return null;
  const master = createPool(url);
  const schema = `unverifiable_${randomBytes(10).toString('hex')}`;
  let pool: pg.Pool | undefined;
  try {
    await master.query(`CREATE SCHEMA ${schema}`);
    pool = new pg.Pool({ connectionString: url, options: `-c search_path=${schema}`, max: 4 });
    await migrate(pool);
    return await fn(pool);
  } finally {
    await pool?.end();
    await master.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await master.end();
  }
}

const finding = (cveId: string, id: string, assetName: string, vendor?: string, product?: string): Finding =>
  ({
    id,
    cveId,
    matchedAssetId: id,
    matchedAssetName: assetName,
    matchedAssetVendor: vendor,
    matchedAssetProduct: product,
    matchedCpe: `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`,
    matchingMethod: 'exact',
    matchingEvidence: `Evidence for ${cveId} on ${assetName}`,
    confidence: 0,
    notificationStatus: 'REVIEW_REQUIRED',
    status: 'MONITORED',
    autoDispatchedAt: null,
    advisoryId: null,
    reviewNotifiedAt: null,
    cve: {
      cveId,
      title: cveId,
      description: 'desc',
      publishedDate: '2026-01-01T00:00:00Z',
      modifiedDate: '2026-01-01T00:00:00Z',
      cvss: { version: '3.1', score: 7.5, vector: 'AV:N/AC:L', severity: 'HIGH' },
      cwe: [],
      cpeMatches: [],
      epss: { score: 0, percentile: 0 },
      cisaKev: { inKev: false, dueDate: null, cveNotes: '' },
      exploitStatus: 'None',
      remediation: { play: [], nextSteps: [] },
      sourceFeeds: [],
    },
    timeline: [],
  }) as unknown as Finding;

const recipient = (id: string, email: string, group: 'SECURITY_TEAM' | 'EVERYONE'): EmailRecipient => ({
  id,
  name: email,
  email,
  role: 'admin',
  deliveryGroup: group,
  subscriptionTier: 'ALL_SEVERITIES',
  enabled: true,
  deliverySuccessRate: 1,
});

test('unverifiable matches are batched into a single combined email per recipient', { skip: !process.env.TEST_DATABASE_URL }, async () => {
  const outcome = await withDatabase(async (pool) => {
    const findings: Finding[] = [
      finding('CVE-2026-10001', 'f1', 'server-1', 'acme', 'widget'),
      finding('CVE-2026-10002', 'f2', 'server-2', 'acme', 'gadget'),
      finding('CVE-2026-10003', 'f3', 'server-3'),
    ];
    const recipients: EmailRecipient[] = [
      recipient('r1', 'sec-1@example.com', 'SECURITY_TEAM'),
      recipient('r2', 'sec-2@example.com', 'SECURITY_TEAM'),
    ];

    // One queued notification per recipient, NOT one per finding.
    const queued = await queueUnverifiableMatchNotification(pool, findings, recipients);
    assert.equal(queued, 2, 'one combined email per recipient');

    const rows = await pool.query<OutboxRow>(
      `SELECT id, dedupe_key, advisory_id, payload FROM outbox WHERE advisory_id LIKE 'UNVERIFIABLE:%' ORDER BY target_id`,
    );
    assert.equal(rows.rowCount, 2, 'exactly two combined jobs enqueued');

    for (const row of rows.rows) {
      const payload = row.payload as {
        subject: string;
        cveIds: string[];
        unverifiableMatch: { findings: unknown[]; cveIds: string[] };
        findingRevisions: Record<string, string>;
        contentRevision: string;
      };
      assert.equal(payload.unverifiableMatch.findings.length, 3, 'each email carries all findings');
      assert.deepEqual(payload.cveIds, ['CVE-2026-10001', 'CVE-2026-10002', 'CVE-2026-10003']);
      assert.equal(payload.subject, '[Threat intelligence] for Review - Unverifiable matches (3 findings)');
      assert.equal(Object.keys(payload.findingRevisions).length, 3, 'findingRevisions covers every finding');
      assert.ok(row.dedupe_key, 'dedupe key populated');
    }

    // A re-queue of the identical batch dedupes against the existing jobs instead
    // of producing duplicates (ON CONFLICT no-ops on non-FAILED rows).
    const requeued = await queueUnverifiableMatchNotification(pool, findings, recipients);
    assert.equal(requeued, 0, 'identical batch does not re-queue');
    const after = await pool.query(
      `SELECT count(*)::int AS n FROM outbox WHERE advisory_id LIKE 'UNVERIFIABLE:%'`,
    );
    assert.equal(after.rows[0].n, 2, 'no additional jobs after re-queue');
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

const digest = (overrides: Partial<ZeroDayDigestPayload> = {}): ZeroDayDigestPayload => ({
  digestId: 'DIGEST_acme_widget',
  vendor: 'acme',
  product: 'widget',
  matchIds: ['m1', 'm2'],
  matchCount: 2,
  findings: [
    {
      findingId: 'f1',
      cveId: undefined,
      assetName: 'server-1 (acme widget)',
      evidence: 'Potential zero-day: vendor and product mentioned without a CVE.',
      credibilityScore: 71,
    },
    {
      findingId: 'f2',
      cveId: 'CVE-2026-30001',
      assetName: 'server-2 (acme widget)',
      evidence: 'Article references a CVE matched to this product.',
      credibilityScore: 64,
    },
  ],
  articles: [{ id: 'a1', title: 'Acme widget flaw exploited', url: 'https://example.com/a1', sourceFeeds: ['THREAT_FEED'] }],
  ...overrides,
});

test('zero-day digests deliver one consolidated email per recipient and dedupe', { skip: !process.env.TEST_DATABASE_URL }, async () => {
  // Audit C-3: exceeding the per-run zero-day cap used to withhold the
  // suppressed findings from every notification path with nothing to replace
  // them. The digest must reach the Security team, once per recipient.
  const outcome = await withDatabase(async (pool) => {
    const recipients: EmailRecipient[] = [
      recipient('r1', 'sec-1@example.com', 'SECURITY_TEAM'),
      recipient('r2', 'sec-2@example.com', 'SECURITY_TEAM'),
      recipient('r3', 'everyone@example.com', 'EVERYONE'),
    ];
    const payload = digest();
    assert.equal(await queueZeroDayDigestNotification(pool, payload, recipients), 2, 'Security team only');

    const rows = await pool.query<OutboxRow>(
      `SELECT id, dedupe_key, advisory_id, payload FROM outbox WHERE advisory_id='ZERODAY:DIGEST_acme_widget'`,
    );
    assert.equal(rows.rowCount, 2, 'one job per Security-team recipient');
    const body = rows.rows[0].payload as { subject: string; zeroDayDigest: ZeroDayDigestPayload };
    assert.match(body.subject, /ZERO-DAY DIGEST/);
    assert.match(body.subject, /acme \/ widget/);
    assert.equal(body.zeroDayDigest.findings.length, 2, 'every withheld match is named');

    // Re-queueing an unchanged digest must be a no-op.
    assert.equal(await queueZeroDayDigestNotification(pool, digest(), recipients), 0, 'identical digest dedupes');

    // A digest without a CVE still delivers: that is the whole point of the
    // zero-day path, and a payload filtered on cveIds would drop it.
    const noCve = digest({ matchIds: ['m9'], digestId: 'DIGEST_acme_gadget', findings: [payload.findings[0]] });
    assert.equal(await queueZeroDayDigestNotification(pool, noCve, recipients), 2);
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('zero-day digest job delivers without an advisory row', { skip: !process.env.TEST_DATABASE_URL }, async () => {
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'emailConfig', 'main', {
      provider: 'SMTP',
      host: 'localhost',
      port: 25,
      fromEmail: '',
      user: '',
      password: '',
    });
    const recipients: EmailRecipient[] = [recipient('r1', 'sec-1@example.com', 'SECURITY_TEAM')];
    for (const r of recipients) await put(pool, 'recipients', r.id, r);
    assert.equal(await queueZeroDayDigestNotification(pool, digest(), recipients), 1);

    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      WORKER_ENABLED: 'false',
    });
    const requester: Requester = async () => {
      throw new Error('No network expected');
    };
    let sent = 0;
    const delivered = await deliverNext(pool, config, requester, async () => {
      sent++;
      return `msg-${randomUUID()}`;
    });
    assert.equal(delivered, true, 'digest job is deliverable');
    assert.equal(sent, 1, 'transport called once');
    const status = await pool.query<{ status: string }>(`SELECT status FROM outbox LIMIT 1`);
    assert.equal(status.rows[0].status, 'ACCEPTED');
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('unverifiable match email is stamped reviewNotifiedAt on transport acceptance', { skip: !process.env.TEST_DATABASE_URL }, async () => {
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, reviewUnverifiableMatches: true });
    await put(pool, 'emailConfig', 'main', {
      provider: 'SMTP',
      host: 'localhost',
      port: 25,
      fromEmail: '',
      user: '',
      password: '',
    });
    const recipients: EmailRecipient[] = [
      recipient('r1', 'sec-1@example.com', 'SECURITY_TEAM'),
      recipient('r2', 'sec-2@example.com', 'SECURITY_TEAM'),
    ];
    for (const r of recipients) await put(pool, 'recipients', r.id, r);
    const findings: Finding[] = [
      finding('CVE-2026-20001', 'f1', 'server-1', 'acme', 'widget'),
      finding('CVE-2026-20002', 'f2', 'server-2', 'acme', 'gadget'),
    ];
    for (const f of findings) await put(pool, 'findings', f.id, f);

    const queued = await queueUnverifiableMatchNotification(pool, findings, recipients);
    assert.equal(queued, 2, 'one notification per recipient');

    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      WORKER_ENABLED: 'false',
    });
    const requester: Requester = async () => {
      throw new Error('No network expected');
    };

    let sent = 0;
    const delivered = await deliverNext(pool, config, requester, async () => {
      sent++;
      return `msg-${randomUUID()}`;
    });
    assert.equal(delivered, true, 'deliverNext should process a queued job');
    assert.equal(sent, 1, 'mail sender called exactly once');

    for (const f of findings) {
      const updated = await get<Finding>(pool, 'findings', f.id);
      assert.ok(
        updated?.reviewNotifiedAt,
        `finding ${f.id} should have reviewNotifiedAt set after acceptance`,
      );
    }

    // The second recipient's job is still pending; deliver it so both email
    // logs record ACCEPTED. The findings are already stamped — the put is
    // an idempotent skip for the second job.
    sent = 0;
    const delivered2 = await deliverNext(pool, config, requester, async () => {
      sent++;
      return `msg-${randomUUID()}`;
    });
    assert.equal(delivered2, true, 'second recipient job is processed');
    assert.equal(sent, 1, 'mail sender called for the second recipient job');

    for (const f of findings) {
      const updated = await get<Finding>(pool, 'findings', f.id);
      assert.ok(updated?.reviewNotifiedAt, `finding ${f.id} retains reviewNotifiedAt`);
    }

    // Re-queueing the same batch produces no new jobs: dedupe_key prevents
    // duplicates and the findings are now marked as notified.
    const requeued = await queueUnverifiableMatchNotification(pool, findings, recipients);
    assert.equal(requeued, 0, 'already-notified findings do not re-queue');
    const after = await pool.query(
      `SELECT count(*)::int AS n FROM outbox WHERE advisory_id LIKE 'UNVERIFIABLE:%'`,
    );
    assert.equal(after.rows[0].n, 2, 'no additional outbox rows after re-queue');

    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});
