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
import { eligibleForReviewNotification } from '../src/utils/findingDelivery.ts';
import { renderUnverifiableReviewEmail } from '../server/reviewEmail.ts';
import { settingsSchema } from '../server/validation.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import type { AppSettings, WatchListItem } from '../src/types/index.ts';

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

async function saveReviewFinding(pool: pg.Pool, value: Finding): Promise<Finding> {
  const asset: WatchListItem = {
    id: value.matchedAssetId, vendor: value.matchedAssetVendor || 'acme',
    product: value.matchedAssetProduct || 'widget', assetTag: value.matchedAssetName,
    version: '1.*', cpes: [], active: true, ownerGroup: 'SOC', createdAt: new Date().toISOString(),
  };
  asset.cpes = [`cpe:2.3:a:${asset.vendor}:${asset.product}:1.*:*:*:*:*:*:*:*`];
  const cve = { ...value.cve, cpeMatches: [`cpe:2.3:a:${asset.vendor}:${asset.product}:1.5:*:*:*:*:*:*:*`] };
  const policy = { ...DEFAULT_SETTINGS, ...await get<AppSettings>(pool, 'settings', 'main'), scopeHours: 0 };
  const matched = runVulnerabilityPipeline([], [cve], [asset], [], [], policy).newFindings[0];
  assert.ok(matched);
  const result = { ...matched, id: value.id };
  await put(pool, 'watchlist', asset.id, asset);
  await put(pool, 'cveData', cve.cveId, cve);
  await put(pool, 'findings', result.id, result);
  return result;
}

test('unverifiable matches are batched into a single combined email per recipient', { skip: !process.env.TEST_DATABASE_URL }, async () => {
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, reviewUnverifiableMatches: true });
    const first = finding('CVE-2026-10001', 'f1', 'server-1', 'acme', 'widget');
    const findings: Finding[] = [
      first,
      { ...first },
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

test('review thresholds retain boundaries and reject invalid settings', () => {
  const policy = { reviewUnverifiableMatches: true, reviewConfidenceThreshold: 70 };
  for (const [confidence, expected] of [[69, false], [70, true], [90, true], [100, true], [NaN, false], [101, false]] as const) {
    assert.equal(eligibleForReviewNotification({ ...finding('CVE-2026-10001', 'f1', 'asset'), confidence }, policy), expected);
  }
  const candidate = { ...finding('CVE-2026-10001', 'f1', 'asset'), confidence: 80 };
  assert.equal(eligibleForReviewNotification({ ...candidate, notificationStatus: 'QUEUED_FOR_DISPATCH' }, policy), false);
  assert.equal(eligibleForReviewNotification({ ...candidate, status: 'FALSE_POSITIVE' }, policy), false);
  assert.equal(eligibleForReviewNotification(candidate, { ...policy, reviewUnverifiableMatches: false }), false);
  for (const value of [-1, 101, 70.5, NaN]) assert.equal(settingsSchema.safeParse({ ...DEFAULT_SETTINGS, reviewConfidenceThreshold: value }).success, false);
  assert.equal(settingsSchema.parse(DEFAULT_SETTINGS).reviewConfidenceThreshold, 0);
  assert.equal(settingsSchema.parse({ ...DEFAULT_SETTINGS, emailEnabled: false }).emailEnabled, false);
  assert.equal(settingsSchema.safeParse({ ...DEFAULT_SETTINGS, emailEnabled: 'false' }).success, false);
});

test('overlapping review batches reserve each finding once per recipient', { skip: !url }, async () => {
  await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, reviewUnverifiableMatches: true });
    const first = finding('CVE-2026-10101', 'f1', 'first');
    const second = finding('CVE-2026-10102', 'f2', 'second');
    const target = recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM');
    await Promise.all([
      queueUnverifiableMatchNotification(pool, [first], [target]),
      queueUnverifiableMatchNotification(pool, [first, second], [target]),
    ]);
    const rows = (await pool.query('SELECT payload FROM outbox')).rows;
    const ids = rows.flatMap((row) => row.payload.unverifiableMatch.findings.map((item: { findingId: string }) => item.findingId)).sort();
    assert.deepEqual(ids, ['f1', 'f2']);
    assert.equal(await queueUnverifiableMatchNotification(pool, [first, second], [target]), 0);
  });
});

test('review email links sources safely and escapes evidence', () => {
  const candidate = finding('CVE-2026-10001', 'f1', '<img src=x onerror=alert(1)>');
  candidate.matchingEvidence = '<script>alert(1)</script>';
  candidate.cve.remediation.vendorAdvisoryRef = 'javascript:alert(1)';
  const rendered = renderUnverifiableReviewEmail([candidate]);
  assert.ok(rendered.html.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2026-10001"'));
  assert.ok(rendered.text.includes('https://nvd.nist.gov/vuln/detail/CVE-2026-10001'));
  assert.ok(!rendered.html.includes('<script>'));
  assert.ok(!rendered.html.includes('<img src=x'));
  candidate.cve.remediation.vendorAdvisoryRef = 'https://vendor.example/security/CVE-2026-10001?a=1&b=2';
  assert.ok(renderUnverifiableReviewEmail([candidate]).html.includes('href="https://vendor.example/security/CVE-2026-10001?a=1&amp;b=2"'));
  candidate.cve.remediation.vendorAdvisoryRef = 'https://user:secret@vendor.example/advisory';
  assert.ok(!renderUnverifiableReviewEmail([candidate]).html.includes('user:secret'));
  const timestamped = renderUnverifiableReviewEmail([candidate], 'America/Los_Angeles');
  assert.ok(timestamped.text.includes('CVE published: 31 Dec 2025, 16:00 UTC-8 | 2026-01-01 00:00:00 UTC'));
  assert.ok(timestamped.text.includes('Source updated: 31 Dec 2025, 16:00 UTC-8 | 2026-01-01 00:00:00 UTC'));
  candidate.cve.versionRange = { versionEndExcluding: '1.0' };
  candidate.cve.cpeMatchDetails = [{ criteria: candidate.matchedCpe }];
  const criterion = renderUnverifiableReviewEmail([candidate]);
  assert.ok(criterion.html.includes('No version bounds specified for the matched criterion'));
  assert.ok(!criterion.html.includes('&lt; 1.0'));
});

test('review batches honor confidence and each recipient subscription', { skip: !url }, async () => {
  await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, reviewUnverifiableMatches: true, reviewConfidenceThreshold: 70 });
    const low = { ...finding('CVE-2026-10010', 'low', 'low asset'), confidence: 70 };
    low.cve.cvss.severity = 'LOW';
    const high = { ...finding('CVE-2026-10011', 'high', 'high asset'), confidence: 85 };
    high.cve.cisaKev = { ...high.cve.cisaKev, isKev: true };
    const below = { ...finding('CVE-2026-10012', 'below', 'below asset'), confidence: 69 };
    const queued = await queueUnverifiableMatchNotification(pool, [low, high, below], [
      recipient('all', 'all@example.invalid', 'SECURITY_TEAM'),
      { ...recipient('high', 'high@example.invalid', 'SECURITY_TEAM'), subscriptionTier: 'CRITICAL_HIGH_ONLY' },
      { ...recipient('kev', 'kev@example.invalid', 'SECURITY_TEAM'), subscriptionTier: 'CISA_KEV_ONLY' },
      recipient('everyone', 'everyone@example.invalid', 'EVERYONE'),
    ]);
    assert.equal(queued, 3);
    const rows = (await pool.query('SELECT target_id,payload FROM outbox ORDER BY target_id')).rows;
    assert.deepEqual(rows[0].payload.cveIds, [low.cveId, high.cveId]);
    for (const row of rows.slice(1)) assert.deepEqual(row.payload.cveIds, [high.cveId]);
    for (const row of rows) assert.ok(!row.payload.html.includes(below.cveId));
  });
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
    await put(pool, 'settings', 'main', {
      ...DEFAULT_SETTINGS,
      reviewUnverifiableMatches: true,
      timezone: 'Pacific/Honolulu',
    });
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
    const candidates: Finding[] = [
      finding('CVE-2026-20001', 'f1', 'server-1', 'acme', 'widget'),
      finding('CVE-2026-20002', 'f2', 'server-2', 'acme', 'gadget'),
    ];
    const findings: Finding[] = [];
    for (const candidate of candidates) findings.push(await saveReviewFinding(pool, candidate));

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

test('review delivery rechecks current policy and evidence before sending', { skip: !url }, async (t) => {
  await withDatabase(async (pool) => {
    const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: url, APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64') });
    const request: Requester = async () => { throw new Error('No network expected'); };
    const mutations: [string, (entry: Finding) => Promise<unknown>][] = [
      ['review confidence raised', async () => put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, reviewUnverifiableMatches: true, reviewConfidenceThreshold: 80 })],
      ['review notices disabled', async () => put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, reviewUnverifiableMatches: false })],
      ['finding promoted', async (entry) => put(pool, 'findings', entry.id, { ...entry, notificationStatus: 'QUEUED_FOR_DISPATCH' })],
      ['recipient changed', async () => put(pool, 'recipients', 'r1', recipient('r1', 'new@example.invalid', 'SECURITY_TEAM'))],
      ['subscription narrowed', async () => put(pool, 'recipients', 'r1', { ...recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM'), subscriptionTier: 'CISA_KEV_ONLY' })],
      ['product removed', async () => pool.query("DELETE FROM records WHERE kind='watchlist'")],
      ['CVE withdrawn', async (entry) => put(pool, 'cveWithdrawals', entry.cveId, { modifiedDate: '2027-01-01T00:00:00Z' })],
      ['source evidence changed', async (entry) => put(pool, 'cveData', entry.cveId, { ...entry.cve, description: 'Updated source evidence' })],
    ];
    for (const [name, mutate] of mutations) await t.test(name, async () => {
      await pool.query('DELETE FROM records; DELETE FROM outbox');
      await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, reviewUnverifiableMatches: true });
      const target = recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM');
      await put(pool, 'recipients', target.id, target);
      const entry = await saveReviewFinding(pool, finding('CVE-2026-20011', 'f1', 'server', 'acme', 'widget'));
      assert.equal(await queueUnverifiableMatchNotification(pool, [entry], [target]), 1);
      await mutate(entry);
      let sent = 0;
      await deliverNext(pool, config, request, async () => { sent++; return 'must-not-send'; });
      assert.equal(sent, 0);
      assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'FAILED');
      assert.equal((await get<Finding>(pool, 'findings', entry.id))?.reviewNotifiedAt, null);
      if (name === 'review confidence raised') {
        await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, reviewUnverifiableMatches: true });
        assert.equal(await queueUnverifiableMatchNotification(pool, [entry], [target]), 1);
        await deliverNext(pool, config, request, async () => { sent++; return 'policy-restored'; });
        assert.equal(sent, 1);
        assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 1);
        assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'ACCEPTED');
      }
    });
    await t.test('two workers send once and acceptance preserves concurrent operator changes', async () => {
      await pool.query('DELETE FROM records; DELETE FROM outbox');
      await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, reviewUnverifiableMatches: true });
      const target = recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM');
      await put(pool, 'recipients', target.id, target);
      const entry = await saveReviewFinding(pool, finding('CVE-2026-20012', 'f1', 'server', 'acme', 'widget'));
      await queueUnverifiableMatchNotification(pool, [entry], [target]);
      let sent = 0;
      const sender = async () => {
        sent++;
        await put(pool, 'findings', entry.id, { ...entry, status: 'FALSE_POSITIVE' });
        return 'accepted-once';
      };
      await Promise.all([deliverNext(pool, config, request, sender), deliverNext(pool, config, request, sender)]);
      assert.equal(sent, 1);
      const saved = await get<Finding>(pool, 'findings', entry.id);
      assert.equal(saved?.status, 'FALSE_POSITIVE');
      assert.ok(saved?.reviewNotifiedAt);
    });
  });
});
