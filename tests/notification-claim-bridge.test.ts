import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { createPool, migrate, put } from '../server/db.ts';
import { queueConsolidatedFindingNotifications, queueDigestAdvisory, consolidatedFindingsDocument, queueZeroDayDigestNotification, findingHtmlAttachment, queueEveryoneDeliveryJobs, type ZeroDayDigestPayload } from '../server/delivery.ts';
import { runDailyDigest } from '../server/dailyDigest.ts';
import { claimsForJob, claimItems, reconcileDuplicateOutboxClaims } from '../server/deliveryClaims.ts';
import { newsArticleIdentity } from '../server/newsEmail.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { Finding, EmailRecipient } from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;

async function fixture(fn: (pool: pg.Pool) => Promise<void>) {
  const admin = createPool(database!);
  const schema = `notification_claim_${randomBytes(8).toString('hex')}`;
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({ connectionString: database, options: `-c search_path=${schema}`, max: 4 });
  try {
    await migrate(pool);
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    await put(pool, 'recipients', 'r1', {
      id: 'r1', name: 'SOC', email: 'security@example.invalid', enabled: true,
      deliveryGroup: 'SECURITY_TEAM', subscriptionTier: 'ALL_SEVERITIES', deliverySuccessRate: 1,
    } as EmailRecipient);
    await fn(pool);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
}

const finding = {
  id: 'f-one', cveId: 'CVE-2026-80001', status: 'MONITORED', notificationStatus: 'REVIEW_REQUIRED',
  matchedAssetId: 'asset-one', matchedAssetName: 'server-1', matchedAssetVendor: 'acme', matchedAssetProduct: 'widget',
  matchedCpe: 'cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*', confidence: 70,
  matchingEvidence: 'Version range is not confirmed by the vendor',
  matchingMethod: 'STRICT_CPE_INTERVAL', exploitRisk: 'NONE',
  advisoryId: null, reviewNotifiedAt: null, autoDispatchedAt: null, timeline: [],
  cve: {
    cveId: 'CVE-2026-80001', title: 'Test issue', description: 'Test issue',
    publishedDate: new Date().toISOString(), modifiedDate: new Date().toISOString(),
    cvss: { severity: 'HIGH', score: 8.1, version: '3.1', vector: '' },
    cwe: [], cpeMatches: ['cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*'],
    remediation: { vendorAdvisoryRef: 'https://vendor.example/issue', immediateActions: [], workarounds: [] },
    epss: { score: 0.02, percentile: 0.1 },
    sourceFeeds: ['NVD'], cisaKev: { isKev: false },
  },
} as unknown as Finding;

test('legacy digest and main consolidated queue share finding claims', { skip: !database }, async () => {
  await fixture(async (pool) => {
    assert.equal(await queueConsolidatedFindingNotifications(pool, [finding]), 1);
    const advisory = consolidatedFindingsDocument([finding], new Date()).advisory;
    const digest = await queueDigestAdvisory(pool, advisory, [finding]);
    assert.equal(digest.jobs, 0);
    const messages = await pool.query("SELECT id FROM outbox WHERE channel='email'");
    assert.equal(messages.rowCount, 1, 'same finding cannot be sent twice through a second queue');
  });
});

test('an accepted outbox job repairs a missing finding claim on dedupe', { skip: !database }, async () => {
  await fixture(async (pool) => {
    const job = await pool.query<{ id: string; dedupe_key: string }>(
      `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,delivery_outcome)
       VALUES(gen_random_uuid(),'old:email:r1','email','r1','FINDINGS:old',
              '{"includedFindingIds":["f-one"]}'::jsonb,'ACCEPTED','ACCEPTED')
       RETURNING id,dedupe_key`,
    );
    const requests = claimsForJob('r1', 'finding', ['f-one']);
    const claimed = await claimItems(pool, requests);
    assert.equal(claimed.granted.length, 1);
    await reconcileDuplicateOutboxClaims(pool, job.rows[0].dedupe_key, claimed.granted);
    const status = await pool.query<{ state: string; job_id: string }>(
      `SELECT state,job_id FROM delivery_claims WHERE recipient_id='r1' AND kind='finding' AND item_id='f-one'`,
    );
    assert.equal(status.rows[0]?.state, 'DELIVERED');
    assert.equal(status.rows[0]?.job_id, job.rows[0].id);
  });
});

test('an accepted news job repairs its article claim; subsequent news is suppressed', { skip: !database }, async () => {
  await fixture(async (pool) => {
    const article = { id: 'feed-1', url: 'https://example.com/story?id=123&utm_source=feed' };
    const articleIdentity = newsArticleIdentity(article);
    const job = await pool.query<{ id: string; dedupe_key: string }>(
      `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,delivery_outcome)
       VALUES(gen_random_uuid(),'news-old:email:r1','email','r1','NEWS:feed-1',
              $1::jsonb,'ACCEPTED','ACCEPTED')
       RETURNING id,dedupe_key`,
      [JSON.stringify({ newsEvidence: { articles: [article] } })],
    );
    const requests = claimsForJob('r1', 'article', [articleIdentity]);
    assert.equal((await claimItems(pool, requests)).granted.length, 1);
    await reconcileDuplicateOutboxClaims(pool, job.rows[0].dedupe_key, requests);
    const claim = await pool.query<{ state: string }>(
      `SELECT state FROM delivery_claims WHERE recipient_id='r1' AND kind='article' AND item_id=$1`,
      [articleIdentity],
    );
    assert.equal(claim.rows[0]?.state, 'DELIVERED');
    assert.equal((await claimItems(pool, requests)).granted.length, 0);
  });
});


test('Security-first defers only findings Security is subscribed to', { skip: !database }, async () => {
  await fixture(async (pool) => {
    await put(pool, 'settings', 'main', {
      ...DEFAULT_SETTINGS, deferEveryoneUntilSecurityDelivered: true,
    });
    await put(pool, 'recipients', 'r1', {
      id: 'r1', name: 'Security', email: 'security@example.invalid', enabled: true,
      deliveryGroup: 'SECURITY_TEAM', subscriptionTier: 'CRITICAL_HIGH_ONLY', deliverySuccessRate: 1,
    } as EmailRecipient);
    await put(pool, 'recipients', 'r2', {
      id: 'r2', name: 'Everyone', email: 'everyone@example.invalid', enabled: true,
      deliveryGroup: 'EVERYONE', subscriptionTier: 'ALL_SEVERITIES', deliverySuccessRate: 1,
    } as EmailRecipient);
    const low = {
      ...finding, id: 'f-low', cveId: 'CVE-2026-80002',
      cve: { ...finding.cve, cveId: 'CVE-2026-80002', cvss: { ...finding.cve.cvss, severity: 'LOW', score: 3.0 } },
    } as Finding;
    assert.equal(await queueConsolidatedFindingNotifications(pool, [finding, low]), 2);
    const rows = await pool.query<{ target_id: string; payload: { includedFindingIds: string[] } }>(
      "SELECT target_id,payload FROM outbox WHERE channel='email' AND status='QUEUED' ORDER BY target_id",
    );
    assert.deepEqual(rows.rows.map((r) => [r.target_id, r.payload.includedFindingIds]), [
      ['r1', ['f-one']], ['r2', ['f-low']],
    ]);
  });
});


test('the daily digest claims each finding it carries so a later queue cannot duplicate it', { skip: !database }, async () => {
  await fixture(async (pool) => {
    await put(pool, 'settings', 'main', {
      ...DEFAULT_SETTINGS,
      timezone: 'UTC',
      dailyDigest: { enabled: true, time: '00:00', includeHealthReport: false },
    });
    // Deliberately no CVE cache / watchlist entry: the digest must still carry a
    // finding that was already queued for dispatch (its rematch has no verdict,
    // so the stored deliverable state is authoritative).
    await put(pool, 'findings', finding.id, { ...finding, notificationStatus: 'QUEUED_FOR_DISPATCH' });
    await put(pool, 'recipients', 'r1', {
      id: 'r1', name: 'SOC', email: 'security@example.invalid', enabled: true,
      dailyDigest: true, deliveryGroup: 'SECURITY_TEAM', subscriptionTier: 'ALL_SEVERITIES',
      deliverySuccessRate: 1,
    } as EmailRecipient);

    assert.equal(await runDailyDigest(pool), 1);
    const job = (await pool.query<{ id: string; status: string; payload: { includedFindingIds: string[] } }>(
      "SELECT id,status,payload FROM outbox WHERE channel='email'",
    )).rows[0];
    assert.equal(job.status, 'QUEUED', 'there is no review status in the daily digest path');
    assert.deepEqual(job.payload.includedFindingIds, [finding.id]);
    const claim = (await pool.query<{ state: string; job_id: string }>(
      `SELECT state,job_id FROM delivery_claims
        WHERE recipient_id='r1' AND kind='finding' AND item_id=$1`,
      [finding.id],
    )).rows[0];
    assert.equal(claim?.state, 'CLAIMED');
    assert.equal(claim?.job_id, job.id, 'the digest claim is attached to the digest job');

    // The consolidated queue shares the same durable claim, so it cannot send
    // the same finding to the same mailbox a second time.
    assert.equal(await queueConsolidatedFindingNotifications(pool, [finding]), 0);
    assert.equal(
      (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE channel='email'")).rows[0].n,
      1,
    );
  });
});

test('queueEveryoneDeliveryJobs never queues a second copy to the same mailbox', { skip: !database }, async () => {
  await fixture(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, deferEveryoneUntilSecurityDelivered: true });
    await put(pool, 'recipients', 'sec', {
      id: 'sec', name: 'Security', email: 'shared@example.invalid', enabled: true,
      deliveryGroup: 'SECURITY_TEAM', subscriptionTier: 'ALL_SEVERITIES', deliverySuccessRate: 1,
    } as EmailRecipient);
    await put(pool, 'recipients', 'everyone', {
      id: 'everyone', name: 'Everyone', email: 'shared@example.invalid', enabled: true,
      deliveryGroup: 'EVERYONE', subscriptionTier: 'ALL_SEVERITIES', deliverySuccessRate: 1,
    } as EmailRecipient);
    await put(pool, 'advisories', 'FINDINGS:shared-mailbox', {
      id: 'FINDINGS:shared-mailbox', title: 'Shared mailbox', severity: 'HIGH',
      cveIds: [finding.cveId], findingIds: [finding.id], createdDate: new Date().toISOString(),
      deliveryStatus: 'PENDING', recipientCount: 1, executiveSummary: '', remediationInstructions: '',
      vendorLink: '', affectedSystems: [],
    });
    const accepted = await pool.query<{ id: string }>(
      `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,delivery_outcome,priority)
       VALUES(gen_random_uuid(),'findings:shared:email:sec','email','sec','FINDINGS:shared-mailbox',
              $1::jsonb,'ACCEPTED','ACCEPTED',0)
       RETURNING id`,
      [JSON.stringify({ subject: 'Shared', text: 'Shared', html: '<html></html>', includedFindingIds: [finding.id] })],
    );
    const acceptedJob = {
      id: accepted.rows[0].id,
      dedupe_key: 'findings:shared:email:sec',
      channel: 'email',
      target_id: 'sec',
      advisory_id: 'FINDINGS:shared-mailbox',
      payload: { subject: 'Shared', text: 'Shared', html: '<html></html>', includedFindingIds: [finding.id] },
      status: 'ACCEPTED',
      priority: 0,
    } as unknown as Parameters<typeof queueEveryoneDeliveryJobs>[1];

    assert.equal(await queueEveryoneDeliveryJobs(pool, acceptedJob, { ...DEFAULT_SETTINGS, deferEveryoneUntilSecurityDelivered: true }), 0);
    assert.equal(
      (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE target_id='everyone'")).rows[0].n,
      0,
      'the shared mailbox already has the accepted Security job',
    );
  });
});

test('a deferred Everyone delivery claims its findings and blocks a second copy', { skip: !database }, async () => {
  await fixture(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, deferEveryoneUntilSecurityDelivered: true });
    await put(pool, 'recipients', 'sec', {
      id: 'sec', name: 'Security', email: 'security@example.invalid', enabled: true,
      deliveryGroup: 'SECURITY_TEAM', subscriptionTier: 'ALL_SEVERITIES', deliverySuccessRate: 1,
    } as EmailRecipient);
    await put(pool, 'recipients', 'everyone', {
      id: 'everyone', name: 'Everyone', email: 'everyone@example.invalid', enabled: true,
      deliveryGroup: 'EVERYONE', subscriptionTier: 'ALL_SEVERITIES', deliverySuccessRate: 1,
    } as EmailRecipient);
    await put(pool, 'advisories', 'FINDINGS:distinct-mailbox', {
      id: 'FINDINGS:distinct-mailbox', title: 'Distinct mailbox', severity: 'HIGH',
      cveIds: [finding.cveId], findingIds: [finding.id], createdDate: new Date().toISOString(),
      deliveryStatus: 'PENDING', recipientCount: 1, executiveSummary: '', remediationInstructions: '',
      vendorLink: '', affectedSystems: [],
    });
    const accepted = await pool.query<{ id: string }>(
      `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,delivery_outcome,priority)
       VALUES(gen_random_uuid(),'findings:distinct:email:sec','email','sec','FINDINGS:distinct-mailbox',
              $1::jsonb,'ACCEPTED','ACCEPTED',0)
       RETURNING id`,
      [JSON.stringify({ subject: 'Distinct', text: 'Distinct', html: '<html></html>', includedFindingIds: [finding.id] })],
    );
    const acceptedJob = {
      id: accepted.rows[0].id,
      dedupe_key: 'findings:distinct:email:sec',
      channel: 'email',
      target_id: 'sec',
      advisory_id: 'FINDINGS:distinct-mailbox',
      payload: { subject: 'Distinct', text: 'Distinct', html: '<html></html>', includedFindingIds: [finding.id] },
      status: 'ACCEPTED',
      priority: 0,
    } as unknown as Parameters<typeof queueEveryoneDeliveryJobs>[1];

    assert.equal(await queueEveryoneDeliveryJobs(pool, acceptedJob, { ...DEFAULT_SETTINGS, deferEveryoneUntilSecurityDelivered: true }), 1);
    const everyoneJob = (await pool.query<{ id: string; status: string }>(
      "SELECT id,status FROM outbox WHERE target_id='everyone'",
    )).rows[0];
    assert.equal(everyoneJob.status, 'QUEUED', 'the deferred broadcast is auto-dispatched, never reviewed');
    const claim = (await pool.query<{ state: string; job_id: string }>(
      `SELECT state,job_id FROM delivery_claims
        WHERE recipient_id='everyone' AND kind='finding' AND item_id=$1`,
      [finding.id],
    )).rows[0];
    assert.equal(claim?.state, 'CLAIMED');
    assert.equal(claim?.job_id, everyoneJob.id);

    const everyoneRecipient = (await pool.query<{ data: EmailRecipient }>(
      "SELECT data FROM records WHERE kind='recipients' AND id='everyone'",
    )).rows[0].data;
    assert.equal(
      await queueConsolidatedFindingNotifications(pool, [finding], { recipients: [everyoneRecipient] }),
      0,
      'the Everyone claim blocks the consolidated queue from repeating the finding',
    );
  });
});

test('an oversized findings HTML attachment fails before any provider send', () => {
  assert.throws(() => findingHtmlAttachment({
    advisory_id: 'FINDINGS:too-large',
    payload: { html: '<html>' + 'x'.repeat(4_000_001) + '</html>' },
  } as unknown as import('../server/delivery.ts').Job), /exceeds the attachment limit/);
});

test('a consolidated batch queues one webhook per event-subscribed hook; webhook-only findings still dispatch', { skip: !database }, async () => {
  await fixture(async (pool) => {
    await put(pool, 'webhooks', 'hook-all', {
      id: 'hook-all', name: 'All events', url: 'https://hooks.example.invalid/all',
      provider: 'GENERIC_HMAC', secretToken: 'secret', enabled: true, events: ['ALL'], deliveryCount: 0,
    });
    await put(pool, 'webhooks', 'hook-critical', {
      id: 'hook-critical', name: 'Critical only', url: 'https://hooks.example.invalid/critical',
      provider: 'GENERIC_HMAC', secretToken: 'secret', enabled: true, events: ['CRITICAL'], deliveryCount: 0,
    });
    await put(pool, 'webhooks', 'hook-disabled', {
      id: 'hook-disabled', name: 'Disabled', url: 'https://hooks.example.invalid/off',
      provider: 'GENERIC_HMAC', secretToken: 'secret', enabled: false, events: ['ALL'], deliveryCount: 0,
    });
    // This HIGH finding is permitted by ALL only: the CRITICAL hook must not
    // receive it, and the disabled hook must receive nothing.
    assert.equal(await queueConsolidatedFindingNotifications(pool, [finding]), 2);
    const hooks = (await pool.query<{ target_id: string; advisory_id: string; payload: { includedFindingIds: string[] } }>(
      "SELECT target_id,advisory_id,payload FROM outbox WHERE channel='webhook' ORDER BY target_id",
    )).rows;
    assert.deepEqual(hooks.map((row) => row.target_id), ['hook-all']);
    assert.match(hooks[0].advisory_id, /^FINDINGS:[0-9a-f]{24}$/);
    assert.deepEqual(hooks[0].payload.includedFindingIds, ['f-one']);

    // A repeat pass re-derives the same content revision, so neither surface is
    // queued twice.
    assert.equal(await queueConsolidatedFindingNotifications(pool, [finding]), 0);
    assert.equal(
      (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE channel='webhook'")).rows[0].n,
      1,
    );
  });
});
