import { createHash } from 'node:crypto';
import type { Db } from '../db.ts';
import { enqueue } from '../delivery.ts';
import type { EmailRecipient, Finding } from '../../src/types/index.ts';
import { recipientSubscriptions } from '../../src/types/index.ts';
import {
  consolidatedFindingsDocument,
  deliveryRevisionEvidence,
} from '../delivery.ts';
import { readNativeEvidence } from './notificationEvidence.ts';

/**
 * Escapes a feed-derived value for an HTML text node or attribute.
 *
 * The correlation alert carries article titles, URLs and match reasons straight
 * from ingested feeds. Rendering them uneescaped would let a hostile source
 * inject markup into a delivered email.
 */
const submitSafe = (value: string) =>
  String(value ?? '').replace(/[&<>"']/g, (character) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!,
  );

/**
 * Builds a Finding[] from native correlation evidence so every delivered match
 * goes through the same `renderFindingsDocument` template as pipeline findings.
 * Matches without a CVE get a synthetic advisory ID derived from the source
 * advisory so they are still trackable and deduplicated.
 */
function findingsFromEvidence(
  advisoryId: string,
  evidence: NonNullable<Awaited<ReturnType<typeof readNativeEvidence>>>,
): Finding[] {
  const shortHash = createHash('sha256').update(advisoryId).digest('hex').slice(0, 6);
  const syntheticCveId = `VND-${new Date().getFullYear()}-${shortHash.toUpperCase()}`;
  return evidence.matches.map((match) => ({
    id: crypto.randomUUID(),
    cveId: syntheticCveId,
    cve: {
      cveId: syntheticCveId,
      title: evidence.article.title,
      description: evidence.article.content ?? evidence.article.title,
      publishedDate: new Date().toISOString(),
      modifiedDate: new Date().toISOString(),
      cvss: { version: 'UNKNOWN', score: 0, vector: '', severity: 'UNKNOWN' },
      cwe: [],
      cpeMatches: [],
      sourceFeeds: [],
      epss: { score: 0, percentile: 0 },
      cisaKev: { isKev: false },
      exploitStatus: 'None',
      remediation: {
        patchUrl: evidence.article.url,
        vendorAdvisoryRef: evidence.article.url,
        immediateActions: [],
        workarounds: [],
        rollbackPlan: '',
        stepByStep: [],
      },
    },
    matchedAssetId: match.assetId,
    matchedAssetName: `${match.vendor} / ${match.product}`,
    matchedAssetVendor: match.vendor,
    matchedAssetProduct: match.product,
    matchedAssetPurls: [],
    matchedCpe: '',
    matchingMethod: 'NATIVE_CORRELATION',
    matchingEvidence: match.reason,
    confidence: match.confidence === 'HIGH' ? 100 : match.confidence === 'MEDIUM' ? 60 : 0,
    exploitRisk: 'STANDARD',
    notificationStatus: 'QUEUED_FOR_DISPATCH',
    status: 'MONITORED',
    autoDispatchedAt: null,
    advisoryId,
    executionId: undefined,
    reviewNotifiedAt: null,
    timeline: [
      {
        timestamp: new Date().toISOString(),
        action: 'Matched native correlation evidence',
        system: 'Server correlation engine',
        details: match.reason,
      },
    ],
  }));
}

export async function queueNativeNotifications(db: Db): Promise<number> {
  const policy = await db.query<{ notifications_enabled: boolean; low_confidence_alerts_enabled: boolean }>(
    'SELECT notifications_enabled, low_confidence_alerts_enabled FROM correlation_policy WHERE id=1',
  );
  if (!policy.rows[0]?.notifications_enabled) return 0;
  const lowConfidenceAlerts = policy.rows[0].low_confidence_alerts_enabled === true;
  const recipientRows = await db.query<{
    data: EmailRecipient;
  }>(`SELECT data FROM records WHERE kind='recipients'
    AND data->>'enabled'='true'
    AND (
      data->>'subscriptionTier'='ALL_SEVERITIES'
      OR data->'subscriptions' ? 'ALL_SEVERITIES'
    ) ORDER BY id LIMIT 1001`);
  const hookRows = await db.query<{ data: { id: string; enabled: boolean; events: string[] } }>(
    `SELECT data FROM records WHERE kind='webhooks'
    AND data->>'enabled'='true' ORDER BY id LIMIT 1001`);
  if (recipientRows.rows.length > 1000 || hookRows.rows.length > 1000)
    throw new Error('NOTIFICATION_FANOUT_LIMIT');
  const recipients = recipientRows.rows.map((row) => row.data),
    hooks = hookRows.rows.map((row) => row.data);
  const articles = await db.query<{ advisory_id: string }>(
    `SELECT DISTINCT m.advisory_id FROM correlation_matches m
    CROSS JOIN correlation_policy p LEFT JOIN correlation_notifications n ON n.advisory_id=m.advisory_id
    WHERE p.id=1 AND p.notifications_enabled AND m.created_at>=p.notifications_since
    AND (n.advisory_id IS NULL OR m.created_at>n.queued_at)
    AND EXISTS (
      SELECT 1 FROM correlation_matches candidate
      JOIN correlation_match_evidence e ON e.advisory_id=candidate.advisory_id AND e.asset_id=candidate.asset_id
      JOIN correlation_asset_inventory i ON i.id=candidate.asset_id
      WHERE candidate.advisory_id=m.advisory_id AND e.asset_revision=i.revision
    )
    AND (SELECT count(*) FROM (SELECT 1 FROM correlation_matches fanout WHERE fanout.advisory_id=m.advisory_id LIMIT 1001) bounded)<=1000
    AND ($1::boolean OR NOT EXISTS(SELECT 1 FROM correlation_matches other WHERE other.advisory_id=m.advisory_id AND other.confidence<>'HIGH'))
    ORDER BY m.advisory_id LIMIT 20`,
    [lowConfidenceAlerts],
  );

  let queued = 0;
  if (!articles.rows.length) return 0;
  for (const { advisory_id: advisoryId } of articles.rows) {
    const evidence = await readNativeEvidence(db, advisoryId);
    if (!evidence) continue;
    // Multi-select: the finding tier may live in the legacy scalar or in the
    // subscription list, so both are consulted.
    const eligibleRecipients = recipients.filter(
      (rec) => rec.enabled && recipientSubscriptions(rec).includes('ALL_SEVERITIES'),
    );
    // Webhooks are machine-to-machine: automated consumers only ever see HIGH-confidence evidence.
    const eligibleHooks =
      evidence.confidence === 'HIGH'
        ? hooks.filter((hook) => hook.enabled && hook.events.includes('ALL'))
        : [];
    if (!eligibleRecipients.length && !eligibleHooks.length) continue;
    const claim = await db.query(
      `INSERT INTO correlation_notifications(advisory_id,evidence_hash) VALUES($1,$2)
      ON CONFLICT(advisory_id) DO UPDATE SET evidence_hash=EXCLUDED.evidence_hash,queued_at=now()
      WHERE correlation_notifications.evidence_hash<>EXCLUDED.evidence_hash RETURNING advisory_id`,
      [advisoryId, evidence.evidenceHash],
    );
    if (!claim.rowCount) {
      await db.query(
        'UPDATE correlation_notifications SET queued_at=now() WHERE advisory_id=$1 AND evidence_hash=$2',
        [advisoryId, evidence.evidenceHash],
      );
      continue;
    }
    const findings = findingsFromEvidence(advisoryId, evidence);
    const { advisory, document } = consolidatedFindingsDocument(findings, new Date());
    const evidenceMap = deliveryRevisionEvidence(findings);
    const contentRevision = createHash('sha256')
      .update(
        JSON.stringify({
          findingIds: findings.map((f) => f.id).sort(),
          ...evidenceMap,
        }),
      )
      .digest('hex')
      .slice(0, 20);
    const payload = {
      ...document,
      cveIds: advisory.cveIds,
      includedFindingIds: findings.map((f) => f.id),
      ...evidenceMap,
      contentRevision,
      generatedAt: new Date().toISOString(),
      digestKey: advisory.id,
      nativeCorrelation: {
        advisoryId,
        evidenceHash: evidence.evidenceHash,
        confidence: evidence.confidence,
      },
    };
    const identity = `native:${advisoryId}:${evidence.evidenceHash}`;
    for (const recipient of eligibleRecipients) {
      if (
        await enqueue(
          db,
          'email',
          recipient.id,
          `NATIVE:${advisoryId}`,
          { ...payload, recipientEmail: recipient.email },
          `${identity}:email:${recipient.id}`,
          'QUEUED',
        )
      )
        queued++;
    }
    for (const hook of eligibleHooks)
      if (
        await enqueue(
          db,
          'webhook',
          hook.id,
          `NATIVE:${advisoryId}`,
          payload,
          `${identity}:webhook:${hook.id}`,
        )
      )
        queued++;
  }
  return queued;
}
