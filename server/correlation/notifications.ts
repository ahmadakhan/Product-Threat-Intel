import type { Db } from '../db.ts';
import { enqueue } from '../delivery.ts';
import type { EmailRecipient, WebhookEndpoint } from '../../src/types/index.ts';
import { readNativeEvidence } from './notificationEvidence.ts';
/** Runs inside a transaction: event claim and existing outbox insertion commit together. */
export async function queueNativeNotifications(db: Db): Promise<number> {
  const policy = await db.query<{ notifications_enabled: boolean }>('SELECT notifications_enabled FROM correlation_policy WHERE id=1');
  if (!policy.rows[0]?.notifications_enabled) return 0;
  const recipientRows = await db.query<{
    data: EmailRecipient;
  }>(`SELECT data FROM records WHERE kind='recipients'
    AND data->>'enabled'='true' AND data->>'subscriptionTier'='ALL_SEVERITIES' ORDER BY id LIMIT 1001`);
  const hookRows = await db.query<{ data: WebhookEndpoint }>(`SELECT data FROM records WHERE kind='webhooks'
    AND data->>'enabled'='true' AND (data->'events') ? 'ALL' ORDER BY id LIMIT 1001`);
  if (recipientRows.rows.length > 1000 || hookRows.rows.length > 1000)
    throw new Error('NOTIFICATION_FANOUT_LIMIT');
  const recipients = recipientRows.rows.map((row) => row.data),
    hooks = hookRows.rows.map((row) => row.data);
  if (!recipients.length && !hooks.length) return 0;
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
    [recipients.length > 0],
  );
  if (!articles.rowCount) return 0;
  let queued = 0;
  for (const { advisory_id: advisoryId } of articles.rows) {
    const evidence = await readNativeEvidence(db, advisoryId);
    if (!evidence) continue;
    const eligibleRecipients = recipients.filter(
      (rec) => rec.enabled && rec.subscriptionTier === 'ALL_SEVERITIES',
    );
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
    const nativeCorrelation = {
      advisoryId,
      evidenceHash: evidence.evidenceHash,
      confidence: evidence.confidence,
    };
    const subject =
      `[Threat intelligence] [${evidence.confidence} confidence] ${evidence.article.title}`.replace(
        /[\r\n]/g,
        ' ',
      );
    const text =
      `${evidence.article.title}\n\nEvidence confidence: ${evidence.confidence}\nSource: ${evidence.article.url}\n\n` +
      evidence.matches
        .map((match) => `${match.vendor} / ${match.product} (${match.assetId}): ${match.reason}`)
        .join('\n') +
      '\n\nThis is an applicability signal. Confirm source authenticity and affected versions before remediation.';
    const payload = { subject, text, cveIds: [], nativeCorrelation };
    const identity = `native:${advisoryId}:${evidence.evidenceHash}`;
    for (const recipient of eligibleRecipients) {
      const review = evidence.confidence === 'MEDIUM' || recipient.deliveryGroup === 'EVERYONE';
      if (
        await enqueue(
          db,
          'email',
          recipient.id,
          `NATIVE:${advisoryId}`,
          { ...payload, recipientEmail: recipient.email },
          `${identity}:email:${recipient.id}`,
          review ? 'REVIEW' : 'QUEUED',
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
