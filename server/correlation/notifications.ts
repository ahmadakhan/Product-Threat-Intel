import type { Db } from '../db.ts';
import { enqueue } from '../delivery.ts';
import type { EmailRecipient, WebhookEndpoint } from '../../src/types/index.ts';
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
/** Runs inside a transaction: event claim and existing outbox insertion commit together. */
export async function queueNativeNotifications(db: Db): Promise<number> {
  const policy = await db.query<{ notifications_enabled: boolean; low_confidence_alerts_enabled: boolean }>(
    'SELECT notifications_enabled, low_confidence_alerts_enabled FROM correlation_policy WHERE id=1',
  );
  if (!policy.rows[0]?.notifications_enabled) return 0;
  const lowConfidenceAlerts = policy.rows[0].low_confidence_alerts_enabled === true;
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
  // No early return on an empty audience. Two independent gates used to be
  // conflated here: "is anyone listening?" (no recipient and no hook) and "may
  // unconfirmed evidence be delivered?". The old code used the audience size as
  // the confidence switch, so with no HIGH-eligible recipient a MEDIUM match was
  // withheld, and with any recipient it was delivered. Both answers are now
  // explicit; an empty audience simply queues nothing below.
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
    // The confidence gate is an operator decision, never an inference from how
    // many recipients happen to exist. It used to be bound to `recipients.length
    // > 0`, so on a deployment with no eligible recipient the "all matches must
    // be HIGH" rule silently switched off instead of withholding.
    [lowConfidenceAlerts],
  );


  let queued = 0;
  // LOW evidence is intentionally NOT delivered, even with low-confidence alerts
  // on. `low_confidence_review_buffer` is where the engine files everything it
  // could not attribute to an asset: a bare co-occurrence of two words, an
  // advisory whose text *negates* applicability ("not affected", "false
  // positive"), and version-ordering ambiguity. Its rows exist to be reviewed,
  // and several of them assert that the asset is NOT exposed — delivering those
  // as alerts would be actively wrong, which no confidence label can repair.
  //
  // Only MEDIUM evidence (a thesaurus-resolved vendor/product whose version
  // range could not be confirmed, or an operator-verified match) is delivered
  // without a review step. The switch above widens delivery from HIGH to HIGH+
  // MEDIUM; it never reaches into the review buffer.
  if (!articles.rows.length) return 0;
  for (const { advisory_id: advisoryId } of articles.rows) {
    const evidence = await readNativeEvidence(db, advisoryId);
    if (!evidence) continue;
    const eligibleRecipients = recipients.filter(
      (rec) => rec.enabled && rec.subscriptionTier === 'ALL_SEVERITIES',
    );
    // Webhooks are machine-to-machine: an unconfirmed match would arrive without
    // the human-readable notice an email carries, so automated consumers only
    // ever see HIGH-confidence evidence.
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
    // Every delivered match names an attributed asset: review-buffer evidence is
    // never delivered, so there is no empty-asset case to paper over.
    const describeMatch = (match: { vendor: string; product: string; assetId: string; reason: string }) =>
      `${match.vendor} / ${match.product} (${match.assetId}): ${match.reason}`;
    const reasonLines = evidence.matches.map(describeMatch).join('\n');
    // The notice names every match that could not be confirmed, so an operator
    // can see exactly which vendor/product pairs still need version verification
    // rather than being told only that *something* was uncertain.
    const unconfirmedNotice =
      evidence.unconfirmedMatches.length && evidence.confidence !== 'HIGH'
        ? `${evidence.confidence}-confidence correlation: ${evidence.unconfirmedMatches.length} match(es) could not be confirmed against an installed version.\n` +
          evidence.unconfirmedMatches.map((match) => `- ${describeMatch(match)}`).join('\n') +
          '\nConfirm the affected version against vendor guidance before remediation.'
        : '';
    const text =
      `${evidence.article.title}\n\nEvidence confidence: ${evidence.confidence}\nSource: ${evidence.article.url}\n\n` +
      reasonLines +
      (unconfirmedNotice ? `\n\n${unconfirmedNotice}` : '') +
      '\n\nThis is an applicability signal. Confirm source authenticity and affected versions before remediation.';
    // A body is required: the worker sends `payload.html` whenever it is present,
    // so a native alert without one shipped a message part that dropped the
    // confidence statement entirely.
    const html =
      '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
      `<title>${submitSafe(subject)}</title></head>` +
      '<body style="margin:0;padding:24px;background:#f1f3f5;font-family:Arial,Helvetica,sans-serif;">' +
      '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #dfe4e8;border-top:4px solid #1e40af;">' +
      '<tr><td style="padding:20px 24px;border-bottom:1px solid #dfe4e8;">' +
      '<p style="margin:0;font-size:14px;font-weight:700;color:#17212b;">VulnStream Enterprise</p>' +
      '<p style="margin:3px 0 0;font-size:12px;color:#52606d;">THREAT INTELLIGENCE / CORRELATION SIGNAL</p></td></tr>' +
      '<tr><td style="padding:24px;">' +
      `<p style="margin:0 0 12px;"><span style="display:inline-block;padding:4px 9px;border-radius:4px;background:${evidence.confidence === 'HIGH' ? '#1e40af' : '#b7791f'};color:#ffffff;font-size:11px;font-weight:700;">${submitSafe(evidence.confidence)} CONFIDENCE</span></p>` +
      `<h1 style="margin:0 0 12px;font-size:20px;line-height:28px;color:#111827;">${submitSafe(evidence.article.title)}</h1>` +
      `<p style="margin:0 0 4px;font-size:13px;color:#374151;"><strong>Source:</strong> ${submitSafe(evidence.article.url)}</p>` +
      `<p style="margin:0 0 12px;font-size:13px;color:#374151;"><strong>Evidence confidence:</strong> ${submitSafe(evidence.confidence)}</p>` +
      `<pre style="margin:0;padding:12px;background:#f7f8fa;border-left:3px solid #b7791f;font-size:13px;line-height:20px;color:#374151;white-space:pre-wrap;word-break:break-word;">${submitSafe(reasonLines)}</pre>` +
      (unconfirmedNotice
        ? `<p style="margin:12px 0 0;padding:8px 10px;background:#fffbeb;border-left:3px solid #b7791f;font-size:13px;line-height:19px;color:#7c2d12;"><strong>${submitSafe(evidence.confidence)} confidence notice:</strong> ${submitSafe(unconfirmedNotice.replace(`${evidence.confidence}-confidence correlation: `, ''))}</p>`
        : '') +
      '<p style="margin:12px 0 0;font-size:13px;line-height:20px;color:#52606d;">This is an applicability signal. Confirm source authenticity and affected versions before remediation.</p>' +
      '</td></tr></table></body></html>';
    const payload = { subject, text, html, cveIds: [], nativeCorrelation };
    const identity = `native:${advisoryId}:${evidence.evidenceHash}`;
    for (const recipient of eligibleRecipients) {
      // Every recipient is queued for delivery, whatever the evidence confidence
      // or delivery group: there is no review queue. The subject names the
      // confidence and the body lists every unconfirmed match, so a MEDIUM- or
      // LOW-confidence correlation is disclosed rather than withheld. Whether
      // such an advisory is delivered at all is decided once, above, by the
      // operator's low-confidence switch.
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
