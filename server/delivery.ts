import { validateNativeDelivery, type NativeDelivery } from './correlation/notificationEvidence.ts';
import { describeError, writeEvent } from './events';
import { classifyDeliveryError, computeRetryDelay, getMlRuntime } from './ml/integration.ts';
import { advisoryEmail } from './advisoryEmail';
import { advisoryFilename, renderAdvisoryPdf, unverifiableMatchFilename } from './pdf';
import type pg from 'pg';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { DEFAULT_SETTINGS, DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import type {
  WatchListItem,
  NormalizedCVE,
  AliasEntry,
  IntelligenceArticle,
  IntelligenceMatch,
} from '../src/types/index.ts';
/** Payload carried by a news (IntelligenceMatch) delivery job. */
export interface NewsEvidencePayload {
  /** IntelligenceMatch.id this job was queued from. */
  matchId: string;
  /** Primary article, retained for backwards-compatible consumers. */
  article: Pick<IntelligenceArticle, 'id' | 'title' | 'url' | 'sourceFeeds' | 'publishedDate'>;
  /** Complete evidence set that contributed to this match. */
  articles: Array<Pick<IntelligenceArticle, 'id' | 'title' | 'url' | 'sourceFeeds' | 'publishedDate'>>;
  /** Asset the article was matched against. */
  asset: { name: string; vendor?: string; product?: string };
  /** CVE identifiers referenced by the matched article, if any. */
  cveIds: string[];
  /** Structured evidence text for the email body. */
  evidence: string;
  /** True when the article describes an unassigned vulnerability (potential zero-day). */
  zeroDay?: boolean;
  credibilityScore?: number;
}
/** Zero-day evidence consolidated into a digest instead of individual alerts. */
export interface ZeroDayDigestPayload {
  /** `DIGEST_<vendor>_<product>` identity from `rankAndRateLimitZeroDays`. */
  digestId: string;
  vendor: string;
  product: string;
  /** Matches this digest replaces. Kept for audit, not for re-dispatch. */
  matchIds: string[];
  matchCount: number;
  findings: Array<{
    findingId?: string;
    cveId?: string;
    assetName: string;
    evidence: string;
    credibilityScore?: number;
  }>;
  articles: Array<{ id: string; title: string; url: string; sourceFeeds: string[] }>;
}

/** Per-finding record inside an unverifiable-match batch. */
export interface UnverifiableMatchFinding {
  findingId: string;
  asset: { name: string; vendor?: string; product?: string };
  cveId: string;
  evidence: string;
  severity: string;
  cvssScore: number;
}
/** Payload carried by an unverifiable-match review notification delivery job. */
export interface UnverifiableMatchPayload {
  /** Findings batched into this single combined notification, in display order. */
  findings: UnverifiableMatchFinding[];
  /** CVE identifiers referenced across the batch, de-duplicated and sorted. */
  cveIds: string[];
  /** Workspace timezone used for publication/update timestamps in the rendered email. */
  timezone?: string;
}
import { buildAliasMap, parseCPE23 } from '../src/utils/cpeMatcher';
import { randomUUID, createHmac, createHash } from 'node:crypto';
import { mergeCveRecords, stableJson } from '../src/utils/deduplicator';
import nodemailer from 'nodemailer';
import type { Config } from './config';
import { transaction, get, getMany, list, put, appendAudit, schemaLockKey } from './db';
import type { Db } from './db';
import { createRequester, type Requester } from './network';
import { isFindingDelivery, eligibleForReviewNotification } from '../src/utils/findingDelivery.ts';
import { renderUnverifiableReviewEmail } from './reviewEmail.ts';
import {
  effectiveSubject,
  normalizeEmailSubject,
  renderReviewEdits,
  renderReviewText,
} from './emailEdits';
import {
  EMAIL_PROVIDER_LABELS,
  EmailProviderError,
  emailIsConfigured,
  lookupProviderDelivery,
  sendProviderEmail,
} from './emailProviders';
import { decrypt, encryptionKeys } from './secrets';
import { isSmtpEmailProvider } from '../src/types/index.ts';
import type {
  Advisory,
  Finding,
  EmailRecipient,
  WebhookEndpoint,
  EmailDeliveryLog,
  WebhookDeliveryLog,
  AlertedCVE,
  EmailConfiguration,
  AppSettings,
  ReviewEdits,
} from '../src/types/index.ts';
export interface Job {
  id: string;
  dedupe_key: string;
  channel: 'email' | 'webhook';
  target_id: string;
  advisory_id: string;
  payload: {
    subject: string;
    text: string;
    html?: string;
    recipientEmail?: string;
    cveIds: string[];
    nativeCorrelation?: NativeDelivery;
    cveRevisions?: Record<string, string>;
    findingRevisions?: Record<string, string>;
      /** Provider-assigned message id of a prior attempt that could not be recorded. */
      unconfirmedProviderId?: string;
      /**
     * Digest jobs carry only the findings the target is subscribed to. Delivery
     * revalidation and receipt accounting must use this subset, not the union
     * advisory, or a KEV-only recipient would be blocked by unrelated findings.
     */
    includedFindingIds?: string[];
    /** Stable per-batch key used for CVE dispatch accounting across recipients. */
    digestKey?: string;
    /**
     * IntelligenceMatch (security news/advisory) evidence queued for direct
     * delivery to the Security team. When present, the job carries no advisory
     * row and is validated as a news bundle instead.
     */
    newsEvidence?: NewsEvidencePayload;
    /**
     * Unverifiable-match evidence queued for direct delivery to the Security
     * team. The match could not verify the version range, so the finding is held
     * for review despite a product-identity correlation.
     */
    unverifiableMatch?: UnverifiableMatchPayload;
    /**
     * Zero-day digest consolidated under the per-run cap
     * (`rankAndRateLimitZeroDays`). When present, the job is a standalone summary
     * of withheld zero-day evidence and carries no advisory row. The findings it
     * names are NOT part of the ordinary dispatch path — they were removed from
     * it deliberately — so delivery must not treat them as a finding bundle.
     */
    zeroDayDigest?: ZeroDayDigestPayload;
    /**
     * The content revision this payload was queued under. Queueing proves the
     * revision; re-deriving it later from the advisory does not. The advisory a
     * digest job references is the union of every recipient's findings, so the
     * content-derived key differs from the per-recipient key for any mixed
     * subscription set. Approval re-hashes the stored payload and must compare
     * against this value, not a recomputed union revision.
     */
    contentRevision?: string;
    /**
     * When true, the job is a calendar daily-digest delivery: an overall summary
     * email. Such jobs never carry a PDF attachment — the body is the summary
     * itself — so the sender skips PDF rendering entirely.
     */
    dailyDigest?: boolean;
  };
  attempts: number;
  prior_attempt_at?: Date | string | null;
  lock_token: string;
  review_approved?: boolean;
  edits?: ReviewEdits;
  priority?: number;
}
export type MailSender = (
  job: Job,
) => Promise<string | { id: string; provider: EmailDeliveryLog['provider'] }>;

/**
 * Applies the operator's review edits to a queued job.
 *
 * This is the single place where the email body, its plain-text companion and
 * the subject are reconciled. `deliverNext` calls it before handing the job to
 * the transport, and `buildPdfAttachment` renders the PDF from the same
 * `payload.html`, so an edit made in the Action Center cannot update the email
 * without updating its attachment.
 *
 * The transform is idempotent (see `renderReviewEdits`), which matters because
 * approval may already have merged the notice/comment into the stored body.
 */
export function applyJobEdits(job: Job): Job {
  if (!job.edits || !Object.keys(job.edits).length) return job;
  const edits = job.edits;
  return {
    ...job,
    payload: {
      ...job.payload,
      html: renderReviewEdits(job.payload.html, edits),
      text: renderReviewText(job.payload.text, edits),
      subject: effectiveSubject(job.payload.subject, edits),
    },
  };
}
export interface EmailAttachment {
  filename: string;
  content: Buffer;
  contentType: string;
}
export interface EmailRetryPolicy {
  /** When false, a transient failure becomes terminal after the first attempt. */
  enabled: boolean;
  /** Total attempts, including the first send. */
  maxAttempts: number;
  initialDelayMinutes: number;
  maxDelayMinutes: number;
}
const boundedInt = (value: unknown, fallback: number, min: number, max: number) => {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
};
/**
 * Resolves the operator-configured retry policy. Persisted settings from older
 * deployments may not contain these fields yet, so missing values fall back to
 * the documented defaults instead of disabling retries silently.
 */
export function emailRetryPolicy(settings?: Partial<AppSettings> | null): EmailRetryPolicy {
  const initialDelayMinutes = boundedInt(
    settings?.emailRetryInitialDelayMinutes,
    DEFAULT_SETTINGS.emailRetryInitialDelayMinutes,
    1,
    1440,
  );
  return {
    enabled: settings?.emailRetryEnabled ?? DEFAULT_SETTINGS.emailRetryEnabled,
    maxAttempts: boundedInt(settings?.emailRetryMaxAttempts, DEFAULT_SETTINGS.emailRetryMaxAttempts, 1, 20),
    initialDelayMinutes,
    maxDelayMinutes: Math.max(
      initialDelayMinutes,
      boundedInt(settings?.emailRetryMaxDelayMinutes, DEFAULT_SETTINGS.emailRetryMaxDelayMinutes, 1, 10080),
    ),
  };
}
export const DEFAULT_EMAIL_RETRY_POLICY = emailRetryPolicy(DEFAULT_SETTINGS);
/**
 * Exponential backoff capped by the configured maximum, so a provider outage is
 * retried durably without hammering the relay and without retrying forever.
 */
export const emailRetryDelayMs = (attempt: number, policy: EmailRetryPolicy) =>
  Math.min(
    policy.maxDelayMinutes * 60_000,
    policy.initialDelayMinutes * 60_000 * 2 ** Math.max(0, attempt - 1),
  );
export function emailRetryDelayPlan(
  attempt: number,
  policy: EmailRetryPolicy,
  mlDelayMs?: number,
): { delayMs: number; source: 'OPERATOR' | 'ML' | 'ML_CAPPED' } {
  const operatorDelayMs = emailRetryDelayMs(attempt, policy);
  if (mlDelayMs === undefined || !Number.isFinite(mlDelayMs) || mlDelayMs <= operatorDelayMs)
    return { delayMs: operatorDelayMs, source: 'OPERATOR' };
  const ceiling = policy.maxDelayMinutes * 60_000;
  return {
    delayMs: Math.min(ceiling, mlDelayMs),
    source: mlDelayMs > ceiling ? 'ML_CAPPED' : 'ML',
  };
}
export function observedRetryDelay(
  priorAttemptAt: Date | string | null | undefined,
  attemptStartedAt: number,
): { delayMs: number; observed: boolean } {
  if (!priorAttemptAt) return { delayMs: 0, observed: false };
  const priorTime = new Date(priorAttemptAt).getTime();
  return Number.isFinite(priorTime)
    ? { delayMs: Math.max(0, attemptStartedAt - priorTime), observed: true }
    : { delayMs: 0, observed: false };
}
/** Human-readable schedule stored on the delivery log for operator visibility. */
export const emailRetrySchedule = (policy: EmailRetryPolicy) =>
  policy.enabled
    ? Array.from(
        { length: policy.maxAttempts },
        (_, index) => `${Math.round(emailRetryDelayMs(index + 1, policy) / 60_000)}m`,
      )
    : [];
/**
 * Content-relevant CVE fingerprint used for delivery staleness checks.
 *
 * Only fields that affect advisory content (severity, remediation links,
 * CISA KEV status in the finding-detail line) or matching applicability are
 * included. Enrichment and metadata fields — EPSS scores, exploit status,
 * exploitation sources, source-feed attribution, publication/modification
 * timestamps, CPE weakness IDs — are excluded because feed refreshes update
 * them independently of the matching engine without altering the advisory a
 * recipient receives.
 *
 * This deliberately mirrors the field set of `matchingCveSignature` in
 * pipeline.ts (the signature the pipeline uses for its reusable-match
 * optimisation) plus `cvss`, `remediation` and `cisaKev.isKev`, all of which
 * surface in delivered content. Aligning these two signatures prevents a
 * benign enrichment refresh from triggering a false "CVE intelligence
 * changed" failure when the pipeline correctly treats the refresh as a
 * no-op.
 */
export const revision = (cve: NormalizedCVE) => {
  const canonical = mergeCveRecords([cve]).get(cve.cveId) || cve;
  return createHash('sha256')
    .update(
      stableJson({
        cveId: canonical.cveId,
        title: canonical.title,
        description: canonical.description,
        cvss: canonical.cvss,
        cpeMatches: canonical.cpeMatches,
        cpeMatchDetails: canonical.cpeMatchDetails,
        versionRange: canonical.versionRange,
        purls: canonical.purls,
        applicabilityRequiresReview: canonical.applicabilityRequiresReview,
        applicabilityPolicy: canonical.applicabilityPolicy,
        remediation: canonical.remediation,
        isKev: canonical.cisaKev?.isKev ?? false,
      }),
    )
    .digest('hex');
};
/**
 * Finding fingerprint for delivery staleness checks and advisory content
 * revision (dedupe key).
 *
 * `exploitRisk` is intentionally excluded: it is derived from enrichment
 * data (EPSS, KEV, exploit status) that the pipeline refreshes independently
 * of matching. Including it would make the content-revision change whenever
 * a feed refresh updated a score, which in turn prevents the ON-CONFLICT
 * resurrection of a failed job from matching (different dedupe key) and
 * forces a new advisory even though the delivered email content — severity,
 * remediation links, affected systems — is unchanged. The revalidation
 * already catches genuine applicability changes via the `!match` and
 * `notificationStatus` checks below.
 *
 * `matchedCpe` and the free-text `matchingEvidence` are excluded as well: the
 * CPE recorded is the NVD criterion in one context and the inventory CPE in
 * another, while the evidence string embeds the confidence the policy happened
 * to require. Both describe *how* the match was spelled, not *whether* the
 * asset is affected, so including them made revalidation report "inventory or
 * matching evidence changed" — and the bundle fail — after a benign policy or
 * spelling difference. Affected-system content is covered by `assetName`.
 */
export const findingRevision = (finding: Finding) =>
  createHash('sha256')
    .update(
      stableJson({
        cveId: finding.cveId,
        assetId: finding.matchedAssetId,
        assetName: finding.matchedAssetName,
        // Include the matched asset vendor/product so a cosmetic identity
        // label change (e.g. an alias thesaurus rename) re-renders a digest
        // summary instead of silently shipping stale labels. Pure enrichment
        // fields remain excluded to avoid churn on feed refreshes.
        assetVendor: finding.matchedAssetVendor,
        assetProduct: finding.matchedAssetProduct,
      }),
    )
    .digest('hex');
/**
 * Content revision for one advisory. Queueing the same advisory revision twice
 * is idempotent; a materially changed advisory (new findings, revised severity,
 * summary, remediation, or changed CVE evidence) gets a new revision and can be
 * delivered again.
 */
export const advisoryRevision = (advisory: Advisory, findings: Finding[]) =>
  createHash('sha256')
    .update(
      stableJson({
        advisory: {
          // The advisory ID is intentionally excluded: pipeline-created
          // advisories receive a new random ID on every run, so including it
          // would defeat idempotent delivery of unchanged content. An explicit
          // operator dispatch key still distinguishes intentional resends.
          title: advisory.title,
          severity: advisory.severity,
          // Delivery content is a set, not a sequence. Sorting here keeps the
          // dedupe key stable when the pipeline or a digest buffer returns the
          // same findings in a different database order.
          cveIds: [...advisory.cveIds].sort(),
          findingIds: [...advisory.findingIds].sort(),
          executiveSummary: advisory.executiveSummary,
          remediationInstructions: advisory.remediationInstructions,
          affectedSystems: [...advisory.affectedSystems].sort(),
          isDigestBatch: advisory.isDigestBatch ?? false,
          vendorLink: advisory.vendorLink ?? '',
        },
        findings: findings
          .map((finding) => [
            finding.id,
            findingRevision(finding),
            // A CVE evidence change (affected CPEs, version range, remediation,
            // severity) alters the delivered advisory even when the finding row
            // itself is unchanged. `revision` excludes enrichment noise, so this
            // honours the documented dedupe contract without churn on feed
            // refreshes.
            revision(finding.cve),
          ])
          .sort(([left], [right]) => left.localeCompare(right)),
      }),
    )
    .digest('hex')
    .slice(0, 20);
export const SEVERITY_ORDER = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#16a34a',
  UNKNOWN: '#6b7280',
};
const uniqueSorted = (values: string[]) => Array.from(new Set(values)).sort();
/** Highest severity in a set of findings, used for combined digest subjects. */
const highestSeverity = (findings: Finding[]): Advisory['severity'] =>
  findings.reduce(
    (severity, finding) =>
      SEVERITY_ORDER.indexOf(finding.cve.cvss.severity) > SEVERITY_ORDER.indexOf(severity)
        ? finding.cve.cvss.severity
        : severity,
    'UNKNOWN' as Advisory['severity'],
  );
const findingDetail = (finding: Finding) =>
  `${finding.cveId} | ${finding.cve.cvss.severity}${finding.cve.cisaKev?.isKev ? ' | CISA KEV' : ''} | ${finding.matchedAssetName}`;
/** Deterministic vendor link so batch ordering cannot change the dedupe key. */
const vendorLinkFor = (findings: Finding[]) =>
  uniqueSorted(
    findings
      .map((finding) => finding.cve.remediation.vendorAdvisoryRef || finding.cve.remediation.patchUrl)
      .filter((link): link is string => !!link),
  )[0] || '';
/**
 * Builds the advisory view for a set of findings. Every recipient receives a
 * view containing exactly the findings its subscription permits, while the
 * persisted advisory is the union of all views for queue accounting.
 */
function digestView(advisory: Advisory, findings: Finding[]): Advisory {
  const cveIds = uniqueSorted(findings.map((finding) => finding.cveId));
  const systems = uniqueSorted(findings.map((finding) => finding.matchedAssetName));
  const severity = highestSeverity(findings);
  const vulnerabilitySeverityParts: string[] = [];
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const) {
    const count = findings.filter((finding) => finding.cve.cvss.severity === sev).length;
    if (count) vulnerabilitySeverityParts.push(count + ' ' + sev.charAt(0) + sev.slice(1).toLowerCase());
  }
  const vulnerabilitySeveritySummary = vulnerabilitySeverityParts.length
    ? vulnerabilitySeverityParts.join(', ')
    : '0 vulnerabilities';
  const summary =
    findings.length === 1
      ? '1 inventory correlation requires investigation. Confirm applicability and consult the vendor before remediation.'
      : `${findings.length} inventory correlations across ${systems.length} system${systems.length === 1 ? '' : 's'} require investigation. Confirm applicability and consult the vendor before remediation.`;
  return {
    ...advisory,
    title: `Vulnerability ${findings.length === 1 ? 'notice' : 'digest'}: ${vulnerabilitySeveritySummary}`,
    severity,
    cveIds,
    findingIds: findings.map((finding) => finding.id),
    executiveSummary: summary,
    affectedSystems: systems,
    vendorLink: vendorLinkFor(findings),
    isDigestBatch: true,
  };
}
const advisoryPriority = (findings: Finding[]) =>
  Math.max(
    0,
    ...findings.map((finding) =>
      finding.cve.cisaKev?.isKev
        ? 100
        : finding.exploitRisk === 'REPORTED_IN_WILD_EXPLOIT' ||
            finding.exploitRisk === 'WEAPONIZED_EXPLOIT' ||
            finding.cve.exploitationSources?.length
          ? 50
          : finding.notificationStatus === 'REVIEW_REQUIRED'
            ? 50
            : 0,
    ),
  );
export function recipientAllows(recipient: EmailRecipient, finding: Finding): boolean {
  return (
    recipient.subscriptionTier === 'ALL_SEVERITIES' ||
    (recipient.subscriptionTier === 'CRITICAL_HIGH_ONLY' &&
      ['CRITICAL', 'HIGH'].includes(finding.cve.cvss.severity)) ||
    (recipient.subscriptionTier === 'CISA_KEV_ONLY' && finding.cve.cisaKev?.isKev)
  );
}
export function webhookAllows(hook: WebhookEndpoint, finding: Finding): boolean {
  return (
    hook.events.includes('ALL') ||
    (hook.events.includes('CRITICAL') && finding.cve.cvss.severity === 'CRITICAL') ||
    (hook.events.includes('CISA_KEV') && finding.cve.cisaKev?.isKev)
  );
}
/** Renders the advisory HTML to a PDF attachment for the job, or undefined when
 *  PDF delivery is disabled, the job carries no HTML body, or rendering fails.
 *  Failures degrade to HTML-only delivery instead of blocking the send.
 *
 *  The caller passes the job *after* `applyJobEdits`, so the PDF is rendered
 *  from the same body the recipient receives. Rendering from `payload.html`
 *  directly left an operator's edit (or a custom body override) visible in the
 *  email but absent from its attachment. */
async function buildPdfAttachment(job: Job, config: Config, db?: Db): Promise<EmailAttachment | undefined> {
  // The sender may be called directly (queue test email, digest) with a job
  // whose edits were not applied; normalise here so there is no path that
  // renders a PDF from an unedited body.
  const content = applyJobEdits(job);
  if (config.ATTACH_ADVISORY_PDF !== 'true' || !content.payload.html) return undefined;
  // Operational self-healing alerts are infrastructure messages, not advisories;
  // they must never carry a PDF attachment.
  if (typeof job.advisory_id === 'string' && job.advisory_id.startsWith('SELFHEAL:')) return undefined;
  if (content.payload.dailyDigest) return undefined;
  try {
    const pdf = await renderAdvisoryPdf(content.payload.html);
    // Timestamped `ddMMMyyyyHHMM.pdf` in the workspace timezone, so the
    // attachment name matches the Generated stamp inside the advisory. The
    // sender is also invoked without a db handle (standalone cron), in which
    // case the renderer's default zone is used.
    const timezone = db
      ? ((await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS).timezone
      : undefined;
    const filename = job.advisory_id?.startsWith('UNVERIFIABLE:')
      ? unverifiableMatchFilename(new Date(), timezone)
        : advisoryFilename(job.advisory_id);
    return {
      filename,
      content: Buffer.from(pdf),
      contentType: 'application/pdf',
    };
  } catch (error) {
    if (db)
      await writeEvent(db, {
        category: 'EMAIL',
        level: 'WARNING',
        code: 'delivery.pdf_attachment_failed',
        message: 'Advisory PDF attachment could not be generated; delivering HTML only',
        context: {
          jobId: job.id,
          channel: job.channel,
          advisoryId: job.advisory_id,
          error: String((error as Error)?.message || error),
        },
      }).catch(() => undefined);
    return undefined;
  }
}
export type DeliveryConfirmation = 'delivered' | 'not-delivered' | 'unknown';
/**
 * Decides, without ever contacting the transport, whether a previous attempt
 * may already have delivered this message.
 *
 * Evidence that the provider accepted the message is committed only after the
 * send returns, so an attempt that sent and then lost its commit is
 * indistinguishable from one that never sent. The provider's own record of the
 * message id is therefore authoritative, and it is queried when the local
 * evidence is inconclusive. Only when that lookup cannot answer is the job
 * withheld rather than resent.
 *
 * SMTP failures before submission can be retried. Losing the connection after
 * DATA may hide acceptance, so an ambiguous outcome is not blindly resent.
 */
async function confirmPriorDelivery(
  db: Db,
  job: Job,
  config: Config,
  request: Requester,
): Promise<DeliveryConfirmation> {
  if (job.channel !== 'email') return 'not-delivered';
  const log = await get<EmailDeliveryLog>(db, 'emailLogs', job.id);
  if (log?.sentAt || log?.status === 'ACCEPTED') return 'delivered';
  // The recorded cause of the failure is decisive. A transport that provably
  // rejected the message (4xx/5xx response, refused SMTP session) means retrying
  // cannot duplicate it. The structured `transportRejected` flag is authoritative
  // (audit M-6): it is set by the finalize path from the concrete failure type,
  // not inferred from message text. The regex remains only for logs written
  // before the flag existed.
  if (log?.transportRejected === true) return 'not-delivered';
  if (log?.transportRejected === false) {
    // Explicitly not rejected: the attempt failed for an unknown reason
    // (timeout, reset, dropped socket) — fall through to provider confirmation.
  } else if (
    log?.errorMessage &&
    /HTTP \d{3}\b|did not accept the recipient|not configured|is missing/i.test(log.errorMessage)
  )
    return 'not-delivered';
  const saved = (await get<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
  // The local evidence is inconclusive, so ask the provider. This is the only
  // way to tell an attempt that delivered and lost its receipt from one that
  // never left, and it is what lets those jobs be recovered instead of held.
  const messageId = job.payload.unconfirmedProviderId || log?.providerId || '';
  if (!messageId) return 'unknown';
  const token = decrypt(saved.apiKey, encryptionKeys(config), `email-provider:${saved.provider}`);
  if (!token) return 'unknown';
  return lookupProviderDelivery(saved, token, messageId, request);
}

export function createMailSender(
  config: Config,
  db?: Db,
  request: Requester = createRequester(config),
): MailSender {
  const transporter = config.SMTP_HOST
    ? nodemailer.createTransport({
        host: config.SMTP_HOST,
        port: config.SMTP_PORT,
        secure: config.SMTP_PORT === 465,
        requireTLS: true,
        auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASSWORD } : undefined,
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 20000,
        disableFileAccess: true,
        disableUrlAccess: true,
      })
    : null;
  return async (job) => {
    const saved = (db && (await get<EmailConfiguration>(db, 'emailConfig', 'main'))) || DEFAULT_EMAIL_CONFIG;
    if (!emailIsConfigured(saved, config)) throw new Error('Email provider is not configured');
    if (job.channel === 'email') {
      const settings = (db && (await get<AppSettings>(db, 'settings', 'main'))) || DEFAULT_SETTINGS;
      if (settings.emailEnabled === false) throw new Error('Email delivery is disabled by settings');
    }
    const attachment = await buildPdfAttachment(job, config, db);
    if (!isSmtpEmailProvider(saved.provider)) {
      const token = decrypt(saved.apiKey, encryptionKeys(config), `email-provider:${saved.provider}`);
      if (!token) throw new Error('Email provider token is missing');
      const mailjetSecret =
        saved.provider === 'MAILJET_API'
          ? decrypt(saved.mailjetApiSecret, encryptionKeys(config), `email-mailjet:${saved.provider}`)
          : saved.mailjetApiSecret;
      const provider = EMAIL_PROVIDER_LABELS[saved.provider];
      try {
        const id = await sendProviderEmail(
          { ...saved, mailjetApiSecret: mailjetSecret },
          token,
          job,
          request,
          config.MAILJET_SANDBOX_MODE === 'true',
          attachment,
        );
        return { id, provider };
      } catch (error) {
        if (error instanceof EmailProviderError) {
          error.provider = provider;
          throw error;
        }
        throw new EmailProviderError(`${provider} connection failed`, 502, 0, provider);
      }
    }
    const fromEmail = saved.fromEmail || config.SMTP_FROM;
    if (!fromEmail) throw new Error('SMTP from address is not configured');
    const fromDomain = fromEmail.split('@').pop() || 'localhost';
    const configuredSmtpHost = saved.smtpHost;
    const usesDeploymentSmtp = saved.provider === 'SMTP' && !configuredSmtpHost;
    const smtpPassword = usesDeploymentSmtp
      ? config.SMTP_PASSWORD
      : decrypt(saved.smtpPassword, encryptionKeys(config), `email-smtp:${saved.provider}`);
    const smtpTransport = usesDeploymentSmtp
      ? transporter
      : nodemailer.createTransport({
          host: configuredSmtpHost || config.SMTP_HOST,
          port: saved.smtpPort,
          secure: saved.smtpSecurity === 'IMPLICIT_TLS',
          requireTLS: saved.smtpSecurity === 'STARTTLS',
          auth: saved.smtpUsername ? { user: saved.smtpUsername, pass: smtpPassword } : undefined,
          connectionTimeout: 10000,
          greetingTimeout: 10000,
          socketTimeout: 20000,
          dnsTimeout: 5000,
          disableFileAccess: true,
          disableUrlAccess: true,
        });
    if (!smtpTransport) throw new Error('SMTP is not configured');
    const result = await smtpTransport.sendMail({
      from: { address: fromEmail, name: saved.fromName },
      ...(saved.replyTo ? { replyTo: saved.replyTo } : {}),
      to: job.payload.recipientEmail,
      subject: job.payload.subject,
      text: job.payload.text,
      html: job.payload.html,
      messageId: `<${job.id}@${fromDomain}>`,
      headers: {
        'X-BA-Threat-Intel-Delivery-ID': job.id,
        'Auto-Submitted': 'auto-generated',
        'List-Unsubscribe': saved.unsubscribeUrl || `<mailto:${fromEmail}?subject=unsubscribe>`,
        // RFC 8058 one-click is only valid for an HTTP(S) unsubscribe URL. A
        // mailto fallback is handled by the mail client, not an HTTP POST.
        ...(saved.unsubscribeUrl && /^https?:\/\//i.test(saved.unsubscribeUrl)
          ? { 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' }
          : {}),
      },
      ...(attachment ? { attachments: [attachment] } : {}),
    });
    if (
      !result.accepted?.some(
        (address) => String(address).toLowerCase() === job.payload.recipientEmail?.toLowerCase(),
      )
    )
      throw new Error('SMTP did not accept the recipient');
    return { id: result.messageId, provider: 'SMTP_Relay' };
  };
}
export async function enqueue(
  db: Db,
  channel: Job['channel'],
  targetId: string,
  advisoryId: string,
  payload: Job['payload'],
  dedupe: string,
  initialStatus: 'QUEUED' | 'REVIEW' = 'QUEUED',
  priority = 0,
  edits: ReviewEdits = {},
) {
  // Master switch: when email delivery is disabled, no email job is queued at
  // all. Provider configuration is left intact; only transport is blocked.
  if (channel === 'email') {
    const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    if (settings.emailEnabled === false) return null;
  }
  const id = randomUUID();
  // A content revision that already exists is normally a duplicate. The one
  // safe exception is a bundle that was terminally failed because its findings
  // were temporarily inapplicable: the pipeline only calls queueAdvisory again
  // after revalidating the current inventory, so the same revision can be
  // re-opened without ever having been accepted by a transport. Transport,
  // recipient, and subscription failures are deliberately not resurrected.
  const inserted = await db.query(
    `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,priority,edits)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
     ON CONFLICT(dedupe_key) DO UPDATE SET
       advisory_id=EXCLUDED.advisory_id,
       payload=EXCLUDED.payload,
       status=EXCLUDED.status,
       priority=EXCLUDED.priority,
       edits=EXCLUDED.edits,
       attempts=0,
       next_attempt=now(),
       error=NULL,
       provider_id=NULL,
       locked_at=NULL,
       lock_token=NULL,
       updated_at=now()
     WHERE outbox.status='FAILED'
       AND (COALESCE(outbox.error,'') LIKE '%no longer applicable%'
         OR (outbox.advisory_id LIKE 'UNVERIFIABLE:%' AND COALESCE(outbox.error,'') LIKE 'Review notification%'))
     RETURNING id`,
    [
      id,
      dedupe,
      channel,
      targetId,
      advisoryId,
      JSON.stringify(payload),
      channel === 'email' ? initialStatus : 'QUEUED',
      priority,
      JSON.stringify(channel === 'email' ? edits : {}),
    ],
  );
  if (!inserted.rowCount) return null;
  const insertedId = inserted.rows[0].id as string;
  if (channel === 'email') {
    const configuration = (await get<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
    const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    await put(db, 'emailLogs', insertedId, {
      id: insertedId,
      recipientEmail: payload.recipientEmail || '',
      advisoryId,
      subject: payload.subject,
      provider: EMAIL_PROVIDER_LABELS[configuration.provider],
      status: initialStatus === 'REVIEW' ? 'REVIEW_REQUIRED' : 'QUEUED',
      attemptCount: 0,
      retrySchedule: emailRetrySchedule(emailRetryPolicy(settings)),
      nextRetryTime: initialStatus === 'REVIEW' ? null : new Date().toISOString(),
      sentAt: '',
    } satisfies EmailDeliveryLog);
  } else {
    const hook = await get<WebhookEndpoint>(db, 'webhooks', targetId);
    await put(db, 'webhookLogs', insertedId, {
      id: insertedId,
      endpointId: targetId,
      endpointName: hook?.name || '',
      provider: hook?.provider || 'GENERIC_HMAC',
      advisoryId,
      cveId: payload.cveIds.join(', '),
      status: 'QUEUED',
      statusCode: 0,
      hmacSignature: '',
      sentAt: '',
    } satisfies WebhookDeliveryLog);
  }
  return insertedId;
}
/**
 * Canonical evidence-map builder for one set of findings (audit L-6).
 *
 * Every enqueue site (queueAdvisory, queueBulkNotificationAdvisory,
 * queueDigestAdvisory, the pipeline's legacy-payload rebuild) used to inline the
 * same two `Object.fromEntries` folds over `findingRevision`/`revision`. Divergence
 * between them would make the dedupe contract depend on which site built the
 * payload. This function is the one definition; callers spread it into their
 * payload. `cveIds`/`findingIds` keys are already unique per construction site.
 */
export function deliveryRevisionEvidence(findings: readonly Finding[]): {
  cveRevisions: Record<string, string>;
  findingRevisions: Record<string, string>;
} {
  return {
    cveRevisions: Object.fromEntries(findings.map((finding) => [finding.cveId, revision(finding.cve)])),
    findingRevisions: Object.fromEntries(findings.map((finding) => [finding.id, findingRevision(finding)])),
  };
}
export async function queueAdvisory(
  db: Db,
  advisory: Advisory,
  findings: Finding[],
  html?: string,
  dispatchKey?: string,
) {
  const recipients = await list<EmailRecipient>(db, 'recipients'),
    hooks = await list<WebhookEndpoint>(db, 'webhooks');
  const selected = recipients.filter(
    (r) => r.enabled && findings.length > 0 && findings.every((finding) => recipientAllows(r, finding)),
  );
  // Deduplicate by content revision, not just advisory ID: a genuinely revised
  // advisory may be delivered again, while a repeated queue pass over the same
  // revision remains idempotent. Pipeline-created advisories get a new random
  // ID on every run, so the default dispatch key must be content-derived; an
  // explicit key (operator resend) still overrides it.
  const contentRevision = advisoryRevision(advisory, findings);
  const payload = {
    ...advisoryEmail(advisory, html, undefined, { findings }),
    cveIds: advisory.cveIds,
    ...deliveryRevisionEvidence(findings),
    contentRevision,
  };
  const stableDispatchKey = dispatchKey ?? contentRevision;
  let count = 0;
  const priority = advisoryPriority(findings);
  // When `deferEveryoneUntilSecurityDelivered` is enabled and at least one
  // Security-team recipient is in the batch, Everyone-group recipients are NOT
  // queued here. They are queued in REVIEW status by the delivery worker once a
  // Security-team delivery for this advisory is confirmed ACCEPTED, so the
  // operator can preview and edit the same payload before the broader broadcast.
  const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
  const deferEveryone = settings.deferEveryoneUntilSecurityDelivered;
  const hasSecurityRecipients = selected.some((r) => r.deliveryGroup !== 'EVERYONE');
  for (const recipient of selected) {
    if (deferEveryone && hasSecurityRecipients && recipient.deliveryGroup === 'EVERYONE') continue;
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        advisory.id,
        { ...payload, recipientEmail: recipient.email },
        `${stableDispatchKey}:${contentRevision}:email:${recipient.id}`,
        recipient.deliveryGroup === 'EVERYONE' ? 'REVIEW' : 'QUEUED',
        priority,
      )
    )
      count++;
  }
  for (const hook of hooks.filter(
    (h) => h.enabled && findings.length > 0 && findings.every((finding) => webhookAllows(h, finding)),
  ))
    if (
      await enqueue(
        db,
        'webhook',
        hook.id,
        advisory.id,
        payload,
        `${stableDispatchKey}:${contentRevision}:webhook:${hook.id}`,
        'QUEUED',
        priority,
      )
    )
      count++;
  if (!count) return 0;
  advisory.recipientCount = selected.length;
  advisory.deliveryStatus = count ? 'PENDING' : 'DRAFT';
  await put(db, 'advisories', advisory.id, advisory);
  return count;
}
/**
 * After a Security-team delivery is confirmed ACCEPTED by the transport, queue
 * the same email for Everyone-group recipients in REVIEW status. This is the
 * deferred half of the `deferEveryoneUntilSecurityDelivered` setting: the
 * Security team sees the alert first, and once the delivery is confirmed the
 * identical payload enters the operator review queue for Everyone recipients.
 *
 * Reuses the accepted job's payload verbatim — apart from the per-recipient
 * address — so the Everyone group receives the same email. The enqueue dedupe
 * key is content-stable, so repeated invocations (one per Security-team
 * recipient) create at most one job set even if several deliveries succeed.
 */
export async function queueEveryoneReviewJobs(
  db: Db,
  acceptedJob: Job,
  settings: AppSettings,
): Promise<number> {
  if (!settings.deferEveryoneUntilSecurityDelivered) return 0;
  // Only trigger from a Security-team (or legacy undefined) delivery, never
  // from another Everyone job that was just approved and accepted.
  const securityRecipient = await get<EmailRecipient>(db, 'recipients', acceptedJob.target_id);
  if (!securityRecipient || securityRecipient.deliveryGroup === 'EVERYONE') return 0;
  const advisory = await get<Advisory>(db, 'advisories', acceptedJob.advisory_id);
  if (!advisory) return 0;
  // Reuse the accepted delivery's payload verbatim, stripping only the
  // per-recipient email address so each Everyone job gets its own.
  const { recipientEmail: _omit, ...sharedPayload } = acceptedJob.payload as Job['payload'] & {
    recipientEmail?: string;
  };
  const dispatchKey =
    acceptedJob.payload.digestKey ??
    acceptedJob.dedupe_key.split(':email:')[0].split(':webhook:')[0];
  const contentRevision = sharedPayload.contentRevision ?? acceptedJob.advisory_id;
  // Skip recipients that already have a pending or active job for this advisory.
  // This guards against duplicates when the setting was toggled on after initial
  // queuing, or when the daily-digest path already queued Everyone recipients.
  const pending = await db.query<{ target_id: string }>(
    // Channel-scoped (audit M-5): a webhook job for the same advisory shares
    // nothing with an email recipient — including the target id space is fine,
    // but the ids are opaque strings, so a webhook row could name a target id
    // equal to an email recipient id only by coincidence. The original query
    // also admitted other channels' rows to the "already active" set, which is
    // wrong for the same reason: an accepted webhook must not suppress queuing
    // an Everyone email. Restrict to the email channel.
    //
    // `ACCEPTED` is included deliberately: this function is called for *every*
    // accepted Security-team job, including an operator resend of the same
    // advisory. With only REVIEW/QUEUED/SENDING here, resending one security
    // email re-queued the same broadcast for everyone in the Everyone group —
    // a duplicate email per recipient with no content change.
    "SELECT target_id FROM outbox WHERE advisory_id=$1 AND channel='email' AND status IN ('REVIEW','QUEUED','SENDING','ACCEPTED')",
    [acceptedJob.advisory_id],
  );
  const activeTargets = new Set(pending.rows.map((row) => row.target_id));
  const everyoneRecipients = (await list<EmailRecipient>(db, 'recipients')).filter(
    (r) => r.enabled && r.deliveryGroup === 'EVERYONE',
  );
  if (!everyoneRecipients.length) return 0;
  let queued = 0;
  const priority = acceptedJob.priority ?? 0;
  for (const recipient of everyoneRecipients) {
    if (activeTargets.has(recipient.id)) continue;
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        acceptedJob.advisory_id,
        { ...sharedPayload, recipientEmail: recipient.email },
        `${dispatchKey}:everyone:${contentRevision}:email:${recipient.id}`,
        'REVIEW',
        priority,
      )
    )
      queued++;
  }
  if (queued) {
    await writeEvent(db, {
      category: 'EMAIL',
      level: 'INFO',
      code: 'delivery.everyone_queued_after_security',
      message: `Queued ${queued} Everyone-group review job(s) for advisory ${acceptedJob.advisory_id} after Security-team delivery was confirmed`,
      context: {
        advisoryId: acceptedJob.advisory_id,
        securityJobId: acceptedJob.id,
        everyoneJobsQueued: queued,
      },
    });
    await appendAudit(
      db,
      'Everyone review jobs queued',
      `${acceptedJob.advisory_id}: ${queued} job(s) after security delivery acceptance`,
      'delivery-worker',
      'EMAIL',
      'INFO',
    );
  }
  return queued;
}
export interface BulkNotificationOptions {
  /**
   * Operator-supplied subject override. The queued delivery subject (and the
   * log shown in the Action Center) must match what the recipient receives.
   */
  subject?: string;
  /** Review edits persisted with every new job and applied at send time. */
  edits?: ReviewEdits;
}

export async function queueBulkNotificationAdvisory(
  db: Db,
  advisory: Advisory,
  findings: Finding[],
  html: string,
  recipients: EmailRecipient[],
  dispatchKey?: string,
  options: BulkNotificationOptions = {},
): Promise<number> {
  if (findings.length === 0) return 0;
  const contentRevision = advisoryRevision(advisory, findings);
  const baseEmail = advisoryEmail(advisory, html, undefined, { findings });
  const payload = {
    ...baseEmail,
    subject: normalizeEmailSubject(options.subject) ?? baseEmail.subject,
    cveIds: advisory.cveIds,
    ...deliveryRevisionEvidence(findings),
    contentRevision,
  };
  const stableDispatchKey = dispatchKey ?? contentRevision;
  const priority = advisoryPriority(findings);
  const edits = options.edits ?? {};
  let count = 0;
  for (const recipient of recipients)
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        advisory.id,
        { ...payload, recipientEmail: recipient.email },
        `${stableDispatchKey}:${contentRevision}:email:${recipient.id}`,
        recipient.deliveryGroup === 'EVERYONE' ? 'REVIEW' : 'QUEUED',
        priority,
        edits,
      )
    )
      count++;
  if (!count) return 0;
  advisory.recipientCount = recipients.length;
  advisory.deliveryStatus = 'PENDING';
  await put(db, 'advisories', advisory.id, advisory);
  return count;
}
/**
 * Queues one email per eligible Security-team recipient for an
 * `IntelligenceMatch` (security news/advisory evidence) that matched the
 * monitored vendor + product inventory. Each job carries no Advisory row
 * and is delivered as a standalone news alert by `deliverNext`.
 *
 * Runs inside the pipeline transaction: the outbox insert commits with the
 * match record, so a crash between match storage and dispatch cannot drop
 * evidence or double-count it on the next run — the per-match dedupe key is
 * idempotent across runs.
 */
export async function queueNewsEvidenceNotifications(
  db: Db,
  match: IntelligenceMatch,
  articleOrArticles: IntelligenceArticle | IntelligenceArticle[],
  asset: { name: string; vendor?: string; product?: string },
  recipients: EmailRecipient[],
): Promise<number> {
  const selected = recipients.filter(
    (r) => r.enabled && (r.deliveryGroup === 'SECURITY_TEAM' || r.deliveryGroup === undefined),
  );
  if (!selected.length) return 0;
  const articles = (Array.isArray(articleOrArticles) ? articleOrArticles : [articleOrArticles])
    .filter((article, index, all) => all.findIndex((candidate) => candidate.id === article.id) === index)
    .sort((a, b) => a.id.localeCompare(b.id));
  if (!articles.length) return 0;
  const primary = articles[0];
  const cveIds = [...new Set([
    ...articles.flatMap((article) => article.cveIds.filter(Boolean)),
    ...(match.cveId ? [match.cveId] : []),
  ])].sort();
  const assetLine = asset.vendor && asset.product ? `${asset.vendor} / ${asset.product}` : asset.name;
  // Article title/url/source feeds are feed-controlled. The body is plain text,
  // so this is not HTML injection, but an unescaped CR/LF or control character
  // lets a feed forge header-like lines in the delivered message and poison a
  // downstream ticketing parser. Collapse the same way the subject does.
  const safeLine = (value: string) =>
    value.replace(/[\r\n\t]+/g, ' ').replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '').trim();
  const subject = `[Threat intelligence] [NEWS] ${safeLine(primary.title)}`;
  const evidenceLines = articles.map((article) => {
    const sourceName = article.sourceFeeds.length ? article.sourceFeeds.map(safeLine).join(', ') : 'security news';
    const publishedAt = safeLine(article.modifiedDate || article.publishedDate);
    return `${safeLine(article.title)}\nSource: ${safeLine(article.url)}\nPublished: ${publishedAt}\nSource feed: ${sourceName}`;
  }).join('\n\n');
  const text =
    `${evidenceLines}\n\nMatched asset: ${assetLine}\n` +
    (cveIds.length ? `CVE reference(s): ${cveIds.join(', ')}\n` : '') +
    `Evidence: ${match.evidence}\n\n` +
    (match.zeroDay ? '** Potential zero-day: no assigned CVE **\n' : '') +
    'This is applicability evidence, not a confirmed advisory. Confirm source authenticity and consult the vendor before remediation.';
  const articlePayloads = articles.map((article) => ({
    id: article.id,
    title: article.title,
    url: article.url,
    sourceFeeds: [...article.sourceFeeds],
    publishedDate: article.publishedDate,
  }));
  const newsEvidence: NewsEvidencePayload = {
    matchId: match.id,
    article: articlePayloads[0],
    articles: articlePayloads,
    asset,
    cveIds,
    evidence: match.evidence,
    zeroDay: match.zeroDay,
    credibilityScore: match.credibilityScore,
  };
  const evidenceRevision = articles.map((article) => `${article.id}:${article.modifiedDate || article.publishedDate}`).join('|');
  const contentRevision = `${match.id}:${evidenceRevision}`;
  // Audit finding: the dedupe identity must survive a match-id change. The
  // matcher keys a match on `hash(cveId || articleId)`, so the same asset's
  // evidence gets a new id once a zero-day article is later linked to a CVE —
  // keying only on match.id re-notified the whole security team for evidence
  // it already had. Bind the identity to the asset (and the CVE when one is
  // known) so re-correlation of the same coverage collapses into one job.
  const identity = `news:${match.assetId}:${match.cveId ?? 'uncve'}:${evidenceRevision}`;
  let queued = 0;
  for (const recipient of selected) {
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        `NEWS:${match.id}`,
        {
          subject,
          text,
          cveIds,
          newsEvidence,
          contentRevision,
          recipientEmail: recipient.email,
        },
        `${identity}:email:${recipient.id}`,
        'QUEUED',
      )
    )
      queued++;
  }
  return queued;
}

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, ch =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);

const stripCrlf = (value: string) => value.replace(/[\r\n]/g, ' ');

/**
 * Queues a single combined review notification per eligible Security-team
 * recipient for every unverifiable finding in `findings` — product correlations
 * whose version ranges could not be confirmed. Each job carries no Advisory row
 * and is delivered as a standalone review notification by `deliverNext`.
 *
 * All findings are batched into one email rather than one email per finding, so
 * a pipeline pass that produced N unverifiable matches produces M combined
 * emails (one per recipient) instead of N*M individual emails.
 *
 * The email header reads "for Review - Unverifiable matches" in bold, so the
 * security team knows the matches need manual verification before remediation.
 */
export async function queueUnverifiableMatchNotification(
  db: Db,
  findings: Finding[],
  recipients: EmailRecipient[],
): Promise<number> {
  if (!('release' in db)) {
    return transaction(db, (client) => queueUnverifiableMatchNotification(client, findings, recipients),
      undefined, { locks: ['review-notifications'] });
  }
  await db.query(`SELECT pg_advisory_xact_lock(hashtext($1), ${schemaLockKey})`, ['review-notifications']);
  const settings = { ...DEFAULT_SETTINGS, ...await get<AppSettings>(db, 'settings', 'main') };
  const uniqueFindings = [...new Map(findings.map((finding) => [finding.id, finding])).values()];
  const eligible = uniqueFindings.filter(
    (finding) => eligibleForReviewNotification(finding, settings) && !finding.reviewNotifiedAt,
  );
  const selected = recipients.filter(
    (r) => r.enabled && (r.deliveryGroup === 'SECURITY_TEAM' || r.deliveryGroup === undefined),
  );
  if (eligible.length === 0 || selected.length === 0) return 0;
  const pending = await db.query<{ target_id: string; finding_id: string }>(
    `SELECT target_id,entry->>'findingId' AS finding_id FROM outbox
     CROSS JOIN LATERAL jsonb_array_elements(CASE
       WHEN jsonb_typeof(payload->'unverifiableMatch'->'findings')='array'
       THEN payload->'unverifiableMatch'->'findings' ELSE '[]'::jsonb END) entry
     WHERE channel='email' AND status=ANY($1::text[]) AND target_id=ANY($2::text[])
       AND entry->>'findingId'=ANY($3::text[])
     UNION ALL
     SELECT target.id,records.id FROM records CROSS JOIN unnest($2::text[]) target(id)
     WHERE kind='findings' AND records.id=ANY($3::text[])
       AND COALESCE(data->>'reviewNotifiedAt','')<>''`,
    [['QUEUED', 'SENDING'], selected.map((recipient) => recipient.id), eligible.map((finding) => finding.id)],
  );
  const reserved = new Map<string, Set<string>>();
  for (const row of pending.rows) {
    const ids = reserved.get(row.target_id) ?? new Set<string>();
    ids.add(row.finding_id);
    reserved.set(row.target_id, ids);
  }
  // Sort findingLines by severity in descending order: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
  const findingLines = eligible
    .map((finding) => {
      const asset =
        finding.matchedAssetName || finding.matchedAssetVendor || finding.matchedAssetProduct || 'unknown asset';
      const vendor = finding.matchedAssetVendor;
      const product = finding.matchedAssetProduct;
      const evidence = stripCrlf(finding.matchingEvidence);
      const cveId = finding.cveId;
      const severity = finding.cve.cvss.severity;
      const cvssScore = finding.cve.cvss.score;
      const severityColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN;
      const parsedAssetCpe = parseCPE23(finding.matchedCpe);
      const assetVersion = parsedAssetCpe.isValid && parsedAssetCpe.version !== '*'
        ? parsedAssetCpe.version
        : undefined;
      const vulnRange = finding.cve.versionRange;
      const vulnVersionRange = vulnRange
        ? [
            vulnRange.versionStartIncluding ? `>=${vulnRange.versionStartIncluding}` : vulnRange.versionStartExcluding ? `>${vulnRange.versionStartExcluding}` : undefined,
            vulnRange.versionEndIncluding ? `<=${vulnRange.versionEndIncluding}` : vulnRange.versionEndExcluding ? `<${vulnRange.versionEndExcluding}` : undefined,
          ].filter(Boolean).join(' to ') || '*'
        : undefined;
      return {
        asset,
        vendor,
        product,
        assetVersion,
        vulnVersionRange,
        evidence,
        cveId,
        severity,
        cvssScore,
        severityColor,
        findingId: finding.id,
        cveDescription: finding.cve.description || '',
      };
    })
    .sort((a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity));
  const unverifiableMatch: UnverifiableMatchPayload = {
    findings: findingLines.map((f) => ({
      findingId: f.findingId,
      asset: { name: f.asset, vendor: f.vendor, product: f.product },
      cveId: f.cveId,
      evidence: f.evidence,
      severity: f.severity,
      cvssScore: f.cvssScore,
    })),
    cveIds: [...new Set(eligible.map((finding) => finding.cveId))].sort(),
  };
  let queued = 0;
  for (const recipient of selected) {
    const ownFindings = eligible.filter((finding) => recipientAllows(recipient, finding) &&
      !reserved.get(recipient.id)?.has(finding.id));
    if (!ownFindings.length) continue;
    const ownIds = new Set(ownFindings.map((finding) => finding.id));
    const ownLines = unverifiableMatch.findings.filter((finding) => ownIds.has(finding.findingId));
    const cveIds = [...new Set(ownFindings.map((finding) => finding.cveId))].sort();
    const findingIds = [...ownIds].sort();
    const findingRevisions = Object.fromEntries(ownFindings.map((finding) => [finding.id, findingRevision(finding)]));
    const cveRevisions = Object.fromEntries(ownFindings.map((finding) => [finding.cveId, revision(finding.cve)]));
    const { subject, text, html } = renderUnverifiableReviewEmail(ownFindings, settings.timezone);
    const batchRevision = createHash('sha256').update(stableJson({ findingRevisions, cveRevisions, html })).digest('hex');
    const contentRevision = `${findingIds.join(',')}:${batchRevision}`;
    const identity = `unverifiable:${findingIds.join(',')}:${contentRevision}`;
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        `UNVERIFIABLE:${findingIds.join(',')}`,
        {
          subject,
          text,
          html,
          cveIds,
          findingRevisions,
          cveRevisions,
          contentRevision,
          unverifiableMatch: { findings: ownLines, cveIds, timezone: settings.timezone },
          recipientEmail: recipient.email,
        },
        `${identity}:email:${recipient.id}`,
        'QUEUED',
        advisoryPriority(ownFindings),
      )
    )
      queued++;
  }
  return queued;
}

/**
 * Queues one consolidated email per Security-team recipient for a zero-day
 * digest produced by `rankAndRateLimitZeroDays`.
 *
 * Audit C-3: the per-run zero-day cap removed the suppressed matches *and* their
 * counterpart findings from the notification path. Nothing replaced them, so
 * exceeding the cap turned a notification storm into silence. The digest is now
 * delivered as a single summary, keeping the cap's cost bound (one email per
 * recipient per digest) while the operator still learns the evidence exists.
 *
 * Idempotent per recipient per content revision, exactly like the news path: the
 * same digest re-derived on a later run produces the same dedupe key.
 */
export async function queueZeroDayDigestNotification(
  db: Db,
  digest: ZeroDayDigestPayload,
  recipients: EmailRecipient[],
): Promise<number> {
  const selected = recipients.filter(
    (r) => r.enabled && (r.deliveryGroup === 'SECURITY_TEAM' || r.deliveryGroup === undefined),
  );
  if (!selected.length || !digest.findings.length) return 0;
  const safeLine = (value: string) =>
    value.replace(/[\r\n\t]+/g, ' ').replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '').trim();
  const productLabel = `${digest.vendor} / ${digest.product}`;
  const subject = safeLine(
    `[Threat intelligence] [ZERO-DAY DIGEST] ${productLabel} (${digest.matchCount} matches)`,
  );
  const lines = digest.findings.map((finding, index) =>
    [
      `${index + 1}. Asset: ${safeLine(finding.assetName)}`,
      finding.cveId ? `   CVE: ${safeLine(finding.cveId)}` : '   CVE: (none assigned - potential zero-day)',
      `   Evidence: ${safeLine(finding.evidence)}`,
      typeof finding.credibilityScore === 'number'
        ? `   Credibility: ${finding.credibilityScore}/100`
        : '',
    ]
      .filter(Boolean)
      .join('\n'),
  );
  const sources = digest.articles.length
    ? `\n\nSources:\n${digest.articles.map((article) => `- ${safeLine(article.title)}\n  ${safeLine(article.url)}`).join('\n')}`
    : '';
  const text =
    `Zero-day digest for ${safeLine(productLabel)}\n\n` +
    `${digest.matchCount} potential zero-day match(es) were consolidated into this digest ` +
    `because the per-run notification cap was reached. Each item below was withheld from ` +
    `individual delivery and requires manual triage.\n\n` +
    `${lines.join('\n\n')}${sources}\n\n` +
    'This is applicability evidence, not a confirmed advisory. Confirm source authenticity and consult the vendor before remediation.';
  const articleIds = digest.articles.map((article) => article.id).sort();
  const evidenceRevision = articleIds.join(',') || 'no-articles';
  const contentRevision = `${digest.digestId}:${digest.matchIds.slice().sort().join(',')}:${evidenceRevision}`;
  const identity = `zeroday:${digest.digestId}:${contentRevision}`;
  const payload: ZeroDayDigestPayload = {
    ...digest,
    articles: digest.articles.map((article) => ({ ...article, sourceFeeds: [...article.sourceFeeds] })),
  };
  let queued = 0;
  for (const recipient of selected) {
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        `ZERODAY:${digest.digestId}`,
        {
          subject,
          text,
          cveIds: [...new Set(digest.findings.map((finding) => finding.cveId).filter(Boolean))].sort() as string[],
          zeroDayDigest: payload,
          contentRevision,
          recipientEmail: recipient.email,
        },
        `${identity}:email:${recipient.id}`,
        'QUEUED',
      )
    )
      queued++;
  }
  return queued;
}

export interface DigestQueueResult {
  /** Persisted union advisory, or the supplied advisory when nothing was queued. */
  advisory: Advisory;
  /** Number of transport jobs created (email + webhook). */
  jobs: number;
  /** Findings that were included in at least one job. */
  findingIds: string[];
  /** Number of targets that could receive at least one finding. */
  eligible: number;
}

/**
 * Queues one combined email per recipient (and one webhook per endpoint) for a
 * batch of findings.
 *
 * The union advisory is persisted for queue accounting and UI visibility, while
 * each transport receives a recipient-specific view containing only the findings
 * its subscription tier permits. This is what makes a single digest safe for a
 * mixed set of ALL_SEVERITIES, CRITICAL_HIGH_ONLY and CISA_KEV_ONLY subscribers.
 *
 * Deduplication is content-derived and per target. Re-running the same batch is
 * idempotent, and the stable Message-ID in `createMailSender` lets the receiving
 * provider collapse a retry that raced a process crash.
 */
export async function queueDigestAdvisory(
  db: Db,
  advisory: Advisory,
  findings: Finding[],
  render?: (advisory: Advisory, findings: Finding[]) => string | undefined,
  dispatchKey?: string,
): Promise<DigestQueueResult> {
  const recipients = (await list<EmailRecipient>(db, 'recipients')).filter((recipient) => recipient.enabled);
  const hooks = (await list<WebhookEndpoint>(db, 'webhooks')).filter((hook) => hook.enabled);

  const recipientBatches = new Map<string, Finding[]>();
  for (const recipient of recipients) {
    const permitted = findings.filter((finding) => recipientAllows(recipient, finding));
    if (permitted.length) recipientBatches.set(recipient.id, permitted);
  }
  const webhookBatches = new Map<string, Finding[]>();
  for (const hook of hooks) {
    const permitted = findings.filter((finding) => webhookAllows(hook, finding));
    if (permitted.length) webhookBatches.set(hook.id, permitted);
  }

  const includedIds = new Set<string>();
  for (const batch of [...recipientBatches.values(), ...webhookBatches.values()])
    for (const finding of batch) includedIds.add(finding.id);
  const included = findings.filter((finding) => includedIds.has(finding.id));
  if (!included.length) return { advisory, jobs: 0, findingIds: [], eligible: 0 };

  const union = digestView(advisory, included);
  const contentRevision = advisoryRevision(union, included);
  const stableDispatchKey = dispatchKey ?? contentRevision;
  const priority = advisoryPriority(included);
  let jobs = 0;
  let recipientCount = 0;

  for (const [recipientId, batch] of recipientBatches) {
    const recipient = recipients.find((candidate) => candidate.id === recipientId)!;
    const view = digestView(union, batch);
    const payload = {
      ...advisoryEmail(view, render?.(view, batch), batch.map(findingDetail), { findings: batch }),
      cveIds: view.cveIds,
      includedFindingIds: batch.map((finding) => finding.id),
      ...deliveryRevisionEvidence(batch),
      digestKey: stableDispatchKey,
      contentRevision,
      recipientEmail: recipient.email,
    };
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        union.id,
        payload,
        `${stableDispatchKey}:${contentRevision}:email:${recipient.id}`,
        recipient.deliveryGroup === 'EVERYONE' ? 'REVIEW' : 'QUEUED',
        priority,
      )
    ) {
      jobs++;
      recipientCount++;
    }
  }

  for (const [hookId, batch] of webhookBatches) {
    const view = digestView(union, batch);
    const payload = {
      ...advisoryEmail(view, render?.(view, batch), batch.map(findingDetail), { findings: batch }),
      cveIds: view.cveIds,
      includedFindingIds: batch.map((finding) => finding.id),
      ...deliveryRevisionEvidence(batch),
      digestKey: stableDispatchKey,
      contentRevision,
    };
    if (
      await enqueue(
        db,
        'webhook',
        hookId,
        union.id,
        payload,
        `${stableDispatchKey}:${contentRevision}:webhook:${hookId}`,
        'QUEUED',
        priority,
      )
    )
      jobs++;
  }

  if (!jobs)
    return {
      advisory: union,
      jobs: 0,
      // These findings were already accepted by an identical queued batch.
      // Callers use this to discard them from their local buffer.
      findingIds: included.map((finding) => finding.id),
      eligible: recipientBatches.size + webhookBatches.size,
    };

  union.recipientCount = recipientCount;
  union.deliveryStatus = 'PENDING';
  await put(db, 'advisories', union.id, union);
  return {
    advisory: union,
    jobs,
    findingIds: included.map((finding) => finding.id),
    eligible: recipientBatches.size + webhookBatches.size,
  };
}

export async function deliverNext(
  pool: pg.Pool,
  config: Config,
  request: Requester,
  sendMail: MailSender,
): Promise<boolean> {
  const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
  const job = await transaction(pool, async (db) => {
    const claimed = await db.query(
      `WITH candidate AS (
         SELECT id,
           CASE WHEN channel='email' AND attempts > 0 THEN
             (SELECT occurred_at FROM operational_events
              WHERE code='ml.delivery.outcome' AND context->>'jobId'=outbox.id::text
              ORDER BY id DESC LIMIT 1)
           END AS prior_attempt_at
         FROM outbox
         WHERE ((status='QUEUED' AND next_attempt<=now()) OR
           (status='SENDING' AND locked_at<now()-interval '2 minutes'))
           AND (channel<>'email' OR $2::boolean)
         ORDER BY priority DESC, next_attempt
         FOR UPDATE SKIP LOCKED LIMIT 1
       )
       UPDATE outbox AS o
       SET status='SENDING',locked_at=now(),lock_token=$1,attempts=attempts+1,updated_at=now()
       FROM candidate AS c WHERE o.id=c.id
       RETURNING o.*,c.prior_attempt_at`,
      [randomUUID(), settings.emailEnabled !== false],
    );
    return claimed.rows[0] as Job | undefined;
  });
  if (!job) return false;
  const attemptStartedAt = Date.now();
  const observedDelay = job.channel === 'email' && job.attempts > 1
    ? observedRetryDelay(job.prior_attempt_at, attemptStartedAt)
    : { delayMs: 0, observed: false };
  const retryDelayObserved = observedDelay.delayMs;
  let transportAttempted = false;
  // Email retries follow the operator policy; webhooks retain the historical
  // six-attempt policy because their budget is not exposed as an email setting.
  const retryPolicy = emailRetryPolicy(job.channel === 'email' ? settings : DEFAULT_SETTINGS);
  // Master switch: when email delivery is disabled, no outbound email is
  // generated or sent. Provider configuration is left intact; only transport
  // is blocked. Fail closed so a disabled setting can never leak an email.
  let permanent = false;
  let providerId = '',
    statusCode = 0,
    signature = '',
    error = '',
    retryNotBefore = 0;
  // Structured transport failure for the event log; `error` stays the short
  // message used by retry policy and the outbox row.
  let errorInfo: Record<string, unknown> = {};
  let emailProvider: EmailDeliveryLog['provider'] | undefined,
    routeToReview = false;
  // Declared outside the try block: it is assigned inside and read again by the
  // post-delivery bookkeeping below. A block-scoped `const` made that read a
  // compile error and, under a non-strict loader, a ReferenceError *after* the
  // mail/webhook had already been sent — the outbox row would then never be
  // marked ACCEPTED and the alert would be re-sent on every retry.
  let declaredCveIds: string[] = [];
  let declaredFindingIds: string[] = [];
  // Set when the revalidation detects a stale advisory bundle so the catch
  // block can trigger an immediate rebuild instead of a hard permanent failure.
  let staleAdvisory = false;
  // Set when a legacy payload was rebuilt from current intelligence during this
  // attempt, so the recovery path does not rebuild the same payload twice.
  let legacyRebuilt = false;
  // Set when the bundle is blocked by a finding that is deliberately held for
  // review (confidence policy or unverifiable applicability) rather than one
  // whose applicability changed. A rebuild cannot change a held verdict, so the
  // job is routed to operator review instead of a permanent FAILED + rebuild.
  let holdGated = false;
  // Set when the transport returned 2xx but the attempt could not be marked
  // ACCEPTED because the response was rejected (confirm-before-send). This only
  // happens for email; a webhook response needs no confirmation.
  let unconfirmedError = '';
  // Structured classification of the last transport failure (audit M-6): true
  // when the provider provably rejected the message. Persisted on the delivery
  // log so confirmPriorDelivery does not have to re-infer it from error text.
  let transportRejected = false;
  try {
    if (job.payload.unverifiableMatch) {
      const currentSettings = { ...DEFAULT_SETTINGS, ...await get<AppSettings>(pool, 'settings', 'main') };
      const ids = job.payload.unverifiableMatch.findings.map((finding) => finding.findingId);
      const [recipient, stored, aliases] = await Promise.all([
        get<EmailRecipient>(pool, 'recipients', job.target_id),
        getMany<Finding>(pool, 'findings', ids),
        list<import('../src/types/index.ts').AliasEntry>(pool, 'aliases'),
      ]);
      if (!recipient?.enabled ||
          ![undefined, 'SECURITY_TEAM'].includes(recipient.deliveryGroup) ||
          recipient.email !== job.payload.recipientEmail || !ids.length) {
        permanent = true;
        throw new Error('Review notification recipient is no longer eligible');
      }
      const [assets, cves, withdrawals] = await Promise.all([
        getMany<WatchListItem>(pool, 'watchlist', [...stored.values()].map((finding) => finding.matchedAssetId)),
        getMany<NormalizedCVE>(pool, 'cveData', [...stored.values()].map((finding) => finding.cveId)),
        getMany<{ modifiedDate: string }>(pool, 'cveWithdrawals', [...stored.values()].map((finding) => finding.cveId)),
      ]);
      const fresh: Finding[] = [];
      const vendorAliases = buildAliasMap(aliases, 'VENDOR');
      const productAliases = buildAliasMap(aliases, 'PRODUCT');
      for (const id of ids) {
        const finding = stored.get(id);
        const asset = finding && assets.get(finding.matchedAssetId);
        const cve = finding && (cves.get(finding.cveId) ?? finding.cve);
        const withdrawal = finding && withdrawals.get(finding.cveId);
        const withdrawn = withdrawal && (!Number.isFinite(Date.parse(cve?.modifiedDate ?? '')) ||
          !Number.isFinite(Date.parse(withdrawal.modifiedDate)) || Date.parse(cve!.modifiedDate) <= Date.parse(withdrawal.modifiedDate));
        const current = finding && asset?.active && cve && !withdrawn
          ? runVulnerabilityPipeline([], [cve], [asset], [], [], { ...currentSettings, scopeHours: 0 },
              'Review revalidation', false, vendorAliases, productAliases, undefined, aliases).newFindings[0]
          : undefined;
        if (!finding || !current || !eligibleForReviewNotification(finding, currentSettings) ||
            !eligibleForReviewNotification(current, currentSettings) || !recipientAllows(recipient, current) ||
            job.payload.findingRevisions?.[id] !== findingRevision(current) ||
            job.payload.cveRevisions?.[current.cveId] !== revision(current.cve)) {
          permanent = true;
          throw new Error('Review notification no longer matches current inventory, evidence or confidence policy');
        }
        fresh.push({ ...current, id });
      }
      if (renderUnverifiableReviewEmail(fresh).html !== job.payload.html) {
        permanent = true;
        throw new Error('Review notification content changed; a refreshed review is required');
      }
    }
    if (!retryPolicy.enabled && job.attempts > 1 && job.channel === 'email') {
      permanent = true;
      throw new Error('Automatic email retry is disabled by the current settings');
    }
    // Approval resets the attempt count. The transport budget still applies
    // after approval, including recovery of an abandoned sending lease.
    if (job.attempts > retryPolicy.maxAttempts) {
      permanent = true;
      throw new Error('Delivery retry budget exhausted after worker recovery');
    }
    let native: NativeDelivery | undefined;
    if (job.payload.nativeCorrelation) {
      try {
        native = await validateNativeDelivery(pool, job);
      } catch {
        // Native validation is deterministic: a payload that fails once (policy
        // off, evidence hash mismatch, confidence demoted) fails on every retry.
        permanent = true;
        throw new Error('Native evidence or notification policy is no longer applicable');
      }
      if (native.confidence === 'MEDIUM' && !job.review_approved) {
        routeToReview = true;
        throw new Error('Native medium-confidence evidence requires security review');
      }
    }
    const advisory = await get<Advisory>(pool, 'advisories', job.advisory_id);
    const currentFindings: Finding[] = [];
    // Zero-day digest jobs are standalone summaries: their findings were
    // deliberately withheld from the dispatch path, so there is no advisory and
    // no applicable-finding revalidation to perform.
    //
    // Operational alerts (self-healing watchdog) are the same shape: they are
    // infrastructure messages keyed SELFHEAL:* with no advisory row. Without
    // this exemption they were terminally rejected as "Queued advisory no longer
    // exists" and the Security team never received a degradation alert.
    const isOperationalAlert =
      typeof job.advisory_id === 'string' && job.advisory_id.startsWith('SELFHEAL:');
    if (
      !advisory &&
      !native &&
      !isOperationalAlert &&
      !job.payload.newsEvidence &&
      !job.payload.unverifiableMatch &&
      !job.payload.zeroDayDigest &&
      job.advisory_id !== 'TEST'
    ) {
      permanent = true;
      throw new Error('Queued advisory no longer exists');
    }
    // A digest job intentionally carries only the subset of the advisory that
    // this target may receive. Legacy and non-digest jobs omit these fields and
    // are validated against the whole advisory exactly as before.
    declaredCveIds = job.payload.cveIds ?? advisory?.cveIds ?? [];
    declaredFindingIds = job.payload.includedFindingIds ?? advisory?.findingIds ?? [];
    if (advisory && declaredCveIds.some((id) => !job.payload.cveRevisions?.[id])) {
      // Jobs queued before content-revision evidence existed cannot be validated
      // against the advisory they describe. Rebuild the payload from the
      // current CVE cache first; revalidation below then decides whether it is
      // still deliverable. If the rebuild cannot produce evidence for every
      // declared CVE (e.g. the CVE was removed from the cache), the bundle is
      // stale and recovery rebuilds it from the current inventory instead.
      const { rebuildLegacyDeliveryPayload } = await import('./pipeline');
      if (await rebuildLegacyDeliveryPayload(pool, job)) {
        legacyRebuilt = true;
        declaredCveIds = job.payload.cveIds ?? advisory.cveIds;
      }
      if (declaredCveIds.some((id) => !job.payload.cveRevisions?.[id])) {
        permanent = true;
        staleAdvisory = true;
        throw new Error(
          'Advisory revision is no longer applicable; rebuild legacy queued payload from current intelligence',
        );
      }
    }
    if (advisory && !declaredFindingIds.length && !job.payload.digestKey) {
      // Nothing in this bundle can still be delivered; recover through the same
      // current-inventory rebuild path instead of a bare operator-facing error.
      // A bundle keyed as a digest carries its own content revision per CVE, so
      // it is validated below like any other payload even when it references no
      // findings (a consolidated digest view can legitimately be a summary).
      permanent = true;
      staleAdvisory = true;
      throw new Error('Advisory has no findings; rebuild from current inventory before delivery');
    }
    if (advisory) {
      // Revalidation must use the same operator-managed aliases as the pipeline
      // that produced the finding; otherwise an alias-matched finding is
      // permanently rejected as "no longer applicable".
      const aliasEntries = await list<AliasEntry>(pool, 'aliases');
      const vendorAliases = buildAliasMap(aliasEntries, 'VENDOR');
      const productAliases = buildAliasMap(aliasEntries, 'PRODUCT');
      const invalid: string[] = [];
      let revalidationError = '';
      const findingMap = await getMany<Finding>(pool, 'findings', declaredFindingIds);
      const findings = [...findingMap.values()];
      const assetIds = [...new Set(findings.map((f) => f.matchedAssetId))];
      const cveIds = [...new Set(findings.map((f) => f.cveId))];
      // Only inventory that is still active can confirm a finding. A paused,
      // disabled or deleted asset must not let a queued advisory pass the
      // applicability recheck and reach the transport, so inactive rows are
      // dropped here and the finding is reported as no longer matching below.
      const [storedAssets, cveMap, withdrawalMap] = await Promise.all([
        getMany<WatchListItem>(pool, 'watchlist', assetIds),
        getMany<NormalizedCVE>(pool, 'cveData', cveIds),
        getMany<{ modifiedDate: string }>(pool, 'cveWithdrawals', cveIds),
      ]);
      const assetMap = new Map([...storedAssets].filter(([, asset]) => asset.active !== false));
      for (const id of declaredFindingIds) {
        const finding = findingMap.get(id);
        const asset = finding ? assetMap.get(finding.matchedAssetId) : undefined;
        const cachedCve = finding ? cveMap.get(finding.cveId) : undefined;
        const withdrawal = finding ? withdrawalMap.get(finding.cveId) : undefined;
        // Retention may delete the regenerable threat-cache record while a
        // manually reviewed advisory is still queued. The finding embeds the
        // validated CVE snapshot, so fall back to it instead of permanently
        // rejecting an otherwise deliverable bundle.
        const cve = cachedCve || finding?.cve;
        // Revalidation is a safety check, not a reason to lose the job. A corrupt
        // stored asset/CVE row made runVulnerabilityPipeline throw, which skipped
        // the commit below entirely: the outbox row stayed SENDING until the
        // two-minute lease expired, was re-claimed, and hit the same corrupt row
        // for every attempt until the budget was gone. The batch error also
        // rejected the worker tick that had already committed earlier deliveries.
        let match: Finding | undefined;
        let revalidationFailed = false;
        try {
          match =
            asset && cve
              ? runVulnerabilityPipeline(
                  [],
                  [cve],
                  [asset],
                  [],
                  [],
                  // Fall back to the documented defaults for any setting the stored
                  // object does not carry, so revalidation applies the same policy
                  // the pipeline used instead of an implicit 90% threshold.
                  { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
                  'Server worker',
                  false,
                  vendorAliases,
                  productAliases,
                  undefined,
                  aliasEntries,
                ).newFindings[0]
              : undefined;
        } catch {
          revalidationFailed = true;
        }
        // A failed recheck cannot prove the finding is still applicable, so the
        // job is held (never sent) and committed as retryable instead of being
        // mislabelled as a permanent stale-bundle failure.
        if (revalidationFailed) {
          revalidationError = 'Finding applicability could not be re-verified; delivery deferred';
          continue;
        }
        if (match) currentFindings.push(match);
        const reason = !finding
          ? 'a finding was removed'
          : ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status)
            ? 'a finding was resolved or dismissed'
            : cve && withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate)
              ? 'a CVE was withdrawn'
              : cve &&
                  job.payload.cveRevisions?.[cve.cveId] &&
                  job.payload.cveRevisions[cve.cveId] !== revision(cve)
                ? 'CVE intelligence changed'
                : !match
                  ? 'current inventory no longer matches'
                  : match.notificationStatus !== 'QUEUED_FOR_DISPATCH'
                    ? (holdGated = true) && 'current applicability or confidence policy requires review'
                    : job.payload.findingRevisions?.[id] !== findingRevision(match)
                      ? 'inventory or matching evidence changed'
                      : undefined;
        if (reason) invalid.push(reason);
      }
      // A safety-check failure defers the whole bundle: it is retried on the
      // normal backoff and can never reach the transport while unproven.
      if (revalidationError) throw new Error(revalidationError);
      // The queued payload contains the complete advisory. Sending it after any
      // finding becomes stale would disclose or act on invalidated inventory.
      // Mark the bundle as stale and trigger an immediate rebuild instead of
      // surfacing this as a hard error that requires operator intervention.
      if (invalid.length) {
        // A first-pass send nobody approved yet is held for review; an approved
        // send that is still held keeps the stale-bundle recovery so the finding
        // returns to the review queue rather than being re-sent silently.
        if (
          holdGated &&
          !currentFindings.some((finding) => finding.notificationStatus === 'QUEUED_FOR_DISPATCH') &&
          !job.review_approved &&
          job.channel === 'email'
        ) {
          routeToReview = true;
          throw new Error(`Some advisory findings require review: ${[...new Set(invalid)].join('; ')}.`);
        }
        permanent = true;
        staleAdvisory = true;
        throw new Error(
          `Some advisory findings are no longer applicable; rebuild from current inventory. Reason: ${[...new Set(invalid)].join('; ')}.`,
        );
      }
    }
    if (job.channel === 'email') {
      if (job.target_id !== 'test') {
        const rec = await get<EmailRecipient>(pool, 'recipients', job.target_id);
        if (!rec?.enabled || rec.email !== job.payload.recipientEmail) {
          permanent = true;
          throw new Error('Recipient removed, changed, or disabled');
        }
        if (native && rec.subscriptionTier !== 'ALL_SEVERITIES') {
          permanent = true;
          throw new Error('Recipient subscription no longer permits unscored intelligence');
        }
        if (advisory && !currentFindings.every((finding) => recipientAllows(rec, finding))) {
          permanent = true;
          throw new Error('Recipient subscription no longer permits all advisory findings');
        }
        if (rec.deliveryGroup === 'EVERYONE' && !job.review_approved) {
          routeToReview = true;
          throw new Error('Recipient now requires security review');
        }
      }
      // Confirm before sending. A failed attempt whose outcome is unknown (the
      // send threw after the transport had already accepted the message, or a
      // worker crash left the attempt count advanced) is sent again by a retry.
      // HTML advisory bodies do not carry the delivery id, so this confirmation
      // is the only way to prevent a duplicate alert. The check never blocks a
      // first attempt or an operator-approved send.
      if (job.attempts > 1 && !job.review_approved && config.MAIL_CONFIRM_BEFORE_SEND === 'true') {
        const confirmation = await confirmPriorDelivery(pool, job, config, request);
        if (confirmation === 'delivered') {
          providerId = 'CONFIRMED_PRIOR_DELIVERY';
          throw Object.assign(new Error('A previous attempt was already accepted by the transport'), {
            confirmedPriorAcceptance: true,
          });
        }
        if (confirmation === 'unknown') {
          // The provider could not answer (not allowlisted, console disabled, or
          // an error). That is a transient condition, not proof of duplication:
          // the job stays retryable and is re-confirmed on the next attempt. If
          // the retry budget ends first it is committed FAILED, which is visible
          // to the operator and never silently re-sent.
          throw new Error(
            'Previous delivery outcome could not be confirmed yet; the resend is deferred until it can be',
          );
        }
      }
      // Record the attempt before the transport is contacted. A crash between
      // the provider accepting the message and the commit is then detectable,
      // and the confirmation above resolves it on recovery.
      await transaction(pool, async (db) => {
        const log = await get<EmailDeliveryLog>(db, 'emailLogs', job.id);
        if (log)
          await put(db, 'emailLogs', job.id, {
            ...log,
            status: 'SENDING',
            attemptCount: job.attempts,
            nextRetryTime: null,
          });
      });
      // Apply operator edits exactly once, before the transport sees the job.
      // The PDF attachment is built from `payload.html` inside the sender, so
      // this same value drives both the emailed body and the attachment.
      transportAttempted = true;
      const result = await sendMail(applyJobEdits(job));
      providerId = typeof result === 'string' ? result : result.id;
      if (typeof result !== 'string') emailProvider = result.provider;
    } else {
      const hook = await get<WebhookEndpoint>(pool, 'webhooks', job.target_id);
      if (!hook?.enabled) {
        permanent = true;
        throw new Error('Webhook removed or disabled');
      }
      if (native && (native.confidence !== 'HIGH' || !hook.events.includes('ALL'))) {
        permanent = true;
        throw new Error('Webhook subscription does not permit native intelligence');
      }
      if (advisory && !currentFindings.every((finding) => webhookAllows(hook, finding))) {
        permanent = true;
        throw new Error('Webhook event subscription no longer permits all advisory findings');
      }
      const url = decrypt(hook.url, encryptionKeys(config), `webhook-url:${hook.id}`),
        secret = decrypt(hook.secretToken, encryptionKeys(config), `webhook:${hook.id}`);
      const body = JSON.stringify(
        hook.provider === 'GENERIC_HMAC'
          ? { id: job.id, advisoryId: job.advisory_id, ...job.payload }
          : { text: job.payload.text },
      );
      const timestamp = Math.floor(Date.now() / 1000).toString();
      signature = 'sha256=' + createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
      const response = await request(url, {
        method: 'POST',
        body,
        headers: {
          'content-type': 'application/json',
          'x-vulnstream-signature': signature,
          'x-vulnstream-timestamp': timestamp,
          'idempotency-key': job.id,
        },
        timeoutMs: 25000,
        socketTimeoutMs: 15000,
      });
      statusCode = response.status;
      if (statusCode < 200 || statusCode >= 300) {
        const rawDelay = response.headers['retry-after'];
        const delay = (Array.isArray(rawDelay) ? rawDelay[0] : rawDelay)?.trim();
        if (delay) {
          const retryAt = /^\d+$/.test(delay)
            ? Date.now() + Number(delay) * 1000
            : /[a-z]/i.test(delay)
              ? Date.parse(delay)
              : NaN;
          if (retryAt > Date.now()) {
            if (!Number.isFinite(retryAt) || retryAt > 8640000000000000) {
              permanent = true;
              throw new Error(
                'Webhook Retry-After exceeds supported scheduling range; operator review required',
              );
            }
            retryNotBefore = retryAt;
          }
        }
        permanent = statusCode >= 400 && statusCode < 500 && ![408, 429].includes(statusCode);
        throw new Error(`Webhook HTTP ${statusCode}`);
      }
      providerId = String(statusCode);
    }
  } catch (e) {
    errorInfo = describeError(e);
    error = e instanceof Error ? e.message : 'Delivery failed';
    // Audit M-6: classify *why* the attempt failed, not just whether it did.
    // A provable rejection (HTTP 4xx/5xx body from the provider, refused SMTP
    // session, or missing configuration) means the transport never accepted the
    // message — retrying cannot duplicate it. Everything else (timeout, socket
    // reset, dropped connection) leaves the outcome unknown, and only a
    // provider lookup can then decide whether a resend is safe.
    const smtpFailure = e as { command?: unknown; responseCode?: unknown };
    const beforeSubmission = typeof smtpFailure?.command === 'string' &&
      /^(CONN|AUTH(?: .*)?|EHLO|HELO|STARTTLS|MAIL FROM|RCPT TO)$/i.test(smtpFailure.command);
    const rejectedData = smtpFailure?.command === 'DATA' && typeof smtpFailure.responseCode === 'number' &&
      smtpFailure.responseCode >= 400 && smtpFailure.responseCode < 600;
    transportRejected =
      e instanceof EmailProviderError
        ? e.status >= 400 && e.status < 500
        : beforeSubmission || rejectedData || /HTTP \d{3}\b|did not accept the recipient|not configured|is missing/i.test(error);
    if (e instanceof EmailProviderError) {
      permanent = e.status >= 400 && e.status < 500 && ![408, 429].includes(e.status);
      retryNotBefore = e.retryAt;
      emailProvider = e.provider;
    }
    if ((e as { confirmedPriorAcceptance?: boolean }).confirmedPriorAcceptance) {
      // The transport already has this message. Clear the error so the job is
      // committed ACCEPTED; a later bookkeeping failure is escalated by the
      // caller instead of being retried as an unconfirmed send.
      error = '';
      errorInfo = {};
      unconfirmedError = 'Delivery accepted by the transport but receipt bookkeeping did not complete';
    }
  }
  let finalized = false;
  try {
  await transaction(pool, async (db) => {
    const current = await db.query('SELECT status,lock_token FROM outbox WHERE id=$1 FOR UPDATE', [job.id]);
    if (current.rows[0]?.lock_token !== job.lock_token) return;
    const failed =
        !!error &&
        !routeToReview &&
        (permanent || !retryPolicy.enabled || job.attempts >= retryPolicy.maxAttempts),
      mlDelayMs = getMlRuntime()?.deliveryOptimizer.isTrained() ? computeRetryDelay(job.attempts) : undefined,
      retryDelay = emailRetryDelayPlan(job.attempts, retryPolicy, mlDelayMs);
    const retryDelayBaseAt = Date.now();
    const nextAttemptAt = Math.max(retryNotBefore, retryDelayBaseAt + retryDelay.delayMs);
    const next = new Date(nextAttemptAt);
    const scheduledRetryDelayMs = nextAttemptAt - retryDelayBaseAt;
    const scheduledRetryDelaySource = retryNotBefore > retryDelayBaseAt + retryDelay.delayMs
      ? 'PROVIDER_RETRY_AFTER'
      : retryDelay.source;
    await db.query(
      'UPDATE outbox SET status=$2,next_attempt=$3,error=$4,provider_id=$5,locked_at=NULL,lock_token=NULL,updated_at=now() WHERE id=$1',
      [
        job.id,
        routeToReview ? 'REVIEW' : error ? (failed ? 'FAILED' : 'QUEUED') : 'ACCEPTED',
        next,
        // Keep the reason on a review-routed job: the operator needs it in the
        // review queue, and the reviewer must not have to re-derive why.
        !routeToReview && !error ? null : error || null,
        providerId || null,
      ],
    );
    if (error && !routeToReview && !failed) {
      // A rate-limited or blackholed endpoint must not be hammered once per
      // queued job. Share this target's backoff with its remaining pending work;
      // bound the batch so the global state lock is not held across the queue.
      await db.query(
        `WITH pending AS (
           SELECT id FROM outbox
           WHERE channel=$1 AND target_id=$2 AND status='QUEUED' AND id<>$3 AND next_attempt < $4
           ORDER BY next_attempt
           LIMIT 1000
         )
         UPDATE outbox o SET next_attempt=$4, updated_at=now() FROM pending p WHERE o.id=p.id`,
        [job.channel, job.target_id, job.id, next],
      );
    }
    if (job.channel === 'email') {
      const log = await get<EmailDeliveryLog>(db, 'emailLogs', job.id);
      if (log) {
        // Only stamp sentAt when the email is accepted; preserve the existing
        // value on RETRYING so a provider-accepted-but-temporarily-deferred
        // timestamp survives the retry cycle.
        const status = routeToReview
          ? 'REVIEW_REQUIRED'
          : error
            ? failed
              ? 'FAILED'
              : 'RETRYING'
            : 'ACCEPTED';
        const sentAt =
          status === 'ACCEPTED' ? new Date().toISOString() : status === 'RETRYING' ? log.sentAt : undefined;
        await put(db, 'emailLogs', job.id, {
          ...log,
          provider: emailProvider || log.provider,
          // Persist the transport-assigned message id so a later retry can ask
          // the provider whether the prior attempt was accepted (see
          // confirmPriorDelivery). Without this the lookup is dead code and HTTP
          // providers with non-status transport failures stay `unknown` until
          // the retry budget is spent.
          providerId: providerId || undefined,
          // Audit M-6: record whether the transport provably rejected this
          // attempt, so the resend-withhold decision never depends on matching
          // error-message text.
          transportRejected,
          status,
          attemptCount: job.attempts,
          retryDelayMs: error && !failed ? scheduledRetryDelayMs : undefined,
          retryDelaySource: error && !failed ? scheduledRetryDelaySource : undefined,
          errorMessage: routeToReview ? undefined : error || undefined,
          nextRetryTime: routeToReview ? null : error && !failed ? next.toISOString() : null,
          sentAt,
          // A test message or generated digest is not a finding email and never
          // enters the Action Center. Every real accepted finding delivery
          // becomes a PENDING follow-up action; an already-actioned log is never
          // reopened by a retry.
          ...(status === 'ACCEPTED' && job.target_id !== 'test' && isFindingDelivery(job.advisory_id)
            ? {
                actionStatus: log.actionStatus === 'ACTIONED' ? 'ACTIONED' : 'PENDING',
              }
            : {}),
        });
      }
    } else {
      const log = await get<WebhookDeliveryLog>(db, 'webhookLogs', job.id);
      if (log)
        await put(db, 'webhookLogs', job.id, {
          ...log,
          status: error ? (failed ? 'FAILED' : 'QUEUED') : 'SUCCESS',
          statusCode,
          hmacSignature: signature,
          // FIX: Preserve sentAt on retry (QUEUED) and null on permanent
          // failure (FAILED), mirroring the email-log sentAt fix. The old
          // `error ? '' : ...` cleared the timestamp on every error including
          // retries, losing the original dispatch time.
          sentAt: !error ? new Date().toISOString() : failed ? null : log.sentAt,
        });
      if (!error) {
        const hook = await get<WebhookEndpoint>(db, 'webhooks', job.target_id);
        if (hook) await put(db, 'webhooks', hook.id, { ...hook, deliveryCount: hook.deliveryCount + 1 });
      }
    }
    if (job.channel === 'email' && job.target_id !== 'test') {
      const recipient = await get<EmailRecipient>(db, 'recipients', job.target_id);
      if (recipient) {
        const counts = (
          await db.query(
            "SELECT count(*) FILTER (WHERE status='ACCEPTED')::int AS accepted, count(*) FILTER (WHERE status IN ('ACCEPTED','FAILED'))::int AS terminal FROM outbox WHERE channel='email' AND target_id=$1",
            [job.target_id],
          )
        ).rows[0];
        await put(db, 'recipients', recipient.id, {
          ...recipient,
          deliverySuccessRate: counts.terminal ? (counts.accepted / counts.terminal) * 100 : 0,
        });
      }
    }
    const advisory = await get<Advisory>(db, 'advisories', job.advisory_id);
    if (advisory) {
      const totals = (
        await db.query(
          "SELECT count(*) FILTER(WHERE status='FAILED')::int AS failed,count(*) FILTER(WHERE status IN ('REVIEW','QUEUED','SENDING'))::int AS pending,count(*) FILTER(WHERE status='ACCEPTED')::int AS accepted FROM outbox WHERE advisory_id=$1",
          [advisory.id],
        )
      ).rows[0];
      // Acceptance by a transport is not proof of inbox delivery. A bundle whose
      // only outcome so far is a transport failure stays FAILED; an advisory can
      // have several batches over its lifetime (daily digests, re-queued
      // findings), so an earlier acceptance must not be overwritten by a later
      // partial failure, and a failure must not erase an accepted bundle.
      advisory.deliveryStatus = Number(totals.pending)
        ? 'PENDING'
        : Number(totals.accepted)
          ? 'ACCEPTED'
          : Number(totals.failed)
            ? 'FAILED'
            : advisory.deliveryStatus;
      await put(db, 'advisories', advisory.id, advisory);
      if (!error) {
        const dispatchKey = job.payload.digestKey ?? job.dedupe_key.split(':email:')[0].split(':webhook:')[0];
        const dispatchIds = declaredCveIds.map((cveId) => `${cveId}:${dispatchKey}`);
        const priorAlerts = await getMany<AlertedCVE>(db, 'alertedCves', declaredCveIds);
        const priorDispatches = await getMany(db, 'alertDispatches', dispatchIds);
        for (const cveId of declaredCveIds) {
          const prior = priorAlerts.get(cveId);
          const now = new Date().toISOString();
          // Digest jobs carry one batch key across every recipient, so the same
          // CVE is counted once even when several subscription cohorts receive
          // it. Non-digest jobs retain the original content-revision key.
          const same =
            prior?.lastDispatchKey === dispatchKey || !!priorDispatches.get(`${cveId}:${dispatchKey}`);
          await put(db, 'alertDispatches', `${cveId}:${dispatchKey}`, {
            cveId,
            dispatchKey,
            acceptedAt: now,
          });
          await put(db, 'alertedCves', cveId, {
            cveId,
            firstAlertedAt: prior?.firstAlertedAt || now,
            lastAlertedAt: now,
            advisoryId: advisory.id,
            recipientEmails: Array.from(
              new Set([
                ...(prior?.recipientEmails || []),
                ...(job.channel === 'email' ? [job.payload.recipientEmail!] : []),
              ]),
            ),
            status: 'DISPATCHED',
            lastDispatchKey: dispatchKey,
            dispatchCount: (prior?.dispatchCount || 0) + (same ? 0 : 1),
          } satisfies AlertedCVE);
        }
      }
      // Batch-fetch all finding rows in a single query instead of per-finding.
      const findingMap = await getMany<Finding>(db, 'findings', advisory.findingIds);
      // Only the findings this target actually delivered describe this
      // recipient's bundle. Assessment or digest bundles that are already
      // accepted must not be flipped back to FAILED because the digest window
      // rolled over and a later partial bundle for the same advisory is still
      // pending.
      const deliveredIds =
        job.payload.includedFindingIds !== undefined ? new Set(job.payload.includedFindingIds) : undefined;
      for (const findingId of deliveredIds ?? advisory.findingIds) {
        const f = findingMap.get(findingId);
        if (!f) continue;
        // A finding held for review was queued in this bundle deliberately
        // (assessment and digest payloads may include them). Once the transport
        // for that bundle accepts it, its notification lifecycle is dispatched;
        // otherwise it would remain REVIEW_REQUIRED — perpetually re-selected by
        // the daily digest — while its advisory reports ACCEPTED. A rejected or
        // still-pending bundle keeps the hold in place.
        const reviewHeld = f?.notificationStatus === 'REVIEW_REQUIRED';
        const releasedByReview = reviewHeld && !error && !totals.pending && !totals.failed;
        // Generated advisories (pipeline, digest, daily) are never bound to the
        // findings they describe — only manually reviewed advisories set
        // `advisoryId`. Gating this bookkeeping on that binding left every
        // auto-queued finding marked QUEUED_FOR_DISPATCH after an accepted send,
        // so it was re-queued and re-sent on the next pipeline run. A
        // REVIEW_REQUIRED finding released by this acceptance has neither
        // field set yet, so it must be admitted explicitly.
        if (f.advisoryId === advisory.id || (!f.advisoryId && f.autoDispatchedAt) || releasedByReview)
          await put(db, 'findings', findingId, {
            ...f,
            advisoryId: f.advisoryId ?? advisory.id,
            notificationStatus: releasedByReview
              ? 'AUTO_DISPATCHED'
              : ['NOT_APPLICABLE', 'REVIEW_REQUIRED'].includes(f.notificationStatus)
                ? f.notificationStatus
                : totals.pending
                  ? 'QUEUED_FOR_DISPATCH'
                  : totals.failed
                    ? 'DELIVERY_FAILED'
                    : 'AUTO_DISPATCHED',
            autoDispatchedAt:
              (releasedByReview || !reviewHeld) && !totals.pending && !totals.failed
                ? new Date().toISOString()
                : null,
          });
    }
    }
    // Unverifiable-match notifications carry no advisory row, so the advisory
    // bookkeeping above is skipped. Without parallel tracking, the findings
    // remain REVIEW_REQUIRED after the transport accepts the combined email and
    // are re-selected — and re-queued — on every pipeline run. The dedupe_key
    // prevents an actual duplicate for unchanged content, but a benign finding
    // revision change (vendor/product/asset label) would produce a new dedupe
    // key and fire the notification a second time. Stamp the acceptance here so
    // the pipeline can exclude already-notified findings and guarantee the email
    // is sent at most once.
    if (job.payload.unverifiableMatch && !error && !routeToReview) {
      const notifiedIds = job.payload.unverifiableMatch.findings.map((f) => f.findingId);
      const now = new Date().toISOString();
      await db.query(`UPDATE records SET data=jsonb_set(data,'{reviewNotifiedAt}',to_jsonb($2::text)),updated_at=now()
        WHERE kind='findings' AND id=ANY($1::text[]) AND COALESCE(data->>'reviewNotifiedAt','')=''`, [notifiedIds, now]);
    }
    // After a Security-team delivery is confirmed ACCEPTED, queue the same
    // email for Everyone-group recipients in REVIEW status so an operator can
    // preview, edit, and approve the broader broadcast. This is the deferred
    // half of the `deferEveryoneUntilSecurityDelivered` setting; the function
    // is a no-op when the setting is off or the recipient is not Security-team.
    if (job.channel === 'email' && !error && !routeToReview && job.target_id !== 'test') {
      await queueEveryoneReviewJobs(db, job, settings);
    }
    await writeEvent(db, {
      category: job.channel === 'email' ? 'EMAIL' : 'EVENT',
      level: error ? 'WARNING' : 'INFO',
      code: error ? 'delivery.attempt_failed' : 'delivery.accepted',
      message: error ? 'Delivery attempt failed; retry policy applied' : 'Transport accepted delivery',
      context: {
        jobId: job.id,
        channel: job.channel,
        attempt: job.attempts,
        advisoryId: job.advisory_id,
        ...(error ? errorInfo : {}),
      },
    });
    if (job.channel === 'email' && transportAttempted && !routeToReview && !staleAdvisory && !holdGated && !unconfirmedError) {
      const observedStatus = Number(/HTTP\s+(\d{3})\b/i.exec(error)?.[1] ?? statusCode);
      const classification = classifyDeliveryError({
        provider: emailProvider ?? 'unknown', statusCode: observedStatus,
        errorMessage: error, attemptNumber: job.attempts, hourOfDay: new Date().getUTCHours(),
      });
      await writeEvent(db, {
        category: 'ML', code: 'ml.delivery.outcome', message: 'Observed delivery attempt outcome',
        context: {
          jobId: job.id, provider: emailProvider ?? 'unknown', attempt: job.attempts, delayMs: retryDelayObserved,
          delayObserved: observedDelay.observed,
          succeeded: !error, isRateLimited: observedStatus === 429, isPermanentFailure: permanent,
        },
      });
      if (error) await writeEvent(db, {
        category: 'ML', code: 'ml.delivery.classification', message: 'Delivery classification recommendation',
        context: { ...classification, jobId: job.id, authoritativePermanent: permanent },
      });
      if (error) await writeEvent(db, {
        category: 'ML', code: 'ml.delivery.error', message: 'Observed transport error classification',
        context: {
          provider: emailProvider ?? 'unknown', statusCode: observedStatus,
          errorMessage: error.slice(0, 1000), attemptNumber: job.attempts,
          hourOfDay: new Date().getUTCHours(), isPermanent: permanent,
        },
      });
    }
    if (failed && error) {
      await writeEvent(db, {
        category: job.channel === 'email' ? 'EMAIL' : 'EVENT',
        level: 'ERROR',
        code: 'delivery.exhausted',
        message: `Delivery retries exhausted for advisory ${job.advisory_id}; permanent failure`,
        context: {
          jobId: job.id,
          channel: job.channel,
          attempts: job.attempts,
          advisoryId: job.advisory_id,
          error,
          ...errorInfo,
        },
      });
    }
    await appendAudit(
      db,
      error ? 'Delivery attempt failed' : 'Delivery accepted',
      `${job.channel} delivery ${job.id}; attempt ${job.attempts}`,
      'delivery-worker',
      job.channel === 'email' ? 'EMAIL' : 'WEBHOOK',
      error ? 'WARNING' : 'INFO',
    );
    finalized = true;
  });
  } catch (bookkeepingError) {
    if (!unconfirmedError) throw bookkeepingError;
    // The transport already holds this message but the receipt could not be
    // recorded. Report it loudly instead of rethrowing: a rethrown error makes
    // the worker tick look failed, and the row is still SENDING so a later
    // attempt would resend. The lease expiry plus confirm-before-send is the
    // backstop if this process dies here.
    await writeEvent(pool, {
      category: 'EMAIL',
      level: 'ERROR',
      code: 'delivery.receipt_unconfirmed',
      message: unconfirmedError,
      context: { jobId: job.id, advisoryId: job.advisory_id, attempt: job.attempts, ...describeError(bookkeepingError) },
    }).catch(() => undefined);
  }
  if (finalized && staleAdvisory) {
    try {
      const { rebuildFromCurrentInventory } = await import('./pipeline');
      await rebuildFromCurrentInventory(pool, job.advisory_id, error, { payloadRebuilt: legacyRebuilt });
    } catch (rebuildError) {
      await writeEvent(pool, {
        category: 'EMAIL',
        level: 'ERROR',
        code: 'delivery.rebuild_failed',
        message: 'Stale delivery was retained as failed; rebuilding could not complete',
        context: { jobId: job.id, advisoryId: job.advisory_id, ...describeError(rebuildError) },
      });
    }
  }

  return true;
}
