import type {
  AppSettings,
  ThreatFeed,
  WatchListItem,
  NormalizedCVE,
  Finding,
  Advisory,
  AlertedCVE,
  EmailRecipient,
  WebhookEndpoint,
  WebhookDeliveryLog,
  EmailDeliveryLog,
  AuditLog,
  PipelineExecution,
  TemplateCustomization,
  EmailConfiguration,
  IntelligenceArticle,
  IntelligenceMatch,
  AliasEntry,
} from '../src/types/index.ts';
import type { ZeroDayDigest } from '../src/engine/pipelineEngine.ts';
import {
  DEFAULT_TEMPLATE_CUSTOMIZATION,
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  DEFAULT_DAILY_DIGEST_TEMPLATE,
  DEFAULT_NEWS_EMAIL_CUSTOMIZATION,
  DEFAULT_NEWS_EMAIL_TEMPLATE,
} from '../src/utils/templateCompiler.ts';
import { DEFAULT_ADVISORY_EMAIL_TEMPLATE } from '../src/utils/defaultAdvisoryEmailTemplate.ts';
export const DEFAULT_EMAIL_CONFIG: EmailConfiguration = {
  provider: 'SMTP',
  fromEmail: '',
  fromName: 'BA Threat Intel',
  apiKey: '',
  replyTo: '',
  unsubscribeUrl: '',
  apiEndpoint: '',
  apiHeaderKey: 'Authorization',
  apiAuthPrefix: 'Bearer',
  apiSourceDomain: '',
  smtpHost: '',
  smtpPort: 587,
  smtpSecurity: 'STARTTLS',
  smtpUsername: '',
  smtpPassword: '',
  mailtrapMode: 'LIVE',
  mailtrapInboxId: '',
  postmarkMessageStream: 'outbound',
  mailjetApiSecret: '',
};
/**
 * Timezone applied when the operator has not configured one in Settings.
 *
 * Resolved from the runtime clock rather than a hard-coded IANA name: the
 * browser reports the operator's local zone and the server reports its own.
 * Rendering and the daily-digest schedule both use this fallback, so a fresh
 * deployment displays local time instead of UTC.
 */
export const DEFAULT_TIMEZONE = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
})();

export const DEFAULT_SETTINGS: AppSettings = {
  scopeHours: 24,
  schedulerIntervalMinutes: 60,
  schedulerEnabled: true,
  advisoryPrefix: 'ADV-',
  // Every finding is dispatched; there is no review queue. The advisory states
  // the limitation on the finding itself.
  autoDispatchNewsToSecurityTeam: false,
  mlAutoDispatchThreshold: 90,
  deferEveryoneUntilSecurityDelivered: false,
  digestBatchingEnabled: true,
  digestWindowMinutes: 5,
  emailRetryEnabled: true,
  emailRetryMaxAttempts: 6,
  emailRetryInitialDelayMinutes: 1,
  emailRetryMaxDelayMinutes: 60,
  emailEnabled: true,
  securityPolicy: {
    sessionTimeoutMins: 30,
    minPasswordLen: 14,
    maxLoginAttempts: 5,
    lockoutMins: 15,
    autoAliasTtlDays: 30,
  },
  // Standard keeps the event table small enough to stay fast during an
  // incident; verbose is an explicit forensic choice.
  logVerbosity: 'standard',
  retentionConfig: {
    enabled: false,
    retentionHours: 24,
    cleanupIntervalMinutes: 60,
    maxArchivedRecords: 10000,
    autoCleanup: true,
    retentionMode: 'rolling',
  },
  timezone: DEFAULT_TIMEZONE,
  dailyDigest: {
    enabled: true,
    time: '09:00',
    includeHealthReport: true,
  },
  selfHealing: {
    enabled: true,
    cooldownMinutes: 30,
    emailNotifications: true,
  },
  // Confidence is shown by default, with the historical 100% bar: any finding
  // whose match confidence is short of a perfect match carries its notice, which
  // preserves the pre-setting behavior for existing deployments.
  matchConfidence: {
    enabled: true,
    threshold: 100,
  },
};
/**
 * Collections that can grow without bound in a large installation. `/api/state`
 * returns only a bounded recent slice plus exact counts for these kinds; the
 * paginated `/api/collections/:kind` endpoint is the source for full browsing.
 */
export const HEAVY_COLLECTION_KINDS = [
  'cveData',
  'findings',
  'advisories',
  'alertedCves',
  'emailLogs',
  'webhookLogs',
  'executions',
  'auditLogs',
  'intelligenceArticles',
  'intelligenceMatches',
  // Audit F-3: digests accumulate one row per vendor/product that ever hit the
  // zero-day cap. Without this they are invisible to capped browsing and to
  // the archive screen's per-kind counts.
  'zeroDayDigests',
] as const;
export type HeavyCollectionKind = (typeof HEAVY_COLLECTION_KINDS)[number];

export const COLLECTION_KINDS = [
  'feeds',
  'watchlist',
  'recipients',
  'webhooks',
  'aliases',
  ...HEAVY_COLLECTION_KINDS,
] as const;
export type CollectionKind = (typeof COLLECTION_KINDS)[number];

export const isCollectionKind = (value: string): value is CollectionKind =>
  (COLLECTION_KINDS as readonly string[]).includes(value);

export type CollectionCounts = Record<CollectionKind, number>;

/** Aggregate counts used by dashboards and navigation badges. */
export interface AppSummary {
  activeFindings: number;
  criticalFindings: number;
  kevFindings: number;
  deliveredEmails: number;
}

export interface CollectionPage<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  /**
   * Server-side aggregates over the WHOLE filtered collection, not just the
   * returned page. Optional: only collections that compute them (currently
   * emailLogs) populate it. Views that summarise a collection (the Action Center
   * SLA panel) must read these instead of counting the paginated `items`, which
   * would describe at most one page.
   */
  facets?: CollectionFacets;
}

/** Per-status counts over the full filtered collection. */
export interface CollectionFacets {
  statusCounts?: Record<string, number>;
}

export interface AppState {
  feeds: ThreatFeed[];
  watchlist: WatchListItem[];
  cveData: NormalizedCVE[];
  findings: Finding[];
  advisories: Advisory[];
  alertedCves: AlertedCVE[];
  recipients: EmailRecipient[];
  webhooks: WebhookEndpoint[];
  webhookLogs: WebhookDeliveryLog[];
  emailLogs: EmailDeliveryLog[];
  auditLogs: AuditLog[];
  executions: PipelineExecution[];
  settings: AppSettings;
  emailConfig: EmailConfiguration;
  intelligenceArticles: IntelligenceArticle[];
  intelligenceMatches: IntelligenceMatch[];
  /** Zero-day digests consolidated by the per-run cap (audit F-3 exposure). */
  zeroDayDigests: ZeroDayDigest[];
  templateCustomization: TemplateCustomization;
  customAdvisoryTemplate: string | null;
  advisoryTemplate: string;
  dailyDigestCustomization: TemplateCustomization;
  dailyDigestTemplate: string;
  dailyDigestCustomTemplate: string | null;
  newsDigestCustomization: TemplateCustomization;
  newsDigestTemplate: string;
  newsDigestCustomTemplate: string | null;
  aliases: AliasEntry[];
  /** Exact row counts for every collection, independent of the returned slice. */
  counts: CollectionCounts;
  /** Aggregates computed server-side so bounded slices cannot skew KPI cards. */
  summary: AppSummary;
}

const zeroCounts = (): CollectionCounts =>
  Object.fromEntries(COLLECTION_KINDS.map((kind) => [kind, 0])) as CollectionCounts;

export const emptyState = (): AppState => ({
  feeds: [],
  intelligenceArticles: [],
  intelligenceMatches: [],
  zeroDayDigests: [],
  watchlist: [],
  cveData: [],
  findings: [],
  advisories: [],
  alertedCves: [],
  recipients: [],
  webhooks: [],
  webhookLogs: [],
  emailLogs: [],
  auditLogs: [],
  executions: [],
  aliases: [],
  settings: structuredClone(DEFAULT_SETTINGS),
  emailConfig: { ...DEFAULT_EMAIL_CONFIG },
  templateCustomization: { ...DEFAULT_TEMPLATE_CUSTOMIZATION },
  customAdvisoryTemplate: null,
  advisoryTemplate: DEFAULT_ADVISORY_EMAIL_TEMPLATE,
  dailyDigestCustomization: { ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION },
  dailyDigestTemplate: DEFAULT_DAILY_DIGEST_TEMPLATE,
  dailyDigestCustomTemplate: null,
  // The news studio has its own stock palette (system font, slate text, blue
  // accent). Seeding it from the daily digest's customization made the initial
  // snapshot describe the news document with the digest's colours, so an
  // untouched installation opened the studio on a template that did not match
  // the news email actually sent (`server/newsEmail.ts` uses
  // DEFAULT_NEWS_EMAIL_CUSTOMIZATION).
  newsDigestCustomization: { ...DEFAULT_NEWS_EMAIL_CUSTOMIZATION },
  newsDigestTemplate: DEFAULT_NEWS_EMAIL_TEMPLATE,
  newsDigestCustomTemplate: null,
  counts: zeroCounts(),
  summary: { activeFindings: 0, criticalFindings: 0, kevFindings: 0, deliveredEmails: 0 },
});
export type Role = 'ADMIN' | 'OPERATOR' | 'VIEWER';
export interface SessionInfo {
  username: string;
  /** Address the operator's password-reset code is sent to; null until set. */
  email?: string | null;
  role: Role;
  csrfToken: string;
  expiresAt: string;
}
