import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import ipaddr from 'ipaddr.js';
import { FEED_TYPES } from '../src/types/index.ts';
import { RECOMMENDED_FEEDS } from './recommendedFeeds.ts';
const databaseUrl = z
  .string()
  .min(1)
  .refine((value) => {
    try {
      const url = new URL(value);
      return ['postgres:', 'postgresql:'].includes(url.protocol) && Boolean(url.hostname);
    } catch {
      return false;
    }
  }, 'DATABASE_URL must be a valid PostgreSQL connection URL');
const trustProxy = z
  .string()
  .default('')
  .refine((value) => {
    const entries = value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
    if (!entries.length) return true;
    // Express accepts preset names, IPs, and CIDRs. Reject trust-all values:
    // a wildcard proxy setting lets any client spoof X-Forwarded-For and
    // bypass IP-based login throttling and audit attribution.
    return entries.every(
      (entry) =>
        !['true', '*', '0.0.0.0/0', '::/0'].includes(entry.toLowerCase()) &&
        (/^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/.test(entry) ||
          /^[0-9a-f:]+(?:\/\d{1,3})?$/i.test(entry) ||
          ['loopback', 'linklocal', 'uniquelocal'].includes(entry.toLowerCase())),
    );
  }, 'TRUST_PROXY must list explicit proxy IPs, CIDRs, or presets (trust-all is not permitted)');
export const DEFAULT_EGRESS_HOSTS = [
  // Feed, API and mail hosts. Every redirect target of the recommended
  // feeds is listed alongside the URL that redirects to it, because the
  // requester re-validates each hop against this list: a feed whose
  // publisher moves to another host fails with "not in
  // EGRESS_ALLOWED_HOSTS" until its final host appears here.
  // Vulnerability data and enrichment
  'api.osv.dev',
  'services.nvd.nist.gov', // NIST NVD 2.0 — free community vulnerability data service
  // Live OSINT web search (Google Custom Search JSON API)
  'www.googleapis.com',
  'raw.githubusercontent.com',
  'www.cisa.gov',
  'cisa.gov', // cisa.gov redirects to the www spelling
  'api.first.org',
  'api.github.com',
  'api.vulncheck.com',
  'otx.alienvault.com',
  // Mail providers
  'send.api.mailtrap.io',
  'sandbox.api.mailtrap.io',
  'api.sendgrid.com',
  'smtp.sendgrid.net',
  'api.postmarkapp.com',
  'smtp.maileroo.com',
  'smtp.lettr.com',
  'api.mailgun.net',
  'api.eu.mailgun.net',
  'in-v3.mailjet.com',
  'api.mailjet.com',
  'smtp.gmail.com',
  // RSS/Atom sources
  'www.bleepingcomputer.com',
  'isc.sans.edu',
  'api.msrc.microsoft.com',
  'www.fortiguard.com',
  'filestore.fortinet.com',
  'www.kb.cert.org',
  'kb.cert.org', // kb.cert.org redirects to the www spelling
  'thehackernews.com',
  'feeds.feedburner.com', // thehackernews.com redirects here
  'www.securityweek.com',
  'www.rapid7.com',
  'googleprojectzero.blogspot.com',
  'projectzero.google', // googleprojectzero.blogspot.com redirects here
  'krebsonsecurity.com',
  'tools.cisco.com',
  'sec.cloudapps.cisco.com', // tools.cisco.com redirects here
  'security.paloaltonetworks.com',
  'labs.watchtowr.com',
  'www.talosintelligence.com',
  'blog.talosintelligence.com', // the www host has no live feed; the blog serves rss/
  'www.thezdi.com',
  'www.exploit-db.com',
  'www.debian.org',
  'www.cisecurity.com',
  'cisecurity.com', // cisecurity.com redirects to the www spelling
  'cisecurity.org', // www.cisecurity.com -> cisecurity.org -> www.cisecurity.org
  'www.cisecurity.org',
  'seclists.org',
  'blog.sucuri.net',
  'www.welivesecurity.com',
  'wordpress.org',
  // Additional recommended RSS/Atom sources
  'www.darkreading.com',
  'blog.google',
  'cloud.google.com',
  'docs.cloud.google.com', // redirect target of the Google Cloud Security Bulletins feed
  'workspace.google.com',
  'www.greynoise.io',
  'www.malwarebytes.com',
  'cloudblog.withgoogle.com',
  'www.sophos.com',
  'therecord.media',
  'blog.twitter.com',
  'blog.x.com',
  'github.com',
  'github.blog', // github.com/advisories.atom 406s to non-browser agents; github.blog serves the Atom mirror
  'www.pentestpartners.com',
  'www.forbes.com',
  'www.theregister.com',
  'api.theregister.com', // redirect target of The Register Security headlines.atom feed
  'news.google.com',
  // Zero-day and vendor security advisories not previously allowlisted
  'www.cve.org',
  'cve.org', // cve.org redirects to the www spelling
  'support.apple.com',
  'helpx.adobe.com',
  'access.redhat.com',
  'security.access.redhat.com', // live Red Hat errata RSS host
  'security.redhat.com',
  'usn.ubuntu.com',
  'ubuntu.com', // Ubuntu Security Notices feed host (usn.ubuntu.com redirects here)
  'www.crowdstrike.com',
  'crowdstrike.com',
  'securelist.com',
  'www.securelist.com', // feed-kaspersky-securelist uses www.securelist.com
  // SonicWall PSIRT Security Advisories
  'psirtapi.global.sonicwall.com', // RSS API feed: https://psirtapi.global.sonicwall.com/api/v1/feed/rss.xml
  'psirt.global.sonicwall.com', // Web portal redirect target
].join(',');

/**
 * PostgreSQL pool tuning belongs to the environment contract: `pg` accepts
 * `NaN` silently, so a typo such as `POOL_MAX_CONNECTIONS=lots` used to reach
 * the driver as an invalid setting instead of failing startup. Empty strings
 * are treated as unset because Compose renders `${VAR:-}` that way.
 */
const poolNumber = (min: number, max: number, fallback: number) =>
  z.preprocess(
    (value) => (value === '' || value === undefined ? undefined : value),
    z.coerce.number().int().min(min).max(max).default(fallback),
  );

const poolSchema = {
  // Server-side per-session statement guard, applied through libpq options.
  POOL_STATEMENT_TIMEOUT_MS: poolNumber(100, 3_600_000, 15_000),
  POOL_KEEPALIVE_DELAY_MS: poolNumber(0, 600_000, 5_000),
  POOL_MAX_CONNECTIONS: poolNumber(1, 1_000, 25),
  POOL_CONNECTION_TIMEOUT_MS: poolNumber(100, 600_000, 5_000),
  POOL_IDLE_TIMEOUT_MS: poolNumber(1_000, 3_600_000, 30_000),
  POOL_MAX_LIFETIME_MS: poolNumber(1_000, 86_400_000, 600_000),
  // Statement ceiling for the candidate-index refresh. It is a full-corpus
  // rewrite, so it needs far more headroom than interactive statements: the
  // pool-wide POOL_STATEMENT_TIMEOUT_MS (15s default) aborted a legitimate
  // refresh on a large corpus and rolled the whole pipeline run back.
  MATCH_INDEX_STATEMENT_TIMEOUT_MS: poolNumber(1_000, 900_000, 180_000),
};

const schema = z.object({
  ...poolSchema,
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  METRICS_TOKEN: z
    .string()
    .max(256)
    .default('')
    .refine((value) => !value || value.length >= 32, 'Metrics token must contain at least 32 characters'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  DATABASE_URL: databaseUrl,
  APP_ORIGIN: z.url(),
  // Additional exact origins allowed to issue mutating /api requests, comma
  // separated (for example a LAN or Tailscale spelling of the same deployment,
  // or the Vite origin used by `npm run dev`). Each entry is normalised to its
  // origin form and compared exactly; this is not a wildcard. APP_ORIGIN stays
  // the canonical origin used for cookies, secure-cookie detection and the
  // deployment verifier.
  APP_ORIGINS_EXTRA: z.string().max(2048).default(''),
  ALLOW_INSECURE_HTTP: z.enum(['true', 'false']).default('false'),
  ENCRYPTION_KEY: z.string().regex(/^[A-Za-z0-9+/]{43}=$/, 'Must be a base64 encoded 32-byte key'),
  ENCRYPTION_KEYS: z.string().max(2048).default('').refine((value) => {
    const keys = value.split(',').map((key) => key.trim()).filter(Boolean);
    return keys.length <= 16 && keys.every((key) => /^[A-Za-z0-9+/]{43}=$/.test(key) && Buffer.from(key, 'base64').length === 32);
  }, 'ENCRYPTION_KEYS must contain at most 16 comma-separated base64 32-byte keys'),
  // Unset means "use the bundled defaults PLUS every host in the recommended-feed
  // catalog". A non-empty value is an explicit restricted list and replaces the
  // defaults, as OPERATIONS.md documents; on such a deployment the operator must
  // list the feed hosts they actually use. Absent and empty both read as unset:
  // Compose passes `${EGRESS_ALLOWED_HOSTS-}` so an unset variable arrives as
  // `""`, and treating that as deny-all would silently block every feed.
  EGRESS_ALLOWED_HOSTS: z.string().default(''),
  // Appended to the default allowlist instead of replacing it, so a deployment
  // can admit one extra redirect host without having to restate every default.
  EGRESS_ALLOWED_HOSTS_EXTRA: z.string().default(''),
  // Optional live OSINT provider (Google Custom Search JSON API). Leave both
  // empty to disable the Live OSINT Intelligence panel. GOOGLE_CSE_CX is an
  // alias for GOOGLE_CSE_ID for operators used to Google's `cx` parameter.
  GOOGLE_CSE_API_KEY: z.string().trim().max(256).default(''),
  GOOGLE_CSE_ID: z.string().trim().max(128).default(''),
  GOOGLE_CSE_CX: z.string().trim().max(128).default(''),
  TRUST_PROXY: trustProxy,
  SMTP_HOST: z.string().default(''),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(465),
  SMTP_USER: z.string().default(''),
  SMTP_PASSWORD: z.string().default(''),
   SMTP_FROM: z.union([z.email(), z.literal('')]).default(''),
  // A PDF copy of each advisory is attached to outbound emails when enabled.
  // Rendering converts advisory HTML to text and generates a PDF server-side;
  // set ATTACH_ADVISORY_PDF=false to deliver HTML-only messages.
  ATTACH_ADVISORY_PDF: z.enum(['true', 'false']).default('true'),
  // Deprecated compatibility setting. Automatic retries always confirm whether
  // an earlier attempt was delivered; this flag can no longer disable that guard.
  MAIL_CONFIRM_BEFORE_SEND: z.enum(['true', 'false']).default('true'),
  FEED_MAX_DURATION_SECONDS: z.coerce.number().int().min(1).max(7200).default(1800),
  // Retry budget for transient feed transport failures and HTTP 429/502/503/504.
  // Attempts include the initial request; Retry-After and provider pacing remain
  // lower bounds on the delay.
  FEED_RETRY_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(10).default(3),
  FEED_RETRY_BASE_DELAY_MS: z.coerce.number().int().min(0).max(60000).default(2000),
  FEED_RETRY_MAX_DELAY_MS: z.coerce.number().int().min(0).max(120000).default(30000),
  FEED_RETRY_JITTER_FACTOR: z.coerce.number().min(0).max(1).default(0.2),
  // Watchdog silence window for guarded background jobs. A job's heartbeat
  // resets this timer, so it bounds one silent stretch (a slow request or a
  // wedged statement), not a whole ingestion run. The floor stays above the
  // longest healthy silent phase (a 120 s NVD request plus socket and pool
  // timeouts); operators should raise it, never lower it, when a legitimate
  // phase can stay silent longer than five minutes.
  STUCK_PROMISE_MS: z.coerce.number().int().min(240_000).max(3_600_000).default(300_000),
  // Background work (pipeline, outbox, digest, retention, ML training,
  // session cleanup) runs unless explicitly disabled. This must stay `true`:
  // .env and .env.example do not set it, so a `false` default silently turns
  // every deployment that does not opt in into an API-only process that
  // ingests nothing and delivers nothing. Replicas that must not run
  // background work set WORKER_ENABLED=false explicitly.
  WORKER_ENABLED: z.enum(['true', 'false']).default('true'),

  MAILJET_SANDBOX_MODE: z.enum(['true', 'false']).default('false'),
  // Control-plane fault simulation. Disabled unless an operator opts in, and
  // refused outright in production. It previously keyed off NODE_ENV alone,
  // which meant a staging/production image started with NODE_ENV=development
  // (a routine debugging move) exposed an endpoint that can open the shared
  // circuit breaker and halt ingestion for every replica.
  FAULT_SIMULATION_ENABLED: z.enum(['true', 'false']).default('false'),
  // Dead-man's switch. See server/correlation/heartbeat.ts: this is the only
  // mechanism that detects a TOTAL outage, because every other alert is
  // evaluated by something that also dies in a total outage.
  HEARTBEAT_URL: z.string().max(2048).default(''),
  HEARTBEAT_INTERVAL_SECONDS: z.coerce.number().int().min(15).max(3600).default(60),
  HANG_DETECTION_ENABLED: z.enum(['true', 'false']).default('false'),
  // Dead-letter queue for correlation pipeline. Defaults to an app-local
  // directory instead of /tmp because /tmp is subject to OS cleanup and may be
  // world-readable on shared hosts. The DeadLetterQueue creates this directory
  // with mode 0o700 at startup.
  CORRELATION_DLQ_DIRECTORY: z.string().default('data/correlation-dlq'),
  CORRELATION_DLQ_STORAGE_MODE: z.enum(['database', 'filesystem']).default('filesystem'),
  ML_DIRECTORY: z.string().default('/var/lib/vulnstream/ml'),
  ML_STORAGE_MODE: z.enum(['database', 'filesystem']).default('filesystem'),
  // HMAC key for ML artifacts. A short key weakens the integrity check, and an
  // unset key makes signature verification a no-op, so production requires it.
  // An empty value is "unset" (Compose renders ${ML_SIGNING_KEY:-} that way and
  // .env.example ships blank) rather than a zero-length key.
  ML_SIGNING_KEY: z.preprocess(
    (value) => (value === '' ? undefined : value),
    z.string().min(32, 'ML_SIGNING_KEY must contain at least 32 characters').optional(),
  ),
  ML_LOOKBACK_DAYS: z.coerce.number().int().min(1).max(90).default(7),
  // Controls stdout verbosity for structured operational logs. 'standard' keeps
  // output to lifecycle and error events; 'verbose' adds per-tick detail for
  // pipeline, ingestion, delivery, and retention steps to aid troubleshooting.
  LOG_LEVEL: z.enum(['standard', 'verbose']).default('standard'),
  // Unique instance ID for distributed leader election. Set explicitly for
  // stable leadership across restarts; defaults to a random UUID per process.
  INSTANCE_ID: z.string().trim().min(1).max(128).optional(),
});
export type Config = z.infer<typeof schema>;

export interface PoolSettings {
  statementTimeoutMs: number;
  keepAliveDelayMs: number;
  maxConnections: number;
  connectionTimeoutMs: number;
  idleTimeoutMs: number;
  maxLifetimeMs: number;
}

/**
 * Parse the pool settings on their own. `createPool` is also called by scripts
 * and tests that never load the full application config, so it must validate
 * the same variables without requiring DATABASE_URL, APP_ORIGIN, and the rest.
 */
export function loadPoolSettings(env: NodeJS.ProcessEnv = process.env): PoolSettings {
  const parsed = z.object(poolSchema).parse(env);
  return {
    statementTimeoutMs: parsed.POOL_STATEMENT_TIMEOUT_MS,
    keepAliveDelayMs: parsed.POOL_KEEPALIVE_DELAY_MS,
    maxConnections: parsed.POOL_MAX_CONNECTIONS,
    connectionTimeoutMs: parsed.POOL_CONNECTION_TIMEOUT_MS,
    idleTimeoutMs: parsed.POOL_IDLE_TIMEOUT_MS,
    maxLifetimeMs: parsed.POOL_MAX_LIFETIME_MS,
  };
}
/**
 * Union the allowlist with operator additions, lowercased and de-duplicated.
 * Exported so the merge is testable without a full environment.
 *
 * `part` may be a comma-separated list or an array of entries (callers pass the
 * recommended-feed catalog as an array), so both spellings use one definition.
 */
export function mergeAllowedHosts(...parts: (string | readonly string[])[]): string {
  return [
    ...new Set(
      parts
        .flatMap((part) => (Array.isArray(part) ? part : String(part).split(',')))
        .map((h) => h.trim().toLowerCase())
        .filter(Boolean),
    ),
  ].join(',');
}
export function feedEgressHosts(type: unknown, endpoint: unknown, configuredHosts: string[]): string[] {
  const baseline = [
    ...new Set(
      configuredHosts
        .map((host) => host.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, ''))
        .filter(Boolean),
    ),
  ];
  if (!baseline.length) return baseline;
  if (!FEED_TYPES.includes(type as (typeof FEED_TYPES)[number]) || typeof endpoint !== 'string')
    return baseline;
  if (type === 'OTX_API' && endpoint !== 'https://otx.alienvault.com/api/v1/pulses/subscribed/')
    return baseline;
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return baseline;
  }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443'))
    return baseline;
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  return host ? [...new Set([...baseline, host])] : baseline;
}
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.parse(env);
  if (parsed.FEED_RETRY_MAX_DELAY_MS < parsed.FEED_RETRY_BASE_DELAY_MS)
    throw new Error('FEED_RETRY_MAX_DELAY_MS must be >= FEED_RETRY_BASE_DELAY_MS');
  const config = {
    ...parsed,
    INSTANCE_ID: parsed.INSTANCE_ID || randomUUID(),
    // Unset allowlist = bundled defaults + the whole recommended-feed catalog.
    // Every host of every catalogued feed is therefore egress-allowed up front,
    // so adding one from the UI never fails on a missing allowlist entry. Feed
    // requests still pass the SSRF gauntlet (public IP, HTTPS 443, no
    // credentials) on the first hop and on every redirect; this removes the
    // manual hostname step, it does not open egress to arbitrary hosts. A
    // non-empty EGRESS_ALLOWED_HOSTS is an explicit restricted list and replaces
    // the defaults, so its entries are used exactly as given.
    EGRESS_ALLOWED_HOSTS: mergeAllowedHosts(
      parsed.EGRESS_ALLOWED_HOSTS || DEFAULT_EGRESS_HOSTS,
      parsed.EGRESS_ALLOWED_HOSTS_EXTRA,
      ...(parsed.EGRESS_ALLOWED_HOSTS
        ? []
        : [RECOMMENDED_FEEDS.map((feed) => new URL(feed.url).hostname)]),
    ),
    // Every entry must be a bare origin: a path or query could never match the
    // browser's `Origin` header and would only look like a permitted origin.
    APP_ORIGINS_EXTRA: [...new Set(parsed.APP_ORIGINS_EXTRA.split(',').map((entry) => entry.trim()).filter(Boolean))]
      .map((entry) => {
        let candidate: URL;
        try {
          candidate = new URL(entry);
        } catch {
          throw new Error(`APP_ORIGINS_EXTRA entry is not a valid URL: ${entry}`);
        }
        if (candidate.origin !== entry)
          throw new Error(`APP_ORIGINS_EXTRA entry must be an origin without a path: ${entry}`);
        return candidate.origin;
      })
      .join(','),
  };
  const origin = new URL(config.APP_ORIGIN);
  if (origin.origin !== config.APP_ORIGIN) throw new Error('APP_ORIGIN must be an origin without a path');
  if (config.ALLOW_INSECURE_HTTP === 'true') {
    let isPrivateIpv4 = false;
    try {
      const address = ipaddr.parse(origin.hostname);
      isPrivateIpv4 = address.kind() === 'ipv4' &&
        ['private', 'carrierGradeNat'].includes(address.range());
    } catch {
      isPrivateIpv4 = false;
    }
    if (config.NODE_ENV !== 'production' || origin.protocol !== 'http:' || !isPrivateIpv4)
      throw new Error('ALLOW_INSECURE_HTTP requires production HTTP on a private or Tailscale IPv4 address');
  }
  if (config.NODE_ENV === 'production' && origin.protocol !== 'https:' && config.ALLOW_INSECURE_HTTP !== 'true')
    throw new Error('Production requires an HTTPS APP_ORIGIN unless ALLOW_INSECURE_HTTP is enabled for a private or Tailscale IPv4 origin');
  if (Buffer.from(config.ENCRYPTION_KEY, 'base64').length !== 32) throw new Error('Invalid encryption key');
  if (config.NODE_ENV === 'production' && !config.ML_SIGNING_KEY)
    throw new Error(
      'ML_SIGNING_KEY is required in production: without it ML artifacts are loaded without integrity verification',
    );
  if (config.NODE_ENV === 'production' && config.FAULT_SIMULATION_ENABLED === 'true')
    throw new Error('FAULT_SIMULATION_ENABLED is not permitted in production');
  if (config.HEARTBEAT_URL) {
    // The ping grants the ability to silence the alarm, so it must be https and
    // must not embed credentials in the URL.
    let url: URL;
    try {
      url = new URL(config.HEARTBEAT_URL);
    } catch {
      throw new Error('HEARTBEAT_URL must be a valid absolute URL');
    }
    if (config.NODE_ENV === 'production' && url.protocol !== 'https:')
      throw new Error('HEARTBEAT_URL must use https in production');
    if (url.username || url.password)
      throw new Error('HEARTBEAT_URL must not embed credentials; use a receiver with a token path');
  }
  // In production /metrics is the only scrape surface, and it authenticates
  // solely against METRICS_TOKEN. Unset, the route answers 404 and a scraper
  // sees an empty target with no explanation — indistinguishable from a broken
  // deploy. Warn once at startup rather than silently degrading observability.
  if (config.NODE_ENV === 'production' && !config.METRICS_TOKEN)
    console.warn(
      JSON.stringify({
        level: 'warning',
        event: 'config.metrics_token_unset',
        message:
          'METRICS_TOKEN is unset, so /metrics returns 404 and no monitoring data is exposed. Set it to the same value the scraper authenticates with.',
      }),
    );
  return config;
}
