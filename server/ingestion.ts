import type { ThreatFeed, NormalizedCVE, IntelligenceArticle } from '../src/types/index.ts';
import { ingestionWindow, recentRevisions, type IngestionState } from './ingestionState';
import { parseSyndication, RSS_MAX_BYTES, RSS_USER_AGENT } from './rss';
import type { Requester, RequestOptions, ResponseData } from './network';
import { cveSchema } from './validation';
import { decrypt, encryptionKeys } from './secrets';
import type { Config } from './config';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import { normalizeCveId, sourceCveContentHash, stableJson } from '../src/utils/deduplicator';
import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
import { paceConcurrent } from './concurrency';
import { cvssSeverity, normalizeCvssVersion, sanitizeCvssVector } from './cvss.ts';
import { OTX_MAX_PAGES, OTX_PAGE_SIZE, OTX_SUBSCRIBED_PULSES_URL, parseOtxPulsePage, validateOtxNextUrl } from './otx.ts';
import {
  GITHUB_ADVISORIES_URL,
  OSV_QUERY_BATCH_URL,
  parseGitHubAdvisories,
  parseOsvVulnerability,
} from './advisoryFeeds.ts';
/** NVD asked us to wait (Retry-After > 60s). Defer to the next run; not a failure. */
export class FeedDeferred extends Error {
  constructor(seconds: number) {
    super(`NVD requested a ${seconds} second retry delay; defer to a later run`);
    this.name = 'FeedDeferred';
  }
}
export interface IngestResult {
  sourceId?: string;
  syncState?: IngestionState;
  cves: NormalizedCVE[];
  articles?: IntelligenceArticle[];
  warnings?: string[];
  kev?: Record<string, NormalizedCVE['cisaKev']>;
  /** Provider-asserted exploited-in-the-wild indicators, distinct from CISA KEV. */
  exploited?: Record<string, true>;
  epss?: Record<string, NormalizedCVE['epss']>;
  /** A successful targeted EPSS response is authoritative only for these IDs. */
  epssScope?: string[];
  withdrawals?: { cveId: string; modifiedDate: string }[];
  rejections?: { feedId: string; cveId?: string; recordHash: string; category: string; summary: string; rejectedAt: string }[];
  count: number;
  etag?: string;
  notModified?: boolean;
  /** End of the fully fetched source window; persisted only after the whole pipeline commits. */
}
export interface IngestContext extends IngestionState {
  /** Last fully committed source checkpoint for the same source configuration. */
  checkpoint?: string;
  /** Latest cached CVE revision times, keyed by canonical CVE ID. */
  knownCveModifiedAt?: ReadonlyMap<string, string>;
  /** Latest cached withdrawal times, keyed by canonical CVE ID. */
  knownWithdrawalAt?: ReadonlyMap<string, string>;
  /**
   * Cached records keyed by canonical CVE ID, used to detect a content change
   * that did not advance the source's lastModified timestamp.
   */
  knownCveContent?: ReadonlyMap<string, NormalizedCVE>;
  /** Active inventory package URLs; OSV queries only versioned package identities. */
  targetPurls?: readonly string[];
}
const CHECKPOINT_OVERLAP_MS = 15 * 60 * 1000;
export function getIngestionWindowStart(end: Date, scopeHours: number, checkpoint?: string, maxHours = 2880): Date {
  const requestedStart = end.getTime() - Math.min(scopeHours, maxHours) * 3600000;
  if (!checkpoint) return new Date(requestedStart);
  const checkpointTime = Date.parse(checkpoint);
  if (!Number.isFinite(checkpointTime)) throw new Error('Saved source checkpoint is invalid; clear it and re-run ingestion');
  if (checkpointTime > end.getTime() + CHECKPOINT_OVERLAP_MS)
    throw new Error('Saved source checkpoint is ahead of the current clock; clear it and re-run ingestion');
  // Keep a bounded overlap for provider indexing delays and timestamps at window edges.
  return new Date(Math.max(0, checkpointTime - CHECKPOINT_OVERLAP_MS));
}
const iso = (s: string) => new Date(s).toISOString();
function normalizeOpenCve(detail: any, feedId: string): NormalizedCVE | null {
  const metrics = detail.metrics || {};
  const metric = metrics.cvssV4_0?.data?.score != null
    ? { ...metrics.cvssV4_0.data, version: normalizeCvssVersion('4.0') }
    : metrics.cvssV3_1?.data?.score != null
      ? { ...metrics.cvssV3_1.data, version: normalizeCvssVersion('3.1') }
      : metrics.cvssV3_0?.data?.score != null
        ? { ...metrics.cvssV3_0.data, version: normalizeCvssVersion('3.0') }
        : metrics.cvssV2_0?.data?.score != null
          ? { ...metrics.cvssV2_0.data, version: normalizeCvssVersion('2.0') }
          : undefined;
  const details: NonNullable<NormalizedCVE['cpeMatchDetails']> = [];
  let applicabilityRequiresReview = false;
  const walk = (node: any) => {
    if (!node || typeof node !== 'object') return;
    if (node.negate || node.operator === 'AND') applicabilityRequiresReview = true;
    for (const match of node.cpeMatch || []) {
      if (match.vulnerable !== true || typeof match.criteria !== 'string') continue;
      const criteria = match.criteria.trim();
      if (!criteria.startsWith('cpe:2.3:')) continue;
      details.push({ criteria, range: {
        versionStartIncluding: match.versionStartIncluding,
        versionStartExcluding: match.versionStartExcluding,
        versionEndIncluding: match.versionEndIncluding,
        versionEndExcluding: match.versionEndExcluding,
      } });
    }
    for (const child of node.nodes || node.children || []) walk(child);
  };
  for (const config of detail.nvd_cpe_configurations || []) walk(config);
  const score = Number(metric?.score || 0);
  const description = String(detail.title || detail.cve_id).slice(0, 30000);
  try {
    return cveSchema.parse({
      cveId: detail.cve_id,
      title: String(detail.title || description).slice(0, 500),
      description,
      publishedDate: iso(detail.created_at),
      modifiedDate: iso(detail.updated_at),
      cvss: {
        version: metric?.version || 'UNKNOWN',
        score,
        vector: sanitizeCvssVector(metric?.vector || ''),
        // A metric present without a usable baseScore (missing, NaN, or the 0
        // storage sentinel) is not a genuine CVSS 0.0 — see the matching
        // comment in normalizeNvd. `cvssSeverity(0)` would mislabel it LOW.
        severity: !metric || !Number.isFinite(score) || metric.score == null ? 'UNKNOWN' : cvssSeverity(score),
      },
      cwe: Array.isArray(detail.weaknesses) ? detail.weaknesses.filter((v: unknown) => typeof v === 'string').slice(0, 100) : [],
      cpeMatches: details.map(({ criteria }) => criteria),
      cpeMatchDetails: details,
      applicabilityRequiresReview: applicabilityRequiresReview || details.length === 0,
      sourceFeeds: [feedId],
      epss: { score: 0, percentile: 0 },
      cisaKev: metrics.kev?.provider === 'cisa' && metrics.kev?.data?.dateAdded
        ? { isKev: true, dateAdded: metrics.kev.data.dateAdded, dueDate: metrics.kev.data.dueDate }
        : { isKev: false },
      exploitStatus: 'None',
      remediation: { patchUrl: '', vendorAdvisoryRef: '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
    });
  } catch {
    return null;
  }
}
export function normalizeNvd(item: any, feedId: string): NormalizedCVE | null {
  const cve = item.cve;
  if (!cve || cve.vulnStatus === 'Rejected') return null;
  const metric =
    cve.metrics?.cvssMetricV40?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV2?.[0]?.cvssData;
  // Keep unscored CVEs for applicability matching. Score 0 is only a storage
  // sentinel; UNKNOWN prevents it from being presented as a real CVSS score.
  let applicabilityRequiresReview = ['Received', 'Awaiting Analysis', 'Undergoing Analysis'].includes(
    cve.vulnStatus,
  );
  const details: NonNullable<NormalizedCVE['cpeMatchDetails']> = [];
  const walk = (node: any) => {
    // Complex AND / negated configurations cannot safely be flattened into an OR.
    if (node.negate || node.operator === 'AND') applicabilityRequiresReview = true;
    for (const m of node.cpeMatch || [])
      if (m.vulnerable === true) {
        const { versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding } = m;
        details.push({
          criteria: m.criteria,
          range: { versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding },
        });
      }
    for (const child of node.nodes || node.children || []) walk(child);
  };
   for (const config of cve.configurations || []) walk(config);
  const validDetails = details.filter((d) => parseCPE23(d.criteria).isValid);
  const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || cve.id;
  const score = metric?.baseScore ?? 0;
  try {
    return cveSchema.parse({
    cveId: cve.id,
    title: description.slice(0, 500),
    description,
    publishedDate: iso(cve.published),
    modifiedDate: iso(cve.lastModified),
    cvss: {
      // metric is selected from cvssMetricV40/V31/V30/V2, each of which carries
      // its own version, so a metric without a matching label is still v3.1.
      version: !metric ? 'UNKNOWN' : normalizeCvssVersion(metric.version),
      score,
      vector: sanitizeCvssVector(metric?.vectorString),
      // `metric?.baseScore ?? 0` collapses "no score reported" and "a genuine
      // 0.0" to the same stored value. The stored `score` field has to pick
      // one (0, for schema compatibility), but severity must not: a metric
      // object that exists without its own baseScore is exactly the storage
      // sentinel case the comment above describes, not a real CVSS 0.0.
      severity: !metric || metric.baseScore == null ? 'UNKNOWN' : cvssSeverity(score),
    },
    cwe: (cve.weaknesses || [])
      .flatMap((w: any) => (w.description || []).filter((d: any) => d.lang === 'en').map((d: any) => d.value))
      .slice(0, 100),
    cpeMatches: validDetails.map((d) => d.criteria),
    cpeMatchDetails: validDetails,
    applicabilityRequiresReview,
    sourceFeeds: [feedId],
    epss: { score: 0, percentile: 0 },
    cisaKev: { isKev: false },
    exploitStatus: 'None',
    remediation: {
      patchUrl: '',
      vendorAdvisoryRef:
        (cve.references || []).find((r: any) => r.tags?.includes('Vendor Advisory'))?.url || '',
      immediateActions: [],
      workarounds: [],
      rollbackPlan: '',
      stepByStep: [],
    },
  });
  } catch {
    return null;
  }
}

export interface CVERejection {
  feedId: string;
  cveId?: string;
  recordHash: string;
  category: string;
  summary: string;
  rejectedAt: string;
}

export function normalizeNvdResult(item: any, feedId: string): { cve: NormalizedCVE | null; rejection?: CVERejection } {
  const cve = normalizeNvd(item, feedId);
  if (cve) return { cve };
  const rawId = normalizeCveId(item?.cve?.id);
  const cveId = item?.cve?.vulnStatus === 'Rejected' ? undefined : rawId || undefined;
  return {
    cve: null,
    rejection: {
      feedId,
      cveId,
      recordHash: stableJson(item).slice(0, 128),
      category: item?.cve?.vulnStatus === 'Rejected' ? 'WITHDRAWN' : 'SCHEMA_VALIDATION',
      summary: item?.cve?.vulnStatus === 'Rejected'
        ? 'Rejected CVE record; withdrawal retained by existing withdrawal handling'
        : 'Record failed normalized CVE schema validation',
      rejectedAt: new Date().toISOString(),
    },
  };
}
export async function ingestFeed(
  feed: ThreatFeed,
  scopeHours: number,
  request: Requester,
  config: Config,
  sleep: (ms: number) => Promise<unknown> = delay,
  targetCveIds: string[] = [],
  onNvdProgress?: (progress: { offset: number; total: number; records: number }) => Promise<void> | void,
  context: IngestContext = {},
): Promise<IngestResult> {
  const upstreamRequest = request;
  request = (url, options = {}) => upstreamRequest(url, {
    ...options,
    ...(feed.requestTimeoutSeconds === undefined ? {} : {
      timeoutMs: feed.requestTimeoutSeconds * 1000,
      socketTimeoutMs: feed.requestTimeoutSeconds * 1000,
    }),
  });
  const headers: Record<string, string> = {};
  // NVD's rolling budgets are 50 requests / 30s with a key and 5 / 30s
  // without one. Keep a small scheduling margin while avoiding the extra
  // throttling in the older 700ms / 6.5s defaults.
  const nvdInterval = Math.max(60000 / feed.rateLimitPerMin, feed.authType === 'API_KEY' ? 610 : 6100);
  if (feed.authType !== 'NONE') {
    let secret: string;
    try { secret = decrypt(feed.authSecretKey || '', encryptionKeys(config), `feed:${feed.id}`); }
    catch { throw new Error('Stored feed credentials could not be decrypted; re-enter the secret or restore the original encryption key'); }
    if (!secret) throw new Error('Feed credentials are not configured');
    if (feed.authType === 'API_KEY') {
      if (feed.type === 'OTX_API') headers['X-OTX-API-KEY'] = secret;
      else headers.apiKey = secret;
    }
    else
      headers.Authorization = `${feed.authType === 'BASIC' ? 'Basic' : 'Bearer'} ${feed.authType === 'BASIC' ? Buffer.from(secret).toString('base64') : secret}`;
  }
  const json = async (
    url: string,
    conditional = true,
    requestOptions: RequestOptions = {},
    retryTransient = false,
  ): Promise<{ data: any; etag: string | undefined; headers: ResponseData['headers'] }> => {
    // Cursor-paginated sources store their index ETag in the sync state rather
    // than the feed record, because it advances per window, not per config.
    if (conditional && (feed.etag || context.indexEtag))
      headers['If-None-Match'] = feed.etag || context.indexEtag!;
    let response: ResponseData;
    for (let attempt = 0; ; attempt++) {
      try {
        response = await request(url, {
          ...requestOptions,
          headers: { ...headers, ...requestOptions.headers },
        });
      } catch (error) {
        const transient = error instanceof Error && (/timed out|timeout|^aborted$|socket hang up|premature close/i.test(error.message) || ['ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'UND_ERR_SOCKET'].includes((error as NodeJS.ErrnoException).code || ''));
        if (!retryTransient || !transient || attempt >= 2) throw error;
        await sleep(Math.max(nvdInterval, 2000 * (attempt + 1)));
        continue;
      }
      const retryableStatus = [429, 502, 503, 504].includes(response.status);
      if (!retryTransient || !retryableStatus || attempt >= 2) break;
      const retryAfter = response.headers['retry-after'];
      const retryAfterValue = Array.isArray(retryAfter) ? retryAfter[0] : retryAfter;
      const retryAfterSeconds = retryAfterValue ? Number(retryAfterValue) : NaN;
      const retryAfterDate = retryAfterValue ? Date.parse(retryAfterValue) : NaN;
      const retryDelay = Number.isFinite(retryAfterSeconds)
        ? retryAfterSeconds * 1000
        : Number.isFinite(retryAfterDate)
          ? retryAfterDate - Date.now()
          : response.status === 429
            ? 30000
            : 2000 * (attempt + 1);
      // Never retry earlier than the provider permits. Long cooldowns defer the
      // source to a later run instead of occupying this worker indefinitely.
      if (retryDelay > 60000)
        throw new FeedDeferred(Math.ceil(retryDelay / 1000));
      await sleep(Math.max(nvdInterval, retryDelay));
    }
    if (response.status === 304) {
      // Cursor-paginated sources carry their index ETag in the sync state.
      if (!conditional || (!feed.etag && !context.indexEtag))
        throw new Error('Feed returned an unexpected conditional response');
      return { data: undefined, etag: feed.etag || context.indexEtag, headers: response.headers };
    }
    if (response.status !== 200)
      throw new Error(
        response.status === 429
          ? 'Feed rate limit reached after retries; wait and run the pipeline again'
          : `Feed returned HTTP ${response.status}`,
      );
    const etag = typeof response.headers.etag === 'string' ? response.headers.etag : undefined;
    try {
      return { data: JSON.parse(response.body), etag, headers: response.headers };
    } catch {
      throw new Error('Feed did not return valid JSON');
    }
  };
  if (feed.type === 'RSS_ATOM') {
    const baseHeaders = { ...headers, 'user-agent': RSS_USER_AGENT,
      ...(feed.etag ? { 'If-None-Match': feed.etag } : {}) };
    let response = await request(feed.url, { headers: { ...baseHeaders, accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml' },
      timeoutMs: 25000, maxResponseBytes: RSS_MAX_BYTES });
    if (response.status === 406 || response.status === 403 || response.status === 404) {
      // Some servers reject the specific RSS/Atom Accept types or the default
      // reader identity with 403/404/406 but will serve the same feed with a
      // broader Accept header. Retry once with */*.
      response = await request(feed.url, { headers: { ...baseHeaders, accept: '*/*' },
        timeoutMs: 25000, maxResponseBytes: RSS_MAX_BYTES });
    }
    if (response.status === 304 && feed.etag) return { cves: [], count: 0, notModified: true, etag: feed.etag };
    if (response.status !== 200) throw new Error(`RSS/Atom source returned HTTP ${response.status}`);
    const result = parseSyndication(response.body, feed.id, scopeHours);
    return { cves: [], ...result, count: result.articles.length, etag: typeof response.headers.etag === 'string' ? response.headers.etag : undefined };
  }
  if (feed.type === 'OTX_API') {
    if (feed.authType !== 'API_KEY' || feed.url !== OTX_SUBSCRIBED_PULSES_URL)
      throw new Error('AlienVault OTX requires its subscribed-pulses API endpoint and an API key');
    const modifiedSince = Date.now() - Math.max(0, scopeHours) * 60 * 60 * 1000;
    const seenPages = new Set<string>();
    const articles: IntelligenceArticle[] = [];
    let pageUrl = new URL(feed.url);
    pageUrl.searchParams.set('limit', String(OTX_PAGE_SIZE));
    for (let pageNumber = 0; pageUrl; pageNumber++) {
      if (pageNumber >= OTX_MAX_PAGES)
        throw new Error(`OTX ingestion exceeded ${OTX_MAX_PAGES} pages; reduce the ingestion window`);
      if (seenPages.has(pageUrl.href)) throw new Error('OTX pagination repeated a page');
      seenPages.add(pageUrl.href);
      const { data } = await json(pageUrl.href, false, {
        timeoutMs: (feed.requestTimeoutSeconds || 60) * 1000,
        socketTimeoutMs: Math.min((feed.requestTimeoutSeconds || 60) * 1000, 30000),
        maxResponseBytes: 8 * 1024 * 1024,
      }, true);
      const page = parseOtxPulsePage(data, feed.id, modifiedSince);
      articles.push(...page.articles);
      if (!page.next) break;
      pageUrl = validateOtxNextUrl(page.next, pageUrl.href);
      pageUrl.searchParams.set('limit', String(OTX_PAGE_SIZE));
      await sleep(Math.max(1000, 60000 / feed.rateLimitPerMin));
    }
    return { cves: [], articles, count: articles.length };
  }
  if (feed.type === 'OSV_API') {
    if (feed.authType !== 'NONE' || feed.url !== OSV_QUERY_BATCH_URL)
      throw new Error('OSV requires the official querybatch API endpoint without authentication');
    const packageUrls = [...new Set(context.targetPurls || [])]
      .filter((purl) => /^pkg:[a-z0-9.+-]+\/.+@[^/?#]+(?:\?.*)?(?:#.*)?$/i.test(purl))
      .sort();
    if (!packageUrls.length)
      return {
        cves: [],
        count: 0,
        warnings: ['OSV requires versioned package URLs on active inventory items'],
      };
    if (packageUrls.length > 5000)
      throw new Error('OSV inventory query exceeds 5,000 versioned package URLs');
    const vulnerabilityPackages = new Map<string, Set<string>>();
    for (let offset = 0; offset < packageUrls.length; offset += 50) {
      const batch = packageUrls.slice(offset, offset + 50);
      let pending = batch.map((purl) => ({ purl, pageToken: undefined as string | undefined }));
      const seenTokens = new Map<string, Set<string>>();
      for (let pageNumber = 0; pending.length; pageNumber++) {
        if (pageNumber >= 20) throw new Error('OSV package query exceeded 20 pages');
        const { data } = await json(OSV_QUERY_BATCH_URL, false, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            queries: pending.map(({ purl, pageToken }) => ({
              package: { purl },
              ...(pageToken ? { page_token: pageToken } : {}),
            })),
          }),
          timeoutMs: 60000,
          socketTimeoutMs: 30000,
          maxResponseBytes: 8 * 1024 * 1024,
        }, true);
        const response = z.object({
          results: z.array(z.object({
            vulns: z.array(z.object({
              id: z.string().min(1).max(200).regex(/^[A-Za-z0-9._-]+$/),
              modified: z.string(),
            })).max(1000).optional(),
            next_page_token: z.string().min(1).max(2000).optional(),
          }).passthrough()).max(50),
        }).passthrough().parse(data);
        if (response.results.length !== pending.length)
          throw new Error('OSV querybatch result count did not match submitted packages');
        const next: typeof pending = [];
        for (let index = 0; index < response.results.length; index++) {
          const item = response.results[index];
          for (const vulnerability of item.vulns || []) {
            if (!Number.isFinite(Date.parse(vulnerability.modified)))
              throw new Error('OSV querybatch returned an invalid modified timestamp');
            const purls = vulnerabilityPackages.get(vulnerability.id) || new Set<string>();
            purls.add(pending[index].purl);
            vulnerabilityPackages.set(vulnerability.id, purls);
            if (vulnerabilityPackages.size > 2000)
              throw new Error('OSV inventory query exceeded 2,000 distinct vulnerabilities');
          }
          if (item.next_page_token) {
            const tokens = seenTokens.get(pending[index].purl) || new Set<string>();
            if (tokens.has(item.next_page_token)) throw new Error('OSV pagination repeated a page token');
            tokens.add(item.next_page_token);
            seenTokens.set(pending[index].purl, tokens);
            next.push({ purl: pending[index].purl, pageToken: item.next_page_token });
          }
        }
        pending = next;
        if (pending.length) await sleep(Math.max(1000, 60000 / feed.rateLimitPerMin));
      }
      if (offset + 50 < packageUrls.length)
        await sleep(Math.max(1000, 60000 / feed.rateLimitPerMin));
    }
    const ids = [...vulnerabilityPackages.keys()].sort();
    const parsed = await paceConcurrent(
      ids,
      Math.max(1000, 60000 / feed.rateLimitPerMin),
      6,
      sleep,
      async (id) => {
        const detailUrl = OSV_QUERY_BATCH_URL.replace(
          /\/querybatch$/,
          `/vulns/${encodeURIComponent(id)}`,
        );
        const { data } = await json(detailUrl, false, {
          timeoutMs: 30000,
          socketTimeoutMs: 20000,
          maxResponseBytes: 4 * 1024 * 1024,
        }, true);
        if (data?.id !== id) throw new Error('OSV detail response did not match the requested vulnerability');
        return parseOsvVulnerability(data, feed.id, [...vulnerabilityPackages.get(id)!]);
      },
    );
    return {
      cves: parsed.flatMap((result) => result.cves),
      articles: parsed.flatMap((result) => result.articles),
      withdrawals: parsed.flatMap((result) => result.withdrawals),
      count: ids.length,
    };
  }
  if (feed.type === 'GITHUB_ADVISORIES') {
    if (feed.authType !== 'NONE' || feed.url !== GITHUB_ADVISORIES_URL)
      throw new Error('GitHub advisories require the official global advisories endpoint without authentication');
    const { start, end, hasMore } = ingestionWindow(scopeHours, context, Date.now(), 24);
    const results: ReturnType<typeof parseGitHubAdvisories> = {
      cves: [],
      articles: [],
      withdrawals: [],
    };
    let after: string | undefined;
    const cursors = new Set<string>();
    for (let page = 1; page <= 10; page++) {
      const url = new URL(GITHUB_ADVISORIES_URL);
      url.searchParams.set('modified', `>=${start.toISOString().slice(0, 10)}`);
      url.searchParams.set('sort', 'updated');
      url.searchParams.set('direction', 'asc');
      url.searchParams.set('per_page', '100');
      if (after) url.searchParams.set('after', after);
      const { data, headers: responseHeaders } = await json(url.href, false, {
        headers: {
          accept: 'application/vnd.github+json',
          'x-github-api-version': '2022-11-28',
          'user-agent': 'VulnStream-Enterprise',
        },
        timeoutMs: 30000,
        socketTimeoutMs: 20000,
        maxResponseBytes: 8 * 1024 * 1024,
      }, true);
      const parsed = parseGitHubAdvisories(data, feed.id, start, end);
      results.cves.push(...parsed.cves);
      results.articles.push(...parsed.articles);
      results.withdrawals.push(...parsed.withdrawals);
      const linkHeader = responseHeaders.link;
      const link = Array.isArray(linkHeader) ? linkHeader.join(',') : linkHeader || '';
      const nextLink = /<([^>]+)>;\s*rel="next"/i.exec(link)?.[1];
      if (!nextLink) break;
      const nextUrl = new URL(nextLink);
      if (nextUrl.origin !== url.origin || nextUrl.pathname !== url.pathname)
        throw new Error('GitHub advisories returned an invalid pagination URL');
      after = nextUrl.searchParams.get('after') || undefined;
      if (!after) throw new Error('GitHub advisories returned a next page without a cursor');
      if (cursors.has(after)) throw new Error('GitHub advisories repeated a pagination cursor');
      cursors.add(after);
      if (page === 10)
        throw new Error('GitHub advisories exceed the ten-page ingestion bound; retry with a narrower window');
      await sleep(Math.max(1000, 60000 / feed.rateLimitPerMin));
    }
    return {
      ...results,
      count: results.cves.length + results.articles.length + results.withdrawals.length,
      syncState: { cursor: end.toISOString(), hasMore },
    };
  }
  if (feed.type === 'CISA_KEV') {
    const { data: rawData, etag } = await json(feed.url);
    if (rawData === undefined) return { cves: [], count: 0, notModified: true, etag };
    const data = z
      .object({
        count: z.number().int().min(0).max(50000).optional(),
        vulnerabilities: z
          .array(
            z.object({
              cveID: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
              dateAdded: z.string(),
              dueDate: z.string(),
              requiredAction: z.string(),
              knownRansomwareCampaignUse: z.enum(['Known', 'Unknown']),
            }),
          )
          .max(50000),
      })
      .parse(rawData);
    if (
      (data.count !== undefined && data.count !== data.vulnerabilities.length) ||
      new Set(data.vulnerabilities.map((v) => v.cveID)).size !== data.vulnerabilities.length
    )
      throw new Error('KEV catalog count mismatch or duplicate CVE');
    return {
      cves: [],
      count: data.vulnerabilities.length,
      etag,
      kev: Object.fromEntries(
        data.vulnerabilities.map((v) => [
          v.cveID,
          {
            isKev: true,
            dateAdded: v.dateAdded,
            dueDate: v.dueDate,
            requiredAction: v.requiredAction,
            knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
          },
        ]),
      ),
    };
  }
  if (feed.type === 'EPSS_API') {
    const epss: Record<string, NormalizedCVE['epss']> = {};
    const requested = [...new Set(targetCveIds.map(normalizeCveId).filter((id): id is string => !!id))].sort();
    const cacheValid = Date.parse(context.epssExpiresAt || '') > Date.now();
    const priorScope = new Set(cacheValid ? context.epssScope : []);
    const scope = requested.filter(id => !priorScope.has(id));
    if (requested.length && !scope.length) return { cves: [], count: 0, notModified: true, syncState: context };
    const epssSync = { epssScope: [...new Set([...priorScope, ...scope])],
      epssExpiresAt: cacheValid ? context.epssExpiresAt : new Date(Date.now() + 3600000).toISOString() };
    const batches: string[][] = [];
    for (const id of scope) {
      if (id.length > 1900) throw new Error('CVE identifier exceeds EPSS request limit');
      const batch = batches[batches.length - 1];
      if (!batch || batch.length >= 100 || [...batch, id].join(',').length > 1900) batches.push([id]);
      else batch.push(id);
    }
    let count = 0,
      requests = 0;
    for (const batch of batches) {
      const seen = new Set<string>();
      let expectedTotal: number | undefined;
      for (let offset = 0; ;) {
        if (requests++) await sleep(60000 / feed.rateLimitPerMin);
        const url = new URL(feed.url);
        // Do not inherit date/score filters: they could hide a requested score.
        url.search = '';
        url.searchParams.set('cve', batch.join(','));
        url.searchParams.set('offset', String(offset));
        url.searchParams.set('limit', '100');
        const { data: page } = await json(url.href, false);
        if (page === undefined) throw new Error('EPSS returned an incomplete conditional response');
        const rows = z
          .array(
            z.object({
              cve: z
                .string()
                .transform((id) => normalizeCveId(id))
                .refine((id) => !!id),
              epss: z.coerce.number().min(0).max(1),
              percentile: z.coerce.number().min(0).max(1),
            }),
          )
          .max(100)
          .parse(page.data);
        const total = Number(page.total);
        if (
          !Number.isInteger(total) ||
          total < 0 ||
          total > batch.length ||
          (expectedTotal !== undefined && total !== expectedTotal) ||
          (page.offset !== undefined && Number(page.offset) !== offset)
        )
          throw new Error('Invalid EPSS pagination response');
        expectedTotal = total;
        for (const row of rows) {
          if (!batch.includes(row.cve!) || seen.has(row.cve!))
            throw new Error('EPSS returned an unexpected or duplicate CVE');
          seen.add(row.cve!);
          epss[row.cve!] = { score: row.epss, percentile: row.percentile };
        }
        count += rows.length;
        offset += rows.length;
        if (offset > total) throw new Error('EPSS response exceeds declared total');
        if (offset === total) break;
        if (!rows.length) throw new Error('EPSS pagination stopped before completion');
      }
    }
    return { cves: [], epss, epssScope: scope, count, syncState: epssSync };
  }
  if (feed.type === 'VULNCHECK_KEV') {
    if (feed.authType !== 'BEARER') throw new Error('VulnCheck KEV requires a Bearer API token');
    const url = new URL(feed.url);
    if (!url.pathname.replace(/\/$/, '').endsWith('/v3/index/vulncheck-kev'))
      throw new Error('VulnCheck endpoint must target /v3/index/vulncheck-kev');
    const { start, end, hasMore } = ingestionWindow(scopeHours, context);
    url.searchParams.set('lastModStartDate', start.toISOString().slice(0, 10));
    url.searchParams.set('lastModEndDate', end.toISOString().slice(0, 10));
    const exploited: Record<string, true> = {};
    const seenCursors = new Set<string>();
    let cursor: string | undefined;
    for (let pageNo = 0; pageNo < 300; pageNo++) {
      const pageUrl = new URL(url);
      // Own pagination parameters; inherited start_cursor/page values can restart a session.
      for (const key of ['cursor', 'start_cursor', 'page']) pageUrl.searchParams.delete(key);
      pageUrl.searchParams.set('limit', '100');
      if (cursor) pageUrl.searchParams.set('cursor', cursor);
      else pageUrl.searchParams.set('start_cursor', '');
      const { data: page } = await json(pageUrl.href, false, { timeoutMs: 30000, maxResponseBytes: 8 * 1024 * 1024 }, true);
      if (!page || !Array.isArray(page.data)) throw new Error('Invalid VulnCheck KEV response');
      if (page.data.length > 100) throw new Error('VulnCheck KEV exceeded the requested page size');
      for (const row of page.data) {
        const record = row?.source || row;
        if (!Array.isArray(record?.cve)) throw new Error('VulnCheck KEV record has no CVE identifiers');
        for (const rawId of record.cve) {
          const id = normalizeCveId(rawId);
          if (!id) throw new Error('VulnCheck KEV returned an invalid CVE identifier');
          exploited[id] = true;
        }
        // Multiple records may share dates, IDs, or CVEs; the CVE set is authoritative.
      }
      const nextCursor = page._meta?.next_cursor;
      if (typeof nextCursor !== 'string' || !nextCursor) break;
      if (seenCursors.has(nextCursor)) throw new Error('VulnCheck KEV cursor did not advance or repeated a previous cursor');
      seenCursors.add(nextCursor);
      cursor = nextCursor;
      if (pageNo === 299) throw new Error('VulnCheck KEV pagination exceeded 30,000 records');
      await sleep(Math.max(1000, 60000 / feed.rateLimitPerMin));
    }
    return { cves: [], exploited, count: Object.keys(exploited).length, syncState: { cursor: end.toISOString(), hasMore } };
  }
  if (feed.type === 'JSON_SEARCH_API') {
    const { data, etag } = await json(feed.url);
    if (data === undefined) return { cves: [], count: 0, notModified: true, etag };
    if (!Array.isArray(data)) throw new Error('JSON_SEARCH_API feed must contain a top-level array');
    const records = data.slice(0, 10000);
    const cves: NormalizedCVE[] = [];
    const rejections: CVERejection[] = [];
    for (const record of records) {
      const parsed = cveSchema.safeParse(record);
      if (!parsed.success) {
        rejections.push({
          feedId: feed.id,
          cveId: typeof (record as any)?.cveId === 'string' ? (record as any).cveId : undefined,
          recordHash: stableJson(record).slice(0, 128),
          category: 'SCHEMA_VALIDATION',
          summary: parsed.error.issues[0]?.message?.slice(0, 240) || 'Record failed schema validation',
          rejectedAt: new Date().toISOString(),
        });
        continue;
      }
      cves.push(parsed.data);
    }
    // Generic feeds may assert VEX, but unsigned claims cannot suppress alerts.
    // Signed per-source statements are retained; the legacy single `vex` field is
    // only accepted through a trusted adapter that can vouch for its provenance.
    return {
      cves: cves.map((c) => ({
        ...c,
        vex: undefined,
        vexStatements: (c.vexStatements ?? []).filter((statement) => statement.signed === true),
        sourceFeeds: [feed.id],
      })),
      count: cves.length,
      rejections,
      etag,
    };
  }
  if (feed.type === 'VULNCHECK_NVD') {
    if (feed.authType !== 'BEARER') throw new Error('VulnCheck NVD++ requires a Bearer API token');
    if (!feed.authSecretKey) throw new Error('VulnCheck NVD++ requires a configured Bearer API token');
    let apiKey: string;
    try {
      apiKey = decrypt(feed.authSecretKey, encryptionKeys(config), `feed:${feed.id}`);
    } catch {
      throw new Error('VulnCheck NVD++ credentials could not be decrypted; re-enter the secret');
    }
    const { start, end } = ingestionWindow(scopeHours, context);
    const url = new URL(feed.url);
    url.searchParams.set('lastModStartDate', start.toISOString());
    url.searchParams.set('lastModEndDate', end.toISOString());
    url.searchParams.set('limit', '1000');
    // The NVD++ index changes only when records change, so the index-level ETag
    // is a valid conditional handle for the whole paginated window: a 304 means
    // no record in the window changed and the previous cursor stays valid.
    const { data: firstOr304, etag } = await json(url.href, true, {
      timeoutMs: 60000,
      socketTimeoutMs: 30000,
      maxResponseBytes: 32 * 1024 * 1024,
      headers: { Authorization: `Bearer ${apiKey}` },
    }, true);
    if (firstOr304 === undefined)
      return { cves: [], count: 0, notModified: true, etag, syncState: context };
    let cursor: string | undefined;
    const cves: NormalizedCVE[] = [];
    const withdrawals: NonNullable<IngestResult['withdrawals']> = [];
    const rejections: NonNullable<IngestResult['rejections']> = [];
    const seenCursors = new Set<string>();
    // Duplicate IDs across pages mean the provider (or the cursor relay) reused
    // records; advancing the cursor past them would silently lose integrity, so
    // the whole run fails atomically instead.
    const seenIds = new Set<string>();
    const revisions: Record<string, string> = {};
    let totalFetched = 0;
    /** Processes one response page: normalizes records, dedupes, records
     *  revisions, and returns the provider's next cursor when paging continues. */
    const processPage = (page: any): string | undefined => {
      if (!page || !Array.isArray(page.vulnerabilities)) throw new Error('Invalid VulnCheck NVD++ response');
      for (const item of page.vulnerabilities) {
        const id = normalizeCveId(item?.cve?.id);
        if (!id || seenIds.has(id)) throw new Error('VulnCheck NVD++ returned an invalid or duplicate CVE');
        seenIds.add(id);
        const incomingModified = Date.parse(item.cve?.lastModified || '');
        // The persisted revision map (syncState.revisions) is the cheap skip: a
        // record whose revision was already ingested is neither re-emitted nor
        // re-counted.
        const revisionSeen = context.revisions?.[id];
        if (
          revisionSeen !== undefined &&
          Number.isFinite(incomingModified) &&
          Date.parse(revisionSeen) >= incomingModified
        )
          continue;
        totalFetched++;
        if (item.cve?.vulnStatus === 'Rejected') {
          // Report the provider's own lastModified, not the local clock: the
          // pipeline compares withdrawal times against the cached revision to
          // decide whether the withdrawal is newer than the record it retracts.
          const modifiedDate = item.cve?.lastModified
            ? iso(item.cve.lastModified)
            : new Date().toISOString();
          withdrawals.push({ cveId: id, modifiedDate });
          continue;
        }
        const cachedModified = Date.parse(context.knownCveModifiedAt?.get(id) || '');
        // Fast path: the cached revision is not older, so re-emit only when the
        // normalized content actually differs (a publisher can correct a score,
        // CPE set or remediation without advancing lastModified).
        if (
          Number.isFinite(cachedModified) &&
          Number.isFinite(incomingModified) &&
          cachedModified >= incomingModified
        ) {
          const cached = context.knownCveContent?.get(id);
          if (!cached) continue;
          const candidate = normalizeNvdItem(item, feed.id);
          if (!candidate) continue;
          const sourceRevision = cached.sourceApplicability?.[feed.id];
          if (
            sourceRevision
              ? sourceRevision.contentHash === sourceCveContentHash(candidate)
              : stableJson(candidate) === stableJson(cached)
          )
            continue;
          cves.push(candidate);
          revisions[id] = candidate.modifiedDate;
          continue;
        }
        const normalized = normalizeNvdItem(item, feed.id);
        if (normalized) {
          cves.push(normalized);
          revisions[id] = normalized.modifiedDate;
        } else {
          rejections.push({
            feedId: feed.id,
            cveId: id,
            recordHash: stableJson(item).slice(0, 128),
            category: 'SCHEMA_VALIDATION',
            summary: 'VulnCheck NVD++ record failed normalization',
            rejectedAt: new Date().toISOString(),
          });
        }
      }
      const nextCursor = page._meta?.next_cursor || page.next_cursor || page.next;
      if (typeof nextCursor !== 'string' || !nextCursor) return undefined;
      if (seenCursors.has(nextCursor)) throw new Error('VulnCheck NVD++ cursor did not advance or repeated a previous cursor');
      seenCursors.add(nextCursor);
      return nextCursor;
    };
    // The first page was already fetched by the conditional probe; process it
    // before paging so no record is lost or fetched twice.
    cursor = processPage(firstOr304);
    for (let pageNo = 0; pageNo < 100 && cursor; pageNo++) {
      const pageUrl = new URL(url);
      for (const key of ['cursor', 'start_cursor', 'page', 'startIndex', 'resultsPerPage']) pageUrl.searchParams.delete(key);
      pageUrl.searchParams.set('cursor', cursor);
      const { data: page } = await json(pageUrl.href, false, {
        timeoutMs: 60000,
        socketTimeoutMs: 30000,
        maxResponseBytes: 32 * 1024 * 1024,
        headers: { Authorization: `Bearer ${apiKey}` },
      }, true);
      cursor = processPage(page);
      if (pageNo === 98 && cursor) throw new Error('VulnCheck NVD++ pagination exceeded 100,000 records');
      // Every fetched continuation page is paced, whether or not another page
      // follows: the request itself consumed provider quota.
      await sleep(Math.max(1000, 60000 / feed.rateLimitPerMin));
      if (!cursor) break;
    }
    return {
      cves,
      count: totalFetched,
      withdrawals,
      rejections,
      etag,
      syncState: { cursor: end.toISOString(), hasMore: cursor !== undefined, revisions, ...(etag ? { indexEtag: etag } : {}) },
    };
  }
  if (feed.type === 'NVD_API') {
    // NIST NVD 2.0 — free community vulnerability data service. No
    // authentication required; unauthenticated rate limit is 5 requests per
    // 30 seconds, so requests are paced at 6-second intervals.
    const { start, end } = ingestionWindow(scopeHours, context);
    const url = new URL(feed.url);
    url.searchParams.set('pubStartDate', start.toISOString());
    url.searchParams.set('pubEndDate', end.toISOString());
    url.searchParams.set('resultsPerPage', '2000');
    url.searchParams.set('startIndex', '0');

    const cves: NormalizedCVE[] = [];
    const withdrawals: NonNullable<IngestResult['withdrawals']> = [];
    const rejections: NonNullable<IngestResult['rejections']> = [];
    const seenIds = new Set<string>();
    const revisions: Record<string, string> = {};
    let totalFetched = 0;
    let offset = 0;
    let hasMore = true;

    for (let pageNo = 0; pageNo < 100 && hasMore; pageNo++) {
      const pageUrl = new URL(url);
      pageUrl.searchParams.set('startIndex', String(offset));
      const { data: page } = await json(pageUrl.href, false, {
        timeoutMs: 60000,
        socketTimeoutMs: 30000,
        maxResponseBytes: 32 * 1024 * 1024,
      }, true);
      if (!page || !Array.isArray(page.vulnerabilities)) throw new Error('Invalid NVD API response');
      for (const item of page.vulnerabilities) {
        const id = normalizeCveId(item?.cve?.id);
        if (!id || seenIds.has(id)) throw new Error('NVD returned an invalid or duplicate CVE');
        seenIds.add(id);
        const incomingModified = Date.parse(item.cve?.lastModified || '');
        const revisionSeen = context.revisions?.[id];
        if (
          revisionSeen !== undefined &&
          Number.isFinite(incomingModified) &&
          Date.parse(revisionSeen) >= incomingModified
        )
          continue;
        totalFetched++;
        if (item.cve?.vulnStatus === 'Rejected') {
          const modifiedDate = item.cve?.lastModified
            ? iso(item.cve.lastModified)
            : new Date().toISOString();
          withdrawals.push({ cveId: id, modifiedDate });
          continue;
        }
        const cachedModified = Date.parse(context.knownCveModifiedAt?.get(id) || '');
        if (
          Number.isFinite(cachedModified) &&
          Number.isFinite(incomingModified) &&
          cachedModified >= incomingModified
        ) {
          const cached = context.knownCveContent?.get(id);
          if (!cached) continue;
          const candidate = normalizeNvdItem(item, feed.id);
          if (!candidate) continue;
          const sourceRevision = cached.sourceApplicability?.[feed.id];
          if (
            sourceRevision
              ? sourceRevision.contentHash === sourceCveContentHash(candidate)
              : stableJson(candidate) === stableJson(cached)
          )
            continue;
          cves.push(candidate);
          revisions[id] = candidate.modifiedDate;
          continue;
        }
        const normalized = normalizeNvdItem(item, feed.id);
        if (normalized) {
          cves.push(normalized);
          revisions[id] = normalized.modifiedDate;
        } else {
          rejections.push({
            feedId: feed.id,
            cveId: id,
            recordHash: stableJson(item).slice(0, 128),
            category: 'SCHEMA_VALIDATION',
            summary: 'NVD record failed normalization',
            rejectedAt: new Date().toISOString(),
          });
        }
      }
      offset += page.vulnerabilities.length;
      hasMore = offset < page.totalResults;
      if (pageNo === 98 && hasMore) throw new Error('NVD API pagination exceeded 200,000 records');
      if (hasMore) await sleep(Math.max(1000, 60000 / feed.rateLimitPerMin));
    }
    return {
      cves,
      count: totalFetched,
      withdrawals,
      rejections,
      syncState: { cursor: end.toISOString(), hasMore: false, revisions },
    };
  }
  throw new Error(`Unsupported feed adapter: ${feed.type}`);
}

/**
 * Normalize a VulnCheck NVD++ item (mirrors NVD CVE API 2.0 format) into a
 * NormalizedCVE. VulnCheck enriches CPEs, CVSS scores, and vendor product tags
 * faster than NIST, but the record structure is compatible with NVD parsing.
 */
function normalizeNvdItem(item: any, feedId: string): NormalizedCVE | null {
  const cve = item.cve;
  if (!cve || cve.vulnStatus === 'Rejected') return null;

  // Extract CVSS metric: prefer NVD primary, fall back to CNA secondary
  const cvssData =
    cve.metrics?.cvssMetricV40?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV2?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV40?.find((m: any) => m.type === 'Secondary')?.cvssData ||
    cve.metrics?.cvssMetricV31?.find((m: any) => m.type === 'Secondary')?.cvssData;
  const score = cvssData?.baseScore ?? 0;
  const version = cvssData ? normalizeCvssVersion(
    cve.metrics?.cvssMetricV40?.[0]?.version ||
    cve.metrics?.cvssMetricV31?.[0]?.version ||
    cve.metrics?.cvssMetricV30?.[0]?.version ||
    cve.metrics?.cvssMetricV2?.[0]?.version ||
    '3.1',
  ) : 'UNKNOWN';
  const vector =
    cvssData?.vectorString || '';

  const details: NonNullable<NormalizedCVE['cpeMatchDetails']> = [];
  const walk = (node: any) => {
    if (!node || typeof node !== 'object') return;
    for (const m of node.cpeMatch || []) {
      if (m.vulnerable === true && typeof m.criteria === 'string' && m.criteria.startsWith('cpe:2.3:')) {
        details.push({
          criteria: m.criteria,
          range: {
            versionStartIncluding: m.versionStartIncluding,
            versionStartExcluding: m.versionStartExcluding,
            versionEndIncluding: m.versionEndIncluding,
            versionEndExcluding: m.versionEndExcluding,
          },
        });
      }
    }
    for (const child of node.nodes || node.children || []) walk(child);
  };

  for (const config of cve.configurations || []) walk(config);
  const validDetails = details.filter((d) => parseCPE23(d.criteria).isValid);

  const description =
    cve.descriptions?.find((d: any) => d.lang === 'en')?.value || cve.id || '';

  const cwe =
    (cve.weaknesses || [])
      .flatMap((w: any) => (w.description || []).filter((d: any) => d.lang === 'en').map((d: any) => d.value))
      .slice(0, 100) || [];

  const cpeMatches = validDetails.map((d) => d.criteria);

  try {
    return cveSchema.parse({
      cveId: cve.id,
      title: description.slice(0, 500),
      description,
      publishedDate: new Date(cve.published).toISOString(),
      modifiedDate: new Date(cve.lastModified).toISOString(),
      cvss: {
        version,
        score,
        vector: sanitizeCvssVector(vector),
        severity: cvssData ? cvssSeverity(score) : 'UNKNOWN',
      },
      cwe,
      cpeMatches,
      cpeMatchDetails: validDetails,
      applicabilityRequiresReview: ['Received', 'Awaiting Analysis', 'Undergoing Analysis'].includes(cve.vulnStatus),
      sourceFeeds: [feedId],
      epss: { score: 0, percentile: 0 },
      cisaKev: { isKev: false },
      exploitStatus: 'None',
      remediation: {
        patchUrl: '',
        vendorAdvisoryRef:
          (cve.references || []).find((r: any) => r.tags?.includes('Vendor Advisory'))?.url || '',
        immediateActions: [],
        workarounds: [],
        rollbackPlan: '',
        stepByStep: [],
      },
    });
  } catch {
    return null;
  }
}
