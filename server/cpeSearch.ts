import type { Db } from './db';
import { list } from './db';
import { decrypt, encryptionKeys } from './secrets';
import { parseCPE23, normalizeCpeForComparison } from '../src/utils/cpeMatcher.ts';
import type { Config } from './config';
import type { Requester } from './network';
import type { ThreatFeed, VulncheckCpeSearchResult, VulncheckCpeSearchResponse } from '../src/types/index.ts';

import { isProductWildcard, dictionaryEntryMatchesWildcard } from '../src/utils/registrationCpe.ts';

const VULNCHECK_NVD_CPE_ENDPOINT = 'https://api.vulncheck.com/rest/json/cpes/2.0';

export function buildCpeUrl(keyword: string, resultsPerPage: number): URL {
  const url = new URL('https://services.nvd.nist.gov/rest/json/cpes/2.0');
  url.searchParams.set('keywordSearch', keyword);
  url.searchParams.set('resultsPerPage', String(resultsPerPage));
  return url;
}

/**
 * Builds a URL for the NVD CPE dictionary API using a cpeMatchString query
 * with wildcard support. Unlike keywordSearch (which matches titles and
 * reference text), cpeMatchString performs structural pattern matching
 * against CPE 2.3 component names, so a wildcard vendor (`*`) finds
 * dictionary entries regardless of the NVD-registered vendor label.
 */
export function buildCpeMatchStringUrl(matchString: string, resultsPerPage: number): URL {
  const url = new URL(VULNCHECK_NVD_CPE_ENDPOINT);
  url.searchParams.set('cpeMatchString', matchString);
  url.searchParams.set('resultsPerPage', String(resultsPerPage));
  return url;
}

/**
 * Escapes special characters in a CPE 2.3 component value for use in a
 * cpeMatchString query. The NVD dictionary stores CPE names with certain
 * characters escaped (e.g. "+" -> "\+", "(" -> "\("), so the match string
 * must apply the same escaping to find matching entries. Wildcard
 * characters `*` and `?` are also escaped so a literal occurrence in the
 * product name is matched rather than treated as a cpeMatchString wildcard.
 */
function escapeCpeComponent(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\+/g, '\\+')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/\:/g, '\\:')
    .replace(/\*/g, '\\*')
    .replace(/\?/g, '\\?');
}

/**
 * Parses the NVD CPE API response body into structured results, deduplicating
 * against an optional set of already-seen CPE names (case-insensitive).
 */
function parseNvdCpeProducts(
  body: string,
  exactCpe?: string,
  seenCpes?: Set<string>,
  viaWildcardVendor?: boolean,
): { results: VulncheckCpeSearchResult[]; totalResults: number } {
  let data: any;
  try {
    data = JSON.parse(body);
  } catch {
    throw new Error('NVD returned a non-JSON CPE search response');
  }

  if (!Array.isArray(data?.products) || !Number.isSafeInteger(data?.totalResults) || data.totalResults < 0)
    throw new Error('NVD returned an invalid CPE search response');

  const configurations: any[] = data.products;
  const results: VulncheckCpeSearchResult[] = [];
  for (const entry of configurations) {
    const cpe = entry?.cpe || entry;
    const name = typeof cpe?.cpeName === 'string' ? cpe.cpeName : '';
    if (!name || cpe?.deprecated === true) continue;
    if (exactCpe && normalizeCpeForComparison(name) !== normalizeCpeForComparison(exactCpe)) continue;
    if (seenCpes && seenCpes.has(normalizeCpeForComparison(name))) continue;
    const parsed = parseCPE23(name);
    if (!parsed.isValid) continue;
    const title =
      Array.isArray(cpe?.titles) && typeof cpe.titles[0]?.title === 'string'
        ? cpe.titles[0].title
        : undefined;
    results.push({
      cpeName: name,
      cpeNameId: typeof cpe?.cpeNameId === 'string' ? cpe.cpeNameId : '',
      part: parsed.part,
      vendor: parsed.vendor,
      product: parsed.product,
      version: parsed.version,
      update: parsed.update,
      targetSw: parsed.targetSw,
      targetHw: parsed.targetHw,
      ...(title ? { title } : {}),
      ...(viaWildcardVendor ? { viaWildcardVendor: true } : {}),
    });
    seenCpes?.add(name.toLowerCase());
  }

  const total = Number.isInteger(data?.totalResults) ? Number(data.totalResults) : results.length;
  return { results, totalResults: total };
}

/** Load the VulnCheck Bearer token; never send it to the NIST host. */
export async function loadNvdApiKey(db: Db, config: Config): Promise<string> {
  let feeds: ThreatFeed[];
  try {
    feeds = await list<ThreatFeed>(db, 'feeds');
  } catch {
    console.warn(JSON.stringify({ level: 'warn', event: 'nvd_api_key_feed_query_failed' }));
    return '';
  }
  const vulncheck = feeds.find((f) => f.type === 'VULNCHECK_NVD' && f.authType === 'BEARER' && f.enabled);
  if (!vulncheck) {
    const vulncheckFeeds = feeds.filter((f) => f.type === 'VULNCHECK_NVD');
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'nvd_api_key_not_configured',
        nvdFeedCount: vulncheckFeeds.length,
        authTypes: vulncheckFeeds.map((f) => f.authType),
        enabledFlags: vulncheckFeeds.map((f) => f.enabled),
      }),
    );
    return '';
  }
  if (!vulncheck.authSecretKey) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'nvd_api_key_missing_secret',
        feedId: vulncheck.id,
      }),
    );
    return '';
  }
  try {
    return decrypt(vulncheck.authSecretKey, encryptionKeys(config), `feed:${vulncheck.id}`);
  } catch (error) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'nvd_api_key_decrypt_failed',
        feedId: vulncheck.id,
        message: error instanceof Error ? error.message : 'unknown error',
      }),
    );
    return '';
  }
}

/**
 * Load the NIST NVD API key from the operator's NVD_API threat feed. NIST
 * raises its rolling budget from 5 to 50 requests per 30 seconds when a key is
 * present. The key is only ever attached to requests for services.nvd.nist.gov;
 * the VulnCheck Bearer token is separately loaded by `loadNvdApiKey`.
 */
export async function loadNistApiKey(db: Db, config: Config): Promise<string> {
  let feeds: ThreatFeed[];
  try {
    feeds = await list<ThreatFeed>(db, 'feeds');
  } catch {
    return '';
  }
  const configured = feeds.filter((feed) => feed.type === 'NVD_API' && feed.authType === 'API_KEY');
  // Prefer the enabled feed, but a configured key still raises the CPE-search
  // budget when ingestion itself is disabled in favour of VulnCheck NVD++.
  const nist = configured.find((feed) => feed.enabled) ?? configured[0];
  if (!nist?.authSecretKey) return '';
  try {
    return decrypt(nist.authSecretKey, encryptionKeys(config), `feed:${nist.id}`);
  } catch (error) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'nist_api_key_decrypt_failed',
        feedId: nist.id,
        message: error instanceof Error ? error.message : 'unknown error',
      }),
    );
    return '';
  }
}

// NIST allows 50 keyed requests per rolling 30 seconds (5 unkeyed). Serialize
// scheduled slots through one process-wide queue so a bulk CPE verification
// cannot exhaust the budget before its last row is checked.
let nistNextRequestAt = 0;
let nistQueue: Promise<void> = Promise.resolve();

async function paceNistRequest(intervalMs: number): Promise<void> {
  let release!: () => void;
  const slot = new Promise<void>((resolve) => {
    release = resolve;
  });
  const previous = nistQueue;
  nistQueue = previous.then(() => slot);
  await previous;
  const now = Date.now();
  const wait = nistNextRequestAt - now;
  nistNextRequestAt = Math.max(now, nistNextRequestAt) + intervalMs;
  if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
  release();
}

/**
 * Queries the NVD CPE dictionary for verified CPE 2.3 names matching the
 * supplied vendor and product keywords. Only well-formed CPE 2.3 entries are
 * returned; partial matches that the NVD keyword search surfaces are parsed and
 * filtered so the operator only selects structurally valid CPEs.
 *
 * The request is issued through the shared SSRF-protected requester, so the NVD
 * host must appear in EGRESS_ALLOWED_HOSTS (it is present by default).
 *
 * `nistApiKey` authenticates requests to the public NIST dictionary; it is
 * never sent to the VulnCheck mirror. `paceNistRequests` keeps bulk callers
 * inside NIST's rolling budget.
 */
export async function searchNvdCpes(
  request: Requester,
  apiKey: string,
  vendor: string,
  product: string,
  limit: number,
  exactCpe?: string,
  cpeNameId?: string,
  nistApiKey = '',
  paceNistRequests = false,
): Promise<VulncheckCpeSearchResponse> {
  // NVD keywordSearch matches titles/reference text, not CPE component names.
  const keyword = `${vendor} ${product}`.replace(/_/g, ' ').replace(/\s+/g, ' ').trim();
  const pageSize = Math.min(Math.max(1, limit), 200);
  const url = buildCpeUrl(keyword, pageSize);
  if (exactCpe) {
    if (!parseCPE23(exactCpe).isValid) throw new Error('Invalid CPE 2.3 expression');
    url.searchParams.delete('keywordSearch');
    if (apiKey) url.hostname = 'api.vulncheck.com';
    if (cpeNameId) url.searchParams.set('cpeNameId', cpeNameId);
    else url.searchParams.set('cpeMatchString', exactCpe);
  }
  const fetchPage = async (key: string, urlObj: URL = url) => {
    const target = new URL(urlObj);
    if (!key) target.hostname = 'services.nvd.nist.gov';
    const targetHost = target.hostname;
    if (paceNistRequests && targetHost === 'services.nvd.nist.gov') {
      await paceNistRequest(nistApiKey ? 650 : 6100);
    }
    return request(target.href, {
      headers: {
        Accept: 'application/json',
        ...(key && targetHost === 'api.vulncheck.com' ? { Authorization: `Bearer ${key}` } : {}),
        ...(nistApiKey && targetHost === 'services.nvd.nist.gov' ? { apiKey: nistApiKey } : {}),
      },
      timeoutMs: 20000,
      socketTimeoutMs: 15000,
      maxResponseBytes: 4 * 1024 * 1024,
      sameHostRedirects: true,
    });
  };
  const effectiveKey = apiKey;

  const rateLimitError = (response: { headers: Record<string, string | string[] | undefined> }) =>
    ({
      __nvdRateLimit: true,
      retryAfter: response.headers['retry-after'],
      status: 429,
      message: 'NVD rate limit reached; retry later',
    }) as NvdRateLimitError;

  const requireOk = (response: {
    status: number;
    headers: Record<string, string | string[] | undefined>;
  }) => {
    if (response.status === 429) throw rateLimitError(response);
    if (response.status !== 200) throw new Error(`NVD CPE search returned HTTP ${response.status}`);
  };

  const seenCpes = new Set<string>();
  const productWildcard = Boolean(exactCpe && isProductWildcard(exactCpe));
  const readExactPage = (body: string) => {
    const parsed = parseNvdCpeProducts(body, productWildcard ? undefined : exactCpe, seenCpes);
    if (!productWildcard) return parsed;
    return {
      results: parsed.results.filter((entry) =>
        dictionaryEntryMatchesWildcard(exactCpe as string, entry.cpeName),
      ),
      totalResults: parsed.totalResults,
    };
  };

  const response = await fetchPage(apiKey);
  requireOk(response);

  if (exactCpe) {
    let exactPage = readExactPage(response.body);

    // A credential routes exact lookups to the VulnCheck NVD mirror. A
    // successful but empty page there is not proof that the identifier is
    // unpublished: the registration gate names the NVD dictionary, and the
    // public NIST service is its authority. Re-check a miss there before
    // reporting that the CPE does not exist.
    if (exactPage.results.length === 0 && apiKey) {
      const nistResponse = await fetchPage('');
      requireOk(nistResponse);
      exactPage = readExactPage(nistResponse.body);
    }
    if (exactPage.results.length) return exactPage;

    // Still no exact match: retry with a wildcard-vendor matchString built
    // from the CPE's product. This handles the common case where the
    // operator's vendor label differs from the NVD-registered vendor (e.g.
    // "notepad-plus-plus" vs. "don_ho").
    const parsed = parseCPE23(exactCpe);
    if (parsed.isValid && parsed.product && parsed.product !== '*') {
      const escapedProduct = escapeCpeComponent(parsed.product);
      const matchString = `cpe:2.3:*:*:${escapedProduct}:*:*:*:*:*:*:*:*`;
      const wildcardUrl = buildCpeMatchStringUrl(matchString, pageSize);
      const wildcardResponse = await fetchPage(effectiveKey, wildcardUrl);
      requireOk(wildcardResponse);
      let widenedPage = parseNvdCpeProducts(wildcardResponse.body, undefined, seenCpes, true);
      if (widenedPage.results.length === 0 && apiKey) {
        const nistResponse = await fetchPage('', wildcardUrl);
        requireOk(nistResponse);
        widenedPage = parseNvdCpeProducts(nistResponse.body, undefined, seenCpes, true);
      }
      return {
        results: [...exactPage.results, ...widenedPage.results],
        totalResults: exactPage.totalResults + widenedPage.totalResults,
      };
    }

    return exactPage;
  }

  const page = readExactPage(response.body);
  const { results, totalResults } = page;

  // When no exact CPE lookup is requested and a product name is supplied,
  // also search with a cpeMatchString that uses a wildcard vendor (`*`).
  // This surfaces NVD dictionary entries even when the operator's vendor
  // label differs from the published NVD vendor (e.g. "notepad_plus_plus"
  // vs. the registered "don_ho"), so the operator can still select a
  // published, verified identifier before saving.
  //
  // These matches are put at the FRONT of the list: a product-name-only
  // match is what the operator is most likely looking for when their typed
  // vendor didn't produce a hit (or wasn't supplied at all), and every
  // result returned here is still an exact, verified NVD dictionary CPE —
  // only the search path differs, never the accuracy of the entry itself.
  if (product.trim()) {
    const escapedProduct = escapeCpeComponent(product.trim());
    const matchString = `cpe:2.3:*:*:${escapedProduct}:*:*:*:*:*:*:*:*`;
    const wildcardUrl = buildCpeMatchStringUrl(matchString, pageSize);
    try {
      const wildcardResponse = await fetchPage(effectiveKey, wildcardUrl);
      if (wildcardResponse.status === 429) throw rateLimitError(wildcardResponse);
      if (wildcardResponse.status === 200) {
        const wildcardParsed = parseNvdCpeProducts(wildcardResponse.body, undefined, seenCpes, true);
        return {
          results: [...wildcardParsed.results, ...results],
          totalResults: totalResults + wildcardParsed.totalResults,
        };
      }
    } catch (error) {
      if (isNvdRateLimitError(error)) throw error;
      // Non-fatal: a failed wildcard search still returns the keyword results
    }
  }

  return page;
}

export interface NvdRateLimitError {
  __nvdRateLimit: boolean;
  retryAfter: string | string[] | undefined;
  status: 429;
  message: string;
}

export function isNvdRateLimitError(error: unknown): error is NvdRateLimitError {
  return typeof error === 'object' && error !== null && (error as NvdRateLimitError).__nvdRateLimit === true;
}

export function nvdRetryAfterSeconds(error: NvdRateLimitError): number | null {
  const raw = error.retryAfter;
  const single = Array.isArray(raw) ? raw[0] : raw;
  if (!single) return null;
  const asSeconds = Number(single);
  if (Number.isFinite(asSeconds)) return Math.max(1, Math.round(asSeconds));
  const asDate = Date.parse(single);
  return Number.isFinite(asDate) ? Math.max(1, Math.round((asDate - Date.now()) / 1000)) : null;
}
