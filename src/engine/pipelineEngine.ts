import type {
  ThreatFeed,
  WatchListItem,
  NormalizedCVE,
  Finding,
  Advisory,
  AlertedCVE,
  PipelineExecution,
  AppSettings,
  ExploitRiskLevel,
  IntelligenceMatch,
  EmailDeliveryLog,
  AuditLog,
  AliasEntry,
} from '../types';
import { normalizeCveId, isWithinPublicationScope, mergeCveRecords } from '../utils/deduplicator';
import {
  DEFAULT_PRODUCT_ALIASES,
  DEFAULT_VENDOR_ALIASES,
  aliasGroupKeys,
  buildAliasMap,
  matchesWatchlistItem,
  normalizeAliasToken,
  parseCPE23,
  type MatchResult,
} from '../utils/cpeMatcher';
import { deriveInventoryAliases } from '../utils/aliasLifecycle';
import { formatExecutionName } from '../utils/executionName';
import { isPublicAddress } from '../utils/ipSafety';
import ipaddr from 'ipaddr.js';
import { randomUUID } from 'node:crypto';
import { shouldAutoDispatch } from '../../server/ml/integration.ts';
import { classifyFinding } from './classification';

/** Feed types treated as authoritative for vendor/product autodispatch
 * even when the CVE record has no CPE applicability data.
 */
const AUTHORITATIVE_FEED_TYPES = new Set(['RSS_ATOM', 'JSON_SEARCH_API', 'VULNCHECK_NVD']);

/** Package identity (`npm/express`) used to index PURL inventory.
 *
 * Audit H-2: one parser only. The engine previously kept a private copy whose
 * `lastIndexOf('@')` did not respect the npm scope boundary, so scoped packages
 * were indexed differently here than in the PostgreSQL candidate index.
 */
import { purlIdentity } from '../utils/cpeMatcher';
export { purlIdentity };
export interface PipelineRunResult {
  execution: PipelineExecution;
  newFindings: Finding[];
  newAdvisories: Advisory[];
  updatedAlertedCves: AlertedCVE[];
  newEmailLogs: EmailDeliveryLog[];
  newAuditLogs: AuditLog[];
}
/** Client-side hint only. The server validates DNS and pins every connection. */
export function validateSsrfSafety(value: string): { safe: boolean; reason?: string } {
  try {
    const u = new URL(value),
      host = u.hostname
        .replace(/^\[|\]$/g, '')
        .replace(/\.$/, '')
        .toLowerCase();
    if (u.protocol !== 'https:' || u.username || u.password)
      return { safe: false, reason: 'HTTPS without URL credentials required' };
    if (u.port && u.port !== '443')
      return { safe: false, reason: 'Non-default port on HTTPS is not permitted' };
    if (
      host === 'localhost' ||
      /\.(localhost|local|internal)$/.test(host) ||
      (ipaddr.isValid(host) && !isPublicAddress(host))
    )
      return { safe: false, reason: 'Non-public destination' };
    return { safe: true };
  } catch {
    return { safe: false, reason: 'Malformed URL' };
  }
}
export function determineExploitRisk(cve: NormalizedCVE): ExploitRiskLevel {
  // Most-severe-signal-first. Active weaponized exploitation outranks a bare
  // "reported in wild" report; the previous order tested the reported/evidence
  // branch first, so any `exploitationSources` entry (or a 'Reported In Wild'
  // status) shadowed an 'Active Weaponized' status and downgraded the label. The
  // risk level drives triage ordering and the UI, so the stronger signal must win.
  return cve.cisaKev?.isKev
    ? 'CISA_KEV_EXPLOITED'
    : cve.exploitStatus === 'Active Weaponized'
      ? 'WEAPONIZED_EXPLOIT'
      : cve.exploitationSources?.length || cve.exploitStatus === 'Reported In Wild'
        ? 'REPORTED_IN_WILD_EXPLOIT'
        : (cve.epss?.score ?? 0) >= 0.4
          ? 'HIGH_EPSS_PROBABILITY'
          : cve.cvss.score >= 7
            ? 'ELEVATED'
            : 'STANDARD';
}
/**
 * VEX enforcement and the exploitability lattice live in their own module so
 * the resolution rules can be tested independently of correlation.
 */
export {
  applyVexSuppression,
  resolveExploitability,
  hasExploitIntelligence,
  vexImpact,
  vexStatementsFor,
} from './exploitability';
/**
 * Rate-limit zero-day matches and consolidate into digests.
 *
 * Zero-day matches (findings without a CVE, or with active exploit indicators)
 * are capped at MAX_ZERO_DAYS_PER_RUN to prevent notification storms.
 * Multiple zero-day matches for the same vendor/product are consolidated into
 * a single advisory (the "zero-day digest" mode).
 */
export const MAX_ZERO_DAYS_PER_RUN = 50;
/**
 * Upper bound on the assets a text-only CVE (no CPE and no PURL) is matched
 * against in one run.
 *
 * Such a CVE cannot be narrowed by the vendor/product index, so without a bound
 * each one costs O(assets) and a provider publishing many of them makes the run
 * O(CVEs x assets). The limit is far above any realistic single-tenant
 * inventory (thousands of assets), so ordinary deployments never hit it; it
 * exists so a pathological corpus cannot turn one run into an unbounded scan.
 */
export const MAX_TEXT_ONLY_CANDIDATE_ASSETS = 5000;
export interface ZeroDayDigest {
  advisoryId: string;
  vendor: string;
  product: string;
  findingIds: string[];
  matchCount: number;
  /** Matches this digest replaces. Server drops them from the persisted set. */
  matchIds: string[];
}

/**
 * Recovers the vendor/product tail from the `"tag (vendor product)"` string
 * that intelligenceMatcher writes into `assetName`.
 *
 * The asset tag itself may contain a parenthesis (`prod (legacy) (acme web)`),
 * so the split must anchor on the LAST '(' — splitting on the first one yields
 * vendor `legacy` and product `prod`. Anything unparseable degrades to the tag
 * rather than inventing structured identity.
 */
/**
 * Identity of the asset a match belongs to, used to group zero-day digests.
 *
 * Prefers the structured vendor/product the matcher records. Parsing the
 * `"tag (vendor product)"` display label is only a fallback for matches built
 * before those fields existed, and it is inherently lossy: a product name
 * containing whitespace or a parenthesis cannot be split back into vendor and
 * product. Grouping on a wrong identity merges unrelated products into one
 * digest, so the structured fields are the source of truth whenever present.
 */
function assetIdentity(match: IntelligenceMatch): { vendor: string; product: string; tag: string } {
  // Structured identity is authoritative; never parse `assetName` for vendor or
  // product — a product name containing parentheses or spaces corrupts the split.
  if (!match.assetVendor || !match.assetProduct) {
    return { vendor: 'unknown', product: 'unknown', tag: match.assetName };
  }
  return {
    vendor: match.assetVendor,
    product: match.assetProduct,
    tag: match.assetName.split(' (')[0]?.trim() || match.assetName.trim(),
  };
}

/**
 * Rate-limit zero-day matches and consolidate them into per-product digests.
 *
 * A match is zero-day evidence when it carries the zero-day flag or has no CVE
 * identity at all. Only the zero-day evidence is capped: non-zero-day matches
 * are always preserved, even when the cap is exceeded.
 *
 * Audit C-2 / M-1 / M-4 / M-9 fixes:
 *  - `matchCount` is the size of the digest group, not of the whole match array
 *    (it previously reported every match in the run, so digests misstated their
 *    own severity).
 *  - `findingIds` is populated from the suppressed matches; it was hardcoded
 *    empty, leaving every digest unactionable.
 *  - grouping is by vendor/product, as documented. Keying on `assetId` produced
 *    one digest per asset, i.e. exactly the notification storm the cap exists to
 *    prevent. The digest prefers the matcher's structured `assetVendor`/
 *    `assetProduct`; parsing the display label is a lossy fallback only for
 *    matches built before those fields existed.
 *  - the digest id uses a `DIGEST_` namespace instead of `ZDIGEST_`, which
 *    mimicked `formatAdvisoryId()` output for an advisory that is never written.
 *  - the counterpart findings of suppressed matches are removed from the
 *    returned finding set. The cap previously limited only the news evidence
 *    while the finding still queued for dispatch.
 */
export function rankAndRateLimitZeroDays(
  findings: Finding[],
  matches: IntelligenceMatch[],
  cap = MAX_ZERO_DAYS_PER_RUN,
): { findings: Finding[]; matches: IntelligenceMatch[]; digests: ZeroDayDigest[] } {
  if (!Number.isInteger(cap) || cap < 1 || cap > MAX_ZERO_DAYS_PER_RUN)
    throw new Error('Zero-day cap must be an integer within the configured maximum');
  // `zeroDay` is set by the matcher from the article's own flag. The previous
  // `!cveId && REVIEW_REQUIRED` fallback predates that field and is now wrong:
  // it counts every unlinked, uncorroborated intelligence match as a zero-day,
  // which both mislabels CVE-less coverage notes and lets ordinary review-rated
  // matches consume the zero-day budget ahead of real ones.
  const isZeroDayEvidence = (m: IntelligenceMatch) => m.zeroDay === true;
  const zeroDayMatches = matches.filter(isZeroDayEvidence);
  if (zeroDayMatches.length <= cap) {
    return { findings, matches, digests: [] };
  }
  // Rank by credibility. Ties break on corroboration depth and then on the
  // stable match id: credibility alone leaves genuinely tied scores ordered by
  // whatever order the database returned, so two identical runs could suppress
  // different zero-days (audit H-1).
  const ranked = [...zeroDayMatches].sort(
    (a, b) =>
      (b.credibilityScore ?? 0) - (a.credibilityScore ?? 0) ||
      b.articleIds.length - a.articleIds.length ||
      a.id.localeCompare(b.id),
  );
  const dropped = ranked.slice(cap);
  if (!dropped.length) return { findings, matches, digests: [] };
  const byProduct = new Map<string, { vendor: string; product: string; matches: IntelligenceMatch[] }>();
  for (const match of dropped) {
    const { vendor, product } = assetIdentity(match);
    const key = `${vendor.toLowerCase()}\u0000${product.toLowerCase()}`;
    const group = byProduct.get(key) || { vendor, product, matches: [] };
    group.matches.push(match);
    byProduct.set(key, group);
  }
  const digests: ZeroDayDigest[] = [];
  for (const { vendor, product, matches: group } of byProduct.values()) {
    digests.push({
      advisoryId: `DIGEST_${vendor}_${product}`.replace(/[^A-Za-z0-9_.-]+/g, '_'),
      vendor,
      product,
      findingIds: [...new Set(group.map((m) => m.findingId).filter((id): id is string => Boolean(id)))],
      matchCount: group.length,
      matchIds: group.map((m) => m.id),
    });
  }
  const droppedIds = new Set(dropped.map((m) => m.id));
  const droppedFindingIds = new Set(digests.flatMap((d) => d.findingIds));
  return {
    findings: droppedFindingIds.size ? findings.filter((finding) => !droppedFindingIds.has(finding.id)) : findings,
    matches: matches.filter((match) => !droppedIds.has(match.id)),
    digests,
  };
}
/** Pure correlation. Network ingestion and transactional outbox delivery live on the server. */
export function runVulnerabilityPipeline(
  _feeds: ThreatFeed[],
  corpus: NormalizedCVE[],
  watchlist: WatchListItem[],
  alerted: AlertedCVE[],
  existing: Finding[],
  settings: AppSettings,
  _caller = 'Server worker',
  includeExistingCandidates = false,
  vendorAliases: Record<string, string[]> = {},
  productAliases: Record<string, string[]> = {},
  candidatePairs?: Map<string, Set<string>>,
  aliasEntries: readonly AliasEntry[] = [],
  /**
   * Reference instant for timeline filtering and finding timestamps. The
   * production pipeline passes nothing and gets wall-clock time; tests pin it so
   * week-scoped window assertions stay deterministic instead of drifting out of
   * range a few days after they are written.
   */
  evaluatedAt: Date = new Date(),
  applicabilityChangedCveIds: Set<string> = new Set(),
): PipelineRunResult {
  const started = evaluatedAt,
    known = new Set(existing.map((f) => `${normalizeCveId(f.cveId)}:${f.matchedAssetId}`)),
    knownCves = new Set(existing.map((f) => normalizeCveId(f.cveId)).filter((id): id is string => Boolean(id)));
  const newFindings: Finding[] = [];
  const alreadyNotified = new Set(existing.filter((f) => f.reviewNotifiedAt || f.autoDispatchedAt)
    .map((f) => `${normalizeCveId(f.cveId)}:${f.matchedAssetId}`));
  const executionId = randomUUID();
  const feedAuthority = new Map(
    _feeds.map((f) => [f.id, AUTHORITATIVE_FEED_TYPES.has(f.type) || f.authoritative === true]),
  );
  // Feed lookup by id for source-category classification (vendor advisory vs
  // third-party feed vs stripped/ambiguous).
  const feedsById = new Map(_feeds.map((f) => [f.id, f]));
  let processed = 0;
  let authoritativeSourceDispatchCount = 0;
  const nowMs = started.getTime();
  const newAuditLogs: AuditLog[] = [];
  /** CVEs whose text-only candidate scan was truncated by the per-CVE cap. */
  const textOnlyTruncations: string[] = [];
  /** Every (CVE, asset) pair emitted this run, for duplicate-integrity checks. */
  const emittedKeys: string[] = [];
  const addAudit = (event: string, details: string, level: 'INFO' | 'WARNING' = 'INFO') => {
    newAuditLogs.push({
      id: randomUUID(),
      timestamp: new Date(nowMs).toISOString(),
      category: 'PIPELINE',
      level,
      event,
      details,
      actor: 'Server worker',
      ipAddress: '',
      context: { outcome: 'RECORDED' },
      // The hash chain is computed by server/db.ts appendAudit when the entry
      // is persisted; these placeholders are never stored.
      prevHash: '',
      hash: '',
    });
  };
  const normalizationStarted = performance.now();
  const latest = mergeCveRecords(corpus);
  const duplicates = corpus.filter((cve) => normalizeCveId(cve.cveId)).length - latest.size;
  const normalizationDurationMs = Math.round(performance.now() - normalizationStarted);
  const activeAssets = watchlist.filter((asset) => asset.active);
  // Auto aliases are derived from the operator's own inventory declarations
  // (vendor/product plus CPEs). They are ephemeral here and persisted by the
  // server pipeline, so both the browser simulation and server correlation
  // resolve the same spellings. Manual aliases always take precedence and are
  // never removed by this merge.
  const autoAliasEntries = deriveInventoryAliases(activeAssets, aliasEntries);
  const mergeAliasMaps = (
    base: Record<string, string[]>,
    extra: Record<string, string[]>,
  ): Record<string, string[]> => {
    const merged: Record<string, string[]> = Object.assign(Object.create(null), base);
    for (const [key, values] of Object.entries(extra))
      merged[key] = [...new Set([...(merged[key] || []), ...values])];
    return merged;
  };
  const effectiveVendorAliases = mergeAliasMaps(vendorAliases, buildAliasMap(autoAliasEntries, 'VENDOR'));
  const effectiveProductAliases = mergeAliasMaps(productAliases, buildAliasMap(autoAliasEntries, 'PRODUCT'));
  // Index inventory once. Matching the entire CVE cache against every asset
  // on every run is the dominant avoidable cost for large installations.
  // The candidate selection is deliberately a superset: wildcard criteria,
  // unstructured assets, and package assets stay eligible for full matching.
  const assetsByProduct = new Map<string, WatchListItem[]>();
  const assetsByPurl = new Map<string, WatchListItem[]>();
  // Assets with neither a CPE nor a PURL can only be matched by the text/alias
  // fallback, so they remain candidates for every CVE. PURL-only assets are
  // reachable through their package bucket instead of being scanned every time.
  const assetsWithoutIdentifiers: WatchListItem[] = [];
  const assetsWithBroadCpes: WatchListItem[] = [];
  // Build alias-expanded indices so assets are candidates when their vendor
  // or product differs from a CVE's by an alias rather than a canonical name.
  // Built-in aliases are included: the matcher accepts them, so the candidate
  // prefilter must not drop the pair before it can be evaluated. Punctuation
  // variants are accepted by the matcher's normalizer (`widget_pro` versus
  // `widget-pro`), so the normalized token is indexed alongside every spelling.
  const aliasVendorKeys = (v: string): string[] =>
    !v
      ? [v]
      : [
          ...new Set([
            v.toLowerCase(),
            normalizeAliasToken(v),
            ...aliasGroupKeys(v, DEFAULT_VENDOR_ALIASES, effectiveVendorAliases),
          ]),
        ];
  const aliasProductKeys = (p: string): string[] =>
    !p
      ? [p]
      : [
          ...new Set([
            p.toLowerCase(),
            normalizeAliasToken(p),
            ...aliasGroupKeys(p, DEFAULT_PRODUCT_ALIASES, effectiveProductAliases),
          ]),
        ];
  // Alias expansion is a pure function of the spelling and the effective alias
  // maps, both of which are fixed for the whole run. Every CVE criterion used to
  // re-expand the same vendor/product names (and every inventory row did it
  // again for the index), which is the hottest allocation path in a large
  // corpus x inventory cross product. Memoise per spelling for this run only.
  const vendorKeyCache = new Map<string, string[]>();
  const productKeyCache = new Map<string, string[]>();
  const cachedVendorKeys = (v: string): string[] => {
    let keys = vendorKeyCache.get(v);
    if (!keys) {
      keys = aliasVendorKeys(v);
      vendorKeyCache.set(v, keys);
    }
    return keys;
  };
  const cachedProductKeys = (p: string): string[] => {
    let keys = productKeyCache.get(p);
    if (!keys) {
      keys = aliasProductKeys(p);
      productKeyCache.set(p, keys);
    }
    return keys;
  };
  for (const asset of activeAssets) {
    const seenPurls = new Set<string>();
    for (const purl of asset.purls ?? []) {
      const identity = purlIdentity(purl);
      if (!identity || seenPurls.has(identity)) continue;
      seenPurls.add(identity);
      const bucket = assetsByPurl.get(identity) || [];
      bucket.push(asset);
      assetsByPurl.set(identity, bucket);
    }
    // The operator-declared vendor/product is an authoritative identity even
    // when the asset's CPEs are stale, more specific, or absent. The matcher's
    // alias and prose paths read these fields directly, so the candidate
    // prefilter must make the asset reachable by them; otherwise a pair the
    // matcher accepts is dropped before matching. Registering the declared
    // identity is a superset (the matcher still decides), so it cannot create a
    // finding on its own.
    const seenProducts = new Set<string>();
    const indexIdentity = (vendor: string, product: string) => {
      if (!vendor || !product) return;
      for (const vendorKey of cachedVendorKeys(vendor))
        for (const productKey of cachedProductKeys(product)) {
          const key = `${vendorKey}\u0000${productKey}`;
          if (seenProducts.has(key)) continue;
          seenProducts.add(key);
          const bucket = assetsByProduct.get(key) || [];
          bucket.push(asset);
          assetsByProduct.set(key, bucket);
        }
    };
    indexIdentity(asset.vendor, asset.product);
    if (!asset.cpes.length) {
      if (!asset.purls?.length) assetsWithoutIdentifiers.push(asset);
      continue;
    }
    let usableIdentity = false;
    for (const cpe of asset.cpes) {
      const parsed = parseCPE23(cpe);
      if (!parsed.isValid) continue;
      usableIdentity = true;
      if (/[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) {
        assetsWithBroadCpes.push(asset);
        break;
      }
      // Register asset under all alias-expanded vendor/product keys.
      indexIdentity(parsed.vendor, parsed.product);
    }
    // A CPE list that is non-empty but entirely malformed yields no structured
    // identity the matcher can use. The candidate prefilter would otherwise make
    // the asset permanently invisible to every CVE with CPE data, so treat it
    // like an unstructured asset and let the alias/text fallback reach it. A
    // PURL still supplies a usable identity, so package-only assets stay in
    // their own bucket.
    if (!usableIdentity && !asset.purls?.length) assetsWithoutIdentifiers.push(asset);
  }
  const candidateAssets = (cve: NormalizedCVE): WatchListItem[] => {
    // A feed may supply per-criterion details *and* additional product criteria
    // in `cpeMatches`. The details carry the authoritative ranges, but the extra
    // criteria are still applicability claims from the same record; ignoring
    // them made the asset invisible to the candidate prefilter and silently
    // dropped a real finding.
    const criteria = cve.cpeMatchDetails?.length
      ? [...new Set([...cve.cpeMatchDetails.map((detail) => detail.criteria), ...cve.cpeMatches])]
      : cve.cpeMatches;
    const candidates = new Map<string, WatchListItem>();
    const add = (items: WatchListItem[]) => items.forEach((asset) => candidates.set(asset.id, asset));
    add(assetsWithoutIdentifiers);
    add(assetsWithBroadCpes);
    if (cve.purls?.length)
      for (const purl of cve.purls) {
        const identity = purlIdentity(purl);
        if (identity) add(assetsByPurl.get(identity) || []);
      }
    if (!criteria.length) {
      // A CVE with no structured identifiers has to use the text/alias fallback
      // against the whole inventory. A package-only advisory stays bounded to
      // the matching package buckets.
      if (!cve.purls?.length) {
        // Bound the text-only fan-out. Matching itself is O(candidates) per CVE,
        // so a provider that publishes many CVEs with no CPE/PURL data would make
        // a run O(CVEs x assets) with nothing to narrow it. The cap is far above
        // any realistic inventory while keeping an adversarial or misconfigured
        // corpus from turning one run into an unbounded scan; the truncation is
        // logged so it is visible rather than silently lossy.
        if (activeAssets.length > MAX_TEXT_ONLY_CANDIDATE_ASSETS) {
          textOnlyTruncations.push(cve.cveId);
          return activeAssets.slice(0, MAX_TEXT_ONLY_CANDIDATE_ASSETS);
        }
        return activeAssets;
      }
      return [...candidates.values()];
    }
    for (const criterion of criteria) {
      const parsed = parseCPE23(criterion);
      if (!parsed.isValid || /[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) {
        add(activeAssets);
        break;
      }
      for (const vendorKey of cachedVendorKeys(parsed.vendor))
        for (const productKey of cachedProductKeys(parsed.product))
          add(assetsByProduct.get(`${vendorKey}\u0000${productKey}`) || []);
    }
    return [...candidates.values()];
  };
  // Assets that can never be reached through a structured identity join are
  // added to every CVE's candidate set, matching candidateAssets' fallback.
  const alwaysCandidateAssets = [...assetsWithoutIdentifiers, ...assetsWithBroadCpes];
  const assetById = new Map(activeAssets.map((asset) => [asset.id, asset]));
  /**
   * When PostgreSQL supplied candidate pairs, iterate only those assets. A CVE
   * absent from the map has a wildcard/unstructured criterion and falls back to
   * the in-process candidate selection, preserving the text/alias path.
   */
  const assetsForCve = (cve: NormalizedCVE, canonical: string): WatchListItem[] => {
    const allowed = candidatePairs?.get(canonical);
    if (!allowed) return candidateAssets(cve);
    const candidates = new Map<string, WatchListItem>();
    for (const id of allowed) {
      const asset = assetById.get(id);
      if (asset) candidates.set(asset.id, asset);
    }
    for (const asset of alwaysCandidateAssets) candidates.set(asset.id, asset);
    return [...candidates.values()];
  };
  const matchingStarted = performance.now();
  for (const raw of latest.values()) {
    const canonical = normalizeCveId(raw.cveId);
    // New detections are gated on the publication event, not on the latest
    // record revision. A provider rewriting `modifiedDate`, the description or
    // the title must not make an old CVE look newly published and re-match it
    // against the whole inventory (which queued finding emails for records that
    // were already processed). A genuine applicability change still overrides
    // the window so a newly added CPE/PURL/range can reach assets that had no
    // previous finding.
    const applicabilityChanged = Boolean(canonical && applicabilityChangedCveIds.has(canonical));
    const inTimelineScope = applicabilityChanged ||
      isWithinPublicationScope(raw.publishedDate, raw.modifiedDate, settings.scopeHours, started);
    // Existing findings stay eligible even outside the window so scope expiry
    // alone cannot turn an active finding into NOT_APPLICABLE during
    // reconciliation.
    if (!canonical || (!inTimelineScope && !knownCves.has(canonical))) continue;
    processed++;
    const cve = { ...raw, cveId: canonical };
    // Everything below depends only on the CVE record, not on the asset being
    // evaluated. It used to be rebuilt inside the asset loop, so a CVE matching
    // N assets allocated N copies of the same criteria set, applicability
    // arrays and source labels. Hoisting it is a pure refactor that removes the
    // dominant allocation cost of the correlation pass.
    //
    // An explicit CPE match criteria is authoritative for its own entry: a
    // per-entry range without bounds means "any version of this product", so the
    // product-level versionRange must not be applied across all criteria. The
    // product-level range is only a fallback when the CVE has no match details
    // at all.
    // Criteria present in `cpeMatches` but not in `cpeMatchDetails` still
    // describe affected products; match them with the product-level range
    // rather than discarding them.
    const detailCriteria = new Set((cve.cpeMatchDetails ?? []).map((detail) => detail.criteria));
    const extraCriteria = cve.cpeMatchDetails?.length
      ? cve.cpeMatches.filter((criteria) => !detailCriteria.has(criteria))
      : [];
    const applicabilitySets = cve.cpeMatchDetails?.length
      ? [
          ...cve.cpeMatchDetails.map(({ criteria, range }) => ({
            cpes: [criteria],
            range: range && Object.values(range).some(Boolean) ? range : undefined,
          })),
          ...(extraCriteria.length ? [{ cpes: extraCriteria, range: cve.versionRange }] : []),
        ]
      : [{ cpes: cve.cpeMatches, range: cve.versionRange }];
    const advisoryLacksApplicabilityData = !(
      cve.cpeMatches?.length ||
      cve.cpeMatchDetails?.length ||
      cve.purls?.length
    );
    const isAuthoritativeSource = cve.sourceFeeds?.some((feedId) => feedAuthority.get(feedId) === true);
    // Build a human-readable source label for the enrichment evidence. Resolve
    // feeds through the id map built once per run; the previous `_feeds.find`
    // inside the finding loop was O(findings x feeds) on every run.
    const sourceLabels = cve.sourceFeeds?.map((feedId) => {
      const feed = feedsById.get(feedId);
      if (!feed) return feedId;
      const t = feed.type;
      if (t === 'RSS_ATOM' || t === 'JSON_SEARCH_API') return 'vendor advisory';
      // VulnCheck NVD++ mirrors both the NVD and MITRE CVE lists, so the
      // label names both upstream registries the record was sourced from.
      if (t === 'VULNCHECK_NVD') return 'authoritative source (NVD/MITRE via VulnCheck NVD++)';
      return `authoritative source (${t})`;
    }).filter(Boolean);
    const sourceLabel = sourceLabels.length > 0 ? sourceLabels.join(' ') : '';
    for (const asset of assetsForCve(cve, canonical)) {
      const key = `${canonical}:${asset.id}`;
      if (!inTimelineScope && !known.has(key)) continue;
      if (known.has(key) && !includeExistingCandidates) continue;
      // Per-CPE ranges apply only to that CPE criterion. PURLs use the
      // package-level range and must never borrow another product's bounds.
      const matches = applicabilitySets.map(({ cpes, range }) =>
        matchesWatchlistItem(
          asset.cpes,
          asset.vendor,
          asset.product,
          cpes,
          cve.title,
          cve.description,
          range,
          asset.purls,
          cve.purls,
          asset.targetHw,
          undefined,
          false,
          effectiveVendorAliases,
          effectiveProductAliases,
          asset.version,
          cve.cisaKev?.isKev === true &&
            !cve.cpeMatches?.length &&
            !cve.cpeMatchDetails?.length &&
            !cve.purls?.length,
        ),
      );
      if (asset.purls?.length && cve.purls?.length)
        matches.push(
          matchesWatchlistItem(
            [],
            '',
            '',
            [],
            '',
            '',
            cve.versionRange,
            asset.purls,
            cve.purls,
            asset.targetHw,
          ),
        );
      // Audit C-1: applicability is a conjunction, not a competition.
      //
      // CPE criteria and package identities describe the same advisory outcome:
      // a CVE affects the asset when *any* of its own criteria applies AND no
      // independent identifier proves it does not. Selecting only the
      // highest-confidence result let a CPE match outrank a PURL that proved a
      // different package version, so an unaffected dependency was dispatched at
      // 90% confidence whenever the advisory also named the product by CPE.
      //
      // Two distinct verdicts are treated as authoritative exclusions:
      //  - the package identity is exact (`matchPurl` requires identity and
      //    version to agree), so a PURL mismatch is a proof, not a spelling
      //    difference;
      //  - `matchesWatchlistItem` returns it early only when nothing else in its
      //    own applicability set matched.
      // A complete product-wide registration (every component but vendor/product
      // wildcarded) is a deliberate, broad "monitor everything" choice by the
      // operator, the same choice that already releases the per-match version
      // hold. The AND/negate flag protects against flattening a CVE's config
      // tree into an OR when a concrete asset might not satisfy every branch;
      // a product-wide registration matches every branch by construction, so
      // the flag has nothing left to protect against for this asset.
      // Structured, not textual: this used to compare `match.evidence` against a
      // sentence, so any rewording of the message silently disabled the guard and
      // let an unaffected dependency be dispatched. Both verdicts are proofs.
      const packageRejected = matches.some((match) => !match.matched && match.packageVerdict !== undefined);
      const result = matches.filter((match) => match.matched).sort((a, b) => b.confidence - a.confidence)[0];
      if (!result?.matched) continue;
      const confirmedProductWideMatch = Boolean(result.productWideAllVersions) && !result.applicabilityRequiresReview;
      const confirmedKevProductOnlyMatch =
        confirmedProductWideMatch && result.method === 'VENDOR_PRODUCT_FALLBACK' && cve.cisaKev?.isKev === true;
      const authoritativeSourceDispatch =
        isAuthoritativeSource &&
        (result.method === 'VENDOR_PRODUCT_FALLBACK' || result.method === 'VENDOR_PRODUCT_ALIAS');
      // packageRejected is the only hard exclusion: it proves the package
      // identifiers disagree with the CPE match, i.e. a false positive.
      const confirmed = !packageRejected;
      // Confidence is always disclosed in the rendered advisory; no threshold
      // gates dispatch. Low-confidence findings dispatch with a note.
      const confidenceNote =
        result.confidence > 0
          ? ` Match confidence ${Math.round(result.confidence)}%.`
          : ` Unverifiable match: version applicability could not be confirmed; treat as review-pending.`;
      const evidence = confirmed
        ? authoritativeSourceDispatch
          ? `This CVE record has been marked for enrichment efforts.${sourceLabel ? ' ' + sourceLabel : ''} ${asset.vendor}/${asset.product}${confidenceNote}`
          : advisoryLacksApplicabilityData
            ? `Product correlation; the advisory has no CPE data yet, so the ${result.confidence}% match was dispatched under the workspace policy${confidenceNote}`
            : `Structured package/version correlation${confidenceNote}`
        : `Product correlation; package identifiers disagree with CPE match; excluded as false positive`;
      const rawFinding: Finding = {
        id: randomUUID(),
        cveId: canonical,
        cve,
        matchedAssetId: asset.id,
        matchedAssetName: `${asset.assetTag} (${asset.vendor} ${asset.product})`,
        matchedAssetVendor: asset.vendor,
        matchedAssetProduct: asset.product,
        matchedAssetPurls: asset.purls,
        matchedCpe: result.matchedCpe || '',
        matchingMethod: result.method,
        matchingEvidence: evidence,
        wildcardScopeMatch: result.wildcardScopeMatch,
        confidence: result.confidence,
        exposure: asset.exposure,
        exploitRisk: determineExploitRisk(cve),
        dispatchDeferred: false,
        // All valid findings dispatch. No review holds, no REVIEW_REQUIRED.
        // Confidence limitations are disclosed in the rendered advisory.
        notificationStatus: confirmed ? 'QUEUED_FOR_DISPATCH' : 'REVIEW_REQUIRED',
        status: 'MONITORED',
        autoDispatchedAt: null,
        advisoryId: null,
        executionId: executionId,
        reviewNotifiedAt: null,
        timeline: [
          {
            timestamp: started.toISOString(),
            action: 'Matched inventory',
            system: 'Server correlation engine',
            details: evidence,
          },
        ],
      };
      // Strict case classification: Case 3 (vendor advisory) > Case 4
      // (third-party feed) > Case 1 (exact match) > Case 2 (wildcard) >
      // No Match. Never mutates the input finding.
      newFindings.push(classifyFinding(rawFinding, cve, asset, feedsById));
      if (authoritativeSourceDispatch && confirmed) authoritativeSourceDispatchCount++;
      known.add(key);
      emittedKeys.push(key);
    }
  }
  // Duplicate integrity. The loop above deduplicates per (CVE, asset), but a
  // duplicate would still be catastrophic - an operator receives the same finding
  // twice - and the persisted store is keyed only by a generated id, so it cannot
  // catch one. Detect it here at the source rather than trusting the call graph:
  // any second emission of the same pair increments this counter, and the
  // execution log records it so a regression is visible on the operations screen
  // instead of only in a downstream email.
  const duplicateFindingPairs = emittedKeys.length - new Set(emittedKeys).size;
  if (duplicateFindingPairs > 0)
    addAudit(
      'MATCH_INTEGRITY_DUPLICATE_PAIRS',
      `${duplicateFindingPairs} duplicate (CVE, asset) finding pair(s) emitted in execution ${executionId}`,
      'WARNING',
    );
  const matchingDurationMs = Math.round(performance.now() - matchingStarted);
  const execution: PipelineExecution = {
    id: executionId,
    name: formatExecutionName(executionId),
    startTime: started.toISOString(),
    endTime: started.toISOString(),
    status: 'COMPLETED',
    scopeHours: settings.scopeHours,
    phases: [
      {
        name: 'Normalize & deduplicate',
        status: 'SUCCESS',
        durationMs: normalizationDurationMs,
        details: `${latest.size} canonical CVEs; ${duplicates} duplicates removed`,
      },
      {
        name: 'Product matching',
        status: 'SUCCESS',
        durationMs: matchingDurationMs,
        details: `${processed} CVEs evaluated against ${activeAssets.length} active products; ${newFindings.length} matches${
          textOnlyTruncations.length
            ? `; ${textOnlyTruncations.length} text-only CVEs capped at ${MAX_TEXT_ONLY_CANDIDATE_ASSETS} candidate assets`
            : ''
        }${duplicateFindingPairs ? `; ${duplicateFindingPairs} duplicate pairs detected` : ''}`,
      },
    ],
    stats: {
      rawIngested: corpus.length,
      normalized: processed,
      deduplicated: processed,
      inRunDuplicatesDropped: duplicates,
      // The engine knows this run's matches but not which of them were already
      // known from earlier runs, so this is the current-match count. The
      // pipeline worker replaces it with the new-detection count before
      // persisting the execution; see countNewFindings.
      matchedWatchlist: newFindings.length,
      autoDispatchedNotifications: 0,
      advisoriesDispatched: 0,
      webhooksFired: 0,
      vexSuppressedCount: 0,
      authoritativeSourceDispatchCount,
    },
    logs: [],
  };
  return {
    execution,
    newFindings,
    newAdvisories: [],
    updatedAlertedCves: structuredClone(alerted),
    newEmailLogs: [],
    newAuditLogs,
  };
}

/**
 * Findings dispatched via an authoritative source without CPE data are pending
 * enrichment re-evaluation. Returns findings whose `matchedCpe` is empty or
 * whitespace, i.e. the correlation engine could not bind them to a CPE and
 * they need a re-scan once CPE data becomes available.
 */
export function enrichmentBacklogCandidates(findings: Finding[]): Finding[] {
  return findings.filter(
    (f) => f.notificationStatus === 'QUEUED_FOR_DISPATCH' &&
      (!f.matchedCpe || !f.matchedCpe.trim()),
  );
}
