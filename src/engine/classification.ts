/**
 * Strict case classification for vulnerability matching.
 *
 * Implements the required priority order:
 *   Case 3 (vendor advisory) > Case 4 (third-party feed match) >
 *   Case 1 (exact vendor+product match) > Case 2 (wildcard match) > No Match
 *
 * Source category determination:
 *   VENDOR_ADVISORY   — official vendor PSIRT/advisory, or CNA is the vendor,
 *                        or record carries a Vendor Advisory reference tag.
 *   THIRD_PARTY_FEED  — news, social, threat blogs, or VulnCheck/NVD assigned
 *                        by a third-party CNA without an official vendor bulletin.
 *   STRIPPED_AMBIGUOUS — source metadata is absent or cannot be attributed.
 *
 * Match precision:
 *   EXACT    — inventory vendor + product match exactly (no wildcard product).
 *   WILDCARD — inventory product is a `*` wildcard registration.
 *
 * Root-subject gating:
 *   For unstructured text, a product must be the root subject of the
 *   vulnerability/patch/threat. Products mentioned only as prerequisites,
 *   unaffected integrations, or attacker infrastructure are excluded.
 */

import type {
  CaseClassification,
  Finding,
  MatchPrecision,
  NormalizedCVE,
  RootSubjectVerdict,
  SourceCategory,
  ThreatFeed,
  WatchListItem,
} from '../types';
import { parseCPE23 } from '../utils/cpeMatcher.ts';
import { evaluateVersionInRange } from '../utils/versionComparator.ts';

/** Vendor advisory reference tags that mark a record as an official vendor bulletin. */
const VENDOR_ADVISORY_TAGS = new Set(['Vendor Advisory', 'Vendor Advisory/PSIRT', 'PSIRT', 'Vendor Security Advisory']);

/** CNA short names that are themselves vendors (authoritative source). */
const VENDOR_CNAS = new Set([
  'cisco',
  'microsoft',
  'paloaltonetworks',
  'palo alto networks',
  'fortinet',
  'vmware',
  'broadcom',
  'apache',
  'f5',
  'kubernetes',
  'nginx',
  'docker',
  'adobe',
  'canonical',
  'hashicorp',
  'sentinelone',
  'n-able',
  'nable',
]);

/**
 * Feed types that are a machine-readable CVE/advisory registry rather than news
 * coverage. NVD mirrors and CVE/OSV registries carry CNA attribution in the
 * record itself; they are never "third-party news" and never a vendor bulletin
 * on their own (Case 3 tests the assigner and references instead).
 */
const REGISTRY_FEED_TYPES = new Set(['VULNCHECK_NVD', 'NVD_API', 'OSV_API', 'GITHUB_ADVISORIES']);

/**
 * General news / search feed types. These are third-party coverage by nature,
 * so a record sourced only from one of them is Case 4 whether or not an
 * operator has marked the feed authoritative.
 */
const GENERAL_FEED_TYPES = new Set(['RSS_ATOM', 'JSON_SEARCH_API', 'OTX_API', 'GOOGLE_CSE']);

/** Keywords that indicate a product is the vulnerable root subject (not a prerequisite). */
const ROOT_SUBJECT_INDICATORS = [
  'vulnerability in',
  'vulnerable in',
  'affects',
  'affected',
  'patched in',
  'fixed in',
  'resolved in',
  'remediated in',
  'security update for',
  'advisory for',
  'cve-',
];

/** Multi-word phrases that place a product in a platform/integration/infrastructure
 * context rather than as the vulnerable subject. Matched as substrings. */
const NON_SUBJECT_PHRASES = [
  'running on',
  'runs on',
  'built on',
  'based on',
  'powered by',
  'command and control',
];
/** Single-word terms that indicate a non-subject context. Matched with word
 * boundaries so 'in'/'on'/'for' cannot false-positive on ordinary prose. */
const NON_SUBJECT_WORDS = ['attacker', 'malware', 'c2', 'infrastructure'];

function nonSubjectContext(text: string): boolean {
  if (NON_SUBJECT_PHRASES.some((phrase) => text.includes(phrase))) return true;
  return NON_SUBJECT_WORDS.some((word) => new RegExp(`\\b${word}\\b`).test(text));
}

/**
 * Whether a source feed is an official vendor advisory.
 *
 * A vendor bulletin must come from a feed that can actually carry one:
 *
 *  - a general news/RSS/search feed is third-party coverage even when an operator
 *    has marked it authoritative — a blog post about a Cisco flaw is not a Cisco
 *    PSIRT advisory, so it must classify as Case 4.
 *  - a registry feed (NVD/VulnCheck CVE/OSV) is official vulnerability data and
 *    is Case 3 on its own; the entry's CNA attribution is tested first.
 *  - any other (vendor-integration) feed type is a bulletin only when the
 *    operator explicitly marked it authoritative.
 */
function isAuthoritativeVendorFeed(feed: ThreatFeed): boolean {
  if (GENERAL_FEED_TYPES.has(feed.type)) return false;
  if (REGISTRY_FEED_TYPES.has(feed.type)) return true;
  return feed.authoritative === true;
}

/**
 * Determines whether the source record is an official vendor advisory/PSIRT.
 *
 * Order matters. CNA attribution is the strongest signal (the vendor itself
 * assigned the CVE). A vendor-advisory reference is next. Feed authority is the
 * last resort and, per {@link isAuthoritativeVendorFeed}, can only come from a
 * registry feed explicitly vouched for by an operator.
 */
function isVendorAdvisory(cve: NormalizedCVE, feeds: Map<string, ThreatFeed>): boolean {
  // CNA is the vendor itself: NVD/VulnCheck records whose assignerShortName is a
  // known vendor CNA (e.g. cisco, microsoft, paloaltonetworks) are official
  // vendor advisories.
  const assigner = (cve.assignerShortName ?? '').toLowerCase();
  if (assigner && VENDOR_CNAS.has(assigner)) return true;
  // Vendor Advisory reference tag in remediation.
  const ref = cve.remediation?.vendorAdvisoryRef || '';
  if (ref) return true;
  // Feed-level authority: a registry feed an operator marked authoritative.
  for (const feedId of cve.sourceFeeds ?? []) {
    const feed = feeds.get(feedId);
    if (feed && isAuthoritativeVendorFeed(feed)) return true;
  }
  return false;
}

/**
 * Determines whether the matched product is the root subject of the
 * vulnerability in unstructured text. Returns UNKNOWN when the text is
 * structured (CPE/PURL) — root-subject analysis only applies to prose.
 */
function rootSubjectVerdict(
  cve: NormalizedCVE,
  vendor: string,
  product: string,
): RootSubjectVerdict {
  const text = `${cve.title} ${cve.description}`.toLowerCase();
  const v = vendor.toLowerCase();
  const p = product.toLowerCase();

  // If the vendor/product only appear in CPE/PURL structured fields, the text
  // itself does not mention them as a subject — structured evidence stands alone.
  const vMentioned = text.includes(v);
  const pMentioned = text.includes(p);
  if (!vMentioned && !pMentioned) return 'UNKNOWN';

  // Look for root-subject indicators near the product/vendor mention.
  const hasRootIndicator = ROOT_SUBJECT_INDICATORS.some((ind) => text.includes(ind));
  const hasNonSubjectCtx = nonSubjectContext(text);

  // Only non-subject indicators (running on, built on …) and no
  // root indicator: the product is mentioned as platform/integration/infrastructure.
  if (hasNonSubjectCtx && !hasRootIndicator) return 'PREREQUISITE_OR_INTEGRATION';

  // Only root indicators: the product is the vulnerable subject.
  if (hasRootIndicator && !hasNonSubjectCtx) return 'ROOT_SUBJECT';

  // Both or neither: ambiguous. Do not guess — return UNKNOWN so the match is
  // retained but flagged for operator review rather than suppressed or auto-trusted.
  return 'UNKNOWN';
}

/**
 * Determines whether the inventory asset's version is confirmed patched
 * (outside the vulnerable range). Returns true when every comparable inventory
 * version is provably OUT_OF_RANGE against the advisory's version bounds.
 */
function versionIsConfirmedPatched(
  asset: WatchListItem,
  cve: NormalizedCVE,
): boolean {
  const ranges = cve.cpeMatchDetails?.length
    ? cve.cpeMatchDetails.map((d) => d.range).filter((r): r is NonNullable<typeof r> => Boolean(r))
    : cve.versionRange ? [cve.versionRange] : [];

  if (!ranges.length) return false; // No version bounds → cannot confirm patch.

  // Collect all comparable inventory versions.
  const versions = new Set<string>();
  if (asset.version && asset.version !== '*' && asset.version !== '-') versions.add(asset.version);
  for (const cpe of asset.cpes) {
    const parsed = parseCPE23(cpe);
    if (parsed.isValid && parsed.version && parsed.version !== '*' && parsed.version !== '-')
      versions.add(parsed.version);
  }
  if (!versions.size) return false; // No version to compare → cannot confirm patched.

  // Every comparable version must be provably outside every range.
  for (const version of versions) {
    let anyInRange = false;
    for (const range of ranges) {
      const verdict = evaluateVersionInRange(version, range);
      if (verdict.verdict === 'IN_RANGE') {
        anyInRange = true;
        break;
      }
    }
    if (anyInRange) return false; // At least one version is inside a vulnerable range.
  }
  return true; // All comparable versions are outside all ranges → confirmed patched.
}

/**
 * Determines match precision: EXACT when the inventory product is a concrete
 * name (not a wildcard), WILDCARD when the product is registered as `*`.
 */
function matchPrecision(asset: WatchListItem): MatchPrecision {
  const product = (asset.product || '').trim().toLowerCase();
  if (product === '*' || product === '-') return 'WILDCARD';
  // Also check CPE product wildcards.
  for (const cpe of asset.cpes) {
    const parsed = parseCPE23(cpe);
    if (parsed.isValid && parsed.product === '*') return 'WILDCARD';
  }
  return 'EXACT';
}

/**
 * Classifies a single CVE×asset match into a case classification, source
 * category, match precision, and root-subject verdict.
 *
 * Priority order (first matching case wins):
 *   1. NO_MATCH — no vulnerable vendor/product, or version confirmed patched.
 *   2. CASE_3_VENDOR_ADVISORY — official vendor advisory/PSIRT, vendor CNA,
 *      or Vendor Advisory reference tag.
 *   3. CASE_4_VENDOR_PRODUCT_GENERAL_FEED — third-party feed/news without
 *      vendor bulletin.
 *   4. CASE_1_VENDOR_EXACT_PRODUCT — stripped/ambiguous metadata, exact match.
 *   5. CASE_2_VENDOR_WILDCARD_PRODUCT — stripped/ambiguous metadata, wildcard.
 */
export function classifyMatch(
  cve: NormalizedCVE,
  asset: WatchListItem,
  feeds: Map<string, ThreatFeed>,
  matchingMethod: string,
  matchConfidence: number,
): {
  caseClassification: CaseClassification;
  sourceCategory: SourceCategory;
  matchPrecision: MatchPrecision;
  rootSubject: RootSubjectVerdict;
} {
  const precision = matchPrecision(asset);
  const vendor = (asset.vendor || '').toLowerCase();
  const product = (asset.product || '').toLowerCase();

  // Root-subject analysis only applies when the match came from text/alias
  // fallback, not from structured CPE/PURL evidence.
  const isTextFallback =
    matchingMethod === 'VENDOR_PRODUCT_FALLBACK' || matchingMethod === 'VENDOR_PRODUCT_ALIAS';
  const rootSubject = isTextFallback ? rootSubjectVerdict(cve, vendor, product) : 'UNKNOWN';

  // No Match: version confirmed patched.
  if (versionIsConfirmedPatched(asset, cve)) {
    return {
      caseClassification: 'NO_MATCH',
      sourceCategory: 'STRIPPED_AMBIGUOUS',
      matchPrecision: precision,
      rootSubject,
    };
  }

  // No Match: no vendor or product present (empty identity). Wildcards are a
  // legitimate Case 2 registration, not a no-match, so they are excluded here.
  if (!vendor || !product) {
    return {
      caseClassification: 'NO_MATCH',
      sourceCategory: 'STRIPPED_AMBIGUOUS',
      matchPrecision: precision,
      rootSubject,
    };
  }

  const isVendorAdv = isVendorAdvisory(cve, feeds);

  // Case 3: Vendor Advisory — highest priority.
  if (isVendorAdv) {
    return {
      caseClassification: 'CASE_3_VENDOR_ADVISORY',
      sourceCategory: 'VENDOR_ADVISORY',
      matchPrecision: precision,
      rootSubject,
    };
  }

  // Case 4: Third-party feed / general news — source is not a vendor advisory.
  // A registry feed is authoritative infrastructure rather than third-party
  // coverage, so it does not make a record Case 4. A general news/RSS feed is
  // third-party by nature: it is Case 4 whether or not an operator trusted it.
  const sourceFeeds = cve.sourceFeeds ?? [];
  const hasThirdPartyFeed = sourceFeeds.some((fid) => {
    const feed = feeds.get(fid);
    if (!feed) return false;
    if (GENERAL_FEED_TYPES.has(feed.type)) return true;
    return !REGISTRY_FEED_TYPES.has(feed.type) && feed.authoritative !== true;
  });
  // Case 4: third-party feed/news present without a vendor bulletin.
  if (hasThirdPartyFeed) {
    return {
      caseClassification: 'CASE_4_VENDOR_PRODUCT_GENERAL_FEED',
      sourceCategory: 'THIRD_PARTY_FEED',
      matchPrecision: precision,
      rootSubject,
    };
  }
  // Stripped/ambiguous metadata (no feeds, or all feeds already resolved to
  // Case 3): distinguish exact vs wildcard product registration.
  if (precision === 'EXACT') {
    return {
      caseClassification: 'CASE_1_VENDOR_EXACT_PRODUCT',
      sourceCategory: 'STRIPPED_AMBIGUOUS',
      matchPrecision: 'EXACT',
      rootSubject,
    };
  }
  return {
    caseClassification: 'CASE_2_VENDOR_WILDCARD_PRODUCT',
    sourceCategory: 'STRIPPED_AMBIGUOUS',
    matchPrecision: 'WILDCARD',
    rootSubject,
  };
}

/**
 * Attaches classification fields to a finding produced by the pipeline engine.
 * Returns a new Finding object with caseClassification, sourceCategory, and
 * matchPrecision set. Does not mutate the input.
 */
export function classifyFinding(
  finding: Finding,
  cve: NormalizedCVE,
  asset: WatchListItem,
  feeds: Map<string, ThreatFeed>,
): Finding {
  const classification = classifyMatch(
    cve,
    asset,
    feeds,
    finding.matchingMethod,
    finding.confidence ?? 0,
  );

  return {
    ...finding,
    caseClassification: classification.caseClassification,
    sourceCategory: classification.sourceCategory,
    matchPrecision: classification.matchPrecision,
  };
}
