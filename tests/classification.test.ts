import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyMatch, classifyFinding } from '../src/engine/classification.ts';
import type {
  CaseClassification,
  Finding,
  MatchPrecision,
  NormalizedCVE,
  RootSubjectVerdict,
  SourceCategory,
  ThreatFeed,
  WatchListItem,
} from '../src/types/index.ts';

function cve(overrides: Partial<NormalizedCVE> = {}): NormalizedCVE {
  return {
    cveId: 'CVE-2026-0001',
    title: 'Sample advisory',
    description: 'A sample vulnerability description.',
    publishedDate: '2026-01-01T00:00:00Z',
    modifiedDate: '2026-01-01T00:00:00Z',
    cvss: { version: '3.1', score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', severity: 'HIGH' },
    cwe: [],
    cpeMatches: [],
    sourceFeeds: [],
    epss: { score: 0, percentile: 0 },
    cisaKev: { isKev: false },
    exploitStatus: 'None',
    remediation: {
      patchUrl: '',
      vendorAdvisoryRef: '',
      immediateActions: [],
      workarounds: [],
      rollbackPlan: '',
      stepByStep: [],
    },
    ...overrides,
  } as NormalizedCVE;
}

function asset(overrides: Partial<WatchListItem> = {}): WatchListItem {
  return {
    id: 'asset-1',
    vendor: 'acme',
    product: 'gateway',
    version: '1.2.3',
    cpes: ['cpe:2.3:a:acme:gateway:1.2.3:*:*:*:*:*:*:*'],
    purls: [],
    assetTag: 'Acme Gateway',
    ownerGroup: 'SOC',
    active: true,
    createdAt: '2026-01-01T00:00:00Z',
    ...overrides,
  } as WatchListItem;
}

function feed(id: string, type: ThreatFeed['type'], authoritative = false): ThreatFeed {
  return {
    id,
    name: id,
    type,
    url: `https://example.com/${id}`,
    authType: 'NONE',
    rateLimitPerMin: 60,
    enabled: true,
    healthStatus: 'HEALTHY',
    lastSync: null,
    latencyMs: 0,
    vendorSeed: false,
    itemCountLastRun: 0,
    ssrfValidated: false,
    authoritative,
  } as ThreatFeed;
}

const feeds = new Map<string, ThreatFeed>([
  ['rss', feed('rss', 'RSS_ATOM', true)],
  ['vc', feed('vc', 'VULNCHECK_NVD')],
  ['mitre', feed('mitre', 'JSON_SEARCH_API')],
  ['blog', feed('blog', 'GOOGLE_CSE')],
]);

const baseFinding = (overrides: Record<string, unknown> = {}): Finding =>
  ({
    id: 'finding-1',
    cveId: 'CVE-2026-0001',
    cve: cve(),
    matchedAssetId: 'asset-1',
    matchedAssetName: 'Acme Gateway (acme gateway)',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'gateway',
    matchedCpe: 'cpe:2.3:a:acme:gateway:1.2.3:*:*:*:*:*:*:*',
    matchingMethod: 'VENDOR_PRODUCT_FALLBACK',
    matchingEvidence: 'text match',
    confidence: 70,
    exploitRisk: 'STANDARD',
    notificationStatus: 'REVIEW_REQUIRED' as const,
    status: 'MONITORED' as const,
    autoDispatchedAt: null,
    advisoryId: null,
    reviewNotifiedAt: null,
    timeline: [],
    ...overrides,
  }) as Finding;

test('Case 3: vendor CNA (assignerShortName) classifies as vendor advisory', () => {
  const c = cve({ assignerShortName: 'cisco', cpeMatches: ['cpe:2.3:a:cisco:ios:*:*:*:*:*:*:*:*'] });
  const a = asset({ vendor: 'cisco', product: 'ios', cpes: ['cpe:2.3:a:cisco:ios:*:*:*:*:*:*:*'] });
  const { caseClassification, sourceCategory } = classifyMatch(c, a, feeds, 'STRICT_CPE', 100);
  assert.equal(caseClassification, 'CASE_3_VENDOR_ADVISORY');
  assert.equal(sourceCategory, 'VENDOR_ADVISORY');
});

test('Case 3: vendorAdvisoryRef classifies as vendor advisory', () => {
  const c = cve({
    assignerShortName: 'mitre',
    remediation: { ...cve().remediation, vendorAdvisoryRef: 'https://cisco.com/advisory' },
    cpeMatches: ['cpe:2.3:a:cisco:ios:*:*:*:*:*:*:*'],
  });
  const a = asset({ vendor: 'cisco', product: 'ios', cpes: ['cpe:2.3:a:cisco:ios:*:*:*:*:*:*:*'] });
  const { caseClassification, sourceCategory } = classifyMatch(c, a, feeds, 'STRICT_CPE', 100);
  assert.equal(caseClassification, 'CASE_3_VENDOR_ADVISORY');
  assert.equal(sourceCategory, 'VENDOR_ADVISORY');
});

test('Case 4: an operator-authoritative RSS_ATOM feed is trusted coverage, not a vendor advisory', () => {
  // Authority on a news feed means "we trust this publisher", not "this is the
  // vendor's PSIRT". Classifying it Case 3 reported third-party blog posts as
  // official vendor advisories, which is a source-attribution defect: the security
  // team must be able to tell a Cisco PSIRT bulletin from a blog about Cisco.
  const c = cve({ assignerShortName: 'mitre', sourceFeeds: ['rss'] });
  const a = asset();
  const { caseClassification, sourceCategory } = classifyMatch(c, a, feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(caseClassification, 'CASE_4_VENDOR_PRODUCT_GENERAL_FEED');
  assert.equal(sourceCategory, 'THIRD_PARTY_FEED');
});

test('Case 3: a registry feed (VULNCHECK_NVD) is an official advisory source', () => {
  const c = cve({ assignerShortName: 'mitre', sourceFeeds: ['vc'] });
  const { caseClassification, sourceCategory } = classifyMatch(c, asset(), feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(caseClassification, 'CASE_3_VENDOR_ADVISORY');
  assert.equal(sourceCategory, 'VENDOR_ADVISORY');
});

test('Case 4: non-vendor CNA (mitre) via third-party feed is general feed', () => {
  const c = cve({ assignerShortName: 'mitre', sourceFeeds: ['blog'] });
  const a = asset();
  const { caseClassification, sourceCategory } = classifyMatch(c, a, feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(caseClassification, 'CASE_4_VENDOR_PRODUCT_GENERAL_FEED');
  assert.equal(sourceCategory, 'THIRD_PARTY_FEED');
});

test('Case 4: third-party feed with wildcard product registration', () => {
  const c = cve({ assignerShortName: 'mitre', sourceFeeds: ['blog'], cpeMatches: [] });
  const a = asset({
    product: '*',
    cpes: ['cpe:2.3:a:acme:*:*:*:*:*:*:*:*:*:*'],
  });
  const { caseClassification, sourceCategory, matchPrecision } = classifyMatch(
    c,
    a,
    feeds,
    'VENDOR_PRODUCT_FALLBACK',
    70,
  );
  assert.equal(caseClassification, 'CASE_4_VENDOR_PRODUCT_GENERAL_FEED');
  assert.equal(sourceCategory, 'THIRD_PARTY_FEED');
  assert.equal(matchPrecision, 'WILDCARD');
});

test('Case 1: exact vendor+product match with stripped metadata', () => {
  const c = cve({ assignerShortName: 'mitre', sourceFeeds: [], cpeMatches: [] });
  const a = asset();
  const { caseClassification, matchPrecision } = classifyMatch(c, a, feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(caseClassification, 'CASE_1_VENDOR_EXACT_PRODUCT');
  assert.equal(matchPrecision, 'EXACT');
});

test('Case 2: wildcard product registration', () => {
  const c = cve({ assignerShortName: 'mitre', sourceFeeds: [], cpeMatches: [] });
  const a = asset({ product: '*', cpes: ['cpe:2.3:a:acme:*:*:*:*:*:*:*:*:*:*'] });
  const { caseClassification, matchPrecision } = classifyMatch(c, a, feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(caseClassification, 'CASE_2_VENDOR_WILDCARD_PRODUCT');
  assert.equal(matchPrecision, 'WILDCARD');
});

test('a broad CPE entry does not downgrade a concrete product registration to WILDCARD', () => {
  // Operators register the real product and also watch every vendor advisory by
  // adding `cpe:2.3:a:acme:*`. The declared product is the registration, so the
  // matched product must stay EXACT (Case 1), not Case 2.
  const c = cve({ assignerShortName: 'mitre', sourceFeeds: [], cpeMatches: [] });
  const a = asset({
    product: 'gateway',
    cpes: ['cpe:2.3:a:acme:gateway:1.2.3:*:*:*:*:*:*:*', 'cpe:2.3:a:acme:*:*:*:*:*:*:*:*:*'],
  });
  const { caseClassification, matchPrecision } = classifyMatch(c, a, feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(matchPrecision, 'EXACT');
  assert.equal(caseClassification, 'CASE_1_VENDOR_EXACT_PRODUCT');
});

test('a CPE-only wildcard registration is still WILDCARD', () => {
  const c = cve({ assignerShortName: 'mitre', sourceFeeds: [], cpeMatches: [] });
  const a = asset({ product: '', cpes: ['cpe:2.3:a:acme:*:*:*:*:*:*:*:*:*'] });
  const { matchPrecision } = classifyMatch(c, a, feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(matchPrecision, 'WILDCARD');
});

test('NO_MATCH: inventory version confirmed patched outside vulnerable range', () => {
  // Advisory affects < 1.2.0; asset is 2.0.0 → confirmed patched.
  const c = cve({
    assignerShortName: 'mitre',
    sourceFeeds: [],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*', range: { versionEndExcluding: '1.2.0' } }],
    cpeMatches: ['cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*'],
  });
  const a = asset({ version: '2.0.0', cpes: ['cpe:2.3:a:acme:gateway:2.0.0:*:*:*:*:*:*:*'] });
  const { caseClassification } = classifyMatch(c, a, feeds, 'STRICT_CPE_INTERVAL', 100);
  assert.equal(caseClassification, 'NO_MATCH');
});

test('NO_MATCH: no vendor or product present', () => {
  const c = cve({ assignerShortName: 'mitre', sourceFeeds: [], cpeMatches: [] });
  const a = asset({ vendor: '', product: '' });
  const { caseClassification } = classifyMatch(c, a, feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(caseClassification, 'NO_MATCH');
});

test('root subject: prerequisite mention is not the vulnerable subject', () => {
  // No root indicator; only a non-subject "built on" mention → prerequisite.
  const c = cve({
    assignerShortName: 'mitre',
    sourceFeeds: [],
    title: 'Client library advisory',
    description: 'Client applications built on acme gateway require a backend.',
    cpeMatches: [],
  });
  const a = asset();
  const { rootSubject } = classifyMatch(c, a, feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(rootSubject, 'PREREQUISITE_OR_INTEGRATION');
});

test('root subject: ambiguous text (root + non-subject indicators) is UNKNOWN', () => {
  // "affects" (root) and "running on" (non-subject) both present → ambiguous.
  const c = cve({
    assignerShortName: 'mitre',
    sourceFeeds: [],
    title: 'OpenSSL vulnerability',
    description: 'An OpenSSL flaw affects client apps running on acme gateway.',
    cpeMatches: [],
  });
  const a = asset();
  const { rootSubject } = classifyMatch(c, a, feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(rootSubject, 'UNKNOWN');
});

test('root subject: direct vulnerability mention is root subject', () => {
  const c = cve({
    assignerShortName: 'mitre',
    sourceFeeds: [],
    title: 'acme gateway vulnerability',
    description: 'A vulnerability in acme gateway allows remote code execution.',
    cpeMatches: [],
  });
  const a = asset();
  const { rootSubject } = classifyMatch(c, a, feeds, 'VENDOR_PRODUCT_FALLBACK', 70);
  assert.equal(rootSubject, 'ROOT_SUBJECT');
});

test('classifyFinding attaches classification fields without mutating input', () => {
  const c = cve({ assignerShortName: 'cisco', cpeMatches: ['cpe:2.3:a:cisco:ios:*:*:*:*:*:*:*'] });
  const a = asset({ vendor: 'cisco', product: 'ios', cpes: ['cpe:2.3:a:cisco:ios:*:*:*:*:*:*:*'] });
  const finding = baseFinding({ matchingMethod: 'STRICT_CPE', confidence: 100 });
  const original = { ...finding };
  const result = classifyFinding(finding as never, c, a, feeds);
  assert.equal(result.caseClassification, 'CASE_3_VENDOR_ADVISORY');
  assert.equal(result.sourceCategory, 'VENDOR_ADVISORY');
  assert.equal(result.matchPrecision, 'EXACT');
  // input not mutated
  assert.equal((finding as unknown as Record<string, unknown>).caseClassification, undefined);
  assert.deepEqual(finding, original);
});

// --- type exports are usable ---
test('CaseClassification, MatchPrecision, SourceCategory, RootSubjectVerdict types are exported', () => {
  const cases: CaseClassification[] = [
    'CASE_1_VENDOR_EXACT_PRODUCT',
    'CASE_2_VENDOR_WILDCARD_PRODUCT',
    'CASE_3_VENDOR_ADVISORY',
    'CASE_4_VENDOR_PRODUCT_GENERAL_FEED',
    'NO_MATCH',
  ];
  assert.ok(cases.includes('CASE_3_VENDOR_ADVISORY'));
  const precisions: MatchPrecision[] = ['EXACT', 'WILDCARD'];
  assert.ok(precisions.includes('WILDCARD'));
  const sources: SourceCategory[] = ['VENDOR_ADVISORY', 'THIRD_PARTY_FEED', 'STRIPPED_AMBIGUOUS'];
  assert.ok(sources.includes('THIRD_PARTY_FEED'));
  const subjects: RootSubjectVerdict[] = ['ROOT_SUBJECT', 'PREREQUISITE_OR_INTEGRATION', 'UNKNOWN'];
  assert.ok(subjects.includes('UNKNOWN'));
});
