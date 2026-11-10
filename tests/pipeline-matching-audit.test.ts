/**
 * Regression tests for the pipeline matching production-readiness audit.
 *
 * Each test corresponds to one finding (C-1, C-2, H-1, H-2, M-1, M-4, M-9, L-1)
 * and fails on the pre-fix implementation.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_ZERO_DAYS_PER_RUN,
  enrichmentBacklogCandidates,
  rankAndRateLimitZeroDays,
  runVulnerabilityPipeline,
} from '../src/engine/pipelineEngine.ts';
import { mergeArticles, matchIntelligence, computeCredibilityScore } from '../src/utils/intelligenceMatcher.ts';
import { purlIdentity } from '../src/utils/cpeMatcher.ts';
import { isPermanentFeedFailure } from '../server/feedRecovery.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type {
  Finding,
  FeedType,
  IntelligenceArticle,
  IntelligenceMatch,
  NormalizedCVE,
  ThreatFeed,
  WatchListItem,
} from '../src/types/index.ts';

const NOW = new Date('2026-10-26T12:00:00Z');
const cpe = (version: string) => `cpe:2.3:a:acme:gateway:${version}:*:*:*:*:*:*:*`;

function cveRecord(overrides: Partial<NormalizedCVE> = {}): NormalizedCVE {
  return {
    cveId: 'CVE-2026-9999',
    title: 'Acme gateway flaw',
    description: 'A flaw in Acme Gateway allows remote code execution.',
    publishedDate: NOW.toISOString(),
    modifiedDate: NOW.toISOString(),
    cvss: { version: '3.1', score: 9.8, severity: 'CRITICAL', vector: '' },
    cwe: [],
    cpeMatches: [cpe('1.5')],
    cpeMatchDetails: [],
    versionRange: undefined,
    purls: undefined,
    sourceFeeds: ['VULNCHECK_NVD'],
    exploitStatus: 'None',
    remediation: { patchUrl: '', vendorAdvisoryRef: '', immediateActions: [] },
    cisaKev: { isKev: false },
    epss: { score: 0, percentile: 0 },
    references: [],
    timeline: [],
    ...overrides,
  } as NormalizedCVE;
}

function assetRecord(overrides: Partial<WatchListItem> = {}): WatchListItem {
  return {
    id: 'a1',
    assetTag: 'svc',
    vendor: 'acme',
    product: 'gateway',
    cpes: [cpe('1.5')],
    purls: ['pkg:npm/lodash@4.17.20'],
    ownerGroup: 'g',
    exposure: 'INTERNAL',
    active: true,
    version: '1.5',
    createdAt: NOW.toISOString(),
    ...overrides,
  } as WatchListItem;
}

const settings = { ...DEFAULT_SETTINGS, scopeHours: 0, autoDispatchEnabled: true };

/* ------------------------------------------------------------------ C-1 */

test('C-1: a contradicting package identifier cannot be outranked by a CPE match', () => {
  // The advisory names the product by CPE (asset is 1.5, advisory is 1.5) and
  // separately a package version the asset does not run (4.17.20 vs 4.17.99).
  // Before the fix the 90% STRICT_CPE result won and auto-dispatched, reporting
  // an unaffected dependency as affected.
  const asset = assetRecord();
  const cve = cveRecord({ purls: ['pkg:npm/lodash@4.17.99'] });
  const [finding] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding, 'the product correlation is retained, not silently dropped');
  assert.notEqual(
    finding.notificationStatus,
    'QUEUED_FOR_DISPATCH',
    'contradicted evidence must never auto-dispatch',
  );
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
  assert.match(finding.matchingEvidence, /package identifiers prove a different version/);
});

test('C-1: a provable package mismatch on its own yields no finding', () => {
  const asset = assetRecord({ cpes: [] });
  const cve = cveRecord({ cpeMatches: [], purls: ['pkg:npm/lodash@4.17.99'] });
  assert.equal(runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings.length, 0);
});

test('C-1: agreeing identifiers still auto-dispatch', () => {
  const asset = assetRecord();
  const cve = cveRecord({ purls: ['pkg:npm/lodash@4.17.29'] });
  // Version differs only outside the asset's installed range: still a mismatch.
  const [held] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.equal(held.notificationStatus, 'REVIEW_REQUIRED');
  // A CPE-only advisory is unaffected by the change.
  const plain = cveRecord();
  const [finding] = runVulnerabilityPipeline([], [plain], [asset], [], [], settings).newFindings;
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
});

/* -------------------------------------------------------------- C-2 / M-* */

function match(i: number, over: Partial<IntelligenceMatch> = {}): IntelligenceMatch {
  return {
    id: `m${i}`,
    cveId: i % 2 ? null : `CVE-2026-${1000 + i}`,
    assetId: `asset${i % 3}`,
    assetName: `tag${i} (acme widget)`,
    articleIds: [`a${i}`],
    status: 'REVIEW_REQUIRED',
    evidence: '',
    zeroDay: i % 2 === 1,
    credibilityScore: 100 - i,
    ...over,
  };
}

test('learned zero-day caps are bounded and preserve every deferred match in a digest', () => {
  const matches = Array.from({ length: 10 }, (_, i) => match(i, { zeroDay: true }));
  const result = rankAndRateLimitZeroDays([], matches, 2);
  assert.equal(result.matches.length, 2);
  assert.equal(result.digests.reduce((sum, digest) => sum + digest.matchCount, 0), 8);
  assert.deepEqual(new Set([...result.matches.map((m) => m.id), ...result.digests.flatMap((d) => d.matchIds)]),
    new Set(matches.map((m) => m.id)));
  for (const cap of [0, -1, 1.5, NaN, Infinity, MAX_ZERO_DAYS_PER_RUN + 1])
    assert.throws(() => rankAndRateLimitZeroDays([], matches, cap), /Zero-day cap/);
});

test('C-2: digests report the group size, not the size of the whole match array', () => {
  const matches = Array.from({ length: 120 }, (_, i) => match(i));
  const { digests } = rankAndRateLimitZeroDays([], matches);
  const dropped = 60 - MAX_ZERO_DAYS_PER_RUN; // 60 zero-day matches, 50 kept
  assert.ok(digests.length > 0);
  assert.equal(
    digests.reduce((sum, d) => sum + d.matchCount, 0),
    dropped,
    'matchCount must sum to the suppressed group, never the whole array',
  );
  for (const digest of digests) assert.notEqual(digest.matchCount, matches.length);
});

test('C-2 / M-4: zero-day digests consolidate by vendor + product, not by asset', () => {
  const matches = Array.from({ length: 120 }, (_, i) => match(i));
  const { digests } = rankAndRateLimitZeroDays([], matches);
  assert.equal(digests.length, 1, 'one advisory per product, not one per asset');
  assert.equal(digests[0].vendor, 'acme');
  assert.equal(digests[0].product, 'widget');
});

test('C-2: a parenthesised asset tag does not corrupt the parsed identity', () => {
  const matches = Array.from({ length: 120 }, (_, i) =>
    match(i, { assetName: `prod (legacy) (acme widget)` }),
  );
  const { digests } = rankAndRateLimitZeroDays([], matches);
  assert.equal(digests[0].vendor, 'acme');
  assert.equal(digests[0].product, 'widget');
});

test('C-2: digest grouping prefers the structured vendor/product over the display label', () => {
  // The display label is `"tag (vendor product)"` and is inherently lossy: a
  // product containing whitespace or a parenthesis cannot be split back. The
  // matcher records the structured identity for exactly this reason, and the
  // digest must group on it — a wrong key merges unrelated products into one
  // digest.
  const matches = Array.from({ length: 60 }, (_, i) =>
    match(i, { zeroDay: true, assetName: `tag (acme widget)`, assetVendor: 'acme', assetProduct: 'web gateway' }),
  );
  const { digests } = rankAndRateLimitZeroDays([], matches);
  assert.equal(digests[0].vendor, 'acme');
  assert.equal(digests[0].product, 'web gateway', 'grouped on the structured product, not the parsed label');
  // The id is built from the same identity, so a space in the product name is
  // preserved in the namespace-safe form.
  assert.equal(digests[0].advisoryId, 'DIGEST_acme_web_gateway');
});

test('M-9: digest ids are not shaped like real advisory ids', () => {
  const matches = Array.from({ length: 120 }, (_, i) => match(i));
  const { digests } = rankAndRateLimitZeroDays([], matches);
  assert.ok(!digests[0].advisoryId.includes('ZDIGEST_'));
  assert.match(digests[0].advisoryId, /^DIGEST_/);
});

test('M-1: suppressed zero-day matches remove their counterpart findings', () => {
  const matches = Array.from({ length: 120 }, (_, i) => match(i, { findingId: `f${i}` }));
  // The findings array must be keyed by the same ids the matches reference;
  // deriving ids from the match id (m12 -> f12) silently targets findings that
  // are not in the array, so the assertion would hold even with the bug present.
  const supplied = matches.map((m) => ({ id: m.findingId })) as unknown as Finding[];
  const result = rankAndRateLimitZeroDays(supplied, matches);
  const droppedFindingIds = new Set(result.digests.flatMap((d) => d.findingIds));
  assert.ok(droppedFindingIds.size > 0, 'digests must carry actionable finding ids');
  assert.ok(
    [...droppedFindingIds].every((id) => supplied.some((finding) => finding.id === id)),
    'every suppressed finding id must exist in the supplied set',
  );
  assert.equal(result.findings.length, supplied.length - droppedFindingIds.size);
  for (const finding of result.findings) assert.ok(!droppedFindingIds.has(finding.id));
});

test('C-2: an unlinked non-zero-day match does not consume the zero-day budget', () => {
  // `!cveId && REVIEW_REQUIRED` used to count as zero-day evidence. That made
  // every CVE-less, review-rated intelligence match a zero-day, so ordinary
  // coverage notes were digested as zero-days and real zero-days lost their
  // slots to them. Only the article's own flag makes a match zero-day.
  const coverage = Array.from({ length: 80 }, (_, i) => match(i, { zeroDay: false, cveId: null }));
  const result = rankAndRateLimitZeroDays([], coverage);
  assert.equal(result.matches.length, coverage.length, 'nothing is capped');
  assert.equal(result.digests.length, 0, 'no zero-day digest is produced');
});

test('C-2: non-zero-day matches survive an exceeded cap untouched', () => {
  const matches = Array.from({ length: 120 }, (_, i) => match(i));
  const input = matches.filter((m) => !m.zeroDay);
  const result = rankAndRateLimitZeroDays([], matches);
  for (const kept of input) assert.ok(result.matches.some((m) => m.id === kept.id));
});

/* ------------------------------------------------------------------ H-1 */

test('H-1: credibility is monotone in corroborating sources', () => {
  const one = computeCredibilityScore(
    { id: 'x', cveId: null, assetId: 'a', assetName: '', articleIds: [], status: 'REVIEW_REQUIRED', evidence: '', zeroDay: true },
    ['RSS_ATOM'],
    false,
  );
  const three = computeCredibilityScore(
    { id: 'x', cveId: null, assetId: 'a', assetName: '', articleIds: [], status: 'REVIEW_REQUIRED', evidence: '', zeroDay: true },
    ['RSS_ATOM', 'VULNCHECK_NVD'],
    false,
  );
  assert.ok(three > one, `expected ${three} > ${one}`);
});

test('credibility scoring applies runtime-trained weights', () => {
  const match = { id: 'x', cveId: null, assetId: 'a', assetName: '', articleIds: [], status: 'REVIEW_REQUIRED' as const, evidence: '', zeroDay: true };
  const defaultScore = computeCredibilityScore(match, ['RSS_ATOM'], false);
  const feedHeavy = computeCredibilityScore(match, ['RSS_ATOM'], false, { feedWeight: 0.9, keywordWeight: 0.1 });
  assert.equal(feedHeavy, 21);
  assert.notEqual(feedHeavy, defaultScore);
});

test('H-1: zero-day ranking is deterministic for tied credibility', () => {
  const tied = Array.from({ length: 80 }, (_, i) =>
    match(i, { zeroDay: true, cveId: null, credibilityScore: 50 }),
  );
  const first = rankAndRateLimitZeroDays([], tied).digests.map((d) => d.matchIds).flat();
  const shuffled = [...tied].reverse();
  const second = rankAndRateLimitZeroDays([], shuffled).digests.map((d) => d.matchIds).flat();
  assert.deepEqual(first.sort(), second.sort(), 'suppression must not depend on input order');
});

test('H-1: a zero-day flagged article still produces a zero-day match', () => {
  // Vendor "acme" is mentioned; the product must be mentioned too for the prose
  // match. Publishing an article about a *different* product ("widget") matches
  // nothing, so the article must name the asset's actual product ("gateway").
  const article: IntelligenceArticle = {
    id: 'zd1',
    url: 'https://example.org/zd',
    title: 'Acme gateway zero-day exploited in the wild',
    summary: 'Acme gateway flaw is being actively exploited with no patch available.',
    publishedDate: NOW.toISOString(),
    modifiedDate: NOW.toISOString(),
    cveIds: [],
    sourceFeeds: ['RSS_ATOM'],
    zeroDay: true,
  };
  const asset = assetRecord({ cpes: [], purls: [] });
  const matches = matchIntelligence([article], [asset], [], [], {}, {}, 0, NOW);
  assert.equal(matches.length, 1, 'vendor + product prose must correlate');
  assert.equal(matches[0].zeroDay, true);
  assert.equal(matches[0].cveId, null);
  assert.match(matches[0].evidence, /Potential zero-day/);
});

test('H-1: merging a resolved article clears zero-day', () => {
  const base: IntelligenceArticle = {
    id: 'zd2',
    url: 'https://example.org/zd2',
    title: 'Acme widget zero-day exploited',
    summary: 'no patch',
    publishedDate: NOW.toISOString(),
    modifiedDate: NOW.toISOString(),
    cveIds: [],
    sourceFeeds: ['feed1'],
    zeroDay: true,
  };
  const [merged] = mergeArticles([
    base,
    { ...base, modifiedDate: '2026-10-27T00:00:00Z', cveIds: ['CVE-2026-12345'], zeroDay: false },
  ]);
  assert.equal(merged.zeroDay, false);
  assert.deepEqual(merged.cveIds, ['CVE-2026-12345']);
});

/* ------------------------------------------------------------------ H-2 */

test('H-2: purlIdentity is scope-aware and matches the matcher identity rule', () => {
  assert.equal(purlIdentity('pkg:npm/express@4.18.2'), 'npm/express');
  assert.equal(purlIdentity('pkg:npm/express'), 'npm/express');
  assert.equal(purlIdentity('pkg:npm/@scope/name@1.2.3'), 'npm/@scope/name');
  assert.equal(purlIdentity('pkg:npm/@scope/name'), 'npm/@scope/name');
  assert.equal(purlIdentity('pkg:pypi/django@4.0?arch=any'), 'pypi/django');
  assert.equal(purlIdentity('not-a-purl'), null);
});

test('H-2: a versionless scoped package is not truncated to its scope', () => {
  assert.notEqual(purlIdentity('pkg:npm/@acme/widget'), 'npm/@acme');
  assert.equal(purlIdentity('pkg:npm/@acme/widget'), 'npm/@acme/widget');
});

/* ------------------------------------------------------------------ L-1 */

test('L-1: a package-only advisory is still treated as having applicability data', () => {
  // applicabilityRequiresReview is set at ingestion, but there is no CPE data.
  // Before the fix the review override was disabled for package-only advisories.
  const asset = assetRecord({ cpes: [], version: '4.17.20' });
  const cve = cveRecord({
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: ['pkg:npm/lodash@4.17.20'],
    applicabilityRequiresReview: true,
  });
  const [finding] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
  assert.equal(finding.confidence, 0);
});

/* ------------------------------------------------------------------ AND/negate vs product-wide wildcard */

test('a product-wide wildcard registration dispatches despite a CVE-level AND/negate hold', () => {
  // NVD configurations combining hardware-model criteria with software criteria
  // via an AND node set applicabilityRequiresReview on the whole CVE, because
  // flattening the tree into independent OR checks can't prove a concrete
  // asset satisfies every branch. A complete product-wide registration (every
  // component but vendor/product wildcarded) matches every branch by
  // construction, so that protection has nothing left to verify here.
  const cve = cveRecord({
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*' }],
    applicabilityRequiresReview: true,
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    purls: [],
    cpes: ['cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*'],
  });
  const [finding] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
});

test('a concrete device match still requires review under the same CVE-level AND/negate hold', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-9998',
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*' }],
    applicabilityRequiresReview: true,
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '7.0.1',
    purls: [],
    cpes: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
  });
  const [finding] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
});

test('a KEV naming the product dispatches for a wildcard registration when sources have no CPE data', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-19868',
    title: 'SonicOS SSLVPN authentication enforcement vulnerability',
    description: 'An authentication enforcement vulnerability affects the SonicOS SSLVPN service.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: true,
    applicabilityPolicy: 'REVIEW_ONLY',
    cisaKev: { isKev: true, dateAdded: '2026-11-06' },
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    purls: [],
    cpes: ['cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*'],
  });
  const [kevFinding] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.ok(kevFinding);
  assert.equal(kevFinding.notificationStatus, 'QUEUED_FOR_DISPATCH');

  const unconfirmedFindings = runVulnerabilityPipeline(
    [],
    [{ ...cve, cveId: 'CVE-2026-19869', cisaKev: { isKev: false } }],
    [asset],
    [],
    [],
    settings,
  ).newFindings;
  assert.equal(unconfirmedFindings.length, 0);
});

/* ------------------------------------------------------------------ NVD enrichment autodispatch */

function nvdFeed(id: string): ThreatFeed {
  return {
    id,
    name: 'NVD',
    type: 'VULNCHECK_NVD',
    url: 'https://api.vulncheck.com/v3/index/nist-nvd2',
    authType: 'NONE',
    rateLimitPerMin: 5,
    enabled: true,
    healthStatus: 'HEALTHY',
    lastSync: null,
    latencyMs: 0,
    vendorSeed: false,
    itemCountLastRun: 0,
    ssrfValidated: false,
  };
}

test('an NVD record with no CPE data autodispatches on an exact vendor/product match and is marked for NVD enrichment', () => {
  // CVE-2026-107154 shape: no CPE data yet, but Vendor SonicWall / Product
  // SonicOS exactly matches the monitored asset. NVD is authoritative.
  const cve = cveRecord({
    cveId: 'CVE-2026-107154',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline([nvdFeed('nvd-1')], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.match(finding.matchingEvidence, /This CVE record has been marked for enrichment efforts/);
  assert.match(finding.matchingEvidence, /sonicwall\/sonicos/);
});

test('a wildcard NVD CPE autodispatches when vendor/product exactly match the asset', () => {
  // cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:* with no asset CPE resolves to
  // the vendor/product identity only; NVD is authoritative so it dispatches.
  const cve = cveRecord({
    cveId: 'CVE-2026-107155',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS.',
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*' }],
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1'],
    purls: undefined,
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline([nvdFeed('nvd-1')], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.match(finding.matchingEvidence, /This CVE record has been marked for enrichment efforts/);
});

test('a non-authoritative record with no CPE data is not autodispatched on vendor/product match alone', () => {
  // OSV is not an authoritative source for applicability evidence, so a
  // vendor/product-only match must go to review even though NVD-style
  // autodispatch would apply for authoritative sources.
  const cve = cveRecord({
    cveId: 'CVE-2026-107156',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['osv-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const feed: ThreatFeed = {
    id: 'osv-1',
    name: 'OSV',
    type: 'OSV_API',
    url: 'https://api.osv.dev/v1/querybatch',
    authType: 'NONE',
    rateLimitPerMin: 5,
    enabled: true,
    healthStatus: 'HEALTHY',
    lastSync: null,
    latencyMs: 0,
    vendorSeed: false,
    itemCountLastRun: 0,
    ssrfValidated: false,
  };
  const [finding] = runVulnerabilityPipeline([feed], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
  assert.ok(!finding.matchingEvidence.includes('marked for enrichment efforts'));
});

/* ------------------------------------------------------------------ NVD enrichment autodispatch: false-positive guards */

test('NVD record with applicabilityPolicy REVIEW_ONLY is NOT autodispatched (operator policy respected)', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-107157',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    applicabilityPolicy: 'REVIEW_ONLY',
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline([nvdFeed('nvd-1')], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
  assert.ok(!finding.matchingEvidence.includes('marked for enrichment efforts'));
});

test('NVD record with contradicting package identifiers on both sides yields no finding (package rejection outranks NVD)', () => {
  // Both asset and CVE assert PURLs that disagree. The PURL-vs-PURL mismatch is
  // authoritative and prevents falling through to the vendor/product text
  // fallback, even though NVD is the authoritative source.
  const cve = cveRecord({
    cveId: 'CVE-2026-107158',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: ['pkg:npm/lodash@4.17.99'],
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '4.17.20',
    cpes: [],
    purls: ['pkg:npm/lodash@4.17.20'],
  });
  const findings = runVulnerabilityPipeline([nvdFeed('nvd-1')], [cve], [asset], [], [], settings).newFindings;
  assert.equal(findings.length, 0);
});

test('NVD record with CVE PURL but asset without PURLs autodispatches via vendor/product text fallback', () => {
  // CVE asserts a PURL the asset doesn't run, so there is no package conflict.
  // The vendor/product text fallback matches, and NVD enrichment dispatch applies.
  const cve = cveRecord({
    cveId: 'CVE-2026-107162',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: ['pkg:npm/lodash@4.17.99'],
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline([nvdFeed('nvd-1')], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.match(finding.matchingEvidence, /This CVE record has been marked for enrichment efforts/);
});

test('NVD record with applicabilityRequiresReview and no CPE data dispatches when autoDispatchUnverifiableMatches is enabled', () => {
  // Wildcard CPE has no version range, so applicabilityRequiresReview is false
  // at match level. But even if it were true, enabling
  // autoDispatchUnverifiableMatches lets the NVD enrichment dispatch proceed.
  const cve = cveRecord({
    cveId: 'CVE-2026-107163',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS.',
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*' }],
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const permissiveSettings = { ...settings, autoDispatchUnverifiableMatches: true };
  const [finding] = runVulnerabilityPipeline([nvdFeed('nvd-1')], [cve], [asset], [], [], permissiveSettings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.match(finding.matchingEvidence, /This CVE record has been marked for enrichment efforts/);
});

test('NVD record with concrete CPE data uses STRICT_CPE path, not NVD enrichment dispatch', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-107159',
    title: 'SonicWall SonicOS 7.0.1 vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS 7.0.1.',
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*', range: { versionStartIncluding: '7.0.0', versionStartExcluding: undefined, versionEndIncluding: undefined, versionEndExcluding: '7.0.2' } }],
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '7.0.1',
    cpes: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline([nvdFeed('nvd-1')], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.equal(finding.matchingMethod, 'STRICT_CPE_INTERVAL');
  assert.ok(!finding.matchingEvidence.includes('marked for enrichment efforts'));
  assert.ok(finding.matchingEvidence.includes('Structured package/version correlation'));
});

test('NVD record with applicabilityRequiresReview AND CPE data is held (cveReviewOverride)', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-107160',
    title: 'SonicWall SonicOS complex vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS with complex configuration.',
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*' }],
    versionRange: { versionStartIncluding: '7.0.0' },
    applicabilityRequiresReview: true,
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '7.0.1',
    cpes: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline([nvdFeed('nvd-1')], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
  assert.equal(finding.confidence, 0);
  assert.ok(!finding.matchingEvidence.includes('marked for enrichment efforts'));
});

test('NVD enrichment dispatch still applies when autoDispatchUnverifiableMatches is false but match is verifiable', () => {
  // Wildcard CPE with no version range: applicabilityRequiresReview is false,
  // so even with autoDispatchUnverifiableMatches=false the match dispatches.
  const cve = cveRecord({
    cveId: 'CVE-2026-107161',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS.',
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*' }],
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const strictSettings = { ...settings, autoDispatchUnverifiableMatches: false };
  const [finding] = runVulnerabilityPipeline([nvdFeed('nvd-1')], [cve], [asset], [], [], strictSettings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.match(finding.matchingEvidence, /This CVE record has been marked for enrichment efforts/);
});

/* ------------------------------------------------------------------ Authoritative source autodispatch (MITRE, vendor advisories) */

function authoritativeFeed(id: string, type: FeedType, authoritativeFlag?: boolean): ThreatFeed {
  const base: ThreatFeed = {
    id,
    name: type,
    type,
    url: 'https://example.com/feed',
    authType: 'NONE',
    rateLimitPerMin: 5,
    enabled: true,
    healthStatus: 'HEALTHY',
    lastSync: null,
    latencyMs: 0,
    vendorSeed: false,
    itemCountLastRun: 0,
    ssrfValidated: false,
  };
  return authoritativeFlag !== undefined ? { ...base, authoritative: authoritativeFlag } : base;
}

test('MITRE record with no CPE data autodispatches on exact vendor/product match', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-107164',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['mitre-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline([authoritativeFeed('mitre-1', 'VULNCHECK_NVD')], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.match(finding.matchingEvidence, /marked for enrichment efforts/);
  assert.match(finding.matchingEvidence, /MITRE/);
  assert.match(finding.matchingEvidence, /sonicwall\/sonicos/);
});

test('vendor advisory RSS_ATOM record with no CPE data autodispatches', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-107165',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['sonicwall-psirt-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline([authoritativeFeed('sonicwall-psirt-1', 'RSS_ATOM')], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.match(finding.matchingEvidence, /marked for enrichment efforts/);
  assert.match(finding.matchingEvidence, /vendor advisory/);
});

test('vendor advisory JSON_SEARCH_API record with no CPE data autodispatches', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-107166',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['sonicwall-advisory-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline([authoritativeFeed('sonicwall-advisory-1', 'JSON_SEARCH_API')], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.match(finding.matchingEvidence, /marked for enrichment efforts/);
  assert.match(finding.matchingEvidence, /vendor advisory/);
});

test('non-authoritative feed type with authoritative:true flag autodispatches', () => {
  // OSV is normally not authoritative, but the per-feed authoritative flag overrides it.
  const cve = cveRecord({
    cveId: 'CVE-2026-107167',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['osv-authoritative-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline(
    [authoritativeFeed('osv-authoritative-1', 'OSV_API', true)],
    [cve], [asset], [], [], settings,
  ).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.match(finding.matchingEvidence, /marked for enrichment efforts/);
});

test('OSV_API without authoritative flag is NOT autodispatched (goes to review)', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-107168',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['osv-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline([authoritativeFeed('osv-1', 'OSV_API')], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
  assert.ok(!finding.matchingEvidence.includes('marked for enrichment efforts'));
});

/* ------------------------------------------------------------------ Duplicate findings prevention */

test('no duplicate findings when same CVE/asset pair matches via multiple feed types', () => {
  // The same CVE asserted by both NVD and MITRE should produce exactly one finding per asset.
  const cve = cveRecord({
    cveId: 'CVE-2026-107169',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1', 'mitre-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const findings = runVulnerabilityPipeline(
    [authoritativeFeed('nvd-1', 'VULNCHECK_NVD'), authoritativeFeed('mitre-1', 'VULNCHECK_NVD')],
    [cve], [asset], [], [], settings,
  ).newFindings;
  // One CVE + one asset = exactly one finding, not one per source feed.
  assert.equal(findings.length, 1);
  const ids = new Set(findings.map((f) => `${f.cveId}:${f.matchedAssetId}`));
  assert.equal(ids.size, 1, 'no duplicate CVE:asset identities');
});

test('no duplicate findings when same CVE matches same asset twice within run', () => {
  // Even if candidate pairs or alias expansion produce the same pair twice,
  // seenFindingKeys prevents duplicate findings.
  const cve = cveRecord({
    cveId: 'CVE-2026-107170',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*' }],
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const findings = runVulnerabilityPipeline([authoritativeFeed('nvd-1', 'VULNCHECK_NVD')], [cve], [asset], [], [], settings).newFindings;
  assert.equal(findings.length, 1);
});

test('all authoritative-source findings dispatch, none go to review', () => {
  // NVD, MITRE, RSS_ATOM, JSON_SEARCH_API, and flag-authoritative OSV all dispatch.
  const cves = [
    cveRecord({ cveId: 'CVE-2026-107171', title: 'SonicWall SonicOS NVD vuln', description: 'SonicWall SonicOS vulnerability via NVD', cpeMatches: [], cpeMatchDetails: [], purls: undefined, applicabilityRequiresReview: false, sourceFeeds: ['nvd-1'] }),
    cveRecord({ cveId: 'CVE-2026-107172', title: 'SonicWall SonicOS MITRE vuln', description: 'SonicWall SonicOS vulnerability via MITRE', cpeMatches: [], cpeMatchDetails: [], purls: undefined, applicabilityRequiresReview: false, sourceFeeds: ['mitre-1'] }),
    cveRecord({ cveId: 'CVE-2026-107173', title: 'SonicWall SonicOS RSS vuln', description: 'SonicWall SonicOS vulnerability via RSS_ATOM', cpeMatches: [], cpeMatchDetails: [], purls: undefined, applicabilityRequiresReview: false, sourceFeeds: ['rss-1'] }),
    cveRecord({ cveId: 'CVE-2026-107174', title: 'SonicWall SonicOS JSON vuln', description: 'SonicWall SonicOS vulnerability via JSON_SEARCH_API', cpeMatches: [], cpeMatchDetails: [], purls: undefined, applicabilityRequiresReview: false, sourceFeeds: ['json-1'] }),
    cveRecord({ cveId: 'CVE-2026-107175', title: 'SonicWall SonicOS Flagged OSV vuln', description: 'SonicWall SonicOS vulnerability via OSV flag', cpeMatches: [], cpeMatchDetails: [], purls: undefined, applicabilityRequiresReview: false, sourceFeeds: ['osv-1'] }),
  ];
  const asset = assetRecord({ vendor: 'sonicwall', product: 'sonicos', version: '*', cpes: [], purls: [] });
  const feeds = [
    authoritativeFeed('nvd-1', 'VULNCHECK_NVD'),
    authoritativeFeed('mitre-1', 'VULNCHECK_NVD'),
    authoritativeFeed('rss-1', 'RSS_ATOM'),
    authoritativeFeed('json-1', 'JSON_SEARCH_API'),
    authoritativeFeed('osv-1', 'OSV_API', true),
  ];
  const findings = runVulnerabilityPipeline(feeds, cves, [asset], [], [], settings).newFindings;
  assert.equal(findings.length, 5, 'all 5 authoritative-source CVEs produce findings');
  for (const f of findings) {
    assert.equal(f.notificationStatus, 'QUEUED_FOR_DISPATCH', `${f.cveId} should not go to review`);
    assert.match(f.matchingEvidence, /marked for enrichment efforts/, `${f.cveId} should have enrichment evidence`);
  }
});

test('flag-authoritative feed source label names the feed type', () => {
  // OSV_API is not in AUTHORITATIVE_FEED_TYPES but the per-feed flag makes it authoritative.
  // The source label should not be empty.
  const cve = cveRecord({
    cveId: 'CVE-2026-107176',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['osv-authoritative-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline(
    [authoritativeFeed('osv-authoritative-1', 'OSV_API', true)],
    [cve], [asset], [], [], settings,
  ).newFindings;
  assert.ok(finding);
  assert.match(finding.matchingEvidence, /authoritative source \(OSV_API\)/);
});

test('authoritative source with match-level applicabilityRequiresReview AND autoDispatchUnverifiableMatches=false goes to review', () => {
  // Asset has no CPEs, so strict CPE can't match. Vendor/product alias matches
  // (sonicwall/sonicos exact). versionRange makes applicabilityRequiresReview=true
  // at match level. authoritativeSourceDispatch boosts confidence to threshold,
  // but confirmed stays false because unverifiableMatch is true and
  // autoDispatchUnverifiableMatches is false.
  const cve = cveRecord({
    cveId: 'CVE-2026-107177',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*', range: { versionStartIncluding: '7.0.0', versionStartExcluding: undefined, versionEndIncluding: undefined, versionEndExcluding: '7.0.2' } }],
    versionRange: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const strictSettings = { ...settings, autoDispatchUnverifiableMatches: false };
  const [finding] = runVulnerabilityPipeline([authoritativeFeed('nvd-1', 'VULNCHECK_NVD')], [cve], [asset], [], [], strictSettings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
  assert.equal(finding.confidence, 90, 'confidence boosted by authoritative dispatch but held by unverifiable match');
  assert.ok(!finding.matchingEvidence.includes('marked for enrichment efforts'));
});

test('authoritative source record with mixed authoritative and non-authoritative feeds dispatches', () => {
  // CVE asserted by both NVD (authoritative) and OSV (not authoritative).
  // Any authoritative source is enough for autodispatch.
  const cve = cveRecord({
    cveId: 'CVE-2026-107178',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1', 'osv-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const [finding] = runVulnerabilityPipeline(
    [authoritativeFeed('nvd-1', 'VULNCHECK_NVD'), authoritativeFeed('osv-1', 'OSV_API')],
    [cve], [asset], [], [], settings,
  ).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.match(finding.matchingEvidence, /marked for enrichment efforts/);
  assert.match(finding.matchingEvidence, /NVD/);
});

test('same CVE from two authoritative feeds produces exactly one finding per asset', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-107179',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1', 'mitre-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    cpes: [],
    purls: [],
  });
  const findings = runVulnerabilityPipeline(
    [authoritativeFeed('nvd-1', 'VULNCHECK_NVD'), authoritativeFeed('mitre-1', 'VULNCHECK_NVD')],
    [cve], [asset], [], [], settings,
  ).newFindings;
  assert.equal(findings.length, 1, 'mergeCveRecords deduplicates CVEs; one CVE:asset = one finding');
});

/* ------------------------------------------------------------------ Circuit breaker tests */

test('maxFindingsPerRun caps authoritative dispatches; remaining matches held for review', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-107180',
    title: 'SonicWall SonicOS vulnerability',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: false,
    sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall', product: 'sonicos', version: '*', cpes: [], purls: [],
  });
  // Only one authoritative dispatch allowed per run.
  const cappedSettings = { ...settings, maxFindingsPerRun: 1 };
  const findings = runVulnerabilityPipeline(
    [authoritativeFeed('nvd-1', 'VULNCHECK_NVD')], [cve], [asset], [], [], cappedSettings,
  ).newFindings;
  assert.equal(findings.length, 1);
  assert.equal(findings[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
});

test('maxDispatchesPerRunPerFeed caps per-feed dispatches', () => {
  const cve1 = cveRecord({
    cveId: 'CVE-2026-107181', title: 'SonicWall SonicOS vuln 1',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [], cpeMatchDetails: [], purls: undefined,
    applicabilityRequiresReview: false, sourceFeeds: ['nvd-1'],
  });
  const cve2 = cveRecord({
    cveId: 'CVE-2026-107182', title: 'SonicWall SonicOS vuln 2',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [], cpeMatchDetails: [], purls: undefined,
    applicabilityRequiresReview: false, sourceFeeds: ['nvd-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall', product: 'sonicos', version: '*', cpes: [], purls: [],
  });
  // Only one dispatch per feed per run.
  const cappedSettings = { ...settings, maxDispatchesPerRunPerFeed: 1 };
  const findings = runVulnerabilityPipeline(
    [authoritativeFeed('nvd-1', 'VULNCHECK_NVD')], [cve1, cve2], [asset], [], [], cappedSettings,
  ).newFindings;
  assert.equal(findings.length, 2, 'both CVEs produce findings');
  // First should dispatch, second should be held due to per-feed cap.
  assert.equal(findings[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.equal(findings[1].notificationStatus, 'REVIEW_REQUIRED');
});

test('maxTotalFindingsPerRun caps total dispatches across all paths', () => {
  const cve1 = cveRecord({
    cveId: 'CVE-2026-107183', title: 'SonicWall SonicOS vuln 1',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [], cpeMatchDetails: [], purls: undefined,
    applicabilityRequiresReview: false, sourceFeeds: ['nvd-1'],
  });
  const cve2 = cveRecord({
    cveId: 'CVE-2026-107184', title: 'SonicWall SonicOS vuln 2',
    description: 'A vulnerability affects SonicWall SonicOS firewall appliances.',
    cpeMatches: [], cpeMatchDetails: [], purls: undefined,
    applicabilityRequiresReview: false, sourceFeeds: ['mitre-1'],
  });
  const asset = assetRecord({
    vendor: 'sonicwall', product: 'sonicos', version: '*', cpes: [], purls: [],
  });
  // Only one total dispatch allowed per run.
  const cappedSettings = { ...settings, maxTotalFindingsPerRun: 1 };
  const findings = runVulnerabilityPipeline(
    [authoritativeFeed('nvd-1', 'VULNCHECK_NVD'), authoritativeFeed('mitre-1', 'VULNCHECK_NVD')],
    [cve1, cve2], [asset], [], [], cappedSettings,
  ).newFindings;
  assert.equal(findings.length, 2, 'both CVEs produce findings');
  assert.equal(findings[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.equal(findings[1].notificationStatus, 'REVIEW_REQUIRED');
});

/* ------------------------------------------------------------------ Enrichment backlog tests */

test('enrichmentBacklogCandidates filters findings dispatched without CPE data', () => {
  const dispatched = {
    id: 'f1', cveId: 'CVE-2026-107185', cve: {} as any,
    matchedAssetId: 'a1', matchedAssetName: 'a1', matchedAssetVendor: 'sonicwall',
    matchedAssetProduct: 'sonicos', matchedAssetPurls: [], matchedCpe: '',
    matchingMethod: 'VENDOR_PRODUCT_FALLBACK',
    matchingEvidence: 'This CVE record has been marked for enrichment efforts. ...',
    confidence: 90, exposure: 'INTERNAL', exploitRisk: 'CRITICAL',
    notificationStatus: 'QUEUED_FOR_DISPATCH', status: 'MONITORED',
    autoDispatchedAt: null, advisoryId: null, executionId: 'x', reviewNotifiedAt: null,
    timeline: [],
  } as any;
  const strictCpe = {
    id: 'f2', cveId: 'CVE-2026-107186', cve: {} as any,
    matchedAssetId: 'a2', matchedAssetName: 'a2', matchedAssetVendor: 'sonicwall',
    matchedAssetProduct: 'sonicos', matchedAssetPurls: [], matchedCpe: 'cpe:...',
    matchingMethod: 'STRICT_CPE_INTERVAL',
    matchingEvidence: 'Structured package/version correlation',
    confidence: 95, exposure: 'INTERNAL', exploitRisk: 'CRITICAL',
    notificationStatus: 'QUEUED_FOR_DISPATCH', status: 'MONITORED',
    autoDispatchedAt: null, advisoryId: null, executionId: 'x', reviewNotifiedAt: null,
    timeline: [],
  } as any;
  const held = {
    id: 'f3', cveId: 'CVE-2026-107187', cve: {} as any,
    matchedAssetId: 'a3', matchedAssetName: 'a3', matchedAssetVendor: 'sonicwall',
    matchedAssetProduct: 'sonicos', matchedAssetPurls: [], matchedCpe: '',
    matchingMethod: 'VENDOR_PRODUCT_FALLBACK',
    matchingEvidence: 'Product correlation; held for review because ...',
    confidence: 70, exposure: 'INTERNAL', exploitRisk: 'CRITICAL',
    notificationStatus: 'REVIEW_REQUIRED', status: 'MONITORED',
    autoDispatchedAt: null, advisoryId: null, executionId: 'x', reviewNotifiedAt: null,
    timeline: [],
  } as any;
  const candidates = enrichmentBacklogCandidates([dispatched, strictCpe, held]);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].cveId, 'CVE-2026-107185');
});

/* ------------------------------------------------------------------ H-5 */

test('H-5: deterministic configuration faults are classified as permanent', () => {
  assert.equal(isPermanentFeedFailure({ status: 404 }), true);
  assert.equal(isPermanentFeedFailure({ status: 400 }), true);
  assert.equal(isPermanentFeedFailure({ status: 422 }), true);
  assert.equal(isPermanentFeedFailure(new Error('Non-public destination')), true);
  assert.equal(isPermanentFeedFailure(new Error('Malformed URL')), true);
  assert.equal(isPermanentFeedFailure(new Error('Saved source checkpoint is invalid; clear it and re-run ingestion')), true);
});

test('H-5: transient failures keep their retry budget', () => {
  assert.equal(isPermanentFeedFailure({ status: 500 }), false);
  assert.equal(isPermanentFeedFailure({ status: 502 }), false);
  assert.equal(isPermanentFeedFailure({ status: 429 }), false);
  assert.equal(isPermanentFeedFailure({ status: 408 }), false);
  assert.equal(isPermanentFeedFailure({ status: 401 }), false);
  assert.equal(isPermanentFeedFailure(new Error('socket hang up')), false);
  assert.equal(isPermanentFeedFailure(new TypeError('fetch failed')), false);
});
