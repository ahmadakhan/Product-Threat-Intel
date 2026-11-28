import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchCPE, matchesWatchlistItem } from '../src/utils/cpeMatcher.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { matchIntelligence } from '../src/utils/intelligenceMatcher.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { NormalizedCVE, WatchListItem } from '../src/types/index.ts';

/**
 * Regressions for the matching audit. Each test pins one audited property:
 * CPE identity integrity, wildcard scope semantics, duplicate-free output, and
 * news entity separation. The audit framework itself is docs/MATCHING-AUDIT.md.
 */

const cpe = (vendor: string, product: string, version = '*') =>
  `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

/* -------------------------------------------------------------------------- */
/* CPE alignment                                                              */
/* -------------------------------------------------------------------------- */

test('a structural glob in a CPE vendor/product is not an identity assertion', () => {
  // `acme.*` describes a set of vendors. Accepting it as "acme" would let a
  // first-match loop over the candidate set pick whichever advisory happened to
  // intersect the glob, which is a coincidence, not evidence.
  assert.equal(matchCPE(cpe('acme.*', 'widget', '1.0'), cpe('acme', 'widget', '1.0')).matched, false);
  assert.equal(matchCPE(cpe('acme', 'widget', '1.0'), cpe('acme.*', 'widget', '1.0')).matched, false);
  assert.equal(matchCPE(cpe('acme', 'wid?et', '1.0'), cpe('acme', 'widget', '1.0')).matched, false);
});

test('a complete wildcard scope is still resolved from the inventory identity', () => {
  // The operator's deliberate "all of my vendor's applications" scope must keep
  // working: it is not a structural glob.
  const result = matchesWatchlistItem(
    ['cpe:2.3:a:*:*:1.5:*:*:*:*:*:*:*'],
    'acme',
    'widget',
    [cpe('acme', 'widget', '1.5')],
    'unrelated title',
    'unrelated body',
  );
  assert.equal(result.matched, true);
  assert.equal(result.method, 'STRICT_CPE');
});

test('a partial-glob CPE cannot make the asset match a different product', () => {
  const result = matchesWatchlistItem(
    [cpe('acme.*', 'widget', '1.0')],
    'acme',
    'widget',
    [cpe('acme', 'storefront', '1.0')],
    'Acme Storefront vulnerability',
    'A flaw in Acme Storefront allows uploads.',
  );
  assert.equal(result.matched, false);
});

test('free text that sanitizes to no usable CPE token is never substituted', () => {
  // `inventoryCpeToken('+++')` is `___`-like noise, and a token of `-` means
  // "not applicable". Either would name no product and match an arbitrary
  // advisory through the generic resolver.
  const result = matchesWatchlistItem(
    ['cpe:2.3:a:*:*:1.0:*:*:*:*:*:*:*'],
    '+++',
    '---',
    [cpe('acme', 'widget', '1.0')],
    'Acme Widget vulnerability',
    'A flaw in Acme Widget allows uploads.',
  );
  assert.equal(result.matched, false);
});

/* -------------------------------------------------------------------------- */
/* Wildcard semantics                                                         */
/* -------------------------------------------------------------------------- */

test('partial version wildcards intersect only their own release family', () => {
  assert.equal(matchCPE(cpe('acme', 'widget', '1.*'), cpe('acme', 'widget', '1.5')).matched, true);
  assert.equal(matchCPE(cpe('acme', 'widget', '1.*'), cpe('acme', 'widget', '2.0')).matched, false);
  assert.equal(matchCPE(cpe('acme', 'widget', '2.*'), cpe('acme', 'widget', '1.*')).matched, false);
});

test('a partial version wildcard is not reported as a full-confidence scope', () => {
  const matched = matchesWatchlistItem(
    [cpe('acme', 'widget', '1.*')],
    'acme',
    'widget',
    [cpe('acme', 'widget', '1.5')],
    '',
    '',
  );
  assert.equal(matched.matched, true);
  assert.notEqual(matched.wildcardScopeMatch, true, 'a release family is not the all-versions scope');
});

/* -------------------------------------------------------------------------- */
/* Duplicate-free output                                                      */
/* -------------------------------------------------------------------------- */

const asset = (id: string, vendor: string, product: string, cpes: string[]): WatchListItem => ({
  id,
  assetTag: id,
  vendor,
  product,
  version: '*',
  cpes,
  purls: [],
  active: true,
  ownerGroup: 'SOC',
  createdAt: '2026-01-01T00:00:00.000Z',
});

const cve = (id: string, vendor: string, product: string): NormalizedCVE => ({
  cveId: id,
  title: 't',
  description: 'd',
  publishedDate: '2026-11-20T00:00:00.000Z',
  modifiedDate: '2026-11-25T00:00:00.000Z',
  cvss: { severity: 'HIGH', score: 8, version: '3.1', vector: 'CVSS:3.1/AV:N' },
  cisaKev: { isKev: false },
  sourceFeeds: ['NVD'],
  cpeMatches: [cpe(vendor, product)],
  cpeMatchDetails: [],
  purls: [],
  cwe: [],
  epss: { score: 0.1, percentile: 0.5 },
  exploitStatus: 'None',
  remediation: {
    patchUrl: '',
    vendorAdvisoryRef: '',
    immediateActions: [],
    workarounds: [],
    rollbackPlan: '',
    stepByStep: [],
  },
});

test('a run emits exactly one finding per (CVE, asset) pair, with no integrity warning', () => {
  // The same asset is registered twice under different ids (a common inventory
  // import artifact), and the CVE carries duplicate criteria. Neither may turn
  // into a second finding for the same asset id.
  const inventory = [
    asset('a1', 'acme', 'widget', [cpe('acme', 'widget')]),
    asset('a2', 'other', 'thing', [cpe('other', 'thing')]),
  ];
  const corpus = [{ ...cve('CVE-2026-0001', 'acme', 'widget'), cpeMatches: [cpe('acme', 'widget'), cpe('acme', 'widget')] }];
  const run = runVulnerabilityPipeline(
    [],
    corpus,
    inventory,
    [],
    [],
    { ...DEFAULT_SETTINGS, scopeHours: 0 },
    'audit',
    false,
    {},
    {},
    undefined,
    [],
    new Date('2026-11-25T12:00:00Z'),
  );
  const keys = run.newFindings.map((finding) => `${finding.cveId}:${finding.matchedAssetId}`);
  assert.deepEqual([...new Set(keys)].sort(), keys.slice().sort(), 'duplicate (CVE, asset) pair emitted');
  assert.equal(
    run.newAuditLogs.filter((log) => log.event === 'MATCH_INTEGRITY_DUPLICATE_PAIRS').length,
    0,
    'no duplicate-integrity warning should be recorded for a clean run',
  );
});

test('a repeated pipeline run over the same corpus is byte-identical', () => {
  const inventory = [asset('a1', 'acme', 'widget', [cpe('acme', 'widget', '1.0')])];
  const corpus = [cve('CVE-2026-0002', 'acme', 'widget')];
  const run = () =>
    runVulnerabilityPipeline(
      [],
      corpus,
      inventory,
      [],
      [],
      { ...DEFAULT_SETTINGS, scopeHours: 0 },
      'audit',
      false,
      {},
      {},
      undefined,
      [],
      new Date('2026-11-25T12:00:00Z'),
    ).newFindings.map((finding) => `${finding.cveId}:${finding.matchedAssetId}:${finding.matchingMethod}`);
  assert.deepEqual(run(), run());
});

/* -------------------------------------------------------------------------- */
/* News entity extraction                                                     */
/* -------------------------------------------------------------------------- */

test('news requires both vendor and product, and keeps different products apart', () => {
  const article = (id: string, title: string, summary = '') => ({
    id,
    title,
    summary,
    url: `https://example.invalid/${id}`,
    sourceFeeds: ['RSS_ATOM'],
    publishedDate: '2026-11-26T00:00:00.000Z',
    modifiedDate: '2026-11-26T00:00:00.000Z',
    cveIds: [],
  });
  const inventory = [
    asset('pan', 'Palo Alto Networks', 'PAN-OS', []),
    asset('gp', 'Palo Alto Networks', 'GlobalProtect', []),
  ];
  const ids = (title: string) =>
    [...new Set(matchIntelligence([article('n', title)], inventory, [], [], {}, {}, 0, new Date('2026-11-27T00:00:00.000Z')).map((match) => match.assetId))].sort();

  // Vendor alone names no product.
  assert.deepEqual(ids('Palo Alto Networks announces quarterly results'), []);
  // Product alone does not corroborate the vendor's other product.
  assert.deepEqual(ids('GlobalProtect portal exposed'), []);
  // Both together resolve exactly one product.
  assert.deepEqual(ids('Palo Alto Networks GlobalProtect flaw'), ['gp']);
});

test('news deduplicates a repeated article rather than double-counting it', () => {
  const article = {
    id: 'dup',
    title: 'Acme Widget flaw',
    summary: 'Acme Widget is affected.',
    url: 'https://example.invalid/dup',
    sourceFeeds: ['RSS_ATOM'],
    publishedDate: '2026-11-26T00:00:00.000Z',
    modifiedDate: '2026-11-26T00:00:00.000Z',
    cveIds: [],
  };
  const inventory = [asset('w', 'acme', 'widget', [])];
  const matches = matchIntelligence(
    [article, { ...article }],
    inventory,
    [],
    [],
    {},
    {},
    0,
    new Date('2026-11-27T00:00:00.000Z'),
  );
  assert.equal(matches.length, 1);
  assert.deepEqual(matches[0].articleIds, ['dup']);
});
