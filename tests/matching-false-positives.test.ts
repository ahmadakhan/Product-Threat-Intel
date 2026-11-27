import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesWatchlistItem } from '../src/utils/cpeMatcher.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { NormalizedCVE } from '../src/types/index.ts';

const HOTEL_CPE = 'cpe:2.3:a:sourcecodester:basic_hotel_online_reservation_system:*:*:*:*:*:*:*:*';
const HOTEL_TITLE = 'SourceCodester Basic Hotel Online Reservation System SQL injection';
const HOTEL_DESC =
  'A SQL injection vulnerability in SourceCodester Basic Hotel Online Reservation System allows remote attackers to execute arbitrary SQL commands via the id parameter in PHP.';

/**
 * Reported false positive: an inventory item `PHP / PHP` was flagged for a
 * SourceCodester hotel-reservation CVE merely because the advisory said "in PHP".
 *
 * The prose fallback justified itself with "vendor AND product are both named",
 * which is only two facts when they are two identities. When vendor and product
 * are the same word, one incidental mention satisfied both tests.
 */
test('a language/runtime name in advisory prose does not match that product', () => {
  for (const [vendor, product] of [
    ['PHP', 'PHP'],
    ['Django', 'Django'],
    ['MySQL', 'MySQL'],
  ]) {
    const result = matchesWatchlistItem([], vendor, product, [HOTEL_CPE], HOTEL_TITLE, HOTEL_DESC);
    assert.equal(result.matched, false, `${vendor}/${product} must not match on a language mention`);
    assert.notEqual(result.method, 'VENDOR_PRODUCT_FALLBACK');
  }
});

test('a generic word in prose does not match an unrelated product', () => {
  // "Php" vendor with an unrelated CPE must not be rescued by the prose either.
  const result = matchesWatchlistItem(
    ['cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*'],
    'PHP', 'PHP', [HOTEL_CPE], HOTEL_TITLE, HOTEL_DESC,
  );
  assert.equal(result.matched, false);
});

test('the prose fallback still matches real, specific products with no CPE data', () => {
  const cases: Array<[string, string, string, string]> = [
    ['Tyche Softwares', 'Input Fields for WooCommerce',
      'Input Fields for WooCommerce vulnerability',
      'A flaw in the Tyche Softwares Input Fields for WooCommerce plugin allows XSS.'],
    ['Atlassian', 'Confluence',
      'Confluence data center flaw',
      'Atlassian Confluence Data Center is vulnerable to remote code execution.'],
    ['WordPress', 'Contact Form 7',
      'Contact Form 7 vulnerability',
      'Automattic Contact Form 7 for WordPress allows unauthenticated file upload.'],
  ];
  for (const [vendor, product, title, description] of cases) {
    const result = matchesWatchlistItem([], vendor, product, [], title, description);
    assert.equal(result.matched, true, `${vendor}/${product} must still match its own advisory`);
  }
});

test('the hotel-reservation CVE flags only the SourceCodester asset end to end', () => {
  const cve: NormalizedCVE = {
    cveId: 'CVE-2026-1111',
    publishedDate: '2026-11-20T00:00:00.000Z',
    modifiedDate: '2026-11-25T00:00:00.000Z',
    title: HOTEL_TITLE,
    description: HOTEL_DESC,
    cvss: { severity: 'HIGH', score: 8, version: '3.1', vector: 'CVSS:3.1/AV:N' },
    cisaKev: { isKev: false },
    sourceFeeds: ['NVD'],
    cpeMatches: [HOTEL_CPE],
    cpeMatchDetails: [],
    purls: [],
    cwe: [],
    epss: { score: 0.1, percentile: 0.5 },
    exploitStatus: 'None',
    remediation: { patchUrl: '', vendorAdvisoryRef: '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
  };
  const asset = (id: string, vendor: string, product: string, cpes: string[]) => ({
    id, vendor, product, version: '*', cpes, assetTag: id, ownerGroup: 'g', active: true,
    createdAt: '2026-01-01T00:00:00.000Z',
  });
  const inventory = [
    asset('correct', 'SourceCodester', 'Basic Hotel Online Reservation System', [HOTEL_CPE]),
    asset('tyche', 'Tyche Softwares', 'Input Fields for WooCommerce', []),
    asset('tyche-cpe', 'Tyche Softwares', 'Input Fields for WooCommerce', [
      'cpe:2.3:a:tychesoftwares:input_fields_for_woocommerce:*:*:*:*:*:*:*:*',
    ]),
    asset('php', 'PHP', 'PHP', []),
    asset('php-cpe', 'PHP', 'PHP', ['cpe:2.3:a:php:php:*:*:*:*:*:*:*:*']),
  ];
  const run = runVulnerabilityPipeline(
    [], [cve], inventory, [], [], { ...DEFAULT_SETTINGS, scopeHours: 0 }, 'audit', false, {}, {}, undefined, [],
    new Date('2026-11-25T12:00:00Z'),
  );
  assert.deepEqual(run.newFindings.map((finding) => finding.matchedAssetId).sort(), ['correct']);
});
