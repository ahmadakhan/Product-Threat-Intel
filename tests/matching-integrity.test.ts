import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { matchIntelligence } from '../src/utils/intelligenceMatcher.ts';
import { normalizeCveId } from '../src/utils/deduplicator.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { NormalizedCVE, WatchListItem } from '../src/types/index.ts';

const cpe = (vendor: string, product: string) => `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`;
const asset = (id: string, vendor: string, product: string): WatchListItem => ({
  id, vendor, product, version: '*', cpes: [cpe(vendor, product)],
  assetTag: id, ownerGroup: 'g', active: true, createdAt: '2026-01-01T00:00:00.000Z',
});
const cve = (id: string, vendor: string, product: string): NormalizedCVE => ({
  cveId: id, publishedDate: '2026-11-20T00:00:00.000Z', modifiedDate: '2026-11-25T00:00:00.000Z',
  title: 't', description: 'd', cvss: { severity: 'HIGH', score: 8, version: '3.1', vector: 'CVSS:3.1/AV:N' }, cisaKev: { isKev: false },
  sourceFeeds: ['NVD'], cpeMatches: [cpe(vendor, product)], cpeMatchDetails: [], purls: [],
  cwe: [], epss: { score: 0.1, percentile: 0.5 }, exploitStatus: 'None',
  remediation: { patchUrl: '', vendorAdvisoryRef: '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
});

/**
 * Matching must be a pure, deterministic function of its input: two identical runs
 * have to produce the same (CVE, asset) set. A non-deterministic matcher makes the
 * same corpus dispatch different findings on different runs, which is exactly what
 * the zero-day rate-limit ordering used to do.
 */
test('the matching pipeline is deterministic and emits no duplicate (CVE, asset) pairs', () => {
  const inventory = [asset('a1', 'acme', 'widget'), asset('a2', 'acme', 'widget'), asset('a3', 'other', 'thing')];
  const corpus = [cve('CVE-2026-1111', 'acme', 'widget'), cve('CVE-2026-2222', 'acme', 'widget'), cve('CVE-2026-3333', 'other', 'thing')];
  const run = () =>
    runVulnerabilityPipeline([], corpus, inventory, [], [], { ...DEFAULT_SETTINGS, scopeHours: 0 }, 'audit', false, {}, {}, undefined, [], new Date('2026-11-25T12:00:00Z'));

  const key = (finding: { cveId: string; matchedAssetId: string }) => `${finding.cveId}:${finding.matchedAssetId}`;
  const first = run().newFindings.map(key);
  const second = run().newFindings.map(key);

  assert.deepEqual([...new Set(first)].sort(), first.slice().sort(), 'no duplicate (CVE, asset) pair');
  assert.deepEqual(first.slice().sort(), second.slice().sort(), 'identical input yields identical output');
  // Two assets of the same product each get their own finding.
  assert.deepEqual(
    first.filter((entry) => entry.startsWith('CVE-2026-1111:')).sort(),
    ['CVE-2026-1111:a1', 'CVE-2026-1111:a2'],
  );
});

test('news matching collapses a repeated article and needs vendor AND product', () => {
  const article = (id: string, title: string, summary: string) => ({
    id, title, summary, url: `https://example.invalid/${id}`, sourceFeeds: ['RSS_ATOM'],
    publishedDate: '2026-11-26T00:00:00.000Z', modifiedDate: '2026-11-26T00:00:00.000Z', cveIds: [],
  });
  const inventory = [asset('a1', 'Palo Alto Networks', 'GlobalProtect'), asset('a2', 'Palo Alto Networks', 'PAN-OS')];
  const match = (articles: ReturnType<typeof article>[]) =>
    [...new Set(matchIntelligence(articles, inventory, [], [], {}, {}, 0, new Date('2026-11-27T00:00:00Z')).map((m) => m.assetId))].sort();

  // The same article ingested twice must produce one match, not two.
  assert.deepEqual(match([article('n1', 'Palo Alto Networks GlobalProtect flaw', 'GlobalProtect portal exploited')]), ['a1']);
  assert.deepEqual(
    match([
      article('n1', 'Palo Alto Networks GlobalProtect flaw', 'GlobalProtect portal exploited'),
      article('n1', 'Palo Alto Networks GlobalProtect flaw', 'GlobalProtect portal exploited'),
    ]),
    ['a1'],
  );
  // Vendor alone, or product alone, must not corroborate any asset: otherwise a
  // GlobalProtect story would attach a finding to a PAN-OS host.
  assert.deepEqual(match([article('n2', 'Palo Alto Networks announces results', 'Quarterly earnings.')]), []);
  assert.deepEqual(match([article('n3', 'GlobalProtect portal exposed', 'An issue in the portal.')]), []);
});

/**
 * CVE ids are validated, not coerced: a malformed id is dropped rather than
 * matching a truncated neighbour. `CVE-2026-1` is not a valid CVE id (the sequence
 * number has at least four digits), and silently accepting it would let a feed
 * error collide with `CVE-2026-0001`.
 */
test('CVE ids are validated against the specification', () => {
  assert.equal(normalizeCveId('CVE-2026-1111'), 'CVE-2026-1111');
  assert.equal(normalizeCveId('cve-2026-1111'), 'CVE-2026-1111');
  assert.equal(normalizeCveId('CVE-2026-1'), null);
  assert.equal(normalizeCveId('CVE-2026-01'), null);
  assert.equal(normalizeCveId('not-a-cve'), null);
  assert.equal(normalizeCveId(''), null);
});
