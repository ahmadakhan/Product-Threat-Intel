import test from 'node:test';
import assert from 'node:assert/strict';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { matchIntelligence } from '../src/utils/intelligenceMatcher.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { IntelligenceArticle, NormalizedCVE, WatchListItem } from '../src/types/index.ts';

const now = new Date('2026-11-11T00:00:00Z');
const cpe = (vendor: string, product: string, version = '1.5') =>
  `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
function asset(vendor = 'acme', product = 'gateway'): WatchListItem {
  return {
    id: 'asset', assetTag: 'asset', vendor, product, version: '1.5',
    cpes: [cpe(vendor, product)], purls: [], active: true,
    ownerGroup: 'SOC', createdAt: now.toISOString(),
  };
}
function advisory(overrides: Partial<NormalizedCVE> = {}): NormalizedCVE {
  return {
    cveId: 'CVE-2020-98001', title: 'Acme Gateway vulnerability', description: 'Acme Gateway flaw',
    publishedDate: '2020-01-01T00:00:00Z', modifiedDate: '2020-01-01T00:00:00Z',
    cvss: { version: '3.1', score: 9.8, severity: 'CRITICAL', vector: '' },
    cpeMatches: [cpe('acme', 'gateway')], sourceFeeds: [], cwe: [],
    remediation: { immediateActions: [], vendorAdvisoryRef: '', patchUrl: '', workarounds: [], rollbackPlan: '', stepByStep: [] },
    cisaKev: { isKev: false }, epss: { score: 0, percentile: 0 }, exploitStatus: 'None',
    ...overrides,
  };
}
function article(title: string): IntelligenceArticle {
  return {
    id: 'news', title, summary: title, url: 'https://example.invalid/story',
    publishedDate: now.toISOString(), modifiedDate: now.toISOString(),
    sourceFeeds: ['rss'], cveIds: [], zeroDay: true,
  };
}
function findings(record: NormalizedCVE, changed = new Set<string>()) {
  return runVulnerabilityPipeline(
    [], [record], [asset()], [], [], { ...DEFAULT_SETTINGS, scopeHours: 24 },
    'regression', true, {}, {}, undefined, [], now, undefined, changed,
  ).newFindings;
}

test('changed applicability re-matches old CVEs against inventory without previous findings', () => {
  const record = advisory();
  assert.equal(findings(record).length, 0, 'ordinary old records remain outside scope');
  const changed = new Set([record.cveId]);
  assert.equal(findings(record, changed).length, 1, 'changed records pass both timeline gates');
  assert.equal(findings(advisory({ cpeMatches: [cpe('acme', 'gateway', '2.0')] }), changed).length, 0,
    'timeline exception must preserve installed-version exclusions');
  assert.equal(findings(advisory({ cpeMatches: [cpe('other', 'database')] }), changed).length, 0,
    'timeline exception must preserve vendor/product exclusions');
});

test('news shares built-in product and vendor aliases without requiring custom copies', () => {
  const story = article('VMware ESXi zero-day vulnerability');
  assert.equal(matchIntelligence([story], [asset('vmware', 'esx')], []).length, 1);
  assert.equal(matchIntelligence([story], [asset('broadcom', 'esxi')], []).length, 1);
  assert.equal(matchIntelligence([story], [asset('other', 'esx')], []).length, 0);
  assert.equal(matchIntelligence([article('Palo Alto Networks GlobalProtect flaw')],
    [asset('paloaltonetworks', 'pan_os')], []).length, 0, 'distinct products stay separate');
});

test('custom aliases add spellings without replacing the shared baseline', () => {
  const vm = asset('vmware', 'esx');
  const custom = { esxi: ['hypervisor-brand'] };
  for (const title of ['VMware ESXi flaw', 'VMware hypervisor-brand flaw']) {
    assert.equal(matchIntelligence([article(title)], [vm], [], [], {}, custom).length, 1);
  }
});

test('news preserves product symbols while accepting separators and Unicode normalization', () => {
  const cpp = asset('microsoft', 'visual_c++');
  for (const title of ['Microsoft Visual C# flaw', 'Microsoft Visual C flaw']) {
    assert.equal(matchIntelligence([article(title)], [cpp], []).length, 0, title);
  }
  for (const title of ['Microsoft Visual C++ flaw', 'Microsoft Visual-C++ flaw', 'Microsoft Visual Ｃ＋＋ flaw', '#Microsoft Visual C++ flaw']) {
    assert.equal(matchIntelligence([article(title)], [cpp], []).length, 1, title);
  }
  const sharp = asset('microsoft', 'visual_c#');
  assert.equal(matchIntelligence([article('Microsoft Visual C++ flaw')], [sharp], []).length, 0);
  assert.equal(matchIntelligence([article('Microsoft Visual C# flaw')], [sharp], []).length, 1);
});
