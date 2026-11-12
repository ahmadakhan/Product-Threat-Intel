import test from 'node:test';
import assert from 'node:assert/strict';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { matchIntelligence } from '../src/utils/intelligenceMatcher.ts';
import { deriveCorrelationAliases } from '../src/utils/aliasLifecycle.ts';
import { buildAliasMap } from '../src/utils/cpeMatcher.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { IntelligenceArticle, NormalizedCVE, WatchListItem, ThreatFeed } from '../src/types/index.ts';

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


test('CVE text fallback preserves symbols and word boundaries before dispatch', () => {
  const source = { id: 'vc', name: 'VC', type: 'VULNCHECK_NVD', enabled: true } as ThreatFeed;
  const run = (product: string, title: string) => runVulnerabilityPipeline(
    [source], [advisory({ title, description: title, cpeMatches: [], sourceFeeds: ['vc'] })],
    [asset('microsoft', product)], [], [], { ...DEFAULT_SETTINGS, scopeHours: 0 },
  ).newFindings;
  for (const product of ['visual_c++', 'visual_c#', 'visual_c']) {
    const own = product.replace('_', ' ');
    assert.equal(run(product, `Microsoft ${own} vulnerability`)[0]?.notificationStatus, 'QUEUED_FOR_DISPATCH');
    for (const other of ['visual c++', 'visual c#', 'visual c'].filter((name) => name !== own)) {
      assert.equal(run(product, `Microsoft ${other} vulnerability`).length, 0, `${product} vs ${other}`);
    }
  }
  assert.equal(run('visual_c++', '#Microsoft Visual Ｃ＋＋ vulnerability').length, 1);
  assert.equal(run('visual_c++', 'Microsoft Visual C+++ vulnerability').length, 0);
});

test('news alias caches are isolated per operator table', () => {
  const gateway = asset('xgateway', 'gateway');
  const story = article('Xenon Gateway flaw');
  assert.equal(matchIntelligence([story], [gateway], [], [], { xgateway: ['xenon'] }).length, 1);
  assert.equal(
    matchIntelligence([story], [gateway], [], [], { xgateway: ['otherbrand'] }).length,
    0,
    'a previous operator alias table must not leak into the next lookup',
  );
  assert.equal(matchIntelligence([story], [gateway], [], [], { xgateway: ['xenon'] }).length, 1);
});

test('correlation aliases use only the matched criterion of a multi-product CVE', () => {
  const watch = asset('cisco', 'gateway');
  const record = advisory({
    cpeMatches: [cpe('cisco_systems', 'gateway'), cpe('cisco_systems', 'gateway_agent')],
  });
  const [matched] = runVulnerabilityPipeline([], [record], [watch], [], [], { ...DEFAULT_SETTINGS, scopeHours: 0 }).newFindings;
  assert.ok(matched);
  assert.equal(matched.matchingMethod, 'VENDOR_PRODUCT_ALIAS');
  const confirmed = { ...matched, autoDispatchedAt: now.toISOString(), notificationStatus: 'AUTO_DISPATCHED' as const };
  const learned = deriveCorrelationAliases([confirmed], [watch], new Map([[record.cveId, record]]));
  assert.equal(buildAliasMap(learned, 'PRODUCT').gateway?.includes('gateway_agent') ?? false, false);
  assert.deepEqual(deriveCorrelationAliases([{ ...confirmed, matchedCpe: '' }], [watch]), []);
  assert.deepEqual(deriveCorrelationAliases([{ ...confirmed, matchedCpe: cpe('cisco_systems', 'removed_product') }], [watch]), []);
});
