/**
 * End-to-end matching coverage for the correlation pipeline.
 *
 * The pipeline has several identity paths (strict CPE, wildcard CPE, version
 * intervals, the alias thesaurus, PURL, and the vendor/product prose fallback)
 * plus the news/advisory evidence matcher. A candidate-prefilter regression in
 * any one of them silently drops a finding instead of failing loudly, so each
 * path is asserted independently here: a real match must produce a finding, and
 * a non-match must not.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { matchIntelligence } from '../src/utils/intelligenceMatcher.ts';
import { mergeCveRecords } from '../src/utils/deduplicator.ts';
import { syncMatchIndex } from '../server/versionIndex.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type {
  Finding,
  IntelligenceArticle,
  NormalizedCVE,
  ThreatFeed,
  WatchListItem,
} from '../src/types/index.ts';

const NOW = new Date('2026-11-12T12:00:00Z');
const settings = {
  ...DEFAULT_SETTINGS,
  scopeHours: 0,
  autoDispatchEnabled: true,
  autoDispatchUnverifiableMatches: true,
};

const cpe = (version = '1.5', vendor = 'acme', product = 'gateway') =>
  `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

function cveRecord(overrides: Partial<NormalizedCVE> = {}): NormalizedCVE {
  return {
    cveId: 'CVE-2026-4242',
    title: 'Acme gateway flaw',
    description: 'A flaw in Acme Gateway allows remote code execution.',
    publishedDate: NOW.toISOString(),
    modifiedDate: NOW.toISOString(),
    cvss: { version: '3.1', score: 9.8, severity: 'CRITICAL', vector: '' },
    cwe: [],
    cpeMatches: [cpe()],
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
    id: 'asset-1',
    assetTag: 'svc',
    vendor: 'acme',
    product: 'gateway',
    cpes: [cpe()],
    purls: [],
    ownerGroup: 'g',
    exposure: 'INTERNAL',
    active: true,
    version: '1.5',
    createdAt: NOW.toISOString(),
    ...overrides,
  } as WatchListItem;
}

const run = (
  corpus: NormalizedCVE[],
  inventory: WatchListItem[],
  existing: Finding[] = [],
  feeds: ThreatFeed[] = [],
  aliases: { vendor?: Record<string, string[]>; product?: Record<string, string[]> } = {},
) =>
  runVulnerabilityPipeline(
    feeds,
    corpus,
    inventory,
    [],
    existing,
    settings,
    'test worker',
    false,
    aliases.vendor ?? {},
    aliases.product ?? {},
    undefined,
    [],
    NOW,
  ).newFindings;

const article = (overrides: Partial<IntelligenceArticle> = {}): IntelligenceArticle =>
  ({
    id: 'article-1',
    title: 'Acme Gateway flaw',
    summary: 'A flaw in Acme Gateway is exploited.',
    url: 'https://example.com/article-1',
    publishedDate: NOW.toISOString(),
    modifiedDate: NOW.toISOString(),
    sourceFeeds: ['feed-rss'],
    cveIds: [],
    zeroDay: false,
    ...overrides,
  }) as IntelligenceArticle;

const news = (
  articles: IntelligenceArticle[],
  inventory: WatchListItem[] = [assetRecord()],
  findings: Finding[] = [],
  corpus: NormalizedCVE[] = [],
  aliases: { vendor?: Record<string, string[]>; product?: Record<string, string[]> } = {},
) =>
  matchIntelligence(
    articles,
    inventory,
    findings,
    corpus,
    aliases.vendor ?? {},
    aliases.product ?? {},
    0,
    NOW,
    undefined,
    new Map([['feed-rss', 'RSS_ATOM']]),
  );

/* ------------------------------------------------------- CPE identity paths */

test('strict CPE identity produces a finding', () => {
  assert.equal(run([cveRecord()], [assetRecord()]).length, 1);
});

test('a product-wide registration (wildcard version) matches a concrete advisory version', () => {
  assert.equal(run([cveRecord()], [assetRecord({ cpes: [cpe('*')] })]).length, 1);
});

test('a wildcard product in the advisory matches a concrete inventory CPE', () => {
  const cve = cveRecord({ cpeMatches: ['cpe:2.3:a:acme:*:*:*:*:*:*:*:*:*'] });
  assert.equal(run([cve], [assetRecord()]).length, 1);
});

test('a wildcard vendor in the advisory matches a concrete inventory CPE', () => {
  const cve = cveRecord({ cpeMatches: ['cpe:2.3:a:*:gateway:*:*:*:*:*:*:*:*'] });
  assert.equal(run([cve], [assetRecord()]).length, 1);
});

test('an inventory version inside the advisory interval matches', () => {
  const cve = cveRecord({
    cpeMatches: [cpe('*')],
    versionRange: { versionStartIncluding: '1.0', versionEndExcluding: '2.0' },
  });
  assert.equal(run([cve], [assetRecord()]).length, 1);
});

test('an inventory version outside the advisory interval is not reported', () => {
  const cve = cveRecord({
    cpeMatches: [cpe('*')],
    versionRange: { versionStartIncluding: '2.0', versionEndExcluding: '3.0' },
  });
  assert.equal(run([cve], [assetRecord()]).length, 0);
});

test('per-criterion ranges apply only to their own criterion', () => {
  const cve = cveRecord({
    cpeMatches: [],
    cpeMatchDetails: [
      { criteria: cpe('*', 'other', 'thing'), range: {} },
      { criteria: cpe('*'), range: { versionStartIncluding: '1.0', versionEndExcluding: '2.0' } },
    ],
  });
  assert.equal(run([cve], [assetRecord()]).length, 1);
});

test('an alias-resolved vendor/product produces a finding', () => {
  const cve = cveRecord({ cpeMatches: [cpe('1.5', 'acme_corp', 'gateway')] });
  const findings = run([cve], [assetRecord({ vendor: 'acme corp' })], [], [], {
    vendor: { 'acme corp': ['acme_corp'] },
  });
  assert.equal(findings.length, 1);
});

/* ------------------------------------------- criteria beyond cpeMatchDetails */

test('cpeMatches criteria missing from cpeMatchDetails still produce findings', () => {
  // A feed (for example a generic JSON_SEARCH_API record or a merged CVE from
  // two sources) can assert both fields with different criteria. The details
  // carry ranges, but the additional criterion is still an applicability claim.
  const cve = cveRecord({
    cpeMatches: [cpe('1.5', 'acme', 'gateway'), cpe('1.5', 'acme', 'widget')],
    cpeMatchDetails: [{ criteria: cpe('1.5', 'acme', 'gateway'), range: {} }],
  });
  assert.equal(run([cve], [assetRecord()]).length, 1, 'the detail criterion matches');
  assert.equal(
    run([cve], [assetRecord({ id: 'asset-2', product: 'widget', cpes: [cpe('1.5', 'acme', 'widget')] })])
      .length,
    1,
    'the extra criterion matches',
  );
});

test('merging two sources unions their criteria instead of dropping one', () => {
  const merged = [
    ...mergeCveRecords([
      cveRecord({
        sourceFeeds: ['feed-a'],
        cpeMatches: [cpe('1.5', 'acme', 'gateway')],
        cpeMatchDetails: [{ criteria: cpe('1.5', 'acme', 'gateway'), range: {} }],
      }),
      cveRecord({
        sourceFeeds: ['feed-b'],
        cpeMatches: [cpe('1.5', 'acme', 'widget')],
        cpeMatchDetails: [],
      }),
    ]).values(),
  ];
  assert.equal(merged.length, 1);
  const widget = assetRecord({ id: 'asset-2', product: 'widget', cpes: [cpe('1.5', 'acme', 'widget')] });
  assert.equal(run(merged, [widget]).length, 1);
});

/* ----------------------------------------------- prose and package evidence */

test('an advisory with no CPE data matches vendor/product in the prose', () => {
  const cve = cveRecord({ cpeMatches: [], cpeMatchDetails: [] });
  assert.equal(run([cve], [assetRecord()]).length, 1);
});

test('an advisory feed record with no CPE data produces a finding', () => {
  const feed = { id: 'feed-rss', type: 'RSS_ATOM' } as ThreatFeed;
  const cve = cveRecord({ cpeMatches: [], cpeMatchDetails: [], sourceFeeds: ['feed-rss'] });
  assert.equal(run([cve], [assetRecord()], [], [feed]).length, 1);
});

test('a package-only inventory item matches a package advisory', () => {
  const cve = cveRecord({
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: ['pkg:npm/lodash@4.17.20'],
  });
  const asset = assetRecord({
    id: 'asset-2',
    vendor: 'lodash',
    product: 'lodash',
    cpes: [],
    purls: ['pkg:npm/lodash@4.17.20'],
  });
  assert.equal(run([cve], [asset]).length, 1);
});

test('an inventory item whose CPE list is entirely malformed still matches by vendor/product', () => {
  // Bulk/legacy data can carry an unparseable CPE. Treating it as a structured
  // identifier made the candidate prefilter skip the asset forever.
  const malformed = assetRecord({ cpes: ['not-a-cpe'] });
  assert.equal(run([cveRecord()], [malformed]).length, 1);
  assert.equal(run([cveRecord({ cpeMatches: [], cpeMatchDetails: [] })], [malformed]).length, 1);
});

/* --------------------------------------------------- duplicates and lifecycle */

test('inactive inventory items are not matched', () => {
  assert.equal(run([cveRecord()], [assetRecord({ active: false })]).length, 0);
});

test('duplicate CVE rows for the same asset produce one finding', () => {
  assert.equal(run([cveRecord(), cveRecord()], [assetRecord()]).length, 1);
});

test('two CPEs on one asset matching one CVE still produce one finding', () => {
  const asset = assetRecord({ cpes: [cpe(), cpe('*')] });
  assert.equal(run([cveRecord()], [asset]).length, 1);
});

test('the same CVE arriving from two feeds produces one finding', () => {
  const rssFeed = { id: 'feed-rss', type: 'RSS_ATOM' } as ThreatFeed;
  const corpus = [
    cveRecord({ sourceFeeds: ['VULNCHECK_NVD'] }),
    cveRecord({ sourceFeeds: ['feed-rss'] }),
  ];
  assert.equal(run(corpus, [assetRecord()], [], [rssFeed]).length, 1);
});

test('re-running against an existing finding creates no duplicate', () => {
  const first = run([cveRecord()], [assetRecord()]);
  assert.equal(first.length, 1);
  assert.equal(run([cveRecord()], [assetRecord()], first).length, 0);
});

/* ------------------------------------------------------ news / RSS evidence */

test('vendor and product together in an article produce a news match', () => {
  assert.equal(news([article()]).length, 1);
});

test('a product mention alone does not produce a news match', () => {
  assert.equal(news([article({ title: 'Gateway flaw', summary: 'A gateway is broken.' })]).length, 0);
});

test('a pluralised product name still matches', () => {
  assert.equal(news([article({ title: 'Acme gateways under attack' })]).length, 1);
});

test('compound vendor and hyphenated product names still match', () => {
  const inventory = [
    assetRecord({ vendor: 'paloaltonetworks', product: 'pan-os', cpes: [cpe('*', 'paloaltonetworks', 'pan_os')] }),
  ];
  assert.equal(news([article({ title: 'Palo Alto Networks PAN-OS flaw' })], inventory).length, 1);
});

test('an operator alias extends news matching', () => {
  const inventory = [assetRecord({ vendor: 'xgateway', product: 'gateway' })];
  const matches = news([article({ title: 'Xenon Gateway flaw' })], inventory, [], [], {
    vendor: { xgateway: ['xenon'] },
  });
  assert.equal(matches.length, 1);
});

test('C++ and C remain distinct identities in article prose', () => {
  const inventory = [assetRecord({ vendor: 'microsoft', product: 'visual_c' })];
  assert.equal(news([article({ title: 'Microsoft Visual C++ runtime flaw' })], inventory).length, 0);
});

test('duplicate articles from multiple feeds merge into one match', () => {
  const matches = news([
    article(),
    article({ sourceFeeds: ['feed-rss', 'feed-other'] }),
  ]);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].articleIds.length, 1);
});

test('a CVE-linked article corroborates a structured finding', () => {
  const cve = cveRecord();
  const [finding] = run([cve], [assetRecord()]);
  const matches = news([article({ cveIds: [cve.cveId] })], [assetRecord()], [finding], [cve]);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].status, 'CORROBORATED');
});

test('a CVE-linked article matches when the advisory has no structured applicability', () => {
  const cve = cveRecord({ cpeMatches: [], cpeMatchDetails: [] });
  const matches = news([article({ cveIds: [cve.cveId] })], [assetRecord()], [], [cve]);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].status, 'REVIEW_REQUIRED');
});

test('news cannot override a structured exclusion for the asset', () => {
  const cve = cveRecord();
  const matches = news([article({ cveIds: [cve.cveId] })], [assetRecord()], [], [cve]);
  assert.equal(matches.length, 0);
});

/* -------------------------------------------------- PostgreSQL candidate index */

test('the candidate index includes criteria absent from cpeMatchDetails', async () => {
  const statements: { sql: string; values: unknown[] }[] = [];
  const db = {
    query: async (sql: string, values: unknown[] = []) => {
      statements.push({ sql, values });
      return { rows: [] };
    },
  } as never;
  const cve = cveRecord({
    cpeMatches: [cpe('1.5', 'acme', 'gateway'), cpe('1.5', 'acme', 'widget')],
    cpeMatchDetails: [{ criteria: cpe('1.5', 'acme', 'gateway'), range: {} }],
  });
  await syncMatchIndex(db, [cve], [assetRecord()]);
  const insert = statements.find((statement) => statement.sql.includes('INSERT INTO match_cve_index'));
  assert.ok(insert, 'the CVE index is written');
  const identities = insert!.values.filter(Array.isArray).flat();
  assert.ok(identities.includes('cpe:acme\u001fgateway'), 'detail criterion is indexed');
  assert.ok(identities.includes('cpe:acme\u001fwidget'), 'extra criterion is indexed');
  assert.ok(insert!.values.includes('cpe-extra-0'), 'the extra criterion gets its own row');
});

/* ------------------------------------------ declared identity / stale CPEs */

test('an asset whose declared product differs from a stale CPE still matches that identity', () => {
  // The operator-declared vendor/product is what the alias and prose matchers
  // read. Indexing only the CPE made the asset invisible to the candidate
  // prefilter before the matcher could evaluate it.
  const asset = assetRecord({ product: 'widget', cpes: [cpe('1.5', 'acme', 'gateway')] });
  const cve = cveRecord({ cpeMatches: [cpe('1.5', 'acme', 'widget')] });
  assert.equal(run([cve], [asset]).length, 1);
});

test('a package-only asset still matches a CPE advisory through its declared identity', () => {
  const asset = assetRecord({ cpes: [], purls: ['pkg:npm/lodash@4.17.20'] });
  assert.equal(run([cveRecord()], [asset]).length, 1);
});

test('the asset candidate index includes the declared vendor/product beside the CPE', async () => {
  const statements: { sql: string; values: unknown[] }[] = [];
  const db = {
    query: async (sql: string, values: unknown[] = []) => {
      statements.push({ sql, values });
      return { rows: [] };
    },
  } as never;
  const asset = assetRecord({ product: 'widget', cpes: [cpe('1.5', 'acme', 'gateway')] });
  await syncMatchIndex(db, [cveRecord({ cpeMatches: [cpe('1.5', 'acme', 'widget')] })], [asset]);
  const insert = statements.find((statement) => statement.sql.includes('INSERT INTO match_asset_index'));
  assert.ok(insert, 'the asset index is written');
  const identities = insert!.values.filter(Array.isArray).flat();
  assert.ok(identities.includes('cpe:acme\u001fwidget'), 'the declared identity is indexed');
  assert.ok(identities.includes('cpe:acme\u001fgateway'), 'the CPE identity is still indexed');
});

test('a declared version outside a concrete advisory criterion is not reported', () => {
  // A concrete criterion version is as authoritative as an interval. Before the
  // fix the alias path ignored it, so a 2.0 asset matched a 1.5-only advisory at
  // 85% confidence with no review gate.
  const asset = assetRecord({ cpes: [], version: '2.0' });
  assert.equal(run([cveRecord()], [asset]).length, 0);
});

test('a declared version matching a concrete advisory criterion is reported', () => {
  const asset = assetRecord({ cpes: [], version: '1.5' });
  assert.equal(run([cveRecord()], [asset]).length, 1);
});
