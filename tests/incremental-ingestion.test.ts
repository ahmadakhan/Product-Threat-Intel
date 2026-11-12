import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ingestionWindow, SYNC_OVERLAP_MS } from '../server/ingestionState';
import { ingestFeed, normalizeNvd } from '../server/ingestion';
import { loadConfig } from '../server/config.ts';
import { encrypt } from '../server/secrets.ts';
import type { ThreatFeed } from '../src/types/index.ts';
const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused', APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64') });
const feed = (type: ThreatFeed['type']): ThreatFeed => ({ id: 'source', name: 'Source', type, url: type === 'VULNCHECK_NVD' ? 'https://api.vulncheck.com/v3/index/nist-nvd2' : 'https://example.com/cves', authType: type === 'VULNCHECK_NVD' ? 'BEARER' : 'NONE', authSecretKey: type === 'VULNCHECK_NVD' ? encrypt('vulncheck-test-token', [config.ENCRYPTION_KEY], 'feed:source') : undefined, rateLimitPerMin: 600, enabled: true, healthStatus: 'UNTESTED', lastSync: null, itemCountLastRun: 0, latencyMs: 0, vendorSeed: false, ssrfValidated: false });
const response = (data: unknown) => ({ status: 200, body: JSON.stringify(data), headers: { etag: 'index-v1' } });
const sleep = async () => {};

test('RSS ingestion identifies the real reader and preserves conditional fetches', async () => {
  const source = { ...feed('RSS_ATOM'), url: 'https://www.bleepingcomputer.com/feed/', etag: 'rss-v1' };
  const result = await ingestFeed(source, 24, async (url, options) => {
    assert.equal(url, source.url);
    assert.equal(options?.headers?.['user-agent'], 'VulnStream/1.0 RSS reader');
    assert.match(options!.headers!.accept, /application\/rss\+xml/);
    assert.equal(options?.headers?.['If-None-Match'], 'rss-v1');
    return {
      status: 200,
      body: `<rss version="2.0"><channel><title>Security News</title><item><title>Security update</title><link>https://www.bleepingcomputer.com/news/security/example/</link><pubDate>${new Date().toUTCString()}</pubDate></item></channel></rss>`,
      headers: { etag: 'rss-v2' },
    };
  }, config, sleep);
  assert.equal(result.articles?.length, 1);
  assert.equal(result.etag, 'rss-v2');
  await assert.rejects(ingestFeed(source, 24, async () => ({ status: 403, body: '<html>Forbidden</html>', headers: {} }), config, sleep), /HTTP 403/);
});

test('bootstrap is bounded and checkpoints catch up without gaps in bounded daily windows', () => {
  const now = Date.parse('2026-10-22T00:00:00Z');
  assert.equal(now - ingestionWindow(2880, {}, now).start.getTime(), 24 * 3600000);
  const checkpoint = now - 72 * 3600000;
  const window = ingestionWindow(24, { cursor: new Date(checkpoint).toISOString() }, now);
  assert.equal(window.start.getTime(), checkpoint - SYNC_OVERLAP_MS);
  assert.equal(window.end.getTime() - window.start.getTime(), 24 * 3600000);
  assert.equal(window.hasMore, true);
  assert.equal(ingestionWindow(24, { cursor: new Date(now + 3600000).toISOString() }, now).incremental, false);
});
test('NVD requests only changes since its checkpoint and reports the frozen end watermark', async () => {
  const cursor = new Date(Date.now() - 3600000).toISOString();
  let end = '';
  const result = await ingestFeed(feed('VULNCHECK_NVD'), 2880, async raw => {
    const url = new URL(raw);
    assert.equal(url.searchParams.get('lastModStartDate'), new Date(Date.parse(cursor) - SYNC_OVERLAP_MS).toISOString().slice(0, 10));
    end = url.searchParams.get('lastModEndDate')!;
    return response({ startIndex: 0, totalResults: 0, vulnerabilities: [], _meta: { next_cursor: null } });
  }, config, sleep, [], undefined, { cursor });
  assert.ok(result.syncState!.cursor!.startsWith(end));
  assert.equal(result.count, 0);
});
test('VULNCHECK_NVD skips unchanged content and advances the checkpoint on a 304', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  const record = (id: string) => ({ cve: { id, vulnStatus: 'Published', published: date, lastModified: date, descriptions: [{ lang: 'en', value: 'Test' }], configurations: [], metrics: [], references: [], weaknesses: [] } });
  const vulncheckUrl = 'https://api.vulncheck.com/v3/index/nist-nvd2';
  const request = async (url: string) =>
    url.startsWith(vulncheckUrl)
      ? response({ vulnerabilities: [record('CVE-2026-98001')], _meta: { next_cursor: null } })
      : response(record('CVE-2026-98001'));
  const first = await ingestFeed(feed('VULNCHECK_NVD'), 24, request, config, sleep);
  assert.equal(first.count, 1);
  // Unchanged content at the same revision is skipped through the content
  // comparison, not through the persisted revision map (which used to hide
  // same-lastModified corrections).
  const second = await ingestFeed(feed('VULNCHECK_NVD'), 24, request, config, sleep, [], undefined, {
    ...first.syncState,
    knownCveModifiedAt: new Map([['CVE-2026-98001', date]]),
    knownCveContent: new Map([['CVE-2026-98001', first.cves[0]]]),
  });
  assert.equal(second.count, 0, 'unchanged content is not re-emitted');
  assert.equal(second.cves.length, 0);
  let conditionalEtag = '';
  const unchanged = await ingestFeed(feed('VULNCHECK_NVD'), 24, async (_url, options) => {
    conditionalEtag = String(options!.headers!['If-None-Match']);
    return { status: 304, body: '', headers: {} };
  }, config, sleep, [], undefined, second.syncState);
  assert.equal(conditionalEtag, 'index-v1');
  assert.equal(unchanged.notModified, true);
  // A 304 must move the window forward; returning the old checkpoint made a
  // quiet feed re-request the same window indefinitely.
  assert.ok(unchanged.syncState?.cursor);
  assert.ok(
    Date.parse(unchanged.syncState!.cursor!) >= Date.parse(second.syncState!.cursor!),
    'the checkpoint advances instead of stalling on 304',
  );
  assert.equal(unchanged.syncState?.indexEtag, 'index-v1');
});

test('VULNCHECK_NVD re-ingests a same-revision correction despite a persisted revision map', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  const base = {
    cve: {
      id: 'CVE-2026-98002',
      vulnStatus: 'Published',
      published: date,
      lastModified: date,
      descriptions: [{ lang: 'en', value: 'Old description' }],
      configurations: [],
      metrics: [],
      references: [],
      weaknesses: [],
    },
  };
  const corrected = {
    ...base,
    cve: { ...base.cve, descriptions: [{ lang: 'en', value: 'Corrected description' }] },
  };
  const result = await ingestFeed(feed('VULNCHECK_NVD'), 24, async () =>
    response({ vulnerabilities: [corrected], _meta: { next_cursor: null } }), config, sleep, [], undefined, {
    revisions: { 'CVE-2026-98002': date },
    knownCveModifiedAt: new Map([['CVE-2026-98002', date]]),
    knownCveContent: new Map([['CVE-2026-98002', normalizeNvd(base, 'source')!]]),
  });
  assert.equal(result.cves.length, 1);
  assert.equal(result.cves[0].description, 'Corrected description');
});
test('VULNCHECK_NVD re-fetches revised records and paces paginated cursors', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  const ids = Array.from({ length: 8 }, (_, n) => `CVE-2026-${98001 + n}`);
  let waits = 0;
  const source = feed('VULNCHECK_NVD');
  const vulncheckUrl = 'https://api.vulncheck.com/v3/index/nist-nvd2';
  const record = (id: string) => ({ cve: { id, vulnStatus: 'Published', published: date, lastModified: date, descriptions: [{ lang: 'en', value: 'Test' }], configurations: [], metrics: [], references: [], weaknesses: [] } });
  // Two cursor pages: the first returns half the CVEs plus a next cursor, the
  // second returns the rest. Each page hop must honor the rate-limit pacing.
  const result = await ingestFeed(source, 24, async url => {
    if (url.startsWith(vulncheckUrl) && !new URL(url).searchParams.has('cursor'))
      return response({ vulnerabilities: ids.slice(0, 4).map(record), _meta: { next_cursor: 'page-2' } });
    if (url.includes('cursor=page-2'))
      return response({ vulnerabilities: ids.slice(4).map(record), _meta: { next_cursor: null } });
    throw new Error(`unexpected detail request: ${url}`);
  }, config, async ms => { assert.ok(ms > 0); waits++; }, [], undefined,
  { cursor: new Date(Date.now() - 3600000).toISOString() });
  assert.equal(result.count, 8, 'all records across cursor pages are counted');
  assert.equal(waits, 1, 'one paced wait between cursor pages');
});
test('EPSS reuses recent scores, queries newly matching CVEs, and refreshes on expiry', async () => {
  let calls = 0;
  const request = async (raw: string) => {
    calls++;
    const ids = new URL(raw).searchParams.get('cve')!.split(',');
    return response({ total: ids.length, data: ids.map(cve => ({ cve, epss: '0.1', percentile: '0.5' })) });
  };
  const first = await ingestFeed(feed('EPSS_API'), 24, request, config, sleep, ['CVE-2026-98001']);
  const second = await ingestFeed(feed('EPSS_API'), 24, request, config, sleep, ['CVE-2026-98001'], undefined, first.syncState);
  assert.equal(second.notModified, true);
  assert.equal(calls, 1);
  const third = await ingestFeed(feed('EPSS_API'), 24, request, config, sleep, ['CVE-2026-98001', 'CVE-2026-98002'], undefined, first.syncState);
  assert.deepEqual(third.epssScope, ['CVE-2026-98002']);
  assert.equal(third.syncState!.epssExpiresAt, first.syncState!.epssExpiresAt);
  const expired = { ...third.syncState, epssExpiresAt: new Date(Date.now() - 1000).toISOString() };
  const refreshed = await ingestFeed(feed('EPSS_API'), 24, request, config, sleep, ['CVE-2026-98001', 'CVE-2026-98002'], undefined, expired);
  assert.equal(calls, 3);
  assert.equal(refreshed.epssScope!.length, 2);
});
test('transient response resets retry without advancing a failed source checkpoint', async () => {
  let calls = 0, waits = 0;
  const result = await ingestFeed(feed('VULNCHECK_NVD'), 24, async () => {
    calls++;
    if (calls === 1) throw Object.assign(new Error('aborted'), { code: 'ECONNRESET' });
    return response({ startIndex: 0, totalResults: 0, vulnerabilities: [] });
  }, config, async () => { waits++; });
  assert.equal(calls, 2);
  assert.equal(waits, 1);
  assert.ok(result.syncState!.cursor);
  await assert.rejects(ingestFeed({ ...feed('VULNCHECK_NVD'), authType: 'API_KEY', authSecretKey: 'invalid-encrypted-data' }, 24, async () => { throw new Error('No network expected'); }, config, sleep), /re-enter the secret/);
});
