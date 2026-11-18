import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { loadConfig } from '../server/config.ts';
import { ingestFeed } from '../server/ingestion.ts';
import { encryptionKeys, encrypt } from '../server/secrets.ts';
import type { ResponseData } from '../server/network.ts';
import type { ThreatFeed } from '../src/types/index.ts';

const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'https://vulnstream.internal',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  WORKER_ENABLED: 'false',
});

const feed: ThreatFeed = {
  id: 'feed-vulncheck-nvd',
  name: 'VulnCheck NVD++',
  type: 'VULNCHECK_NVD',
  url: 'https://api.vulncheck.com/v3/index/nist-nvd2',
  authType: 'BEARER',
  authSecretKey: encrypt('vulncheck-token', encryptionKeys(config), 'feed:feed-vulncheck-nvd'),
  rateLimitPerMin: 1000,
  enabled: true,
} as ThreatFeed;

const respond = (body: unknown, status = 200): ResponseData => ({
  status,
  body: JSON.stringify(body),
  headers: {},
});

/**
 * A provider that always has another page. `page(id)` yields a page whose only
 * record is derived from the cursor, so the test can tell which page arrived.
 */
const endlessProvider = (pageCount: number) => {
  const requested: string[] = [];
  const request = async (url: string): Promise<ResponseData> => {
    const cursor = new URL(url).searchParams.get('cursor');
    requested.push(cursor ?? 'FIRST');
    const n = Number((cursor ?? '0').replace('page-', '')) || 0;
    if (n >= pageCount) return respond({ data: [], _meta: {} });
    return respond({
      data: [{ cve: { id: `CVE-2026-${String(n + 1).padStart(4, '0')}`, lastModified: '2026-01-01T00:00:00.000Z' } }],
      _meta: { next_cursor: `page-${n + 1}` },
    });
  };
  return { request, requested };
};

test('a window larger than the page budget commits progress and resumes instead of failing', async () => {
  // 150 pages: more than the 100-page budget for a single run. The first page
  // comes from the conditional probe, and the budget counts the continuation
  // pages that follow it, so one run reads 101 records.
  const first = endlessProvider(150);
  const run1 = await ingestFeed(feed, 24, first.request as never, config, async () => undefined);
  assert.equal(run1.count, 101, 'one run ingests a full budget of pages rather than throwing');
  assert.equal(
    run1.syncState?.pageCursor,
    'page-101',
    'the next provider cursor is stored for the following run',
  );
  assert.equal(run1.syncState?.hasMore, true, 'the window is reported incomplete');
  assert.equal(
    run1.syncState?.cursor,
    undefined,
    'the checkpoint is not advanced past an incomplete window',
  );
  assert.equal(first.requested[0], 'FIRST', 'the first run starts from the conditional probe');

  // The next run resumes from the stored cursor, with no ETag round-trip.
  const second = endlessProvider(150);
  const run2 = await ingestFeed(
    feed,
    24,
    second.request as never,
    config,
    async () => undefined,
    [],
    undefined,
    { pageCursor: 'page-101', indexEtag: 'etag-from-run-1' as never },
  );
  assert.equal(
    second.requested[0],
    'page-101',
    'the resumed run continues from the stored cursor instead of restarting the window',
  );
  assert.ok(!second.requested.includes('FIRST'), 'a resumed run does not re-fetch the first page');
  assert.equal(run2.count, 49, 'the remainder of the window is ingested');
  assert.equal(run2.syncState?.pageCursor, undefined, 'a completed window clears the resume cursor');
  assert.ok(run2.syncState?.cursor, 'a completed window advances the checkpoint');
});

test('a window that fits in one run carries no resume cursor', async () => {
  const short = endlessProvider(3);
  const result = await ingestFeed(feed, 24, short.request as never, config, async () => undefined);
  assert.equal(result.count, 3);
  assert.equal(result.syncState?.pageCursor, undefined);
  assert.ok(result.syncState?.cursor, 'the checkpoint advances when the window is complete');
});
