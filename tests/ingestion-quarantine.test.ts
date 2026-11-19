import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { loadConfig } from '../server/config.ts';
import { ingestFeed, NVD_RECORD_QUARANTINE_LIMIT, NVD_WINDOW_QUARANTINE_LIMIT, NvdRecordRejected, rejectionKey } from '../server/ingestion.ts';
import { encryptionKeys, encrypt } from '../server/secrets.ts';
import type { ResponseData } from '../server/network.ts';
import type { ThreatFeed } from '../src/types/index.ts';

/**
 * A record a source keeps returning unparseable must neither be retired silently
 * (the original defect) nor block the source forever (the naive fix).
 *
 * The contract: the first attempts fail the window so the checkpoint stays before
 * the bad record; once the record's persisted rejection count reaches the limit
 * it is quarantined — reported in `rejections`, skipped, and the window advances.
 * A cascade of unparseable records fails the run instead of discarding a window.
 */

const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'https://vulnstream.internal',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  WORKER_ENABLED: 'false',
});

const feed = (): ThreatFeed =>
  ({
    id: 'feed-vulncheck-nvd',
    name: 'VulnCheck NVD++',
    type: 'VULNCHECK_NVD',
    url: 'https://api.vulncheck.com/v3/index/nist-nvd2',
    authType: 'BEARER',
    authSecretKey: encrypt('vulncheck-token', encryptionKeys(config), 'feed:feed-vulncheck-nvd'),
    rateLimitPerMin: 1000,
    enabled: true,
  }) as ThreatFeed;

const respond = (body: unknown): ResponseData => ({
  status: 200,
  body: JSON.stringify(body),
  headers: {},
});

/** One valid record and one that cannot normalize (no `published`). */
const providerWithBrokenRecord = (): ((url: string) => Promise<ResponseData>) => async (url: string) => {
  const cursor = new URL(url).searchParams.get('cursor');
  if (cursor) return respond({ data: [], _meta: {} });
  return respond({
    data: [
      {
        cve: {
          id: 'CVE-2026-0001',
          published: '2026-01-01T00:00:00.000Z',
          lastModified: '2026-01-01T00:00:00.000Z',
          descriptions: [{ lang: 'en', value: 'Valid record' }],
        },
      },
      { cve: { id: 'CVE-2026-0002', lastModified: '2026-01-01T00:00:00.000Z' } },
    ],
    _meta: {},
  });
};

const brokenKey = (() => {
  const hash = JSON.stringify({ cve: { id: 'CVE-2026-0002', lastModified: '2026-01-01T00:00:00.000Z' } });
  return rejectionKey('feed-vulncheck-nvd', hash, 'CVE-2026-0002');
})();

test('an unparseable record fails the window until its retry budget is spent', async () => {
  const seen: unknown[] = [];
  await assert.rejects(
    () =>
      ingestFeed(feed(), 24, providerWithBrokenRecord() as never, config, async () => undefined, [], undefined, {
        rejectedOccurrences: new Map(),
      }).catch((error: unknown) => {
        seen.push(error);
        throw error;
      }),
    (error: unknown) => error instanceof NvdRecordRejected,
  );
  const carried = (seen[0] as { rejections?: { cveId?: string }[] }).rejections ?? [];
  assert.equal(carried.length, 1, 'the rejection is reported with the failure');
  assert.equal(carried[0].cveId, 'CVE-2026-0002');
});

test('a record at the quarantine limit is skipped, reported, and the window advances', async () => {
  const result = await ingestFeed(feed(), 24, providerWithBrokenRecord() as never, config, async () => undefined, [], undefined, {
    rejectedOccurrences: new Map([[brokenKey, NVD_RECORD_QUARANTINE_LIMIT]]),
  });
  assert.equal(result.cves.length, 1, 'the readable record is ingested');
  assert.equal(result.cves[0].cveId, 'CVE-2026-0001');
  assert.equal(result.rejections?.length, 1, 'the quarantined record is still reported');
  assert.equal(result.rejections?.[0].cveId, 'CVE-2026-0002');
  assert.ok(result.syncState?.cursor, 'the checkpoint advances so the source can make progress');
});

test('a provider-wide break fails the run instead of discarding the window', async () => {
  const ids = Array.from({ length: NVD_WINDOW_QUARANTINE_LIMIT + 5 }, (_, index) => `CVE-2026-1${String(index).padStart(3, '0')}`);
  const request = async (url: string): Promise<ResponseData> => {
    const cursor = new URL(url).searchParams.get('cursor');
    if (cursor) return respond({ data: [], _meta: {} });
    // Every record is unparseable (no `published`).
    return respond({
      data: ids.map((id) => ({ cve: { id, lastModified: '2026-01-01T00:00:00.000Z' } })),
      _meta: {},
    });
  };
  // Each record has already spent its retry budget, so every one is a candidate
  // for quarantine; the window limit is what must stop the cascade.
  const occurrences = new Map<string, number>(
    ids.map((id) => [
      rejectionKey('feed-vulncheck-nvd', JSON.stringify({ cve: { id, lastModified: '2026-01-01T00:00:00.000Z' } }), id),
      NVD_RECORD_QUARANTINE_LIMIT,
    ]),
  );
  await assert.rejects(
    () => ingestFeed(feed(), 24, request as never, config, async () => undefined, [], undefined, { rejectedOccurrences: occurrences }),
    /more than \d+ unparseable records/,
  );
});
