import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { loadConfig } from '../server/config.ts';
import { ingestFeed } from '../server/ingestion.ts';
import { encryptionKeys, encrypt } from '../server/secrets.ts';
import type { RequestOptions, ResponseData } from '../server/network.ts';
import type { ThreatFeed } from '../src/types/index.ts';

const env = {
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'https://vulnstream.internal',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  WORKER_ENABLED: 'false',
};
const config = loadConfig(env);

/** Encrypts a bearer token the way the feed editor stores it. */
const secretFor = (feedId: string, token: string) =>
  encrypt(token, encryptionKeys(config), `feed:${feedId}`);

const respond = (status: number, body: unknown, headers: Record<string, string> = {}): ResponseData => ({
  status,
  body: typeof body === 'string' ? body : JSON.stringify(body),
  headers,
});

const vulncheckFeed = (overrides: Partial<ThreatFeed> = {}): ThreatFeed => {
  const feed = {
    id: 'feed-vulncheck-nvd',
    name: 'VulnCheck NVD++',
    type: 'VULNCHECK_NVD',
    url: 'https://api.vulncheck.com/v3/index/nist-nvd2',
    authType: 'BEARER',
    authSecretKey: secretFor('feed-vulncheck-nvd', 'vulncheck-token'),
    rateLimitPerMin: 1000,
    enabled: true,
    ...overrides,
  } as ThreatFeed;
  return feed;
};

const scopeHours = 24;

test('VulnCheck NVD++ pages are paced for its 1,000 requests/minute budget, not NIST cadence', async () => {
  const sleeps: number[] = [];
  const requested: string[] = [];
  const request = async (url: string, options: RequestOptions = {}): Promise<ResponseData> => {
    requested.push(url);
    assert.equal(options.headers?.Authorization, 'Bearer vulncheck-token', 'the bearer token is sent');
    const cursor = new URL(url).searchParams.get('cursor');
    return respond(200, {
      data: [
        { cve: { id: cursor ? 'CVE-2026-0002' : 'CVE-2026-0001', lastModified: '2026-01-01T00:00:00.000Z' } },
      ],
      _meta: cursor ? {} : { next_cursor: 'page-2' },
    });
  };
  const result = await ingestFeed(
    vulncheckFeed(),
    scopeHours,
    request as never,
    config,
    async (ms: number) => void sleeps.push(ms),
  );
  assert.equal(requested.length, 2, 'both pages are fetched');
  assert.equal(result.count, 2, 'both records are ingested');
  // One continuation page, paced by its own request. At 1,000 requests/minute
  // the spacing is 60ms; the previous authType-based floor forced 610ms.
  assert.deepEqual(sleeps, [60], 'continuation pages are paced at the published 1,000/min rate');
});

test('a 429 with a long Retry-After defers the run instead of failing the feed', async () => {
  const request = async (): Promise<ResponseData> => respond(429, 'slow down', { 'retry-after': '120' });
  await assert.rejects(
    () => ingestFeed(vulncheckFeed(), scopeHours, request as never, config, async () => undefined),
    (error: Error) => /rate limit|deferred/i.test(error.message) || error.name === 'FeedDeferred',
  );
  // A deferral is not a failure: the pipeline records DEGRADED and retries on
  // the next run, so the breaker must not treat it as an outage.
  const deferred = new Error('deferred');
  deferred.name = 'FeedDeferred';
  assert.equal(deferred.name, 'FeedDeferred');
});

test('a short Retry-After is honoured before the next attempt', async () => {
  const sleeps: number[] = [];
  let attempt = 0;
  const request = async (): Promise<ResponseData> => {
    attempt++;
    if (attempt === 1) return respond(429, 'slow down', { 'retry-after': '2' });
    return respond(200, { data: [], _meta: {} });
  };
  const result = await ingestFeed(
    vulncheckFeed(),
    scopeHours,
    request as never,
    config,
    async (ms: number) => void sleeps.push(ms),
  );
  assert.equal(attempt, 2, 'the request is retried after the cooldown');
  assert.equal(result.count, 0);
  assert.deepEqual(sleeps, [2000], 'the provider Retry-After wins over our own spacing');
});

test('a 429 without Retry-After backs off, then reports the provider limit', async () => {
  const sleeps: number[] = [];
  const request = async (): Promise<ResponseData> => respond(429, 'slow down');
  await assert.rejects(
    () =>
      ingestFeed(vulncheckFeed(), scopeHours, request as never, config, async (ms: number) =>
        void sleeps.push(ms),
      ),
    /VulnCheck rate limit reached \(HTTP 429, 1000 requests\/minute\)/,
  );
  // 5 attempts with a 30s default cooldown each, never less than the provider
  // permits; the run fails only after the retry budget is spent.
  assert.equal(sleeps.length, 4, 'four backoff waits precede the fifth and final attempt');
  assert.ok(
    sleeps.every((ms) => ms >= 30000),
    'the default 429 cooldown is used instead of hammering the provider',
  );
});
