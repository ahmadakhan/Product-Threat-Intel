import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { loadConfig, mergeAllowedHosts } from '../server/config.ts';
import { RECOMMENDED_FEEDS } from '../server/recommendedFeeds.ts';

const baseEnv = () => ({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'https://vulnstream.internal',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  WORKER_ENABLED: 'false',
});

const hosts = (value: string) => new Set(value.split(',').map((host) => host.trim().toLowerCase()));

test('every catalogued threat feed host is allowed without an extra configuration step', () => {
  const allowed = hosts(loadConfig(baseEnv()).EGRESS_ALLOWED_HOSTS);
  const missing = RECOMMENDED_FEEDS.map((feed) => new URL(feed.url).hostname.toLowerCase()).filter(
    (host) => !allowed.has(host),
  );
  assert.deepEqual(missing, [], `feed hosts missing from EGRESS_ALLOWED_HOSTS: ${missing.join(', ')}`);
});

test('the feed catalog does not widen egress beyond its own hosts', () => {
  const allowed = hosts(loadConfig(baseEnv()).EGRESS_ALLOWED_HOSTS);
  assert.equal(allowed.has('*'), false, 'no wildcard entry');
  assert.equal(allowed.has('evil.test'), false, 'an unrelated host stays blocked');
  // A host that merely ends with an allowed name must not match: membership is
  // exact, not a suffix or subdomain rule.
  assert.equal(allowed.has('notservices.nvd.nist.gov'), false);
});

test('operator additions still union with the defaults and the catalog', () => {
  const merged = hosts(
    loadConfig({ ...baseEnv(), EGRESS_ALLOWED_HOSTS_EXTRA: 'feeds.example.test, API.OSV.dev' })
      .EGRESS_ALLOWED_HOSTS,
  );
  assert.equal(merged.has('feeds.example.test'), true, 'operator additions are included');
  assert.equal(merged.has('api.osv.dev'), true, 'defaults survive the extra merge');
  assert.equal(merged.has('api.vulncheck.com'), true, 'a catalogued feed host is included');
});

test('an explicit EGRESS_ALLOWED_HOSTS stays a restricted list', () => {
  const allowed = hosts(
    loadConfig({ ...baseEnv(), EGRESS_ALLOWED_HOSTS: 'internal.example.test' }).EGRESS_ALLOWED_HOSTS,
  );
  assert.deepEqual([...allowed], ['internal.example.test'], 'an explicit list replaces the defaults');
  assert.equal(allowed.has('api.osv.dev'), false, 'the catalog is not added to an explicit list');
});

test('mergeAllowedHosts accepts arrays and comma-separated lists in one call', () => {
  assert.equal(
    mergeAllowedHosts('a.test, B.test', ['c.test', ' a.test '], ''),
    'a.test,b.test,c.test',
    'entries are lowercased, trimmed and de-duplicated across both shapes',
  );
});
