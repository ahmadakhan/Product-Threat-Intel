import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findDuplicateFeedSource, feedSourceKey } from '../server/feedIdentity.ts';
import { RECOMMENDED_FEEDS } from '../server/recommendedFeeds.ts';

test('feed source identity ignores query ordering and fragments', () => {
  assert.equal(
    feedSourceKey('https://example.com/feed?b=2&a=1#latest'),
    feedSourceKey('https://example.com/feed?a=1&b=2'),
  );
});

test('duplicate feed lookup matches canonical endpoints but not the same record', () => {
  const existing = [{ id: 'existing', url: 'https://example.com/feed?b=2&a=1' }];
  assert.equal(
    findDuplicateFeedSource({ id: 'new', url: 'https://example.com/feed?a=1&b=2#latest' }, existing)?.id,
    'existing',
  );
  assert.equal(findDuplicateFeedSource({ id: 'existing', url: existing[0].url }, existing), undefined);
});

test('recommended feeds contain no duplicate endpoints and avoid one-request-per-minute caps', () => {
  const sources = RECOMMENDED_FEEDS.map((feed) => feedSourceKey(feed.url));
  assert.equal(new Set(sources).size, sources.length);
  assert.ok(RECOMMENDED_FEEDS.every((feed) =>
    feed.id === 'feed-github-advisories' ? feed.rateLimitPerMin === 1 : feed.rateLimitPerMin >= 3,
  ));
});

test('recommended public feeds are enabled while credentialed and known-unavailable feeds stay disabled', () => {
  const manualReview = new Set(['feed-twitter-security', 'feed-exploitdb']);
  for (const feed of RECOMMENDED_FEEDS) {
    const down = 'healthStatus' in feed && feed.healthStatus === 'DOWN';
    if (feed.authType !== 'NONE' || down || manualReview.has(feed.id))
      assert.equal(feed.enabled, false, `${feed.id} must stay disabled`);
    else if (feed.vendorSeed)
      assert.equal(feed.enabled, true, `${feed.id} should be enabled`);
  }
  // Every feed marked DOWN must be represented in the disabled catalog; this
  // prevents the enablement rule from silently re-enabling a dead source.
  assert.ok(RECOMMENDED_FEEDS.filter((feed) => 'healthStatus' in feed && feed.healthStatus === 'DOWN')
    .every((feed) => !feed.enabled));
  assert.ok(RECOMMENDED_FEEDS.some((feed) => feed.id === 'feed-cve-org' && !feed.enabled));
  assert.ok(RECOMMENDED_FEEDS.some((feed) => feed.id === 'feed-apple-security' && !feed.enabled));
  assert.ok(RECOMMENDED_FEEDS.some((feed) => feed.id === 'feed-adobe-security' && !feed.enabled));
});

test('recommended catalog includes the official CISA KEV and FIRST EPSS adapters', () => {
  assert.deepEqual(
    RECOMMENDED_FEEDS.filter((feed) => ['feed-cisa-kev', 'feed-epss'].includes(feed.id)).map((feed) => [
      feed.id,
      feed.type,
      feed.url,
      feed.enabled,
    ]),
    [
      ['feed-cisa-kev', 'CISA_KEV', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', true],
      ['feed-epss', 'EPSS_API', 'https://api.first.org/data/v1/epss', true],
    ],
  );
});
