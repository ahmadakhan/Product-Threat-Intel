import test from 'node:test';
import assert from 'node:assert/strict';
import { feedSchema } from '../server/validation.ts';

const feed = (rateLimitPerMin: number) => ({
  name: 'VulnCheck NVD++',
  type: 'VULNCHECK_NVD' as const,
  url: 'https://api.vulncheck.com/v3/index/nist-nvd2',
  authType: 'BEARER' as const,
  rateLimitPerMin,
  enabled: true,
});

test('the feed editor accepts a rate limit up to 5,000 requests per minute', () => {
  assert.equal(feedSchema.parse(feed(5000)).rateLimitPerMin, 5000);
  assert.equal(feedSchema.parse(feed(1000)).rateLimitPerMin, 1000, 'the previous ceiling still works');
  assert.equal(feedSchema.parse(feed(1)).rateLimitPerMin, 1);
  assert.equal(feedSchema.safeParse(feed(5001)).success, false, 'beyond 5,000 is refused');
  assert.equal(feedSchema.safeParse(feed(0)).success, false, 'zero is refused');
  assert.equal(feedSchema.safeParse(feed(12.5)).success, false, 'fractional rates are refused');
});
