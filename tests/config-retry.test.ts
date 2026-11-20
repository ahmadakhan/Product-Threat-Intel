import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../server/config.ts';
import { randomBytes } from 'node:crypto';

const baseEnv = {
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'https://vulnstream.internal',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  FEED_MAX_DURATION_SECONDS: '1800',
};

const throwsWithField = (field: string) => (error: unknown) => {
  if (!(error instanceof Error)) return false;
  const msgCheck = error.message.includes(field);
  if (msgCheck) return true;
  const issues = (error as { issues?: unknown }).issues;
  if (Array.isArray(issues)) {
    return issues.some(
      (issue: unknown) => {
        if (!issue || typeof issue !== 'object' || !('path' in issue)) return false;
        const path = (issue as { path?: unknown }).path;
        return Array.isArray(path) && path.includes(field);
      },
    );
  }
  return false;
};

test('FEED_RETRY_MAX_ATTEMPTS must be an integer 1..10', () => {
  assert.throws(() => loadConfig({ ...baseEnv, FEED_RETRY_MAX_ATTEMPTS: '0' }), throwsWithField('FEED_RETRY_MAX_ATTEMPTS'));
  assert.throws(() => loadConfig({ ...baseEnv, FEED_RETRY_MAX_ATTEMPTS: '11' }), throwsWithField('FEED_RETRY_MAX_ATTEMPTS'));
});

test('FEED_RETRY_BASE_DELAY_MS must be >= 0 and <= 60000', () => {
  assert.throws(() => loadConfig({ ...baseEnv, FEED_RETRY_BASE_DELAY_MS: '-1' }), throwsWithField('FEED_RETRY_BASE_DELAY_MS'));
  assert.throws(() => loadConfig({ ...baseEnv, FEED_RETRY_BASE_DELAY_MS: '60001' }), throwsWithField('FEED_RETRY_BASE_DELAY_MS'));
});

test('FEED_RETRY_MAX_DELAY_MS must be >= 0 and <= 120000', () => {
  assert.throws(() => loadConfig({ ...baseEnv, FEED_RETRY_MAX_DELAY_MS: '-1' }), throwsWithField('FEED_RETRY_MAX_DELAY_MS'));
  assert.throws(() => loadConfig({ ...baseEnv, FEED_RETRY_MAX_DELAY_MS: '120001' }), throwsWithField('FEED_RETRY_MAX_DELAY_MS'));
});

test('FEED_RETRY_MAX_DELAY_MS must be >= FEED_RETRY_BASE_DELAY_MS', () => {
  assert.throws(
    () =>
      loadConfig({
        ...baseEnv,
        FEED_RETRY_BASE_DELAY_MS: '5000',
        FEED_RETRY_MAX_DELAY_MS: '1000',
      }),
    (error: unknown) =>
      error instanceof Error && error.message.includes('FEED_RETRY_MAX_DELAY_MS must be >= FEED_RETRY_BASE_DELAY_MS'),
  );
});

test('FEED_RETRY_JITTER_FACTOR must be between 0 and 1', () => {
  assert.throws(() => loadConfig({ ...baseEnv, FEED_RETRY_JITTER_FACTOR: '-0.1' }), throwsWithField('FEED_RETRY_JITTER_FACTOR'));
  assert.throws(() => loadConfig({ ...baseEnv, FEED_RETRY_JITTER_FACTOR: '1.1' }), throwsWithField('FEED_RETRY_JITTER_FACTOR'));
});

test('valid FEED_RETRY settings are accepted with defaults', () => {
  const config = loadConfig(baseEnv);
  assert.equal(config.FEED_RETRY_MAX_ATTEMPTS, 3);
  assert.equal(config.FEED_RETRY_BASE_DELAY_MS, 2000);
  assert.equal(config.FEED_RETRY_MAX_DELAY_MS, 30000);
  assert.equal(config.FEED_RETRY_JITTER_FACTOR, 0.2);
});