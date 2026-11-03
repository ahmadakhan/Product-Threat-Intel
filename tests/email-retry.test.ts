import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_EMAIL_RETRY_POLICY,
  emailRetryDelayMs,
  emailRetryPolicy,
  emailRetrySchedule,
} from '../server/delivery.ts';
import { settingsSchema } from '../server/validation.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';

test('email retry policy defaults apply to legacy settings', () => {
  assert.deepEqual(emailRetryPolicy(undefined), DEFAULT_EMAIL_RETRY_POLICY);
  assert.deepEqual(emailRetryPolicy({}), {
    enabled: true,
    maxAttempts: 6,
    initialDelayMinutes: 1,
    maxDelayMinutes: 60,
  });
});

test('email retry policy clamps invalid or out-of-range values', () => {
  const policy = emailRetryPolicy({
    emailRetryEnabled: false,
    emailRetryMaxAttempts: 999,
    emailRetryInitialDelayMinutes: 0,
    emailRetryMaxDelayMinutes: 0,
  });
  assert.deepEqual(policy, {
    enabled: false,
    maxAttempts: 20,
    initialDelayMinutes: 1,
    maxDelayMinutes: 1,
  });
  assert.deepEqual(emailRetrySchedule(policy), []);
});

test('email retry backoff doubles and respects the configured ceiling', () => {
  const policy = emailRetryPolicy({
    emailRetryEnabled: true,
    emailRetryMaxAttempts: 8,
    emailRetryInitialDelayMinutes: 2,
    emailRetryMaxDelayMinutes: 10,
  });
  assert.deepEqual(
    [1, 2, 3, 4, 5].map((attempt) => emailRetryDelayMs(attempt, policy)),
    [120_000, 240_000, 480_000, 600_000, 600_000],
  );
  assert.deepEqual(emailRetrySchedule(policy), ['2m', '4m', '8m', '10m', '10m', '10m', '10m', '10m']);
});

test('settings schema defaults retry fields and rejects an inverted delay range', () => {
  const legacy = settingsSchema.parse({
    ...DEFAULT_SETTINGS,
    emailRetryEnabled: undefined,
    emailRetryMaxAttempts: undefined,
    emailRetryInitialDelayMinutes: undefined,
    emailRetryMaxDelayMinutes: undefined,
  });
  assert.equal(legacy.emailRetryEnabled, true);
  assert.equal(legacy.emailRetryMaxAttempts, 6);
  assert.equal(legacy.emailRetryInitialDelayMinutes, 1);
  assert.equal(legacy.emailRetryMaxDelayMinutes, 60);

  assert.equal(
    settingsSchema.safeParse({
      ...DEFAULT_SETTINGS,
      emailRetryInitialDelayMinutes: 30,
      emailRetryMaxDelayMinutes: 10,
    }).success,
    false,
  );
});

test('settings schema applies digestWindowMinutes default for legacy settings', () => {
  const legacy = settingsSchema.parse({
    ...DEFAULT_SETTINGS,
    digestBatchingEnabled: undefined,
    digestWindowMinutes: undefined,
  });
  assert.equal(legacy.digestBatchingEnabled, false);
  assert.equal(legacy.digestWindowMinutes, 5);
});
