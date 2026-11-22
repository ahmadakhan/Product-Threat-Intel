import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_EMAIL_RETRY_POLICY,
  emailRetryDelayPlan,
  emailRetryDelayMs,
  emailRetryPolicy,
  emailRetrySchedule,
  observedRetryDelay,
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

test('ML retry recommendations are capped by the operator maximum and identify their source', () => {
  const policy = emailRetryPolicy({ emailRetryMaxDelayMinutes: 60 });
  assert.deepEqual(emailRetryDelayPlan(2, policy, 120 * 60_000), {
    delayMs: 60 * 60_000,
    source: 'ML_CAPPED',
  });
  assert.deepEqual(emailRetryDelayPlan(2, policy, 20 * 60_000), {
    delayMs: 20 * 60_000,
    source: 'ML',
  });
  const result = emailRetryDelayPlan(2, policy);
  assert.equal(result.source, 'OPERATOR');
  assert.ok(result.delayMs >= 0 && result.delayMs <= 2 * 60_000, `delayMs ${result.delayMs} out of bounds`);
});

test('first attempt is not reported as an observed zero-delay training sample', () => {
  assert.deepEqual(observedRetryDelay(null, 1000), { delayMs: 0, observed: false });
  assert.deepEqual(observedRetryDelay('1970-01-01T00:00:00.500Z', 1000), {
    delayMs: 500,
    observed: true,
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
  const ceilingMs = 10 * 60_000;
  const delays = [1, 2, 3, 4, 5].map((attempt) => emailRetryDelayMs(attempt, policy));
  // Each jittered delay must be within [0, deterministic base delay ceiling].
  for (const [i, delayMs] of delays.entries()) {
    const base = Math.min(ceilingMs, 2 * 60_000 * 2 ** i);
    assert.ok(delayMs >= 0 && delayMs <= base, `attempt ${i + 1}: delayMs ${delayMs} out of [0, ${base}]`);
  }
  // Schedule has one entry per attempt, each a valid minute within the ceiling.
  const schedule = emailRetrySchedule(policy);
  assert.equal(schedule.length, 8);
  for (const entry of schedule) {
    const minutes = Number(entry.replace('m', ''));
    assert.ok(minutes >= 0 && minutes <= 10, `schedule entry ${entry} out of [0, 10]`);
  }
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
  assert.equal(legacy.digestBatchingEnabled, true);
  assert.equal(legacy.digestWindowMinutes, 5);
});
