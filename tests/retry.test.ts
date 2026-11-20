import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withRetry, withDbRetry } from '../server/retry.ts';
import type { Db } from '../server/db.ts';

/**
 * Retry primitive.
 *
 * Pins the properties that make it safe to use in a worker whose process now
 * exits on an unhandled rejection: no orphaned promise may be left running after
 * an attempt times out.
 */

test('a timed-out attempt is cancelled, not left running', async () => {
  let stopped = false;
  await assert.rejects(
    () =>
      withRetry(
        async (signal) => {
          signal?.addEventListener('abort', () => {
            stopped = true;
          });
          // Never settles on its own: only the abort ends it.
          await new Promise<void>((resolve) => signal?.addEventListener('abort', () => resolve()));
          throw signal?.reason;
        },
        { maxAttempts: 1, attemptTimeoutMs: 20 },
      ),
    /Attempt timeout/,
  );
  assert.equal(stopped, true, 'the work was asked to stop rather than abandoned');
});

test('a late rejection from an abandoned attempt cannot become unhandled', async () => {
  let unhandled = false;
  const onUnhandled = () => {
    unhandled = true;
  };
  process.on('unhandledRejection', onUnhandled);
  try {
    await assert.rejects(() =>
      withRetry(
        async () => {
          await new Promise((r) => setTimeout(r, 60));
          throw new Error('late failure after the attempt timed out');
        },
        { maxAttempts: 1, attemptTimeoutMs: 10 },
      ),
    );
    // Give the orphaned promise time to reject if it were still alive.
    await new Promise((r) => setTimeout(r, 120));
    assert.equal(unhandled, false, 'no orphaned rejection escaped');
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});

test('the caller\u2019s abort reason is preserved', async () => {
  const controller = new AbortController();
  const reason = new Error('Worker leadership lost');
  setTimeout(() => controller.abort(reason), 5);
  await assert.rejects(
    () => withRetry(async () => new Promise(() => { }), { maxAttempts: 3, baseDelayMs: 10, signal: controller.signal }),
    (error: unknown) => error === reason,
  );
});

test('withDbRetry refuses a checked-out client (a retry there yields 25P02)', async () => {
  const clientLike = { query: async () => undefined, release: () => { } } as unknown as Db;
  await assert.rejects(() => withDbRetry(clientLike, 'SELECT 1'), /requires a pool/);
});

test('non-retryable errors fail immediately instead of consuming the budget', async () => {
  let calls = 0;
  await assert.rejects(
    () =>
      withRetry(
        async () => {
          calls++;
          throw Object.assign(new Error('permission denied'), { code: '42501' });
        },
        { maxAttempts: 5, baseDelayMs: 1 },
      ),
    /permission denied/,
  );
  assert.equal(calls, 1, 'a permission error is not transient');
});

test('a caller abort during an attempt is terminal, not a retryable failure', async () => {
  const controller = new AbortController();
  let calls = 0;
  const reason = new Error('Worker leadership lost');
  const started = Date.now();
  const run = withRetry(
    async (signal) => {
      calls++;
      // Stay in flight until the caller aborts, then reject the way a real
      // aborted operation does: with an AbortError, which `isRetryable` treats as
      // transient. The loop must still stop, and must not sleep the backoff.
      await new Promise<void>((resolve) => signal?.addEventListener('abort', () => resolve()));
      throw Object.assign(new Error('aborted'), { name: 'AbortError' });
    },
    { maxAttempts: 8, baseDelayMs: 500, signal: controller.signal },
  );
  setTimeout(() => controller.abort(reason), 10);
  await assert.rejects(run, (error: unknown) => error === reason);
  assert.equal(calls, 1, 'no further attempts are made after a caller abort');
  assert.ok(Date.now() - started < 400, 'it does not sleep through the backoff first');
});

test('the backoff sleep is cancelled when the caller aborts mid-sleep', async () => {
  // Without `abortableDelay` the backoff was a bare setTimeout that could not be
  // interrupted: a shutdown that arrived during the sleep waited out the whole
  // remaining delay, so a worker could hang for up to maxDelayMs after being
  // asked to stop. The delay must reject with the caller's reason as soon as
  // the signal aborts.
  const controller = new AbortController();
  const reason = new Error('Worker leadership lost');
  const started = Date.now();
  const run = withRetry(
    async () => {
      throw new Error('socket hang up');
    },
    { maxAttempts: 5, baseDelayMs: 5000, maxDelayMs: 5000, signal: controller.signal },
  );
  setTimeout(() => controller.abort(reason), 10);
  await assert.rejects(run, (error: unknown) => error === reason);
  assert.ok(Date.now() - started < 400, 'the backoff is interrupted instead of sleeping 5s');
});

test('the backoff sleep is cancelled when the caller aborts mid-sleep (short delay)', async () => {
  const controller = new AbortController();
  const reason = new Error('shutdown');
  const started = Date.now();
  const run = withRetry(
    async () => {
      throw new Error('socket hang up');
    },
    { maxAttempts: 5, baseDelayMs: 10000, maxDelayMs: 10000, signal: controller.signal },
  );
  setTimeout(() => controller.abort(reason), 5);
  await assert.rejects(run, (error: unknown) => error === reason);
  assert.ok(Date.now() - started < 400, 'a 10s backoff is cut short by the abort');
});

test('maxAttempts must be an integer greater than or equal to 1', async () => {
  await assert.rejects(() => withRetry(async () => undefined, { maxAttempts: 0 }), /maxAttempts/);
  await assert.rejects(() => withRetry(async () => undefined, { maxAttempts: -1 }), /maxAttempts/);
  await assert.rejects(() => withRetry(async () => undefined, { maxAttempts: 1.5 }), /maxAttempts/);
  await assert.rejects(() => withRetry(async () => undefined, { maxAttempts: '3' as unknown as number }), /maxAttempts/);
});

test('retry delays must be finite, non-negative, and maxDelayMs must be >= baseDelayMs', async () => {
  await assert.rejects(
    () => withRetry(async () => undefined, { baseDelayMs: -1 }),
    /Retry delays must be finite/,
  );
  await assert.rejects(
    () => withRetry(async () => undefined, { maxDelayMs: 100, baseDelayMs: 200 }),
    /maxDelayMs must be >= baseDelayMs/,
  );
  await assert.rejects(
    () => withRetry(async () => undefined, { maxDelayMs: Number.POSITIVE_INFINITY }),
    /Retry delays must be finite/,
  );
});

test('jitterFactor must be between 0 and 1', async () => {
  await assert.rejects(() => withRetry(async () => undefined, { jitterFactor: -0.1 }), /jitterFactor/);
  await assert.rejects(() => withRetry(async () => undefined, { jitterFactor: 1.1 }), /jitterFactor/);
});

test('a valid delay configuration is accepted and the result is returned', async () => {
  let calls = 0;
  const result = await withRetry(
    async () => {
      calls++;
      if (calls < 3) throw new Error('socket hang up');
      return 'ok';
    },
    { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 },
  );
  assert.equal(result, 'ok');
  assert.equal(calls, 3);
});

test('the delay is bounded by maxDelayMs even when jitter would push it over', async () => {
  // The old calculateDelay added jitter to the capped delay without re-capping,
  // so a delay of maxDelayMs + up to jitterFactor*maxDelayMs could be slept.
  // The result must never exceed the configured maximum.
  const delays: number[] = [];
  let attempts = 0;
  await withRetry(
    async () => {
      attempts++;
      if (attempts < 4) throw new Error('socket hang up');
      return 'ok';
    },
    {
      maxAttempts: 6,
      baseDelayMs: 1000,
      maxDelayMs: 1000,
      jitterFactor: 1,
      onRetry: (_attempt, _error, delayMs) => delays.push(delayMs),
    },
  );
  assert.ok(delays.length >= 3, 'the backoff ran for the failed attempts');
  for (const delay of delays) assert.ok(delay <= 1000, `delay ${delay} exceeded maxDelayMs`);
});
