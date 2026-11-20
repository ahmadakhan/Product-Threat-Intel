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
