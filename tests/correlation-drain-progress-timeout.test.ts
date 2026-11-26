/**
 * Regression tests for the correlation drain stall watchdog.
 *
 * The watchdog used to be a one-shot wall-clock timer covering the whole pass.
 * When the event loop was busy - startup ingestion parsing feeds on the main
 * thread is the reproduction - both the awaited continuation and the timer were
 * delayed, so a healthy pass was abandoned and logged as CRITICAL
 * `pending.drain_timeout`. The watchdog now measures time since the last
 * progress checkpoint, and a pass must report a checkpoint after every awaited
 * step. These tests pin that contract:
 *
 *  - a pass that keeps reporting progress outlives the wall-clock budget;
 *  - a pass that stops reporting is aborted and rejected as a stall;
 *  - `drainPass` actually reports every stage boundary, so the budget can only
 *    expire while no awaited work completes.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { CorrelationRuntime, withProgressTimeout } from '../server/correlation/runtime.ts';

/** A base64 32-byte key: the dead-letter queue refuses to construct without one. */
const key = Buffer.alloc(32, 5).toString('base64');

test('progress checkpoints extend the deadline past the wall-clock budget', async () => {
  const startedAt = Date.now();
  let checkpoints = 0;
  const result = await withProgressTimeout(
    async (_signal, onProgress) => {
      // Six steps of 30ms outlive a 40ms budget, but progress is reported after
      // each one, so the watchdog must keep extending the deadline.
      for (let step = 0; step < 6; step++) {
        await delay(30);
        checkpoints++;
        onProgress();
      }
      return 'completed';
    },
    40,
    'test drain',
  );

  assert.equal(result, 'completed');
  assert.equal(checkpoints, 6, 'every step must have run');
  assert.ok(Date.now() - startedAt >= 120, 'the pass must have outlived one wall-clock budget');
});

test('a pass that stops reporting progress is aborted and rejected', async () => {
  let signal: AbortSignal | undefined;
  await assert.rejects(
    withProgressTimeout(
      (workSignal) => {
        signal = workSignal;
        // Never settles and never reports progress: the definition of a wedged
        // statement the watchdog exists to catch.
        return new Promise<never>(() => {});
      },
      60,
      'test drain',
    ),
    (error: Error) => {
      assert.equal(error.name, 'DrainTimeoutError');
      assert.match(error.message, /test drain made no progress for 60ms/);
      return true;
    },
  );
  assert.equal(signal?.aborted, true, 'the abandoned pass must be told to stop taking work');
});

test('drainPass reports progress after every awaited stage', async () => {
  const runtime = new CorrelationRuntime({ query: async () => ({ rows: [] }) } as never, [key], 'unused');
  const state = runtime as unknown as {
    drainPass: (isCancelled: () => boolean, onProgress?: () => void) => Promise<void>;
    cleanupStaleMatches: () => Promise<void>;
    queueNotifications: () => Promise<void>;
    maybeRunRetention: () => Promise<void>;
    pool: { query: (input: unknown, params?: unknown[]) => Promise<{ rows: unknown[] }> };
  };
  const stages: string[] = [];
  state.cleanupStaleMatches = async () => void stages.push('cleanup');
  state.queueNotifications = async () => void stages.push('notify');
  state.maybeRunRetention = async () => void stages.push('retention');
  state.pool.query = async (input: unknown) => {
    // `claimPending` and the sweep pass a `timedQuery` wrapper, not a string.
    const sql = typeof input === 'string' ? input : String((input as { text?: string })?.text ?? '');
    if (sql.includes('count(*)')) return { rows: [{ count: 0 }] };
    return { rows: [] };
  };

  let checkpoints = 0;
  await state.drainPass(
    () => false,
    () => void checkpoints++,
  );

  assert.deepEqual(stages, ['cleanup', 'notify', 'retention']);
  // Before cleanup, after cleanup, after notify, after the exhausted-attempts
  // probe, after retention, after the exhausted sweep, after the empty claim.
  assert.equal(checkpoints, 7, 'each awaited boundary must report a checkpoint');
});
