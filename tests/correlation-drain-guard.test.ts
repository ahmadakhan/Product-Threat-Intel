/**
 * Regression tests for the correlation drain guard.
 *
 * The drain used to be bounded by `withHardTimeout`, which stops *awaiting* a
 * wedged pass but cannot stop it. Its `.finally` then cleared `this.draining`, so
 * the next tick started a replacement pass while the abandoned one was still
 * claiming batches, opening transactions and running a lease heartbeat. The tests
 * below pin the properties the fix relies on:
 *
 *  - a pass cancelled before it starts takes no work at all, and one cancelled
 *    part-way runs no further stage;
 *  - cancelling a pass makes it exit on its own, so the guard it holds is
 *    released by the pass and never by the timeout that gave up on it.
 *
 * The runtime is driven with a stubbed pool; no statement reaches a database.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CorrelationRuntime } from '../server/correlation/runtime.ts';

type DrainInternals = {
  drain: () => Promise<void>;
  drainPass: (isCancelled: () => boolean) => Promise<void>;
  cleanupStaleMatches: () => Promise<void>;
  queueNotifications: () => Promise<void>;
  maybeRunRetention: () => Promise<void>;
  cancelDrain?: () => void;
  draining?: Promise<void>;
  pool: { query: (sql: string, params?: unknown[]) => Promise<{ rows: unknown[] }> };
};

/** A base64 32-byte key: the dead-letter queue refuses to construct without one. */
const key = Buffer.alloc(32, 5).toString('base64');

const asInternals = (runtime: CorrelationRuntime) => runtime as unknown as DrainInternals;

const stubRuntime = () =>
  new CorrelationRuntime(
    { query: async () => ({ rows: [{ depth: 0 }] }) } as never,
    [key],
    'unused',
  );

/** Replaces the drain stages with recorders so no database work happens. */
function recordStages(calls: string[]) {
  return {
    cleanupStaleMatches: async () => void calls.push('cleanup'),
    queueNotifications: async () => void calls.push('notify'),
    maybeRunRetention: async () => void calls.push('retention'),
  };
}

test('a pass cancelled before it starts takes no work', async () => {
  const calls: string[] = [];
  const runtime = stubRuntime();
  const state = asInternals(runtime);
  Object.assign(state, recordStages(calls));
  // The exhausted-attempts probe is the only statement drainPass issues before
  // the first batch; it must not run either.
  let probes = 0;
  state.pool.query = async () => {
    probes++;
    return { rows: [{ count: 0 }] };
  };

  await state.drainPass(() => true);

  assert.deepEqual(calls, [], 'no stage may run for an already-cancelled pass');
  assert.equal(probes, 0, 'an already-cancelled pass must not query the database');
});

test('a pass cancelled part-way runs no further stage', async () => {
  const calls: string[] = [];
  const runtime = stubRuntime();
  const state = asInternals(runtime);
  Object.assign(state, recordStages(calls));
  state.pool.query = async () => ({ rows: [{ count: 0 }] });

  let checks = 0;
  // Checkpoints: (1) before cleanup, (2) after cleanup, (3) after notify. Let the
  // first two through and cancel at the third, so cleanup and notify both ran and
  // nothing after them did.
  await state.drainPass(() => ++checks > 2);

  assert.deepEqual(calls, ['cleanup', 'notify'], 'no stage after the cancellation point may run');
});

test('cancelling a running pass makes it exit and release its own guard', async () => {
  const runtime = stubRuntime();
  const state = asInternals(runtime);
  // A pass whose ingestion stage blocks until it observes the cancellation,
  // standing in for a wedged `processAdvisoryStream`.
  let started!: () => void;
  const ingestionStarted = new Promise<void>((resolve) => {
    started = resolve;
  });
  state.cleanupStaleMatches = async () => { };
  state.queueNotifications = async () => { };
  state.maybeRunRetention = async () => { };
  state.pool.query = async (input: unknown) => {
    // `claimPending` passes a `timedQuery` wrapper rather than a plain string, so
    // the stub must not assume the argument is text.
    const sql = typeof input === 'string' ? input : String((input as { text?: string })?.text ?? '');
    if (sql.includes('attempts')) return { rows: [{ count: 0 }] };
    if (sql.includes('count(*)')) return { rows: [{ depth: 0 }] };
    // `claimPending` (and anything else) blocks until cancellation is signalled.
    started();
    await new Promise<void>((resolve) => {
      const poll = () => (state.cancelDrain ? resolve() : setTimeout(poll, 5));
      poll();
    });
    return { rows: [] };
  };
  // `claimPending` blocks above, so ingestion is never reached. Record it anyway:
  // reaching it after cancellation would be the bug this test guards.
  const processor = (runtime as unknown as { processor: { processAdvisoryStream: unknown } }).processor;
  let ingested = false;
  processor.processAdvisoryStream = async () => {
    ingested = true;
  };

  const pass = state.drain();
  await ingestionStarted;
  assert.equal(typeof state.cancelDrain, 'function', 'the running pass must expose a cancel handle');

  // This is what the timeout handler does.
  state.cancelDrain?.();
  await pass;

  assert.equal(ingested, false, 'a cancelled pass must not start ingesting a batch');
  assert.equal(state.cancelDrain, undefined, 'the pass clears its own cancel handle when it exits');
});