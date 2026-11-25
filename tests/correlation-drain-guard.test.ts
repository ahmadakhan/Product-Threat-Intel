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
 *  - a cancellation observed before a claim means no batch is processed, and the
 *    pass still exits and clears its own cancel handle.
 *
 * The runtime is driven with a stubbed pool; no statement reaches a database.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CorrelationRuntime } from '../server/correlation/runtime.ts';

interface DrainInternals {
  drain: () => Promise<void>;
  drainPass: (isCancelled: () => boolean) => Promise<void>;
  cleanupStaleMatches: () => Promise<void>;
  queueNotifications: () => Promise<void>;
  maybeRunRetention: () => Promise<void>;
  cancelDrain?: () => void;
  pool: { query: (sql: string, params?: unknown[]) => Promise<{ rows: unknown[] }> };
  processor: { processAdvisoryStream: (...args: unknown[]) => Promise<unknown> };
}

/** A base64 32-byte key: the dead-letter queue refuses to construct without one. */
const KEY = Buffer.alloc(32, 5).toString('base64');

const asInternals = (runtime: CorrelationRuntime) => runtime as unknown as DrainInternals;

const stubRuntime = () =>
  new CorrelationRuntime({ query: async () => ({ rows: [] }) } as never, [KEY], 'unused');

/** Replaces the drain stages with recorders so no database work happens. */
const recordStages = (calls: string[]) => ({
  cleanupStaleMatches: async () => void calls.push('cleanup'),
  queueNotifications: async () => void calls.push('notify'),
  maybeRunRetention: async () => void calls.push('retention'),
});

test('a pass cancelled before it starts takes no work', async () => {
  const calls: string[] = [];
  const state = asInternals(stubRuntime());
  Object.assign(state, recordStages(calls));
  let queries = 0;
  state.pool.query = async () => {
    queries++;
    return { rows: [{ count: 0 }] };
  };

  await state.drainPass(() => true);

  assert.deepEqual(calls, [], 'no stage may run for an already-cancelled pass');
  assert.equal(queries, 0, 'an already-cancelled pass must not query the database');
});

test('a pass cancelled part-way runs no further stage', async () => {
  const calls: string[] = [];
  const state = asInternals(stubRuntime());
  Object.assign(state, recordStages(calls));
  state.pool.query = async () => ({ rows: [{ count: 0 }] });

  let checks = 0;
  // Checkpoints: (1) before cleanup, (2) after cleanup, (3) after notify. Cancel
  // at the third, so both earlier stages complete and nothing after them runs.
  await state.drainPass(() => ++checks > 2);

  assert.deepEqual(calls, ['cleanup', 'notify'], 'no stage after the cancellation point may run');
});

test('cancellation is observed before a claim, so no batch is processed', async () => {
  const runtime = stubRuntime();
  const state = asInternals(runtime);
  Object.assign(state, recordStages([]));

  let claimed = 0;
  state.pool.query = async (input: unknown) => {
    // `claimPending` passes a wrapper rather than plain text; never assume a string.
    const sql = typeof input === 'string' ? input : String((input as { text?: string })?.text ?? '');
    if (sql.includes('correlation_pending') && sql.includes('UPDATE')) {
      claimed++;
      return { rows: [{ id: 'p1', payload: {} }] };
    }
    return { rows: [{ count: 0 }] };
  };
  let ingested = 0;
  state.processor.processAdvisoryStream = async () => {
    ingested++;
    return undefined;
  };

  // Cancel as soon as the pass starts running; the loop must observe it before
  // taking a batch.
  let checks = 0;
  await state.drainPass(() => ++checks > 3);

  assert.equal(claimed, 0, 'a cancelled pass must not claim a batch');
  assert.equal(ingested, 0, 'a cancelled pass must not ingest');
});

test('the running pass exposes a cancel handle and clears it on exit', async () => {
  const runtime = stubRuntime();
  const state = asInternals(runtime);
  Object.assign(state, recordStages([]));
  state.pool.query = async () => ({ rows: [{ count: 0 }] });

  const pass = state.drain();
  assert.equal(typeof state.cancelDrain, 'function', 'a running pass must expose cancelDrain');
  state.cancelDrain?.();
  await pass;
  assert.equal(state.cancelDrain, undefined, 'the pass clears its own cancel handle when it exits');
});
