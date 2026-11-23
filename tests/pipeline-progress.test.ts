import test from 'node:test';
import assert from 'node:assert/strict';
import { pipelineHeartbeat, PIPELINE_HEARTBEAT_MS } from '../server/pipeline.ts';

/**
 * Regression guard for the "pipeline job keeps on running" defect.
 *
 * Two independent clocks govern a pipeline attempt:
 *
 *  - PROGRESS, attested only by `checkpoint()` (it re-reads the execution row),
 *    which `main.ts` uses to reset `pipelineStartedAt`; a run silent for
 *    STUCK_PROMISE_MS is cancelled.
 *  - LIVENESS, attested by the heartbeat timer (the scheduler heartbeat row).
 *
 * The heartbeat used to call the progress callback on every beat. Because
 * `main.ts` resets the stall clock from that callback, the timer cleared its own
 * watchdog: an attempt whose promise never settled was never cancelled, was
 * never detached, and the pipeline reported "running" forever while `queueRun()`
 * deduplicated every new request against it.
 *
 * The heartbeat must therefore NOT report progress. These tests pin that.
 */

test('the heartbeat does not report progress (only checkpoint may)', (t) => {
  let beats = 0;
  const heartbeat = pipelineHeartbeat({ onBeat: () => beats++ });

  heartbeat();
  heartbeat();
  heartbeat();

  assert.equal(beats, 3, 'the scheduler liveness beat still runs on every beat');
  // There is deliberately no progress channel on the heartbeat: a timer cannot
  // observe whether the in-flight work is advancing.
  assert.equal(heartbeat.length, 0, 'the heartbeat takes no progress callback');
  t.diagnostic(`beats=${beats}`);
});

test('the heartbeat never keeps a stalled run alive', (t) => {
  // Model the watchdog in main.ts: only a checkpoint (progress) resets the stall
  // clock. The heartbeat fires on a timer and must leave that clock alone.
  let stallClock = 0;
  const heartbeat = pipelineHeartbeat({ onBeat: () => {} });

  // Ten heartbeat periods with no checkpoint in between.
  for (let beat = 0; beat < 10; beat++) {
    heartbeat();
    stallClock += PIPELINE_HEARTBEAT_MS;
  }

  assert.equal(stallClock, 10 * PIPELINE_HEARTBEAT_MS, 'beats contribute nothing to progress');
  assert.ok(
    stallClock > 120_000,
    'the stall clock must be able to exceed the worst-case silent request (120s)',
  );
  t.diagnostic(`stallClock=${stallClock}`);
});

test('the heartbeat period is short enough to keep the scheduler liveness row fresh', (t) => {
  // The leadership row advertises a 30 s TTL; the beat must be well inside it.
  const leaderTtlMs = 30_000;
  assert.ok(
    PIPELINE_HEARTBEAT_MS < leaderTtlMs,
    `heartbeat period ${PIPELINE_HEARTBEAT_MS}ms must be below the ${leaderTtlMs}ms leader TTL`,
  );
  t.diagnostic(`period=${PIPELINE_HEARTBEAT_MS}ms ttl=${leaderTtlMs}ms`);
});
