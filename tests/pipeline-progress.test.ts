import test from 'node:test';
import assert from 'node:assert/strict';
import { pipelineHeartbeat, PIPELINE_HEARTBEAT_MS } from '../server/pipeline.ts';

/**
 * Regression guard: a healthy pipeline must not be cancelled by the
 * supervisor's stuck-promise backstop.
 *
 * `server/main.ts` aborts a run whose `onProgress` has not fired within
 * STUCK_PROMISE_MS. `checkpoint()` — the original source of progress — only
 * runs at request boundaries, so one slow source request produced no signal at
 * all and a healthy run was cancelled as if wedged. The heartbeat timer is the
 * evidence that the run is still alive, and it must hand that evidence to
 * `onProgress` on every beat.
 */

test('the pipeline heartbeat reports progress on every beat', (t) => {
  const beats: string[] = [];
  let progress = 0;
  const heartbeat = pipelineHeartbeat(() => { progress++; }, {
    onBeat: () => beats.push('db'),
  });

  heartbeat();
  heartbeat();
  heartbeat();

  assert.equal(progress, 3, 'every beat must report progress, not just the first');
  assert.equal(beats.length, 3, 'the database heartbeat still runs on every beat');
  t.diagnostic(`progress=${progress} beats=${beats.length}`);
});

test('the heartbeat reports progress even when the database beat is gated', (t) => {
  // The real timer skips the DB round-trip while one is still pending. That
  // gating must not suppress the liveness signal, or a slow database would
  // make a healthy run look wedged again.
  let progress = 0;
  const heartbeat = pipelineHeartbeat(() => { progress++; }, { onBeat: () => {} });

  heartbeat();
  heartbeat();
  assert.equal(progress, 2);
  t.diagnostic(`progress=${progress}`);
});

test('a pipeline without a progress callback still heartbeats', (t) => {
  let beats = 0;
  const heartbeat = pipelineHeartbeat(undefined, { onBeat: () => { beats++; } });
  assert.doesNotThrow(() => heartbeat());
  assert.equal(beats, 1);
  t.diagnostic(`beats=${beats}`);
});

test('the heartbeat period is short enough to outpace the stuck-promise backstop', (t) => {
  // main.ts defaults STUCK_PROMISE_MS to 15 minutes. The heartbeat must fire
  // many times inside that window for the backstop to ever observe liveness.
  const stuckPromiseDefaultMs = 15 * 60_000;
  const signalsWithinWindow = Math.floor(stuckPromiseDefaultMs / PIPELINE_HEARTBEAT_MS);
  assert.ok(
    signalsWithinWindow >= 10,
    `expected several progress signals per stuck-promise window, got ${signalsWithinWindow}`,
  );
  t.diagnostic(`${signalsWithinWindow} signals per ${stuckPromiseDefaultMs / 60_000}-minute window`);
});
