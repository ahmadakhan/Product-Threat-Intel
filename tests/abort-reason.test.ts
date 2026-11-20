import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setAbortReason, ABORT_REASON } from '../server/pipeline.ts';

/**
 * External abort classification.
 *
 * Every external cancel (leadership loss, shutdown, the stall watchdog) is
 * written as:
 *
 *     setAbortReason(controller);
 *     controller.abort(myReason);
 *
 * `setAbortReason` used to abort the controller itself when the signal was not
 * yet aborted, which made the caller's `abort(myReason)` a silent no-op and
 * replaced every cause with a generic "Operation exceeded its deadline". These
 * tests pin the two properties that failure violated.
 */

/** The exact call pattern from server/main.ts. */
function abortLikeMain(label: string): AbortController {
  const controller = new AbortController();
  setAbortReason(controller);
  const reason = Object.assign(new Error(label), { [ABORT_REASON]: true });
  controller.abort(reason);
  return controller;
}

test('an external abort keeps the caller\u2019s reason instead of substituting a deadline', () => {
  for (const label of ['Worker leadership lost', 'Pipeline cancelled during shutdown', 'Pipeline produced no progress']) {
    const { signal } = abortLikeMain(label);
    assert.equal(signal.aborted, true);
    assert.equal((signal.reason as Error).message, label, `reason for "${label}" must survive`);
    assert.equal((signal.reason as Error).name, 'Error', 'the cause must not be rewritten as a TimeoutError');
  }
});

test('setAbortReason does not abort a controller that is still running', () => {
  const controller = new AbortController();
  setAbortReason(controller);
  assert.equal(controller.signal.aborted, false, 'stamping must not cancel in-flight work');
});

test('an external abort carries the sentinel so it classifies as an abort, not a failure', () => {
  const { signal } = abortLikeMain('Worker leadership lost');
  assert.equal((signal.reason as { [ABORT_REASON]?: boolean })[ABORT_REASON], true);
});

test('a real timeout reason is left untouched', () => {
  const controller = new AbortController();
  controller.abort(Object.assign(new Error('too slow'), { name: 'TimeoutError' }));
  setAbortReason(controller);
  assert.equal((controller.signal.reason as Error).name, 'TimeoutError');
  assert.equal((controller.signal.reason as Error).message, 'too slow');
});
