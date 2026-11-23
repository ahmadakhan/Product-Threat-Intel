import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveStudioTemplate } from '../src/context/AppContext.tsx';
import { DEFAULT_DAILY_DIGEST_TEMPLATE } from '../src/utils/templateCompiler.ts';

/**
 * Regression guard for the Daily Digest Studio showing a STALE template.
 *
 * The studio's document used to be derived as
 * `localOverride || compile(customization)` - the server-saved body
 * (`snapshot.dailyDigestCustomTemplate`) was never consulted. A browser whose
 * local copy was empty or out of date therefore kept rendering an old document
 * even after the canonical template was saved, while the "Live Rendering Active"
 * badge (driven by the customization, not the template) looked healthy.
 *
 * The server snapshot is now the saved source of truth, with an in-memory
 * override only for an unsaved "Apply to Preview". These tests pin that order.
 */

const compiled = () => '<!DOCTYPE html><html><body>compiled</body></html>';

test('a server-saved template is shown when no unsaved override exists', (t) => {
  const saved = '<!DOCTYPE html><html><body>saved-on-server</body></html>';
  const resolved = resolveStudioTemplate(null, saved, compiled);

  assert.equal(resolved, saved, 'the server snapshot must win over the compiled default');
  assert.notEqual(resolved, compiled(), 'the compiled document must not shadow the saved body');
  t.diagnostic(`resolved=${resolved.slice(0, 40)}...`);
});

test('a saved canonical template is shown verbatim (new template, not stale)', (t) => {
  // The new canonical document, exactly as the server would persist it.
  const resolved = resolveStudioTemplate(undefined, DEFAULT_DAILY_DIGEST_TEMPLATE, compiled);
  assert.equal(resolved, DEFAULT_DAILY_DIGEST_TEMPLATE);
  assert.match(resolved, /BA Security Advisory/);
  t.diagnostic('canonical template rendered from the snapshot');
});

test('an unsaved override beats the saved template', (t) => {
  const saved = '<!DOCTYPE html><html><body>saved</body></html>';
  const override = '<!DOCTYPE html><html><body>edited-not-saved</body></html>';

  assert.equal(
    resolveStudioTemplate(override, saved, compiled),
    override,
    'Apply to Preview must show the unsaved body until it is saved or discarded',
  );
  t.diagnostic('override wins');
});

test('with nothing saved the compiled customization is used', (t) => {
  for (const empty of [null, undefined, '']) {
    assert.equal(
      resolveStudioTemplate(null, empty, compiled),
      compiled(),
      `an empty saved value (${String(empty)}) must fall through to the compiled document`,
    );
  }
});

test('clearing the override falls back to the saved template, not to the stale one', (t) => {
  const saved = '<!DOCTYPE html><html><body>saved-after-save</body></html>';
  // A saved custom body survives; only the override is cleared on save.
  assert.equal(resolveStudioTemplate(null, saved, compiled), saved);
  // Discarding everything returns to the compiled default.
  assert.equal(resolveStudioTemplate(null, null, compiled), compiled());
});

test('the compiled thunk is not evaluated when a template is already available', (t) => {
  let compiledCalls = 0;
  const counting = () => {
    compiledCalls++;
    return compiled();
  };

  resolveStudioTemplate(null, '<html>saved</html>', counting);
  resolveStudioTemplate('<html>override</html>', null, counting);
  assert.equal(compiledCalls, 0, 'compilation must only run when it is the selected source');

  resolveStudioTemplate(null, null, counting);
  assert.equal(compiledCalls, 1);
  t.diagnostic(`compiledCalls=${compiledCalls}`);
});
