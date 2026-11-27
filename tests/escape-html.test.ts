import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { escapeHtml } from '../shared/escapeHtml.ts';

/**
 * There was one copy of this escape table per module (eleven in total). They
 * agreed at the time, but any later divergence — one copy dropping `'` — would
 * silently turn that module's interpolations into an injection point. Everything
 * now imports `shared/escapeHtml.ts`, and this test keeps it that way.
 */
test('escapeHtml covers every character that can break out of an attribute or tag', () => {
  assert.equal(escapeHtml('&'), '&amp;');
  assert.equal(escapeHtml('<'), '&lt;');
  assert.equal(escapeHtml('>'), '&gt;');
  assert.equal(escapeHtml('"'), '&quot;');
  assert.equal(escapeHtml("'"), '&#39;');
  // Ampersand is replaced first, so entities introduced above are not doubled.
  assert.equal(escapeHtml('&lt;'), '&amp;lt;');
  assert.equal(escapeHtml(`<a href="x" onclick='y'>`), '&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;');
  assert.equal(escapeHtml('Café — 危険'), 'Café — 危険', 'non-ASCII text is preserved');
});

test('no module defines its own HTML escape table any more', () => {
  const tracked = execFileSync('git', ['ls-files', 'server', 'src', 'shared'], { encoding: 'utf8' })
    .split('\n')
    .filter((file) => /\.(ts|tsx)$/.test(file) && file !== 'shared/escapeHtml.ts');
  const offenders = tracked.filter((file) => {
    const source = readFileSync(file, 'utf8');
    // A re-implementation of the entity table (the shared file is excluded above).
    return /&\s*':\s*'&amp;|'&':\s*'&amp;'/.test(source);
  });
  assert.deepEqual(offenders, [], `these files must import shared/escapeHtml.ts instead: ${offenders.join(', ')}`);
});
