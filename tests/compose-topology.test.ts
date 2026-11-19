import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Host capacity and topology are deployment contracts, not preferences: an
 * unlimited db/proxy can consume the host, a second app instance duplicates
 * background work, and a bundled Prometheus is deliberately not shipped.
 * Keep these assertions mechanical so a later edit cannot quietly undo them.
 */
const compose = readFileSync(new URL('../compose.yaml', import.meta.url), 'utf8');

/** Slice one top-level service block (indented two spaces) out of compose.yaml. */
function serviceBlock(name: string): string {
  const start = compose.indexOf(`\n  ${name}:`);
  assert.notEqual(start, -1, `compose.yaml must define a ${name} service`);
  const rest = compose.slice(start + 1);
  const next = rest.search(/\n  [a-z][a-z0-9-]*:\n/);
  return next === -1 ? rest : rest.slice(0, next);
}

test('the app runs as a single instance with explicit 2 CPU / 2 GiB limits', () => {
  assert.match(compose, /^\s{6}replicas: 1$/m);
  assert.doesNotMatch(compose, /^\s{6}replicas: [2-9]\d*$/m);
  const app = serviceBlock('app');
  assert.match(app, /cpus: '2'/);
  assert.match(app, /memory: 2G/);
  assert.match(app, /NODE_OPTIONS: --expose-gc --max-old-space-size=1536/);
});

test('db and proxy have explicit CPU and memory limits', () => {
  for (const name of ['db', 'proxy']) {
    const block = serviceBlock(name);
    assert.match(block, /resources:/, `${name} must declare resources`);
    assert.match(block, /cpus:/, `${name} must limit CPU`);
    assert.match(block, /memory:/, `${name} must limit memory`);
  }
  assert.equal((compose.match(/^\s{8}limits:$/gm) ?? []).length, 3, 'db, app, and proxy all need limits');
});

test('Prometheus is not part of the Compose deployment', () => {
  assert.doesNotMatch(compose, /^\s{2}prometheus:$/m);
  assert.doesNotMatch(compose, /prometheus-data/);
  assert.doesNotMatch(compose, /PROMETHEUS_PORT/);
});
