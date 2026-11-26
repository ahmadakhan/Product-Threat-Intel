import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Host capacity and topology are deployment contracts, not preferences: an
 * unlimited db/proxy can consume the host, the API and worker services must
 * declare explicit limits so neither can starve the host, and a bundled
 * Prometheus is deliberately not shipped. Keep these assertions mechanical so
 * a later edit cannot quietly undo them.
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

test('the API service runs with explicit CPU and memory limits', () => {
  const app = serviceBlock('app');
  assert.match(app, /replicas:/);
  assert.match(app, /cpus: '1'/);
  assert.match(app, /memory: 1G/);
  assert.match(app, /NODE_OPTIONS: --expose-gc --max-old-space-size=1536/);
  assert.match(app, /WORKER_ENABLED:.*false/);
});

test('the worker service runs with explicit CPU and memory limits', () => {
  const worker = serviceBlock('worker');
  assert.match(worker, /replicas: 1/);
  assert.match(worker, /cpus: '2'/);
  assert.match(worker, /memory: 2G/);
  assert.match(worker, /WORKER_ENABLED:.*true/);
  assert.match(worker, /POOL_API_RESERVED_CONNECTIONS: 0/);
});

test('db, proxy, migrate, app and worker have explicit CPU and memory limits', () => {
  // Every service that consumes host resources must declare limits: db, app,
  // worker, proxy, and the one-shot migrate job (it runs a full migration pass
  // and should not be able to starve the host during an upgrade).
  const limited = ['db', 'migrate', 'app', 'worker', 'proxy'];
  for (const name of limited) {
    const block = serviceBlock(name);
    assert.match(block, /resources:/, `${name} must declare resources`);
    assert.match(block, /cpus:/, `${name} must limit CPU`);
    assert.match(block, /memory:/, `${name} must limit memory`);
  }
  assert.equal(
    (compose.match(/^\s{8}limits:$/gm) ?? []).length,
    limited.length,
    `${limited.join(', ')} each need an explicit limits block`,
  );
});

test('long-running services restart after a crash or host reboot', () => {
  for (const name of ['db', 'app', 'proxy']) {
    assert.match(serviceBlock(name), /restart: always/, `${name} must always restart`);
  }
  // migrate is a one-shot job; restarting it would loop forever.
  assert.match(serviceBlock('migrate'), /restart: 'no'/);
});

test('the app and proxy expose healthchecks the host healer can act on', () => {
  const app = serviceBlock('app');
  assert.match(app, /HANG_DETECTION_ENABLED: 'true'/);
  assert.match(app, /healthcheck:/);
  assert.match(app, /\/live/);
  assert.match(serviceBlock('proxy'), /healthcheck:/);
  assert.match(serviceBlock('proxy'), /nc -z 127\.0\.0\.1 80/);
});

test('the host healer service and timer are installed together', () => {
  const service = readFileSync(
    new URL('../deploy/vulnstream-compose-heal.service', import.meta.url),
    'utf8',
  );
  const timer = readFileSync(
    new URL('../deploy/vulnstream-compose-heal.timer', import.meta.url),
    'utf8',
  );
  assert.match(service, /heal-compose\.mjs/);
  assert.match(timer, /Unit=vulnstream-compose-heal\.service/);
  assert.match(timer, /OnBootSec=/);
});

test('Prometheus is not part of the Compose deployment', () => {
  assert.doesNotMatch(compose, /^\s{2}prometheus:$/m);
  assert.doesNotMatch(compose, /prometheus-data/);
  assert.doesNotMatch(compose, /PROMETHEUS_PORT/);
});
