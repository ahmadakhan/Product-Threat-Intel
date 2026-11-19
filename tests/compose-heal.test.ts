import { test } from 'node:test';
import assert from 'node:assert/strict';

import { decideAction, parsePositiveInt, readState } from '../scripts/heal-compose.mjs';

const NOW = 1_700_000_000_000;
const options = { unhealthyThreshold: 2, restartCooldownMs: 5 * 60_000 };
const running = (health: string) => ({ running: true, restarting: false, health });
const unhealthy = running('unhealthy');

test('a stopped long-running service is started', () => {
  const result = decideAction(undefined, { running: false, restarting: false, health: 'none' }, NOW, options);
  assert.equal(result.action, 'start');
  assert.equal(result.state.unhealthyCount, 0);
});

test('a container Docker is already restarting is left alone', () => {
  const result = decideAction(
    { unhealthyCount: 4, lastRestartAt: 0 },
    { running: true, restarting: true, health: 'unhealthy' },
    NOW,
    options,
  );
  assert.equal(result.action, 'none');
  assert.equal(result.state.unhealthyCount, 0);
});

test('healthy and starting containers reset the failure counter', () => {
  for (const health of ['healthy', 'starting', 'none']) {
    const result = decideAction({ unhealthyCount: 2 }, running(health), NOW, options);
    assert.equal(result.action, 'none');
    assert.equal(result.state.unhealthyCount, 0);
  }
});

test('one unhealthy observation is not enough to restart', () => {
  const result = decideAction(undefined, unhealthy, NOW, options);
  assert.equal(result.action, 'none');
  assert.equal(result.state.unhealthyCount, 1);
});

test('consecutive unhealthy observations restart once the threshold is met', () => {
  const result = decideAction({ unhealthyCount: 1 }, unhealthy, NOW, options);
  assert.equal(result.action, 'restart');
  assert.equal(result.state.unhealthyCount, 0);
  assert.equal(result.state.lastRestartAt, NOW);
});

test('the restart cooldown prevents a restart loop while health recovers', () => {
  const state = { unhealthyCount: 1, lastRestartAt: NOW };
  const beforeCooldown = decideAction(state, unhealthy, NOW + 60_000, options);
  assert.equal(beforeCooldown.action, 'none');
  assert.equal(beforeCooldown.state.unhealthyCount, 2);

  const afterCooldown = decideAction(beforeCooldown.state, unhealthy, NOW + 5 * 60_000, options);
  assert.equal(afterCooldown.action, 'restart');
});

test('invalid environment numbers are rejected instead of becoming NaN', () => {
  assert.equal(parsePositiveInt(undefined, 2), 2);
  assert.equal(parsePositiveInt('3', 2), 3);
  assert.equal(parsePositiveInt('0', 2), null);
  assert.equal(parsePositiveInt('not-a-number', 2), null);
  assert.deepEqual(readState('/nonexistent/vulnstream-heal-state.json'), {});
});
