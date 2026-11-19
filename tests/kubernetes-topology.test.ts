import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * The Kubernetes manifest is an alternative deployment path, not a second
 * topology: it must match the single-instance, 2 CPU / 2 GiB, GC-enabled app
 * contract used by Compose. A disruption budget must not block node drains
 * when there is only one pod to evict.
 */
const manifest = readFileSync(
  new URL('../deploy/kubernetes/ha.yaml', import.meta.url),
  'utf8',
);

test('the Kubernetes StatefulSet runs one bounded instance', () => {
  assert.match(manifest, /^\s{2}replicas: 1$/m);
  assert.doesNotMatch(manifest, /^\s{2}replicas: [2-9]\d*$/m);
  assert.match(manifest, /--expose-gc/);
  assert.match(manifest, /--max-old-space-size=1536/);
  assert.match(manifest, /limits: \{cpu: '2', memory: 2Gi\}/);
});

test('the disruption budget allows maintenance with one instance', () => {
  assert.match(manifest, /maxUnavailable: 1/);
  assert.doesNotMatch(manifest, /minAvailable: 1/);
});
