import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ModelRegistry } from '../server/ml/runtime.ts';

const metadata = {
  id: 'containment-model',
  type: 'logistic' as const,
  version: '2026.01.01',
  trainedAt: new Date().toISOString(),
  featureSchema: [],
  description: 'path containment test fixture',
};

/**
 * The manifest is local data, but a corrupted or tampered entry must not turn
 * into an arbitrary file read or delete. Both load and clear resolve paths
 * through the same containment check.
 */
test('manifest artifact paths cannot escape the model directory', async () => {
  const root = mkdtempSync(join(tmpdir(), 'ml-containment-'));
  const models = join(root, 'models');
  mkdirSync(models);
  const outside = join(root, 'outside.json');
  writeFileSync(
    outside,
    JSON.stringify({ metadata: { ...metadata, id: 'outside' }, weights: [1] }),
    'utf8',
  );
  writeFileSync(
    join(models, 'model-manifest.json'),
    JSON.stringify({
      'containment-model': {
        activeVersion: metadata.version,
        artifacts: [
          {
            version: metadata.version,
            path: '../outside.json',
            trainedAt: metadata.trainedAt,
            status: 'ACTIVE',
          },
        ],
      },
    }),
    'utf8',
  );

  try {
    let loaded = false;
    const registry = new ModelRegistry({ directory: models });
    const ok = await registry.loadArtifact(
      {
        load() {
          loaded = true;
        },
      },
      'containment-model',
    );
    assert.equal(ok, false, 'an escaping artifact must not load');
    assert.equal(loaded, false);
    assert.equal(existsSync(outside), true, 'load must not delete or touch the escaping file');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('saving an artifact with a traversing version is rejected', async () => {
  const root = mkdtempSync(join(tmpdir(), 'ml-containment-save-'));
  const models = join(root, 'models');
  mkdirSync(models);

  try {
    const registry = new ModelRegistry({ directory: models });
    await assert.rejects(
      () =>
        registry.save(
          { serialize: () => ({ metadata, weights: [1] }) } as never,
          'containment-model',
          { ...metadata, version: '../../escaped' },
        ),
      /escapes the model directory/,
    );
    assert.equal(existsSync(join(root, 'escaped.json')), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
