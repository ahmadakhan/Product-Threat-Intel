import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../server/config.ts';

const base = {
  DATABASE_URL: 'postgresql://user:pass@localhost:5432/db',
  APP_ORIGIN: 'https://vulnstream.example.com',
  ENCRYPTION_KEY: Buffer.alloc(32, 3).toString('base64'),
  NODE_ENV: 'production',
} as const;

function captureWarnings(fn: () => void): string[] {
  const original = console.warn;
  const warnings: string[] = [];
  console.warn = (...args: unknown[]) => warnings.push(args.join(' '));
  try {
    fn();
  } finally {
    console.warn = original;
  }
  return warnings;
}

test('production without METRICS_TOKEN warns that /metrics will 404', (t) => {
  const warnings = captureWarnings(() =>
    loadConfig({ ...base, PATH: process.env.PATH } as NodeJS.ProcessEnv),
  );
  const warning = warnings.find((line) => line.includes('config.metrics_token_unset'));
  assert.ok(warning, `expected a metrics warning, got: ${JSON.stringify(warnings)}`);
  assert.match(warning, /404/);
  t.diagnostic(warning);
});

test('production with METRICS_TOKEN does not warn', (t) => {
  const warnings = captureWarnings(() =>
    loadConfig({
      ...base,
      METRICS_TOKEN: 'a'.repeat(48),
      PATH: process.env.PATH,
    } as NodeJS.ProcessEnv),
  );
  assert.equal(
    warnings.filter((line) => line.includes('metrics_token_unset')).length,
    0,
  );
  t.diagnostic(`warnings=${warnings.length}`);
});
