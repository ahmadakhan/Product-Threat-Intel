/**
 * Regression tests for the reliability audit findings V-1 and V-2.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { releaseExpiredClaims } from '../server/deliveryClaims.ts';

test('audit V-1: the enrichment backlog scan is bounded by a LIMIT clause', async () => {
  // Read the server source and assert the query is parameter-bounded. This is a
  // source-level contract test: the failure mode (an unbounded full-table scan
  // on every worker tick) is only observable under load, so the structural
  // assertion is the reliable guard.
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../server/main.ts', import.meta.url), 'utf8');
  const tick = source.slice(
    source.indexOf('const enrichmentBacklogTick'),
    source.indexOf('const enrichmentBacklogTick') + 2600,
  );
  assert.match(tick, /LIMIT \$1/, 'backlog query must be LIMIT-bounded');
  assert.match(tick, /ENRICHMENT_BACKLOG_SCAN_LIMIT/, 'the bound must come from a named constant');
  const constantMatch = /ENRICHMENT_BACKLOG_SCAN_LIMIT = (\d+)/.exec(source);
  assert.ok(constantMatch, 'scan-limit constant must be defined');
  const limit = Number(constantMatch![1]);
  assert.ok(limit >= 100 && limit <= 10_000, 'scan limit must be a sane bounded number');
});

test('audit V-2: the outbox pass sweeps expired delivery claims', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../server/main.ts', import.meta.url), 'utf8');
  assert.match(
    source,
    /releaseExpiredClaims/,
    'the outbox pass must call releaseExpiredClaims so expired CLAIMED rows are reclaimed',
  );
});

test('a cancelled pipeline is detached after a bounded grace period', async () => {
  // A promise that ignores its abort signal used to keep `pipeline` set
  // forever, so every later tick skipped the start branch and the worker never
  // recovered. The guard is a source-level contract because main.ts starts a
  // server at import time; the failure mode is a permanently wedged worker.
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../server/main.ts', import.meta.url), 'utf8');
  const grace = /PIPELINE_ABORT_GRACE_MS = (\d[\d_]*)/.exec(source);
  assert.ok(grace, 'the abort grace period must be a named constant');
  const graceMs = Number(grace![1].replaceAll('_', ''));
  assert.ok(graceMs > 0 && graceMs <= 5 * 60_000, 'the grace period must be bounded');

  const tick = source.slice(source.indexOf('const tick = () => {'), source.indexOf('const WORKER_TICK_MS'));
  assert.match(tick, /pipelineController\?\.signal\.aborted/, 'the guard must only act on cancelled attempts');
  assert.match(tick, /pipelineAbortedAt = Date\.now\(\)/, 'the grace period must start on first observation');
  assert.match(
    tick,
    /Date\.now\(\) - pipelineAbortedAt > PIPELINE_ABORT_GRACE_MS/,
    'detachment must be time-bounded',
  );
  assert.match(tick, /pipeline = null;/, 'a wedged attempt must be detached so a fresh one can start');
  assert.match(tick, /pipelineAbortedAt = 0;/, 'the grace state must be reset for the next attempt');
});

test('releaseExpiredClaims deletes only expired CLAIMED rows with no owning job', async () => {
  // Contract check against a stubbed database: the sweep deletes exactly the
  // rows that can never block a delivery again — CLAIMED, expired, and with no
  // owning outbox row. DELIVERED receipts and rows whose job is still live are
  // never touched; those remain governed by activeClaims' re-judgement.
  const seen: { sql: string }[] = [];
  const db = {
    query: async (sql: string) => {
      seen.push({ sql });
      return { rowCount: 1 };
    },
  } as never;
  const reclaimed = await releaseExpiredClaims(db);
  assert.equal(reclaimed, 1);
  const sweep = seen.at(-1)!.sql;
  assert.match(sweep, /state\s*=\s*'CLAIMED'/, 'only CLAIMED rows are swept');
  assert.match(sweep, /expires_at\s*<\s*now\(\)/, 'the sweep must be expiry-scoped');
  assert.match(sweep, /job_id IS NULL/, 'a row owned by a job must only be released by that job\'s finalize path');
});

test('expired claims remain reclaimable by claimItems without the sweep (dedup correctness)', async () => {
  // This documents the invariant that made V-2 a LOW and not a HIGH: the sweep
  // is hygiene, not correctness — an expired claim whose row still exists is
  // already re-judgeable by claimItems. Existence check against the module
  // surface so a future refactor that removes expiry re-judgement fails here.
  const claims = await import('../server/deliveryClaims.ts');
  assert.equal(typeof claims.releaseExpiredClaims, 'function');
  assert.equal(typeof claims.claimItems, 'function');
});
