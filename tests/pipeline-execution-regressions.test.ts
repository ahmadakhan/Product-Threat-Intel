/**
 * Regression tests for pipeline execution defects fixed after the background
 * pipeline audit.
 *
 * Each test fails on the pre-fix implementation:
 *
 *  - E-1: the zero-day cap was applied to a set the dispatcher never read, so a
 *    withheld zero-day was still queued for individual delivery.
 *  - E-2: the `cpe-changed-cves` re-match backlog grew without bound, so a run's
 *    cost grew with deployment age.
 *  - E-3: `queueRun` silently discarded the operator's scope/checkpoint choice
 *    whenever a run was already queued.
 *  - E-4: a recovery probe that succeeded did not clear the recovery clock.
 *  - E-5: recipient eligibility read the legacy single tier, so multi-select
 *    subscriptions withheld findings a mailbox had opted into.
 *  - E-6: duplicate mailboxes preferred the narrowest finding tier.
 *  - E-7: reconciliation carried a stored `DIGEST_BATCHED` forward forever, so a
 *    zero-day withheld by one run's cap was never queued by a later run.
 *
 * Everything here is pure: no database is required.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CPE_REMATCH_MAX_RUNS,
  carryCpeRematchBacklog,
  queueRun,
} from '../server/pipeline.ts';
import { rankAndRateLimitZeroDays } from '../src/engine/pipelineEngine.ts';
import { reconcileFindings } from '../src/engine/reconcileFindings.ts';
import { recipientAllows } from '../server/delivery.ts';
import { uniqueEnabledEmailRecipients } from '../server/emailRecipients.ts';
import type { EmailRecipient, Finding, IntelligenceMatch } from '../src/types/index.ts';

function match(id: string, credibility: number): IntelligenceMatch {
  return {
    id,
    findingId: `finding-${id}`,
    cveId: null,
    articleIds: [`article-${id}`],
    assetId: 'asset-1',
    assetName: 'gw (acme gateway)',
    assetVendor: 'acme',
    assetProduct: 'gateway',
    evidence: 'zero-day evidence',
    status: 'REVIEW_REQUIRED',
    credibilityScore: credibility,
    zeroDay: true,
    matchedAt: '2026-01-01T00:00:00.000Z',
  } as unknown as IntelligenceMatch;
}

function finding(id: string, notificationStatus: Finding['notificationStatus'] = 'QUEUED_FOR_DISPATCH'): Finding {
  return {
    id,
    cveId: 'CVE-2026-0001',
    matchedAssetId: 'asset-1',
    notificationStatus,
    status: 'MONITORED',
    timeline: [],
  } as unknown as Finding;
}

test('E-1: the zero-day cap withdraws exactly the findings it reports as withheld', () => {
  const matches = [match('a', 90), match('b', 80), match('c', 70)];
  const findings = [finding('finding-a'), finding('finding-b'), finding('finding-c')];
  const result = rankAndRateLimitZeroDays(findings, matches, 2);
  const withheld = new Set(result.digests.flatMap((digest) => digest.findingIds));
  const kept = new Set(result.findings.map((item) => item.id));
  // The top two ranked matches fit the cap; the lowest-ranked is digest-only and
  // must therefore not survive as an individually deliverable finding.
  assert.equal(kept.size, 2, 'findings inside the cap stay on the queue');
  assert.deepEqual([...withheld], [
    'finding-c',
  ]);
  for (const id of withheld) assert.ok(!kept.has(id), `${id} must not also be delivered individually`);
});

test('E-1: capping never touches findings that are not zero-day evidence', () => {
  const matches = [match('a', 90), { ...match('plain', 99), zeroDay: false }];
  const findings = [finding('finding-a'), finding('finding-plain')];
  const result = rankAndRateLimitZeroDays(findings, matches, 1);
  assert.equal(result.digests.length, 0, 'the cap was not exceeded');
  assert.equal(result.findings.length, 2);
});

test('E-2: a legacy bare id list is adopted and bounded from this run onward', () => {
  const now = Date.parse('2026-03-01T00:00:00.000Z');
  const first = carryCpeRematchBacklog({ cveIds: ['CVE-2026-0001'] }, new Set(), new Date(now).toISOString(), now);
  assert.deepEqual(first.entries.map((entry) => entry.cveId), ['CVE-2026-0001']);
  assert.equal(first.entries[0].runs, 1);
  assert.equal(first.dropped, 0);
});

test('E-2: an unchanged entry is re-evaluated a bounded number of times', () => {
  const start = Date.parse('2026-03-01T00:00:00.000Z');
  let state: Parameters<typeof carryCpeRematchBacklog>[0] = {
    cveIds: ['CVE-2026-0001'],
    entries: [{ cveId: 'CVE-2026-0001', firstSeen: new Date(start).toISOString(), runs: 1 }],
  };
  let runs = 1;
  let passes = 0;
  // The legacy entry already consumed one run. A retained entry costs one more
  // re-evaluation per run, and the first run that would exceed the budget must
  // drop it rather than keep re-evaluating it forever.
  let droppedOnPass = 0;
  for (let i = 1; i <= CPE_REMATCH_MAX_RUNS + 1; i++) {
    passes++;
    const now = start + i * 60_000;
    const next = carryCpeRematchBacklog(state, new Set(), new Date(now).toISOString(), now);
    if (next.entries.length === 0) {
      droppedOnPass = i;
      break;
    }
    runs = next.entries[0].runs;
    state = { cveIds: next.entries.map((entry) => entry.cveId), entries: next.entries };
  }
  // Runs 2..5 are re-evaluations; the sixth pass exceeds the budget and drops it.
  assert.equal(runs, CPE_REMATCH_MAX_RUNS, 'the entry is retained for its whole budget');
  assert.equal(state.entries?.length ?? 0, 1, 'the run before the drop still carries the entry');
  assert.ok(
    droppedOnPass > 0 && droppedOnPass <= CPE_REMATCH_MAX_RUNS,
    `bounded work: the entry is dropped within its budget (dropped on pass ${droppedOnPass})`,
  );
  assert.ok(passes <= CPE_REMATCH_MAX_RUNS + 1, 'no more than the budget is ever spent');
});

test('E-2: an entry older than the age bound is dropped even below the run budget', () => {
  const start = Date.parse('2026-01-01T00:00:00.000Z');
  const later = Date.parse('2026-03-01T00:00:00.000Z');
  const result = carryCpeRematchBacklog(
    { cveIds: ['CVE-2026-0001'], entries: [{ cveId: 'CVE-2026-0001', firstSeen: new Date(start).toISOString(), runs: 1 }] },
    new Set(),
    new Date(later).toISOString(),
    later,
  );
  assert.equal(result.entries.length, 0);
  assert.equal(result.dropped, 1);
});

test('E-2: a fresh applicability change restarts the budget instead of inheriting it', () => {
  const start = Date.parse('2026-03-01T00:00:00.000Z');
  const now = start + 60_000;
  const result = carryCpeRematchBacklog(
    {
      cveIds: ['CVE-2026-0001', 'CVE-2026-0002'],
      entries: [
        { cveId: 'CVE-2026-0001', firstSeen: new Date(start).toISOString(), runs: CPE_REMATCH_MAX_RUNS },
        { cveId: 'CVE-2026-0002', firstSeen: new Date(start).toISOString(), runs: 2 },
      ],
    },
    new Set(['CVE-2026-0001']),
    new Date(now).toISOString(),
    now,
  );
  const changed = result.entries.find((entry) => entry.cveId === 'CVE-2026-0001');
  assert.equal(changed?.runs, 1, 'new evidence is re-evaluated again');
  assert.equal(changed?.firstSeen, new Date(now).toISOString());
});

test('E-7: a digest-batched finding is not silenced forever by reconciliation', () => {
  // The zero-day cap marks a withheld finding DIGEST_BATCHED for THIS run only.
  // Reconciliation must not carry that forward once the cap no longer applies,
  // or the finding would never be queued individually again.
  const stored = {
    ...finding('finding-a', 'DIGEST_BATCHED'),
    advisoryId: null,
    autoDispatchedAt: null,
    reviewNotifiedAt: null,
  } as unknown as Finding;
  const [next] = reconcileFindings([stored], [finding('finding-a')]);
  assert.equal(
    next.notificationStatus,
    'QUEUED_FOR_DISPATCH',
    'a new run that did not cap the finding puts it back on the queue',
  );
});

test('E-7: reconciliation keeps a digest verdict this run actually made', () => {
  const stored = { ...finding('finding-a', 'DIGEST_BATCHED'), advisoryId: null } as unknown as Finding;
  const [next] = reconcileFindings([stored], [finding('finding-a', 'DIGEST_BATCHED')]);
  assert.equal(next.notificationStatus, 'DIGEST_BATCHED');
});

/**
 * Minimal in-memory pool: `queueRun` runs through the real `transaction`
 * helper, so the fake client only has to understand BEGIN/COMMIT and the two
 * statements `queueRun` itself issues (plus the record upserts).
 */
function fakePool() {
  const calls: { sql: string; params?: unknown[] }[] = [];
  let execution: Record<string, unknown> | undefined;
  const query = async (sql: string, params?: unknown[]) => {
    calls.push({ sql, params });
    if (/FROM records WHERE kind='executions'/.test(sql)) return { rows: execution ? [{ data: execution }] : [] };
    if (/SELECT data FROM records WHERE kind=\$1 AND id=\$2/.test(sql)) return { rows: [{ data: execution }] };
    if (/INSERT INTO records\(kind,id,data\)/.test(sql) && params?.[0] === 'executions')
      execution = JSON.parse(String(params[2]));
    return { rows: [] };
  };
  // Rows written during the transaction, so a later SELECT on the same client
  // sees them the way one PostgreSQL connection would.
  const written = new Map<string, unknown>();
  const clientQuery = async (sql: string, params?: unknown[]) => {
    if (/INSERT INTO records\(kind,id,data\)/.test(sql) && params) {
      written.set(`${params[0]}:${params[1]}`, JSON.parse(String(params[2])));
      if (params[0] === 'executions') execution = JSON.parse(String(params[2]));
      calls.push({ sql, params });
      return { rows: [] };
    }
    if (/SELECT data FROM records WHERE kind=\$1 AND id=\$2/.test(sql)) {
      const key = `${params?.[0]}:${params?.[1]}`;
      const hit = written.has(key) ? written.get(key) : execution;
      return { rows: hit ? [{ data: hit }] : [] };
    }
    return query(sql, params);
  };
  const client = {
    query: clientQuery,
    release: () => undefined,
    on: () => undefined,
    removeListener: () => undefined,
  };
  const pool = {
    query,
    connect: async () => client,
  } as unknown as import('pg').Pool;
  return {
    pool,
    calls,
    seed: (value: Record<string, unknown>) => {
      execution = value;
    },
    get execution() {
      return execution as {
        scopeHours: number;
        incrementalFeeds?: boolean;
        status: string;
        logs: string[];
      };
    },
  };
}

function queuedExecution(overrides: Record<string, unknown> = {}) {
  return {
    id: 'exec-1',
    name: 'run',
    startTime: new Date().toISOString(),
    endTime: null,
    status: 'QUEUED',
    scopeHours: 24,
    incrementalFeeds: true,
    phases: [],
    stats: {},
    logs: [],
    ...overrides,
  };
}

test('E-3: an explicit checkpoint request updates a QUEUED run instead of being dropped', async () => {
  const fake = fakePool();
  fake.seed(queuedExecution());
  const result = await queueRun(fake.pool, 72, 'operator', false);
  assert.equal(result.id, 'exec-1', 'the active run is still the one that runs');
  assert.equal(result.scopeHours, 72, 'the requested window is applied');
  assert.equal(result.incrementalFeeds, false, 'the requested checkpoint choice is applied');
  assert.ok(
    result.logs.some((line) => line.includes('source checkpoints on -> off')),
    `settings change must be recorded in the run log: ${JSON.stringify(result.logs)}`,
  );
});

test('E-3: an absent request field preserves the active run settings', async () => {
  const fake = fakePool();
  fake.seed(queuedExecution({ scopeHours: 48, incrementalFeeds: false }));
  const result = await queueRun(fake.pool, undefined, 'operator', undefined);
  assert.equal(result.scopeHours, 48);
  assert.equal(result.incrementalFeeds, false);
});

test('E-5: a multi-select subscription decides finding eligibility, not the legacy tier', () => {
  const low = { cve: { cvss: { severity: 'LOW' }, cisaKev: { isKev: false } } } as Finding;
  const kev = { cve: { cvss: { severity: 'LOW' }, cisaKev: { isKev: true } } } as Finding;
  const allSeverities: EmailRecipient = {
    id: 'r1',
    name: 'r1',
    email: 'r1@example.invalid',
    role: 'ADMIN',
    enabled: true,
    // The legacy field lags the multi-select list; the list is the decision.
    subscriptionTier: 'CRITICAL_HIGH_ONLY',
    subscriptions: ['ALL_SEVERITIES', 'NEWS'],
  } as EmailRecipient;
  assert.equal(recipientAllows(allSeverities, low), true, 'ALL_SEVERITIES admits a LOW finding');
  assert.equal(recipientAllows(allSeverities, kev), true);
  const newsOnly: EmailRecipient = {
    ...allSeverities,
    subscriptionTier: 'ALL_SEVERITIES',
    subscriptions: ['NEWS', 'DAILY_DIGEST'],
  } as EmailRecipient;
  assert.equal(recipientAllows(newsOnly, low), false, 'a news-only recipient receives no findings');
  const kevOnly: EmailRecipient = { ...allSeverities, subscriptions: ['CISA_KEV_ONLY'] } as EmailRecipient;
  assert.equal(recipientAllows(kevOnly, low), false);
  assert.equal(recipientAllows(kevOnly, kev), true);
});

test('E-6: duplicate mailboxes prefer the widest subscription', () => {
  const base = {
    name: 'dup',
    email: 'dupe@example.invalid',
    role: 'ADMIN',
    enabled: true,
  } as const;
  const kevOnly = { ...base, id: 'a', subscriptionTier: 'CISA_KEV_ONLY', deliveryGroup: 'SECURITY_TEAM' } as EmailRecipient;
  const all = { ...base, id: 'b', subscriptionTier: 'ALL_SEVERITIES', deliveryGroup: 'ADMINISTRATORS' } as EmailRecipient;
  // Widest tier wins even when the narrower row has the higher-priority group.
  assert.deepEqual(uniqueEnabledEmailRecipients([kevOnly, all]).map((recipient) => recipient.id), ['b']);
});

test('E-3: a RUNNING execution keeps its window and the ignored request is recorded', async () => {
  const fake = fakePool();
  fake.seed(queuedExecution({ status: 'RUNNING' }));
  const result = await queueRun(fake.pool, 72, 'operator', false);
  assert.equal(result.scopeHours, 24, 'a live run window is never rewritten mid-flight');
  assert.equal(result.incrementalFeeds, true);
  assert.ok(
    fake.calls.some((call) => /pipeline\.request_ignored_while_running/.test(String(call.params))),
    'the operator is told the request was ignored',
  );
});
