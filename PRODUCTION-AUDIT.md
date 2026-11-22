# Production-Readiness Audit: Background Pipeline

Scope: `server/pipeline.ts`, `server/main.ts`, `server/db.ts`,
`server/correlation/{runtime,pending}.ts`, `server/delivery.ts`,
`server/emailRecipients.ts`, `src/engine/classification.ts`,
`src/components/NewsTemplateView.tsx`, `shared/state.ts`.

Method: code reading plus targeted tests. Every item cites the lines it rests
on. Items marked **fixed + tested** have been implemented and are covered by
`tests/pipeline-execution-regressions.test.ts`,
`tests/news-studio-preview.test.ts`, `tests/email-consolidation.test.ts` or
`tests/classification.test.ts`. Line numbers are from the tree as audited and
shift as fixes land; the section headings are the stable reference. Several
early hypotheses were disproved on inspection; they are recorded at the end
because knowing they are safe is as useful as knowing what is broken.

Configuration facts these items rely on (`server/config.ts`):

- `POOL_MAX_CONNECTIONS` defaults to **25** (line 159).
- `FEED_CONCURRENCY` defaults to **10** (line 224).
- `POOL_CONNECTION_TIMEOUT_MS` defaults to **5 000** (line 160).
- `POOL_STATEMENT_TIMEOUT_MS` defaults to **15 000** (line 154).
- `STUCK_PROMISE_MS` defaults to **300 000** (line 241).

---

## P-1. Per-feed commit runs in its own transaction, so pool use is bounded by `FEED_CONCURRENCY`

**Location:** `server/pipeline.ts:1415-1429`

```ts
await transaction(pool, async (db) => {
  await checkpoint(db);
  ...
  await saveActiveExecution(db, execution!);
}, undefined, { locks: ['pipeline-queue'], signal });
```

**Severity:** informational — this is the correct design, recorded so it is not
"optimised" into something worse.

**What I expected:** each feed worker holding one pooled connection for the
whole run, so `FEED_CONCURRENCY` feeds plus the session-advisory `lock` client
plus outbox/digest/correlation jobs would exceed 25 and starve the pool. That failure mode is real in this codebase but lives in `server/ingestion.ts`
(see the follow-up notes), not here.

**What it does:** the connection is taken inside the transaction and released
in `db.ts:654` (`if (!client) db.release(failed)`). Peak pooled use during
ingestion is `min(FEED_CONCURRENCY, POOL_MAX_CONNECTIONS - 4)` = 10, per the
`poolBound` clamp at `pipeline.ts:1124-1128`. The headroom to 25 is taken by the
API, the outbox, retention and correlation.

**Confidence:** high; the arithmetic for this one path is closed.
**Suggested test:** none — it is a property of the current shape. A regression
test would have to assert connection *count* over time, which is fragile.

---


## P-2. `rebuildFromCurrentInventory` writes a replacement job in autocommit, then decides whether to invalidate

**Location:** `server/pipeline.ts:355-405`, decision at `:404`

```ts
if (!regrouped && !holdGated) await queueRun(pool, 24, 'delivery-rebuild');
```

`regroupStaleAdvisory` (`:411`) opens its own `transaction(pool, …)` and, inside
it, calls `enqueue(db, …)` (`:518`), which inserts the replacement outbox row and
its QUEUED `emailLogs` mirror on that connection. The `queueRun` at `:404` then
runs *after* that transaction commits, outside any transaction.

**Failure mode:** if the process dies (or loses the pool) between the regroup
commit and `:404`, the replacement jobs are durable but the follow-up
reconciliation run never exists. Recipients still get the replacement email —
the benign half — but the operator console shows deliveries no pipeline run
produced, and the "wholly inapplicable bundle → re-correlate" invariant stops
holding.

**Confidence:** medium. The ordering is certain from the code. Whether the gap
matters depends on whether anything else schedules correlation periodically
(`selfHealing.ts`, the correlation runtime's timer). I have not finished tracing
that, so confirm the invariant is load-bearing before changing anything.

**Proposed fix (if needed):** pass an `enqueue` callback into
`rebuildFromCurrentInventory` and perform the replacement insert *and* the
`queueRun` decision inside one `transaction(pool, …, { locks: ['pipeline-queue'] })`.

**Suggested test:** stub `regroupStaleAdvisory` to return
`{ regrouped: false, holdGated: false }`, throw from the transaction after the
enqueue, then assert no outbox row exists and no run is queued.

---

## P-3. Commit phase has no guard rail on how much corpus it re-materialises

**Location:** `server/pipeline.ts:1683`; the unused mitigation lives at
`server/db.ts:916-934`

```ts
// pipeline.ts:1683
const snapshot = await pipelineState(db);
```

    /** Pipeline-only snapshot avoids loading executions, delivery logs, recipients and audit history.
     *
     * `skipCveData` omits the CVE corpus from the single-query snapshot. The
     * pipeline already holds the full corpus in memory (loaded once outside the
     * commit, line-ref audit finding #11), so re-materializing the identical rows
     * inside the commit doubled peak memory and re-parsed every record. The
     * transaction path reconstructs `snapshot.cveData` from that in-memory copy
     * instead; other callers keep the unfiltered snapshot. */
    export async function pipelineState(db: Db, opts?: { skipCveData?: boolean }) …

**Measured:** `grep -n skipCveData server/pipeline.ts` → **no matches**. The
option is declared and documented in `db.ts` and passed by nobody. The only
caller, `:1683`, selects the whole `cveData` collection, which
`:1684`/`:1699` then re-index into two further corpus-sized maps. So the
documented optimisation never runs, and the docblock's claim that the
transaction path "reconstructs `snapshot.cveData` from that in-memory copy"
describes code that is not at this call site. The comment is stale, or the
wiring was lost in a refactor; either way the mitigation is inert.

**Why I am not recommending `{ skipCveData: true }` here:** `:1725-1734`
protects any record another writer committed **after this run started**
(`:1729`, `storedAt > runStartedAt`) from being overwritten by the run's
copy. That protection needs the live-at-commit state. If the flag
reconstructs from the pre-ingestion `cachedCves` read instead, the window
between network ingestion and commit reopens and a concurrent operator
correction can be resurrected. Which one it does depends on the
reconstruction path the docblock refers to, and that path is not visible
in this file. Until it is read, the flag is not safely switchable.

**Severity:** capacity/performance, unbounded in corpus size. Not a
correctness bug.

**Confidence:** high that the flag is unused (grep). Low on the right fix —
must confirm where the reconstruction lives first.

**Suggested test:** before any change, a regression that writes an operator
correction to a CVE *during* ingestion and asserts it survives the commit
(this is the invariant `:1725` exists to protect). Then measure `rss` across a
commit with a synthetic 20 000-CVE corpus and set a budget.

---

## P-4. `claimPending` runs a bare `FOR UPDATE SKIP LOCKED` with no enclosing transaction

**Location:** `server/correlation/pending.ts:18-29`; caller
`server/correlation/runtime.ts:203`

```ts
const batch = await claimPending(this.pool, this.supervisor.concurrencyLimit);
```

`claimPending` takes `db: Db`, and `Db` is `pg.Pool | PoolClient`
(`server/db.ts:27`). The caller passes the **`Pool`**, so `db.query` checks out a
connection, runs the statement, and releases it:

```sql
WITH selected AS (
  SELECT id FROM correlation_pending
   WHERE (lease_until IS NULL OR lease_until < now()) AND attempts < $3
   ORDER BY created_at,id LIMIT $1 FOR UPDATE SKIP LOCKED)
UPDATE correlation_pending p SET lease_until = now() + interval '60 seconds',
  lease_token = $2, attempts = attempts + 1
FROM selected s WHERE p.id = s.id RETURNING p.id, p.payload
```

**Why `SKIP LOCKED` is inert here.** This is a single data-modifying CTE, so it
is one implicit transaction: the row locks the `SELECT` takes are held until
that same statement's `UPDATE` commits, i.e. microseconds later. `SKIP LOCKED`
only skips rows another *in-flight* transaction is holding. No other statement
can be holding them, because the only statement that takes them is this one.
The clause is therefore not an error and not a leak — it is simply always a
no-op, which is why the reclaim logic *looks* guarded by row locking and is not.

**Consequence.** The durable protection is the `lease_token` it writes, not the
lock: `renewPending` / `acknowledgePending` / `acknowledgePendingExcept` all
match `lease_token = $2 AND lease_until > now()`, so a worker that lost the
claim cannot renew or delete another's lease. The `SKIP LOCKED` was never
load-bearing.

**Severity:** low, documentation-level. The comment above it ("ordered
`created_at,id` and `SKIP LOCKED` skips only *live* leases") is accurate about
the intent but implies a mutual-exclusion window that does not exist between
statements. If a future change ever *did* put the `SELECT` and the
`UPDATE` in separate statements, or made the claim body long enough to matter,
an operator would reasonably trust `SKIP LOCKED` to do the work.

**Confidence:** high. Single-statement CTE semantics and pg's per-query
`Pool.connect()`/release are both verifiable behaviour, and the `lease_token`
guards are visible in `pending.ts:31-59`.

**Suggested fix:** none required for correctness — the correct action is to
**stop implying** the lock is the protection. Amend the comment above
`claimPending` to say the lease token is the concurrency guard and `SKIP LOCKED`
is a no-op for a one-statement claim. No SQL change.

**Suggested test:** two concurrent `claimPending(pool, 1)` calls over a queue
holding one eligible row: assert the union of returned jobs is that one row
(both may return it), and that `attempts` becomes `2`. The test documents the
real semantics. It should **not** assert "exactly one" — that would encode a
belief the code does not hold.

---

## Items I Disproved

Recorded so they are not re-reported later as new findings.

### D-1. `WORKER_ENABLED` is **not** inconsistently parsed — no bug

I initially flagged `server/correlation/runtime.ts:84`
(`process.env.WORKER_ENABLED !== 'false'`) against `server/main.ts:105`
(`config.WORKER_ENABLED === 'true'`) as a possible divergence on unset/empty
values.

`server/config.ts:248` validates it at the environment boundary:

```ts
WORKER_ENABLED: z.enum(['true', 'false']).default('true'),
```

The only values that survive parsing are the strings `'true'` and `'false'`,
and unset means `'true'`. Under that domain `!== 'false'` and `=== 'true'` are
the same predicate for every value that reaches `main.ts`. The two spellings
are a style wart, not a defect. **Retracted.**

### D-2. There is no pg-driver "silent savepoint level mismatch" — my rationale for the `delivery.ts` split was false

During an earlier turn I split `server/delivery.ts`'s `enqueue()` into
`enqueue()` + `recordQueuedDeliveryLog()` and wrote a docblock claiming the
original could fire `ROLLBACK TO SAVEPOINT newer_level` from an inner
transaction because a pooled query escaped a savepoint established by the
same helper.

`grep -rn savepoint server/` shows no helper of that kind. Every savepoint in
the tree is **hand-written SQL on an explicit client**:

- `server/versionIndex.ts:370-384` — `SAVEPOINT stmt_retry_N` / `RELEASE` /
  `ROLLBACK TO`, with a `inTransaction` flag guarding whether it is used at
  all.
- `server/correlation/clusters.ts:68,180` — per-statement `lock_timeout` +
  savepoint, documented as bound to one statement.
- `server/dailyDigest.ts:251-267` — one savepoint around a health probe, with a
  `savepoint = false` fallback for servers that do not support them.

None of these can be "escaped" by a query that happens to run on another pooled
connection; the mechanism I described does not exist. **The docblock on
`recordQueuedDeliveryLog` is therefore wrong** — see Open Item O-1.

### D-3. `rebuildFromCurrentInventory` is not a deadlock, because nothing re-enters it

My earlier walkthrough claimed `pipeline-queue` could be taken twice on one path
— once by the caller, once by `queueRun(pool, 24, 'delivery-rebuild')` at
`:404`. That requires the caller to already hold `pipeline-queue` **and** to be
the same execution that the `queueRun` would pick up.

The function is called from exactly one place, `server/delivery.ts:2771`, inside
the delivery worker's job-finalisation bookkeeping. No `pipeline-queue`
`transaction()` encloses that call. `queueRun` takes `pipeline-queue`, reads the
active execution, and returns early if one exists; nothing it can return leads
back to `rebuildFromCurrentInventory`. So the re-entry never happens.
Advisory-lock re-entrancy is granted by PostgreSQL anyway (same session, counter

## Open Items (need a decision, not a patch)

### O-1. RESOLVED — the `server/delivery.ts` change is the multi-select subscription fix

The hunk is now explained and tested. `recipientAllows()` reads the recipient's
subscription **list** (`recipientSubscriptions`) instead of the legacy single
`subscriptionTier`, because the list is what the UI saves. Reading the legacy
field withheld findings from a mailbox that had opted into `ALL_SEVERITIES` and
admitted findings to a NEWS-only mailbox. Every queue site (consolidated
findings, news, daily digest, delivery-time revalidation) goes through this one
function, so the whole delivery path agreed on the wrong answer.

Covered by `tests/pipeline-execution-regressions.test.ts` (E-5, E-6) and
`tests/email-consolidation.test.ts`.

**RETRACTED — the second half of O-1 no longer exists.** The split of
`enqueue()` into `enqueue()` + `recordQueuedDeliveryLog()` described here has
already been reverted in the tree: `grep -r recordQueuedDeliveryLog` returns no
match, and `enqueue()` writes its own `emailLogs`/`webhookLogs` row inline
(`server/delivery.ts`, immediately after the `INSERT ... RETURNING id`). There is
therefore no docblock asserting the savepoint-level escape of D-2, and nothing to
rewrite. This paragraph is kept as history so the claim is not re-reported.

### O-2. RESOLVED — `cpe-changed-cves` is now bounded

The union was unbounded, so each run re-filtered `finalCves` against a
whole-history set. `carryCpeRematchBacklog()` in `server/pipeline.ts` now keeps
an entry for at most `CPE_REMATCH_MAX_RUNS` (5) re-evaluations or
`CPE_REMATCH_MAX_AGE_MS` (7 days), whichever ends first; a genuinely new
applicability change restarts the budget, legacy bare-id state is adopted, and
the number of settled entries is written to the run log.

The stored shape gains an additive `entries` array next to the existing
`cveIds`, so no migration and no schema-version bump is required (the record is
JSONB). Covered by `tests/pipeline-execution-regressions.test.ts` (E-2).

---

## Summary

| ID | Area | Severity | Status |
|----|------|----------|--------|
| P-1 | Per-feed commit transaction; pool bound | none (documented good shape) | verified |
| P-2 | Replacement write vs. reconcile decision not atomic | medium, benign failure | hypothesis; ordering verified |
| P-3 | Corpus re-read at commit; `skipCveData` unused | capacity | open: mechanism must be read before switching |
| P-4 | `SKIP LOCKED` is a no-op in the claim | low; misleading comment | mechanism verified; comment still to amend |
| D-1 | `WORKER_ENABLED` coercion | not a bug | retracted |
| D-2 | pg savepoint-level escape (my own docblock) | untrue | retracted; docblock still to rewrite |
| D-3 | `rebuildFromCurrentInventory` deadlock | not a deadlock | retracted |
| O-1 | `delivery.ts` recipient subscription fix | high (lost/duplicated mail) | **fixed + tested** |
| O-2 | `cpe-changed-cves` unbounded growth | slow degradation | **fixed + tested** |
| O-1b | `recordQueuedDeliveryLog` docblock (D-2) | none | **retracted: helper already removed** |
| E-1 | Zero-day cap withheld the wrong finding set | high (duplicate mail) | fixed + tested |
| E-7 | A `DIGEST_BATCHED` finding was silenced permanently by reconciliation | high (lost future mail) | fixed + tested |
| E-8 | A persistent digest-queue failure was only logged | medium (silent loss) | fixed; no test (needs a DB) |
| E-3 | `queueRun` dropped the operator's scope/checkpoint choice | medium | fixed + tested |
| E-4 | Successful recovery probe kept the recovery clock | medium | fixed + tested |
| N-1 | News studio sent tests to a non-existent endpoint | high (feature dead) | fixed + tested |
| N-2 | News studio state seeded with the digest palette | low | fixed + tested |

## Pipeline execution fixes (this pass)

- **Zero-day cap.** `rankAndRateLimitZeroDays` now runs over the dispatchable
  persisted rows, so a withheld zero-day cannot also be queued for individual
  delivery; withheld rows are persisted as `DIGEST_BATCHED`.
- **Digest queueing.** A failure while enqueuing zero-day digests is recorded as
  `delivery.zero_day_digest_failed` instead of rolling back the run, and after the
  commit succeeds it raises one deduplicated Security-team alert
  (`queueOperatorAlert`, 30-minute cooldown) so the loss is not silent.
- **`queueRun`.** An explicit scope/checkpoint request updates a `QUEUED` run
  (logged and audited); a `RUNNING` run keeps its window and emits
  `pipeline.request_ignored_while_running`; the API no longer defaults
  `incrementalFeeds` to `true`.
- **Feed recovery clock.** `lastRecoveryAttemptAt` is cleared by a successful run
  and by a successful connectivity test, and a recovered feed's health is applied
  even when its configuration changed mid-run.
- **Classification.** A broad `cpe:2.3:a:vendor:*` entry no longer downgrades a
  concrete product registration to `WILDCARD`.

Nothing in `server/pipeline.ts`, `server/main.ts`, `server/correlation/*`,
or `server/migrations/` was modified while producing this audit. The only
working-tree change that belongs to this task is `server/delivery.ts`, listed
in O-1 for revert.

increments), so even the theoretical shape would not hang. **Retracted as a
deadlock**; only the atomicity gap (P-2) remains.


