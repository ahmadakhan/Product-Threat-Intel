# Concurrency, Async and Data-Integrity Audit - 2026-11

Scope: deadlocks, race conditions, lock usage, async/worker reliability, retry
strategies, business-logic alignment. This complements `PRODUCTION-AUDIT.md`; it
does not re-report findings recorded there.

Method: every claim below was checked against the source **and**, where a
database interaction was involved, executed against a disposable PostgreSQL 16
instance. Items that looked like bugs and turned out not to be are listed under
*Disproved* so they are not re-reported.

---

## Findings fixed in this pass

### C-1. Lost update on findings in the delivery finalize (HIGH)

**Location:** `server/delivery.ts` (finalize transaction, the finding loop that
writes `notificationStatus` / `autoDispatchedAt`), and the dead-letter worker in
`server/main.ts` (`get` + `put` on the same finding).

**Defect.** The finalize step is a read-modify-write:

```ts
const findingMap = await getMany<Finding>(db, 'findings', advisory.findingIds); // no lock
...
await put(db, 'findings', findingId, { ...f, notificationStatus: ..., autoDispatchedAt: ... });
```

`getMany` is a plain `SELECT`. The outbox delivers **one job per recipient**, and
those jobs are finalized by concurrent workers that all touch the *same* findings
of a bundle. Each worker read a snapshot and wrote it back, so the last writer
won. Consequences: a status a reconciliation or an operator triage action had just
committed was silently reverted (a finding re-sent, or a `DELIVERY_FAILED` erased),
and `autoDispatchedAt` flapped between the recipients.

**Proof.** Eight concurrent `get`+increment writers against one row produced a
final count of **2** instead of 8 (`get` -> snapshot -> `put` loses 6 updates).
The same experiment through the locked helper produced **8**.

**Fix.** Read the rows `FOR UPDATE` for the duration of the transaction, in a
deterministic id order (see C-5). New `getManyForUpdate` helper in
`server/db.ts`. Applied to:

- the finding loop in the finalize transaction;
- the dead-letter retry worker (`main.ts`), which had the identical shape.

### C-2. Lost update on the per-CVE alert counters (HIGH)

**Location:** `server/delivery.ts`, `alertedCves` / `alertDispatches` block.

**Defect.** `priorAlerts` was read with `getMany` and `dispatchCount` was written
as `(prior?.dispatchCount || 0) + (same ? 0 : 1)`. A digest is delivered to
several subscription cohorts as separate jobs, processed concurrently. Every
worker read the same `prior`, computed the same `+1`, and overwrote the others:
a four-cohort digest recorded `dispatchCount: 1` and kept only one cohort's
addresses in `recipientEmails`. `firstAlertedAt` could also be advanced by the
last writer.

**Fix.** Read the affected `alertedCves` rows `FOR UPDATE`, sorted by id, so the
counter and the recipient set accumulate correctly. Note that the rows exist to
record that a dispatch happened, so an "increment" is naturally the +1 form;
the lock is what makes it correct. (A later contributor should not "simplify"
this back to a plain read: the two-cohort case is exactly where it breaks.)

### C-3. Advisory status and recipient rate written from unlocked snapshots (MEDIUM)

**Location:** `server/delivery.ts`, same finalize transaction.

**Defect.** `advisory.deliveryStatus` was recomputed from a plain
`get<Advisory>` and written back. Concurrent workers for the same advisory each
wrote their own recomputation, so the visible aggregate could settle on a value
that matched no single committed worker's view; an operator edit committed
concurrently was reverted. The recipient's `deliverySuccessRate` had the same
shape via a plain `get<EmailRecipient>`.

**Fix.** Both are now read `FOR UPDATE`. The finalize transaction now documents
and follows one row-lock order that every worker reaches identically:

```
outbox -> {emailLogs | webhookLogs} -> recipients -> advisories
       -> alertedCves (id order) -> findings (id order)
```

Overlapping workers therefore serialize instead of cycling. The invariant is
written at the top of the transaction in `server/delivery.ts` so a future lock
cannot be inserted in a conflicting position by accident. (The pre-existing
`emailLogs`/`webhookLogs` locks are alternatives, and no worker takes both.)

### C-4. Unbounded `count(*)` inside a delivery transaction (MEDIUM)

**Location:** `server/delivery.ts`, recipient success-rate block.

**Defect.** The query counted over the recipient's **entire** outbox history
inside the finalize transaction. Its cost grows with the age of the deployment
and eventually exceeds the statement timeout, failing the finalize of a job whose
mail had already been accepted - which is the exact case a "confirm before
resend" design must never lose. A missing rate was also recorded as `0`, making a
brand-new mailbox look failing.

**Fix.** Bounded window (`DELIVERY_RATE_WINDOW = 200` most recent rows); a
recipient with no finished deliveries in the window keeps its previous rate
instead of being forced to 0.

### C-5. `getManyForUpdate` locks in a deterministic order (supporting fix)

A batch `SELECT ... FOR UPDATE` locks rows in the order the executor visits them,
which can differ between callers and plans -> `40P01`. The helper pins
`ORDER BY id`, and callers deduplicate and sort their id lists. This is what keeps
C-1..C-3 from trading a lost update for a deadlock.

---

### C-6. A stalled pipeline job ran forever: the heartbeat reset its own watchdog (HIGH)

**Symptom.** The pipeline job "keeps on running": the run never finishes, and no
new run can start.

**Location:** `server/pipeline.ts` (`pipelineHeartbeat`, called from the 15 s
timer in `processPipeline`) and `server/main.ts` (`tick`, which resets
`pipelineStartedAt` from the `onProgress` callback).

**Defect.** Two different questions were answered by one signal:

- *did the run make progress?* - `main.ts` cancels an attempt that produces no
  progress for `STUCK_PROMISE_MS`.
- *is the process alive?* - the heartbeat timer.

The heartbeat called `onProgress()` on **every beat**, and `main.ts` used that
callback to reset the stall clock:

```ts
// server/pipeline.ts - the bug
return () => { onProgress?.(); options.onBeat(); };
// server/main.ts
pipeline = processPipeline(..., () => { pipelineStartedAt = Date.now(); });
```

A timer fires from the event loop's timer phase whether the in-flight work is
advancing or waiting forever. So the heartbeat cleared its own watchdog every
15 s, and an attempt whose promise never settled (an aborted feed that ignored
its signal, a query parked on a dead socket) never reached `STUCK_PROMISE_MS`.
It was therefore never cancelled and never detached by
`PIPELINE_ABORT_GRACE_MS`, `pipeline` stayed set for the life of the process,
and the execution row stayed `RUNNING`.

**Why that wedged the queue, not just one run.** `queueRun()` treats any
`QUEUED`/`RUNNING` execution as the active run and returns it unchanged, so
every operator request and every scheduled tick was silently deduplicated
against a run that had long finished. Verified against a real database: with a
stale `RUNNING` row present, `queueRun()` returns that row and creates nothing;
marking it terminal lets the next call create a fresh run.

**Why only the pipeline.** Retention, the daily digest and ML training set their
`*StartedAt` clock once when the run starts and never refresh it, so their
watchdogs always fire. The pipeline was the only job whose clock was refreshed
mid-run - by the very timer meant to be supervised.

**Fix.** The heartbeat now reports **liveness only**. `checkpoint()` - which
re-reads the execution row and throws on stop/connection loss - is the only
progress signal, exactly as `main.ts` documents. Safety is preserved for a
healthy run inside one long request: `STUCK_PROMISE_MS` is floored at 240 s
(default 300 s) against a 120 s worst-case source request, and
`sourceCheckpoint()` runs immediately before and after every request, while
`checkedSleep()` checkpoints every 500 ms.

**Tests.** `tests/pipeline-progress.test.ts` previously asserted the buggy
behaviour ("the pipeline heartbeat reports progress on every beat"); it now pins
the opposite contract. Note the file-level tests for the old behaviour were
removed deliberately, not weakened: they encoded the defect.

## Disproved / verified-safe (do not re-report)

- **`WorkLimiter` over-admission.** `run()` increments `active`, then a queued
  caller's `admit()` resolves and the holder's `finally` decrements - which read
  as a window where two callers are admitted on `concurrency: 1`. Executed
  against the real class: peak concurrent work is **1** in all interleavings
  tested (plain, queue limit 0, abort-while-waiting, deadline rejection).
  No change.
- **Advisory lock order cycle.** All existing `transaction()` call sites take at
  most one domain lock, so no caller can cycle against `audit-chain` (which is
  itself ordered by `LOCK_ORDER`). The order table is consistent with the actual
  call sites.
- **Retry a non-idempotent send.** The transport (`sendMail`) and the webhook
  POST are **not** wrapped in a generic retry. Retry is modeled as outbox
  state (`QUEUED`/`retryable` + `next_attempt`) with a bounded attempt budget, and
  the delivery is keyed by a `dedupe_key`/`contentRevision` so it is idempotent at
  the queue level. Backoff is exponential with additive jitter and a hard
  `maxDelayMinutes` cap. `retryWrappers` in `server/retry.ts` are only used for
  reads/writes, not for transports.
- **`transaction()` / `SKIP LOCKED`.** Claiming in `claimPending` and the outbox
  claim are single data-modifying statements; `SKIP LOCKED` is inert there by
  design (documented in `PRODUCTION-AUDIT.md` P-4). The durable guard is the
  lease token. Unchanged.

---

## Not changed, but operators should know

- The scheduler ticks in `server/main.ts` deliberately **detach** a promise that
  exceeds `STUCK_PROMISE_MS` and start a fresh attempt. That is intentional
  (self-healing), but it means an operation that ignores its `AbortSignal` can
  overlap with its replacement. All of the jobs use generation counters so the
  detached copy can never clear the replacement's guard; the only cost is
  transient duplicated work against the same queue, which the lease/token guards
  absorb.

---

## Verification

| Command | Result |
| --- | --- |
| `npm run lint` | exit 0 |
| `node --import tsx --test tests/concurrency-regressions.test.ts` (with `TEST_DATABASE_URL`) | 3/3 pass |
| full `npm test` with disposable DB (TCP URL) | 1546 tests, **1544 pass, 0 skipped** |

Regression suite added: `tests/concurrency-regressions.test.ts` (real database,
skipped when `TEST_DATABASE_URL` is unset). It proves the lock is held for the
transaction, that 8 concurrent locked increments are all retained, and that a
shared batch transaction with per-row savepoints keeps a good row even when a
sibling row fails.

Negatively verified: with `getManyForUpdate` reduced to a plain `SELECT`, the
same 8-writer experiment yields **2**, i.e. the tests fail without the fix.

### Pre-existing failures seen, NOT caused by this audit

Running the full suite surfaced one unrelated red test. It also fails with every
change from this audit stashed, so it belongs to other in-progress work in the
working tree, not to this pass:

- `tests/email-resend.test.ts` -> *resend to security team creates new advisory
  and queued jobs* (also reported at suite level as *POST /api/email/:id/resend
  re-queues a delivered advisory > security team > everyone*): the fixture
  inserts the original job with `status='SENDING'`, while
  `/api/email/:id/resend` rejects anything `REVIEW`/`QUEUED`/`SENDING` with a 409
  (a deliberate duplicate-send guard in `server/app.ts`). The fixture and the
  guard disagree; the test needs the fixture to use a terminal status
  (`DELIVERED`/`ACCEPTED`), not the guard relaxed. Left untouched: it is another
  change's subject and unrelated to concurrency.

Note on harness: `tests/correlation-recovery.test.ts` only passes when
`TEST_DATABASE_URL` is a TCP URL; it reads `destination.port` to open its proxy
and cannot work over a unix-socket URL. Use
`postgres://user@127.0.0.1:<port>/<db>` for local runs.
