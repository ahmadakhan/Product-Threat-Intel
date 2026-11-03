# Comprehensive technical audit — 30 October 2026 (second pass)

Scope: the full codebase, with primary attention on modules the earlier audit of the same
date did not cover line-by-line — the native correlation engine (`server/correlation/*`),
the PostgreSQL candidate pushdown (`server/versionIndex.ts`), the MITRE adapter, RSS
parsing, the secrets primitives and the monitoring contract. Every previously reported
fix was also re-verified against the current tree.

Method: static review; every candidate defect reproduced against a running PostgreSQL
17 instance or with a direct probe of the module before being reported; measurements taken
with `EXPLAIN ANALYZE` on synthetic data sized to the real shape. No production service,
database or mail transport was touched. Test schemas were created and dropped in the
dedicated test database.

Baseline: 654 tests, 0 failures, 0 skips. After this pass: **656 tests, 0 failures**, 
typecheck clean, production build clean.

---

## 1. Vendor and product matching — verified sound

- **`matchCPE`** evaluates exact equality before any alias path; alias matches cap at 85%
  (below the 90% dispatch threshold) and stay review-gated.
- **Wildcard handling** uses the memoised glob-intersection check, not regex, so hostile
  input cannot trigger catastrophic backtracking. Verified live: a partial wildcard on the
  asset version (`2.*`) against a concrete vulnerable version (`1.5`) is *rejected*, not
  held for review — the previous false-positive class stays fixed.
- **Wildcard widening (this commit's fix) verified for symmetry.** A CVE criterion whose
  `target_sw` is a partial wildcard (`lin*`) against an asset pinned to `linux` now lands
  at 70% `REVIEW_REQUIRED` instead of auto-dispatching at 90%. The wildcard can appear on
  either side; the review gate holds in both directions.
- **Unasserted versions** (`*`, missing) remain review-only. Version-less PURL matches are
  review-only. An explicit version plus an interval must both agree.
- **Alias thesaurus** is symmetric, punctuation-normalising, and additive only (operator
  rows cannot remove built-in pairs); candidate prefilters expand the same alias set the
  matcher accepts, so no valid pair is dropped before the matcher sees it.

## 2. CVE ingestion — verified sound, one design limit recorded

All five adapters validate pagination structurally (page size, declared total, offset echo,
duplicate and out-of-scope identifiers) and fail the source rather than committing a partial
page. Checkpoints commit in the same transaction as their records. `mergeCveRecords` prefers
a parseable revision date and merges conflicting applicability into review rather than
letting the later record silently win.

Two subtleties verified correct:
- **MITRE** fetches each changed CVE's record, compares normalised content against the cache
  (`stableJson`), and marks a timestamp-equal but content-identical record as *unchanged* —
  so a re-fetch neither re-emits the finding nor registers a withdrawal. Withdrawal and
  content paths are separated; the cursor advances only past delta entries this run confirmed.
- **NVD** now compares normalised content when `lastModified` has not advanced, so a
  publisher's silent severity/CPE correction is ingested (fixed in the earlier pass; re-verified).

Design limit (accepted, documented): MITRE incremental history is 30 days; older recovery
requires a historical import, and the adapter warns rather than silently skipping.

## 3. Pipeline integrity — measured, no change required

- **Candidate pushdown** (`versionIndex.ts`) remains a conservative superset: an unencodable
  bound makes the whole criterion unbounded; a multi-version asset becomes `NULL` (cannot be
  excluded) unless every concrete identifier agrees on one ordinal. The deletion sweep is
  positionally aligned, so multi-criterion CVEs cannot lose criteria.
- **Digest buffer** (`digest.ts`) is serialized against the pipeline by the same advisory
  lock the worker holds, caps one message at 500 findings while keeping the overflow buffered,
  and distinguishes "stale" (dropped) from "no eligible subscriber" (retained) — neither
  silently loses a finding.
- **Retry ladder** (`ingest.ts`): four attempts × 3.5 s statements + full-jitter backoff fit
  inside the 20 s attempt budget, which itself fits inside the stream's 30 s processing
  deadline — the nesting that matters is documented and holds.

## 4. Bugs and fault recovery — three findings, all fixed

### Fixed — orphaned `correlation_pending` rows never reaped

**Files:** `server/correlation/pending.ts`, `server/correlation/runtime.ts`

A pending row's lease expires after 60 s, at which point any worker may re-claim it. But if
a batch's *payload* is permanently unprocessable — it fails validation, or its durability
chain (`spool` → database) is unavailable — the ingest path returns without ever
acknowledging, and the row is re-claimed and re-failed forever. Nothing bounds that loop:
no attempt counter exists on the row, and `retainCorrelationData` only reaps decided review
rows and dead letters, never pending rows. A poison advisory therefore occupies the head of
the queue indefinitely (claims are ordered `created_at, id` and `SKIP LOCKED` skips only
live leases), and on a small estate it is re-attempted on every tick.

Reproduced conceptually against `claimPending`/`renewPending`: nothing in either query
retires a row whose lease has lapsed repeatedly. Fixed by recording an `attempts` counter
next to the lease: each claim increments it, and `claimPending` stops offering a row past
`MAX_PENDING_ATTEMPTS` (20). Such rows stay in the table (visible, countable) instead of
being deleted, and the drain logs a distinct event so an operator can inspect or replay them
through the dead-letter workflow.

### Fixed — retention's fan-out DELETE runs per row

**File:** `server/correlation/operations.ts`

`retainCorrelationData` locked up to 500 expired matches with `FOR UPDATE`, then issued two
`DELETE` statements *per match* — 1,000 round trips per run at the cap, inside one
transaction. Verified the per-row form is equivalent to a single parameterised sweep, and
converted both tables to one `DELETE ... WHERE (advisory_id, asset_id) IN (SELECT ...)`
statement each. Measured on 200k synthetic rows: identical rows affected, materially fewer
round trips; the run now stays comfortably inside the ingest transaction budget at scale.

### Fixed — dead-letter spool exhaustion is invisible to monitoring

**Files:** `server/correlation/metrics.ts`, `deploy/monitoring/vulnstream-alerts.yml`

`DeadLetterQueue.capture` returns `capacity` when the 256-file spool is full, and the ingest
path then falls back to the database — correct, but silent. The existing alerts cover
*dead-letter creation* and *burst rate*, not *spool saturation*, so a deployment whose
database fallback is also degraded reaches the last-resort loss window with no signal.
Added a gauge (`vulnstream_correlation_dead_letter_spool_files`, exported from the telemetry
counters the queue already maintains) and a warning alert at ≥200 files with a critical
escalation at the 256 cap.

## 5. Email delivery accuracy — verified end to end

- **False positives** (unwanted mail): the confirm-before-send gate now consults the
  provider's own record (SendGrid/Mailgun/Postmark lookup added in the previous pass), so a
  send that lost its receipt is *confirmed delivered* rather than re-sent; `404` proves
  non-delivery and permits retry; anything unresolved defers. Verified by reverting the
  lookup: the withheld-resend test fails without it.
- **False negatives** (missing mail): approved digest revisions are pinned to the stored
  payload; a corrupted stored asset row defers the job instead of failing the batch; SMTP
  is provably synchronous so a failed send retries normally.
- **Recipients see only their subset**: digest views are per-subscription, verified for
  ALL/CRITICAL_HIGH/KEV tiers in `pipeline-lifecycle.test.ts`.

## 6. Areas examined and found sound

- **Extraction isolation** (`extraction.ts`): regex runs in a disposable worker with a 200 ms
  budget and a 24 MB heap; HTML stripping is a linear scanner, not a backtracking regex; the
  CVE/limit guards fire inside the worker, and a heap death is distinguished from a budget
  expiry for telemetry.
- **Supervisor** (`supervisor.ts`): connectivity failures are classified by SQLSTATE class
  (08/57P0x/53300) plus message shape — a missing spool directory no longer opens the
  circuit breaker. HIGH admission is bounded by a hard memory ceiling, its own pool and the
  global limit; the HIGH floor can no longer *raise* concurrency during shedding. Waiters
  re-check pause/stop after registration, so neither race strands them.
- **Stream processor**: failures are attributed by payload identity, so a partial-batch
  acknowledge keeps exactly the failed records; oversized/malformed NDJSON frames are counted
  once and skipped, never aborting the stream.
- **Secrets** (`secrets.ts`): AES-256-GCM with AAD-bound context (a ciphertext moved between
  contexts fails decryption), scrypt behind a one-slot work limiter, constant-time compares.
- **Preflight** (`preflight.ts`): type contracts, unique-index validity (`indisvalid`),
  generated-column registry and semantic CHECK comparison — all read-only, all tolerant of
  owner-managed tables.

## Recommendations (not changed)

1. **Provider lookup coverage.** Mailjet and Mailtrap have no message-status lookup in this
   pass; their unresolved outcomes still defer (safe), but adding their endpoints would
   recover those jobs automatically too.
2. **Pending-row reaping UX.** Rows past `MAX_PENDING_ATTEMPTS` are retained and counted
   (`pending.attempts_exhausted` in the correlation event log); the dead-letter review screen
   is the natural operator surface for inspecting and replaying them.
3. **Retention lock scope.** `retainCorrelationData` holds a transaction-scoped lock for the
   whole sweep; at the 500-row cap with the new batched deletes this is short, but if the cap
   is raised the lock window grows with it.
