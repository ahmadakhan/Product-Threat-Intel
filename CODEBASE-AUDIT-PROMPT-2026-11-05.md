# Production Audit & Fix Prompt — VulnStream-Enterprise (2026-11-05)

You are a senior security engineer and SRE. Audit the VulnStream-Enterprise codebase for production defects introduced or left behind by the most recent commits, then implement production-grade fixes. **Verify every finding against the current source before changing anything** — the findings below were confirmed by code inspection, but line numbers can shift and some are marked VERIFY.

## Scope

- Focus on the last three commits: `4373410` (Email Delivery Action Center + ML pipeline), `f4157ae` and `c914777` (UI confirmation dialogs).
- The UI dialog commits are large mechanical changes (~2,400 insertions across 15 components). Spot-audit them for regressions; the substantive risk is in the server/ML changes from `4373410`.
- Exclusions: `node_modules/`, `dist/`, `server-dist/`, generated migrations, style-only issues.

## System map

- **Server**: Node 22 + Express (`server/app.ts` router, `server/main.ts` bootstrap), PostgreSQL 17, migrations `001..036`, `REQUIRED_SCHEMA_VERSION = 36`.
- **ML subsystem**: `server/ml/` — `integration.ts` (pipeline wrappers + `initMlRuntime`), `feedback.ts` (zod schemas), `train/` (cron orchestrator, dataProvider, qualityGates), `models/` (18 models), `runtime.ts` (ModelRegistry with manifest + rollback).
- **Delivery**: `server/delivery.ts` (outbox worker, retry policy), `server/emailProviders.ts`.
- **Pipeline**: `server/pipeline.ts` (server worker), `src/engine/pipelineEngine.ts`, `src/engine/reconcileFindings.ts`.
- **Frontend**: React 19 + Vite (`src/`), context in `src/context/AppContext.tsx`.
- Tests: `node --import tsx --test` (`tests/*.test.ts`); gates `npm run lint` (tsc), `npm test`, `npm run build`.

## Confirmed findings — fix these

### F-1 · HIGH · ML · Calibrated credibility score unit mismatch
- **Where**: `server/ml/integration.ts:107-132` (`calibrateCredibilityScore`) and `server/ml/models/confidenceCalibrator.ts:73-107` (`predict`).
- **Defect**: The trained calibrator returns `result.score` as a 0–1 probability and `integration.ts:128` multiplies it by 100 to get a score. But the model's *untrained* path (and the fallback inside `integration.ts:117`) passes the raw 0–100 heuristic through unchanged. So a trained model maps a raw score of 80 to a calibrated score of ~80 only if the underlying training labels were stored as 0–1 — yet feedback samples (`server/ml/feedback.ts:72-74`, `credibilityScore: score` where `score = z.number().min(0).max(100)`) store 0–100. Re-confirm the contract end-to-end: `src/utils/intelligenceMatcher.ts:35` (`computeCredibilityScore` returns 0–100) → `pipeline.ts:1670` → calibrator train samples (`credibility_score` feature = 0–100) → `predict` interpolates against `raw` points in the same 0–100 domain but treats `calibrated` (label mean of 0/1 booleans) as a 0–1 probability. The output scale is therefore inconsistent with both the fallback and the input domain. Decide one contract (score 0–100 everywhere), fix `confidenceCalibrator.train/predict` and `integration.ts` together, and add a regression test asserting `calibrateCredibilityScore(0).score === 0` and `calibrateCredibilityScore(100).score === 100` whether trained or not.

### F-2 · HIGH · ML · Zero-day cap optimizer attributes outcomes to the wrong findings
- **Where**: `server/ml/models/zeroDayRateLimitOptimizer.ts:76-99` (`train`).
- **Defect**: `credibilityScores` is sorted descending (line 78) to simulate the cap keeping the top-N, but `keptOutcomes[i]` / `droppedOutcomes[i]` are indexed in their **original submission order**. The operator's outcome at index 3 may belong to the score at index 7, so the learned `bestCap` is fitted on shuffled labels. Fix: require scores and outcomes to travel together — sort the paired `(score, outcome)` list, or change the schema to accept `Array<{ score, outcome, kept: boolean }>`. Also note the schema in `server/ml/feedback.ts:85-91` only checks array *lengths*, which is what allowed this. Add a training test with distinguishable per-index outcomes that fails under the current code.

### F-3 · HIGH · ML · Feedback outcome enum does not match the model's vocabulary
- **Where**: `server/ml/feedback.ts:48` (`outcome = z.enum(['PATCHED','RESOLVED','FALSE_POSITIVE'])`) vs `server/ml/models/zeroDayRateLimitOptimizer.ts:21-22` (expects `'PATCHED'|'RESOLVED'|'DELIVERED'|'TIDY'|'FALSE_POSITIVE'` and counts `'DELIVERED'` as a true positive at lines 84/94).
- **Defect**: The API accepts a strict subset. Analysts can never submit `DELIVERED`/`TIDY` outcomes, and the trainer's `DELIVERED` branch is dead code. Reconcile the two enums (prefer extending the zod schema to the model's full vocabulary) and add a round-trip test: each accepted enum value reaches `train()` and is classified per the model's documented semantics.

### F-4 · MEDIUM · Delivery · Trained retry policy can override the operator's configured maximum
- **Where**: `server/delivery.ts:1959-1962`.
- **Defect**: `next_attempt` uses `Math.max(emailRetryDelayMs(...), computeRetryDelay(job.attempts))` when the delivery optimizer is trained. `computeRetryDelay` (`server/ml/integration.ts:208-225` → `deliveryOptimizer.computeDelay`) applies the *ML policy's* `maxDelayMinutes` grid (up to 2880 min), which can exceed the operator's `emailRetryMaxDelayMinutes` (default 60, max 10080) that governs `emailRetryDelayMs` (`server/delivery.ts:247-251`). The operator setting becomes a floor, not a cap. Fix: clamp the ML delay with `Math.min(policy.maxDelayMinutes * 60_000, ...)` so the operator configuration remains authoritative, and record in the delivery log which policy produced the delay. Note the call site already guards on `isTrained()`, so the untrained fallback path is not reachable here — keep it that way.

### F-5 · MEDIUM · Delivery · Extra per-retry query and mislabeled training outcome
- **Where**: `server/delivery.ts:1490-1497` and `server/delivery.ts:2213-2220`.
- **Defect**: (a) Every email retry claims a row, then issues a separate `operational_events` lookup for the previous `ml.delivery.outcome` — an extra query on the hot delivery path whose only purpose is `delayMs` for training. (b) `delayObserved` is set to `job.attempts === 1 || Boolean(priorAttempt)`; for attempt 1 with no prior event this records `delayMs: 0, delayObserved: true`, which trains the optimizer that first attempts "observed zero delay" — corrupting the delay→success curve. Fix: only record outcome events where a genuine delay was observed (`priorAttempt` present), or persist the attempt timestamp on the outbox row so no extra query is needed and `delayMs` is always real.

### F-6 · MEDIUM · ML · Unbounded fire-and-forget event writes on hot paths
- **Where**: `server/ml/integration.ts:736-753` (`logMlEvent`, called with `void` at ~12 call sites), including per-finding paths (`calibrateCredibilityScore` per intelligence match in `pipeline.ts:1670`, `computeRetryDelay` per delivery attempt, `cpePreFilter` per CPE).
- **Defect**: Each call issues a concurrent `INSERT INTO operational_events` with no concurrency cap, no batching, and error handling only via `console.error`. Under a large pipeline run or delivery backlog this is an unbounded write amplification against the shared pool (which also feeds `/ready` latency). Fix: coalesce ML events — either batch them per tick/run into one insert, add a bounded queue with drop-oldest overflow (recording the drop count), or reduce logging to WARN/ERROR plus a per-run summary. Keep `ml.delivery.outcome`/`ml.delivery.error` (real training signals) durable; drop per-prediction INFO noise.

### F-7 · MEDIUM · Main · Telemetry sampler gates on a value that starts negative and discards the anomaly result
- **Where**: `server/main.ts:551-571`; initial value at `server/correlation/runtime.ts:39` (`pendingDepth = -1`).
- **Defect**: The sampler returns early when `correlation.pendingDepth < 0`, but that is its initial value until the first successful drain loop refreshes it (`runtime.ts:114-120`). On a worker whose drain never runs, ML telemetry is never sampled and the anomaly detector never trains. Additionally, the `isTelemetryAnomaly(metrics)` result (line 568) is computed and discarded — an anomaly should at minimum write a WARNING event. Fix: sample when `pendingSampledAt === 0 || pendingDepth >= 0` (or default `pendingDepth` to a neutral "unknown" that doesn't block), and persist anomaly results.

### F-8 · RESOLVED · API · `/api/ml/status` model-readiness reporting — verified NOT a defect
- **Where**: `server/app.ts:1604-1622`; `server/ml/runtime.ts:116-141`.
- **Resolution**: `ModelRegistry.loadArtifact` only registers a registry entry (`this.models.set`, line 131) **after** an artifact is read, signature-verified and loaded. When no manifest entry exists for a model it returns `false` without registering anything, so `trained: Boolean(runtime.registry.get(id))` correctly reports 0 trained models with an empty ML directory. No code change required. Do not "fix" this by switching to `entry.model.isTrained()` without first confirming every model class implements it consistently.
- **Optional hardening (LOW, not required)**: surfacing `entry.status` (ACTIVE/DEGRADED/STANDBY_ROLLBACK) in the response would give operators rollback visibility the endpoint currently hides. Only add if you also extend `tests/integration.test.ts:280-295` to cover the untrained-directory case.

### F-9 · LOW · API · `/api/ml/feedback` is write-only until the next cron run
- **Where**: `server/app.ts:1623-1633`; consumer at `server/ml/train/dataProvider.ts:144-151`.
- **Defect**: Feedback is validated, written to `operational_events`, and audited — but never applied to the in-memory runtime (`appendMlFeedback` exists for exactly this and is only used by the training data provider). Acceptable if cron picks it up within a minute, but state that explicitly in the API response (`recorded: true` implies immediate effect) or call the runtime's `record()` for models that support online learning. Also consider a rate limit: the route is authenticated but unthrottled and each call writes a row.

### F-10 · LOW · Frontend · Dead uptime contract fields
- **Where**: `src/utils/systemUptime.ts:1-24`, `src/context/AppContext.tsx:142-164`.
- **Defect**: `loadAverage` is hardcoded `[0,0,0]` (never rendered anywhere — the server endpoint doesn't provide it) and `upSince` is stored but never read by any component. Either wire `upSince` into a tooltip/render or delete both fields from the interface and context state.

## Regression-verify (do not "fix" without evidence)

1. **RSS XXE posture** (`server/rss.ts:64-92`): the previous `hasDeclaration` guard was removed in favor of `processEntities: false` and fast-xml-parser's own DTD handling. Confirmed safe in `tests/news-events.test.ts` (external entities throw, internal entities stay literal). Keep those tests passing; do not reintroduce a regex DOCTYPE guard that breaks the Squarespace/CDATA cases covered there.
2. **UI confirmation dialogs** (`f4157ae`, `c914777`): 15 components each hand-roll inline confirmation state + execute handler + backdrop modal. Spot-check 3–4 of the largest (`SettingsView.tsx`, `CorrelationOperations.tsx`, `WatchListView.tsx`, `TopHeader.tsx`) for: duplicated modal markup worth extracting to one `ConfirmDialog` component, focus-trap/Escape handling consistency (compare against `src/hooks/useDialogFocus.ts`), and double-submit protection that survives React strict-mode double effects.
3. **Schema gate**: `REQUIRED_SCHEMA_VERSION` (`server/db.ts:124`) is 36 and `tests/migrations.test.ts` asserts it equals the max migration number — it must stay green if any migration is added.

## Audit dimensions (beyond the findings above)

For each, report findings in the standard format (File:line, Severity, Category, Description, Impact, Fix, Effort), then implement CRITICAL/HIGH:

1. **ML data integrity**: every training-sample path from event → zod parse → model.train. Look for the F-2 pattern generally (sorting one array while indexing a parallel one) across `server/ml/models/*.ts` and `server/ml/train/*`.
2. **ML fallback parity**: every `integration.ts` wrapper must return values in the *same unit and range* whether trained or not (the F-1 pattern). Check all 14 wrappers, especially `predictMatchConfidence`, `predictExploitRisk`, `predictSeverityTier`, `shouldSelectForDigest`.
3. **Operator authority**: ML recommendations must never override operator configuration (the F-4 pattern). Audit every `getMlRuntime()` call site in `server/` for decisions that bypass settings.
4. **Hot-path cost**: new per-item work added in `4373410` (delivery queries, ML event writes, `assessFindings` over `correlated.newFindings` at `pipeline.ts:1569` — confirm per-finding model predictions are O(findings), not O(findings × models × queries)).
5. **API surface**: the two new routes (`/api/ml/status`, `/api/ml/feedback`) — auth (`requireRole` present), zod validation (present), CSRF coverage (verify the global mutation middleware covers POST), response-shape tests.
6. **Shutdown/lifecycle**: `mlTelemetryRunning` is awaited in `shutdown()` (`main.ts:600-602`) — confirm no other new timer/await pair was missed.
7. **Frontend dialogs**: as in Regression-verify #2.

## Verified baseline (as of 2026-11-05, commit `c914777`)

Recorded so you can distinguish pre-existing failures from regressions introduced by your fixes:

- `npm run lint` — clean, exit 0.
- `npm test` — **857 tests: 794 pass, 0 fail, 63 skipped** (skips are DB/CI-dependent suites that require `TEST_DATABASE_URL`).
- The full CI matrix (`npm run test:ci`, 991 tests) is documented green in `AUDIT-2026-11-04-PRODUCTION.md` and requires a disposable PostgreSQL instance.

## Verification gates (must all pass after fixes)

```
npm run lint        # tsc --noEmit
npm test            # node --import tsx --test --test-concurrency=1 tests/*.test.ts
npm run build       # client + server
```

Add one regression test per fixed finding (F-1 through F-7 minimum). Do not weaken existing tests; `tests/news-events.test.ts` and `tests/migrations.test.ts` must pass unchanged.

## Deliverable

1. A findings table (verified / new / false-positive-after-verification) with severity counts.
2. Implemented fixes, each with its regression test.
3. Confirmation that all three gates pass.
4. Anything you could not verify (e.g. runtime behavior requiring Docker or a live DB) listed explicitly as unverified — do not claim it fixed.

## Findings summary (current state)

| Status | IDs | Severity |
| --- | --- | --- |
| Confirmed — implement | F-1, F-2, F-3 | HIGH ×3 |
| Confirmed — implement | F-4, F-5, F-6, F-7 | MEDIUM ×4 |
| Confirmed — implement | F-9, F-10 | LOW ×2 |
| Verified not a defect — do not change | F-8 | — |

The finding count to close is **9 fixes (3 HIGH, 4 MEDIUM, 2 LOW)**, each with one regression test.
