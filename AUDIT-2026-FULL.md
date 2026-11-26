# Production-Grade Technical Audit — VulnStream-Enterprise

**Scope:** complete codebase (140,750 lines TS/TSX across 372 source files, 47 migrations, 154 test files).
**Method:** automated gates (tsc, npm audit, build), database-backed test suite against a disposable PostgreSQL 17 scratch instance, plus four parallel line-by-line domain audits (server concurrency/data-integrity, engine business logic, client/shared security, migrations/schema).
**Prior audits incorporated:** `PRODUCTION-AUDIT.md` and `AUDIT-2026-CONCURRENCY.md` (their fixed items are NOT re-reported here).
**Severity scale:** CRITICAL / HIGH / MEDIUM / LOW / INFO.

---

## 1. Automated Gate Results

| Gate | Command | Result |
|------|---------|--------|
| Typecheck / lint | `npx tsc --noEmit` | exit 0, zero type errors |
| Dependency audit | `npm audit` / `npm audit --omit=dev` | 0 vulnerabilities |
| Production build | `npm run build` (client + esbuild server) | exit 0 |
| Test suite (DB-backed tier) | `node --import tsx --test --test-concurrency=1 tests/*.test.ts` with `TEST_DATABASE_URL` | **in progress** (scratch DB `vulnstream_audit_scratch` on 127.0.0.1:5432; migrations applied cleanly) |

Note: the first test invocation used `export VAR=val node args...`, which bash parses as multiple `export` assignments and never launched `node`. The suite was re-launched with the correct `TEST_DATABASE_URL='...' node ...` prefix form.

---

## 2. Consolidated Issue vs Resolution

Findings are grouped by domain. `VERIFIED SAFE` and `DISPROVED` items from each agent are summarized per domain; full per-file citations live in the agent outputs (retained in session context).

### 2.1 Server — Concurrency, Async, Data Integrity, Security

| ID | Severity | File:Line | Issue | Resolution |
|----|----------|-----------|-------|------------|
| S-001 | MEDIUM | `server/db.ts:78` | `pg.Pool` options cast through `as any`, bypassing type safety and hiding misconfigured pool knobs at runtime (no inline justification, which AGENTS.md requires for `as any`). | Type the options object via `pg.PoolOptions` or a typed cast; remove `as any`. |
| S-003 | HIGH | `server/pipeline.ts:600-606` | `rebuildFromCurrentInventory` performs autocommit writes (`pool.query` legacy job selection + `rebuildLegacyDeliveryPayload` `UPDATE outbox`) outside any `transaction()`, then enters a separate transaction later — a non-atomic write-then-decision gap where concurrent rebuilds can duplicate or clobber delivery jobs. | Wrap the legacy rebuild loop and `regroupStaleAdvisory` invalidation in a single `transaction()` so the read-rebuild-invalidates decision is atomic. |
| S-004 | MEDIUM | `server/delivery.ts:1583` | Unannotated `as any` cast weakens the Pool-vs-PoolClient feature test; violates the no-unjustified-`any` rule. | Replace with an explicit typed type guard (`(db as pg.Pool).connect !== undefined && (db as pg.PoolClient).release === undefined`). |
| S-005 | MEDIUM | `server/main.ts:348-373` | The 95%-heap memory-pressure path calls `await shutdown(); process.exit(1)`, but `shutdown()` can block on in-flight pipeline/outbox/digest workers and `pool.end()`, so `process.exit(1)` may not run promptly — a wedged shutdown leaves the process alive in an unhealthy state. | Add an independent `setTimeout(() => process.exit(1), 30000)` hard deadline before `await shutdown()`, cleared on successful shutdown. |
| S-006 | MEDIUM | `server/app.ts:2707` | `/api/test-email-connectivity` opens a raw TCP connection (`net.createConnection(smtpHost, smtpPort)`) to an operator-supplied host:port with no egress-allowlist check — an SSRF primitive reachable by any authenticated ADMIN. | Restrict the probe to configured SMTP hosts (validate `smtpHost` against `config.SMTP_HOST`/allowlist) and reject private/link-local/reserved IPs. |
| S-007 | MEDIUM | `server/app.ts:1830-1879` | `/api/audit/cleanup` deletes and rewrites audit-chain rows without taking the `audit-chain` advisory lock at the start, so a concurrent `appendAudit` (db.ts:1028) can interleave and break `prevHash` chain consistency. | Acquire `SELECT pg_advisory_xact_lock(hashtext($1), <schemaLockKey>)` for `audit-chain` as the first statement of the cleanup transaction. |
| S-008 | LOW | `server/ingestion.ts:1116-1119` | `NVD_WINDOW_QUARANTINE_LIMIT` (25) is declared but the guard block is empty, so a provider-wide schema break is not bounded per window despite the constant's stated purpose. | Throw `new Error('NVD window quarantine limit exceeded')` inside the block. |
| S-009 | LOW | `server/auth.ts:277` | The user lookup runs on the pool directly, outside the transaction that incremented `login_attempts`, so a concurrent disable/password change between increment and lookup is not observed until after the attempt is recorded. | Move the user lookup inside the login transaction (after the increment) or re-verify `disabled` under the same lock. |
| S-010 | INFO | `server/correlation/runtime.ts:175` | Unbounded `count(*)` on `correlation_pending` in the drain loop's `finally`, sampled every tick — grows linearly with queue depth. | Telemetry-only, non-transactional, used for `/metrics` depth gauge; not an integrity risk. Accept as-is (listed for completeness). |

**VERIFIED SAFE (server):** `db.ts:876-879` `orderLocks` prevents advisory-lock deadlock cycles; `db.ts:270-322` `safeAdvisoryUnlock` destroys connection on unlock failure; `db.ts:832-907` `transaction()` binds `onAbort`→`cancelBackend` + release flag; `pipeline.ts:488-490` `queueRun` locks active execution `FOR UPDATE`; `pipeline.ts:459-486` generation-guarded promise replacement; `delivery.ts:1963-2000` claim CTE `FOR UPDATE SKIP LOCKED`; `delivery.ts:2670-2682` documented row-lock order; `delivery.ts:2834-2843` `DELIVERY_RATE_WINDOW=200`; `delivery.ts:2933-2936` `getManyForUpdate` sorted id order; `main.ts:917-1052` dead-letter `FOR UPDATE SKIP LOCKED` + per-letter savepoint; `main.ts:778-840` ML `claimToken` conditional updates; `dailyDigest.ts:454,899` `pg_try_advisory_lock` + boolean-result unlock; `auth.ts:116-120` CSRF via `secureEqual` fail-closed; `correlation/pending.ts:32-44` atomic single-statement claim; `correlation/clusters.ts:110-139` partial unique index + `ON CONFLICT`; `correlation/supervisor.ts:556-615` capped priority waiter scheduler; `versionIndex.ts:361-401` transient-code-only retry savepoints; `shared/state.ts:241` roles exactly `ADMIN\|OPERATOR\|VIEWER`.

**DISPROVED (server):** `db.ts:465` interpolated index name is safe (`indexName()` regex `/^[A-Za-z_][A-Za-z0-9_$]*$/`). All prior-audit-context items (finalize lock order, bounded `count(*)`, heartbeat/watchdog, `paceConcurrent` hrtime, `claimPending` SKIP LOCKED, CPE rematch cap, zero-day cap, `queueRun` scope/checkpoint) confirmed fixed/correct.

### 2.2 Engine — Business Logic, Classification, Matching, Reconciliation

| ID | Severity | File:Line | Issue | Resolution |
|----|----------|-----------|-------|------------|
| E-01 | MEDIUM | `src/engine/threatIntelMatcher.ts:768-772,2103,2109` | A concrete product registration paired with a broad wildcard CPE (`cpe:2.3:a:vendor:*`) is reclassified as WILDCARD (Case 2) instead of EXACT (Case 1), downgrading operator-declared identity and altering routing/email grouping. Contradicts `classification.ts`. | Derive precision from the declared product only (EXACT when declared; WILDCARD only for `*`/`-`/absent product), mirroring `classification.ts:265-274`. |
| E-02 | MEDIUM | `src/engine/pipelineEngine.ts:449-450,460` | Every CVE without structured identifiers forces an unbounded O(CVEs × activeAssets) corpus re-read on every run; text-only CVEs scan the whole inventory. | Bound the text/alias fallback via a precomputed inverted vendor/product/alias index and/or a per-CVE candidate cap. |
| E-03 | MEDIUM | `src/engine/pipelineEngine.ts:739; src/types/index.ts:931` | `AlertedCVE.dispatchCount` is never incremented — `runVulnerabilityPipeline` returns `structuredClone(alerted)` unchanged and `reconcileFindings` never touches `alertedCves`, so per-CVE alert counters stay at their initial value forever (lost update). | Increment `dispatchCount`/`lastDispatchAt`/`lastDispatchKey` on the matching `AlertedCVE` when a finding is queued/dispatched; return the mutated set from `runVulnerabilityPipeline`. |
| E-04 | LOW | `src/engine/pipelineEngine.ts:669,704` | `dispatchDeferred` is reset to `false` on every reconciliation (fresh candidate sets `false` at 669; `reconcileFindings` overwrites at 704), discarding a circuit-breaker-held finding's deferred state. | Preserve existing deferral: `dispatchDeferred: old?.dispatchDeferred ?? candidate.dispatchDeferred`. |
| E-05 | MEDIUM | `src/components/ActionCenter.tsx:208-233` | SLA metrics (delivery rate, compliance) are computed from `emailLogs`, the current paginated slice (max 25 rows), not the full collection — contradicting `shared/state.ts:196-198` (KPI aggregates must not be skewed by bounded slices). Displayed SLA is sample-dependent and inaccurate. | Compute delivery rate/compliance from server-side aggregate counts (collection-wide delivered/failed/total) via `useCollection` metadata or a dedicated `/api/email-logs/summary` endpoint. |
| E-06 | LOW | `src/components/ActionCenter.tsx:247,760` | `averageDeliveryTime` actually holds the first-attempt success rate (0–100%), mislabeled as a time; header renders "X% first-attempt". | Rename field to `firstAttemptRate`; introduce a real `averageDeliveryTimeMs` from `sentAt` − `createdAt`, or label the existing rate truthfully. |
| E-07 | LOW | `src/components/ActionCenter.tsx:233` | `slaCompliance` equals the raw overall delivery rate with no time window or threshold — measures volume, not timeliness; can read 100% while deliveries are late. | Define compliance as % accepted within a configured SLA window (derived from `sentAt`/`createdAt`). |
| E-08 | HIGH | `src/components/ThreatIntelligenceSearch.tsx:315-316,334-337,340` | NVD API-key dialog is a silent no-op: `nvdFeed` is hardcoded `{}` and `hasNvdApiKey` hardcoded `false`, so "save" calls `updateFeed({...{}, authType, authSecretKey})` with no feed id/name/type/url the server can update; banner always reads "No NVD feed is configured." | Resolve the configured NVD feed from `feeds` (type `NVD_API`/VULNCHECK_NVD) and pass its `id`; derive `hasNvdApiKey` from whether the resolved feed carries `authSecretKey`. |
| E-09 | LOW | `src/components/ActionCenter.tsx` (no `setInterval`) | No auto-refresh, so live SLA metrics and delivery logs go stale until the operator clicks Refresh — contradicts the required 30-second auto-refresh for live metrics (implemented in `DailyDigestView.tsx:149-161`). | Add a 30-second `useInterval` reload of metrics/logs with unmount cleanup, mirroring `DailyDigestView`. |
| E-010 | LOW | `src/components/ActionCenter.tsx:79-93` | Advertised "advanced filtering by recipient type" is not implemented — `FilterOptions` lacks any recipient-type/delivery-group field. | Add `recipientType`/`deliveryGroup` to `FilterOptions` and pass into `useCollection` filters alongside status/provider/date/advisoryId. |
| E-011 | LOW | `src/engine/pipelineEngine.ts:82-85` | `determineExploitRisk` checks `Reported In Wild` before `Active Weaponized`, so a weaponized exploit (higher-confidence signal) is downgraded to "reported in wild" whenever `exploitationSources` is also present. | Check `Active Weaponized` before `Reported In Wild`, matching `ExploitRiskLevel` severity ordering. |

**VERIFIED SAFE (engine):** `classification.ts:265-274` `matchPrecision` (declared product authoritative); `classification.ts:218-251` `versionIsConfirmedPatched`; `threatIntelMatcher.ts:188-243` `rankAndRateLimitZeroDays` bounded cap; `reconcileFindings.ts:57-65` `DIGEST_BATCHED` carried forward only when withheld again (not silenced permanently); `server/pipeline.ts:2936,2964,3113` zero-day cap over dispatchable persisted rows + `DIGEST_BATCHED` + `delivery.zero_day_digest_failed` with 30-min cooldown dedup; `server/pipeline.ts:351,375,403` `carryCpeRematchBacklog` bounded by `CPE_REMATCH_MAX_RUNS=5` / 7 days; `ActionCenter.tsx:328-343` bulk actions use `Promise.allSettled`; `ThreatAnalyticsView.tsx:596-614` `requestId` dedup ignores superseded fetches.

**DISPROVED (engine):** `src/engine/reconciliation.ts` does not exist; reconciliation lives in `src/engine/reconcileFindings.ts` and `server/pipeline.ts` — no missing module.

### 2.3 Client & Shared — Auth, CSRF, XSS, Secrets

| ID | Severity | File:Line | Issue | Resolution |
|----|----------|-----------|-------|------------|
| C-01 | MEDIUM | `src/components/ErrorBoundary.tsx:86-97` | Unexpected React errors render the error name, message, and component stack directly in the UI; "Copy Diagnostics" places stack traces, component stacks, and user agent on the clipboard, exposing internal implementation details. | Render a generic "Application error occurred" in production; keep `console.error` server-side only; remove or gate "Copy Diagnostics" behind a developer-mode flag. |
| C-02 | LOW | `src/components/LogDetailModal.tsx:114` | `field.value` typed as `React.ReactNode` and rendered via `{field.value}`, bypassing React text-content escaping — a latent XSS vector if a future caller passes unsanitized JSX with event handlers or `javascript:` URIs. | Change `field.value` type to `string`; if rich text is required, pass through `sanitizeEmailHtml` (`src/utils/sanitizeEmailHtml.ts`) first. |
| C-03 | LOW | `src/context/AppContext.tsx:152,485` | The CSRF token is stored in React context and exposed via `useApp()`, so any component (or XSS payload) can read it and construct fully authenticated mutation requests; widens the XSS blast radius beyond what the httpOnly cookie alone allows. | Stop storing the CSRF token in client state; rely on the httpOnly sameSite=strict session cookie (`server/auth.ts:76-84`) as the primary CSRF control, keeping `x-csrf-token` as defense-in-depth from a non-script-accessible double-submit cookie. |

**VERIFIED SAFE (client/shared):** session cookie httpOnly/sameSite=strict/secure (`server/auth.ts:76-84`); all mutations require `Origin` header + `x-csrf-token` validation (`server/auth.ts:117-120`, `server/app.ts:543-552`); roles exactly `ADMIN\|OPERATOR\|VIEWER` (`shared/state.ts:241`); email HTML preview sanitized by dompurify via `sanitizeEmailHtml` (HTML profile, SVG/math/script forbidden) (`ActionCenter.tsx:149,1684; sanitizeEmailHtml.ts:57-68`); visual contenteditable editor re-parses through `sanitizeEmailHtml` before storing (`ActionCenter.tsx:547-564`); Zod validation at boundary for env and all request payloads (`server/config.ts:6-456`, `server/validation.ts:4-584`); `express.json({limit:'2mb', strict:true})` rejects malformed/oversized bodies; single error middleware maps HttpError/ZodError/23505/oversized/malformed JSON (`server/app.ts`); `publicState()` redacts secrets (`server/app.ts:170-185`); no `ENCRYPTION_KEY`/`ML_SIGNING_KEY`/`DATABASE_URL`/`SMTP_PASSWORD` leakage into client bundle (`vite.config.ts`); all 24 page IDs have `App.tsx` branches + Sidebar items (`pages.ts:30-57`, `App.tsx:52-78`, `Sidebar.tsx:48-100`); template text escaped before HTML insertion (`templateCompiler.ts:53-59,394-418`); all bulk Action Center operations call endpoints enforcing `requireAuth + requireRole` (`ActionCenter.tsx:729-791`); CVE links `encodeURIComponent`'d and validated by Zod (`CveLink.tsx:11-21`).

**DISPROVED (client/shared):** XSS via `innerHTML`/`dangerouslySetInnerHTML` — every occurrence routes through `sanitizeEmailHtml` (dompurify HTML profile). No hardcoded secrets in client/shared code. No token leakage via localStorage (only theme preference). No GET-with-side-effects (mutations are POST/PATCH/DELETE only).

### 2.4 Migrations & Schema

| ID | Severity | File:Line | Issue | Resolution |
|----|----------|-----------|-------|------------|
| M-001 | LOW | `server/migrations/009_safe_json_casts.sql:41` | Self-record lacks `ON CONFLICT DO NOTHING`; direct re-execution fails with unique violation 23505, breaking idempotency defense-in-depth (runner skips applied versions, but parity is lost). | Change to `INSERT INTO schema_migrations (version) VALUES (9) ON CONFLICT DO NOTHING;`. |
| M-002 | MEDIUM | `server/migrations/003_record_creation_order.sql:7` | Inline plain `CREATE INDEX records_created_order` on `records` (created in 001, potentially populated at upgrade time); plain CREATE INDEX takes SHARE and blocks writers — the exact hazard the `indexes/` directory exists to eliminate. Version 3 is within `tests/migrations.test.ts` version<=10 carve-out, so tests pass but the strict AGENTS.md rule is violated. | Move to `server/migrations/indexes/` as `CREATE INDEX CONCURRENTLY IF NOT EXISTS records_created_order ...`; remove line 7 from 003. |
| M-003 | MEDIUM | `server/migrations/005_outbox_priority.sql:5` | Inline plain `CREATE INDEX outbox_priority` on pre-existing `outbox` (created 001); SHARE-locks the live delivery queue during upgrade. Version 5 within test carve-out. | Move to `indexes/` as `CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_priority ...`. |
| M-004 | MEDIUM | `server/migrations/007_delivery_and_audit_guards.sql:6-8` | Inline plain partial `CREATE INDEX outbox_target_pending` on pre-existing `outbox`; SHARE-locks the queue during upgrade. Version 7 within test carve-out. | Move to `indexes/` as `CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_target_pending ...`. |
| M-005 | LOW | `server/migrations/indexes/001_correlation_indexes.sql:34` | `correlation_alias_identity` is a redundant unique index duplicating the PRIMARY KEY on `vendor_product_aliases(alias)` (011:15 already creates a unique btree), wasting storage and write amplification with no query benefit. Lookups use `lower(alias)`, served by `correlation_alias_lookup` (line 32), not this PK-duplicating index. | Drop `correlation_alias_identity` from indexes/001; keep `correlation_alias_lookup`. |

**VERIFIED SAFE (migrations):** numbering 001–047 unique, gap-free, contiguous; every migration self-records in `schema_migrations` (009 lacks `ON CONFLICT` — see M-001); `REQUIRED_SCHEMA_VERSION = 47` equals newest migration 047 (`tests/migrations.test.ts`); every migration wrapped in single `BEGIN`/`COMMIT` with `ROLLBACK` on failure and `release(failed)` (`db.ts:499-565`); index DDL all `CREATE [UNIQUE] INDEX CONCURRENTLY IF NOT EXISTS`, applied outside transaction by `applyIndexMigrations()` (`db.ts:329-373`); `transaction()` performs `BEGIN`, optional `SET LOCAL` timeouts, ordered advisory locks, `COMMIT`/`ROLLBACK`, `release(failed)` in `finally` (`db.ts:832-907`); `appendAudit` atomic per mutation with `audit-chain` advisory lock (`db.ts:1010-1053`); pool settings validated by zod at startup and applied in `createPool` (`config.ts:146-177,316-326`; `db.ts:52-78`); `scripts/seed.ts` manual-only, not in migrate/start path (`main.ts:85-87`, `package.json`).

**DISPROVED (migrations):** no duplicate versions, no gaps, all index-file statements are `CONCURRENTLY`, no migration missing self-record, `REQUIRED_SCHEMA_VERSION` does not lag.

---

## 3. Severity Summary

| Severity | Count | IDs |
|----------|-------|-----|
| HIGH | 3 | S-003, E-01, E-08 |
| MEDIUM | 9 | S-001, S-004, S-005, S-006, S-007, E-02, E-03, E-05, M-002/M-003/M-004 |
| LOW | 8 | S-008, S-009, E-04, E-06, E-07, E-09, E-010, E-011, C-02, C-03, M-001, M-005 |
| INFO | 2 | S-010 |

HIGH items are the priority: non-atomic rebuild writes (S-003), CPE wildcard downgrading concrete product identity (E-01), and the silent NVD API-key save no-op (E-08). MEDIUM items include SSRF via the email-connectivity probe (S-006), audit-chain lock gap (S-007), unjustified `any` casts (S-001/S-004), memory-pressure shutdown hang (S-005), unbounded corpus re-read (E-02), unincremented alert counter (E-03), SLA metrics on a paginated slice (E-05), and the three inline index builds on populated tables (M-002/M-003/M-004).

---

## 4. Recommended Next Steps

1. Apply the HIGH and MEDIUM resolutions above.
2. Re-run `npm run lint` (tsc) — must be exit 0.
3. Re-run the full `npm test` against the scratch DB (suite currently in progress; confirm 0 failures, note the pre-existing unrelated `tests/email-resend.test.ts` red that exists independent of this audit).
4. Drop the scratch database when done: `docker exec vulnstream-enterprise-db-1 psql -U vulnstream_migrator -d postgres -c "DROP DATABASE vulnstream_audit_scratch;"`.
5. Do NOT commit unless explicitly requested; no secrets were read or introduced during this audit (`.env` was never opened).

No files were modified during this audit; this is a report only.
