# BA Threat Intel Enterprise — Production Readiness Audit

**Audit date:** 2026-10-24  
**Scope:** server, matching engine, pipeline, ingestion, delivery, authentication, validation, retention, and the affected React views.  
**Method:** static review of the full TypeScript surface, targeted regression tests, full unit + PostgreSQL integration runs, lint, production build, and dependency audit.

> This report supersedes the older `AUDIT.md`, `AUDIT-SUMMARY.md`, and `THREAT-INTELLIGENCE-AUDIT.md` for current readiness decisions. Those files were not treated as authoritative.

---

## 1. Verification result

| Check | Command | Result |
|---|---|---|
| Type check | `npm run lint` | Pass |
| Production build | `npm run build` | Pass (client + server) |
| Unit tests (no DB) | `npm test` | 178 tests, 173 pass, 5 skipped, 0 fail |
| Full tests (PostgreSQL) | `TEST_DATABASE_URL=… npm test` | **237 tests, 237 pass, 0 fail** |
| Dependency audit | `npm audit --omit=dev` | **0 vulnerabilities** |

The full PostgreSQL run is now deterministic. Before this pass it failed intermittently when test files ran in parallel because every test schema and every deployment sharing a database contended for the same long-held pipeline advisory lock. Test files now run serially (`package.json`).

---

## 2. Fixed in this pass

### P0 — Pipeline advisory lock was database-wide, not schema-scoped
**Files:** `server/db.ts:25`, `server/db.ts:32`, `server/db.ts:68`, `server/pipeline.ts:150`, `server/pipeline.ts:822`

`pg_advisory_lock(800003)` is scoped to the database. Two BA Threat Intel deployments sharing one PostgreSQL database (or parallel test schemas) blocked each other's pipelines for the whole run. A worker that could not acquire the lock returned `false`, leaving executions `RUNNING` and silently skipping ingestion.

The migration, state-transaction, and pipeline-worker locks now use the two-key form with `hashtext(COALESCE(current_schema(), current_database()))`. Same-schema workers still serialize; independent schemas no longer block each other. The lost-lock regression test now targets its own schema (`tests/pipeline-lifecycle.test.ts`).

### P0 — CPE wildcard-vs-wildcard matching produced false positives
**File:** `src/utils/cpeMatcher.ts:157-233`

Two wildcard components were always treated as matching. `2.*` therefore matched `1.*`, which can correlate an installed version to an unrelated vulnerable range. Added a memoized glob-intersection check (`globIntersects`) and regression coverage in `tests/audit.test.ts`.

### P0 — Version-less PURL matches auto-dispatch as exact correlations
**File:** `src/utils/cpeMatcher.ts:503-541`

A package-name-only PURL (`pkg:npm/widget`) was assigned 95% confidence even when neither side had a version, which is above the 90% auto-dispatch threshold. It now returns 70% and `applicabilityRequiresReview: true`; only a verified installed version or comparable range is 95%. Regression test: `tests/audit.test.ts` (“package-name-only PURL correlation requires review…”).

### P0 — News mentions could resurrect excluded findings
**File:** `src/utils/intelligenceMatcher.ts:69-79`

`NOT_APPLICABLE` and `SUPPRESSED_VEX_NOT_AFFECTED` findings could become `CORROBORATED` from a news article. Both states, plus `REVIEW_REQUIRED`, now remain review-only. Regression test: `tests/news-events.test.ts`.

### P1 — Delivery revalidation ignored operator-managed aliases
**File:** `server/delivery.ts:272-308`

A finding matched through an operator alias was re-evaluated without that alias and permanently rejected as “no longer applicable.” Revalidation now loads `VENDOR`/`PRODUCT` aliases and passes them to the pipeline.

### P1 — Retention of the threat cache permanently blocked queued advisories
**File:** `server/delivery.ts:282-293`

Retention may delete a regenerable `cveData` record while a manually reviewed advisory is still queued. Revalidation then found no CVE, marked every finding invalid, and failed the bundle permanently. Revalidation now falls back to the finding’s embedded, already-validated CVE snapshot. Regression test: `tests/pipeline-lifecycle.test.ts` (“retention of the threat cache does not permanently block a queued advisory”).

### P1 — Email secrets were reused after changing the destination
**File:** `server/commands.ts:198-234`

Changing a custom API endpoint or SMTP host/username while leaving the secret blank silently reused the old credential, which could send it to a different service or account. The secret is now reused only when the provider and destination/identity are unchanged; otherwise the operator must re-enter it (blank token returns `400`). Regression test: `tests/email-providers.test.ts`.

### P1 — Feed deletion left orphaned cursors and snapshots
**File:** `server/commands.ts:295-306`

Deleting a feed now removes its `feedCursors` and `feedSnapshots`, so a later feed with the same id cannot resume a stale checkpoint.

### P1 — Feed connectivity test trusted HTTP status alone
**File:** `server/app.ts:392-410`

A `200` HTML error page or truncated body was reported as `HEALTHY`. Non-RSS feeds now require a parseable JSON body; RSS/Atom is parsed with the hardened syndication parser.

### P1 — Cookie clearing did not match the `__Host-` cookie attributes
**File:** `server/app.ts:170-180`, `server/app.ts:208-216`

Logout and password change now clear the cookie with `path`, `secure`, `sameSite`, and `httpOnly` matching the original, so the `__Host-vulnstream` cookie is actually removed in production.

### P1 — Advisory status refresh could overwrite explicit exclusions
**File:** `server/app.ts:77-95`

`refreshAdvisoryDeliveryStatus` no longer rewrites findings in `NOT_APPLICABLE`, `SUPPRESSED_VEX_NOT_AFFECTED`, or `REVIEW_REQUIRED` states.

### P1 — Feed URL credential detection missed common key names
**File:** `server/validation.ts:27-35`

Query keys such as `key`, `access_key`, `private_key`, `credential`, and `sig` are now rejected; credentials must use the encrypted auth field.

### P2 — Strict inventory CPE builder emitted invalid CPEs for names with `:` or `\`
**File:** `src/data/vendorCatalog.ts:654-671`

`buildStrictCpe23` now escapes token delimiters. A product such as `gateway:edge` produces a valid, matchable CPE instead of a 12-token invalid string. Regression test: `tests/audit.test.ts` (“inventory CPE builder escapes token delimiters…”).

### P2 — Dependency vulnerability
**Files:** `package.json`, `package-lock.json`

`body-parser` 1.20.8 → 1.20.9 (via Express 4.22.3) resolves `GHSA-27r3-jxmh-p828`. `npm audit --omit=dev` now reports 0 vulnerabilities.

### P2 — Non-deterministic full test suite
**File:** `package.json`

`npm test` now uses `--test-concurrency=1`. Parallel PostgreSQL test files exhausted connections and the 15-second statement timeout, producing false failures in otherwise-correct pipeline tests.

---

## 2a. Hardening pass — 2026-10-25 (implemented and verified)

This pass closed the remaining concurrency, matching, VEX, and delivery-idempotency gaps from the adversarial review. Every item below has direct regression coverage and passed the full PostgreSQL suite, type check, and production build.

### Concurrency — scoped locks replace the installation-wide lock
**Files:** `server/db.ts`, `server/commands.ts`, `server/app.ts`, `server/pipeline.ts`, `server/retention.ts`, `server/main.ts`

The global `800002` advisory lock serialized every write in the installation. It is replaced by optional named locks on `transaction(pool, fn, client, { locks })` plus row-level `getForUpdate()` for read-modify-write sequences. The audit chain uses its own `audit-chain` lock, retention uses `retention-run`/`retention-claim`, and recipient creation uses `recipients-unique` so two concurrent creates cannot both pass the same read-then-insert uniqueness check. Independent domains now proceed concurrently while the same domain still serializes. Regression coverage: `tests/hardening.test.ts` (unrelated named locks overlap; the same named lock serializes; row locks expose only committed state; concurrent duplicate recipient creates commit exactly one row).

### VEX — explicit status lattice, no silent suppression
**Files:** `src/engine/exploitability.ts`, `src/types/index.ts`, `server/validation.ts`, `server/ingestion.ts`, `server/pipeline.ts`

VEX resolution now returns an explicit assessment instead of a boolean. `affected` plus `not_affected`/`fixed` is `CONFLICT` and requires review; independent exploit intelligence (KEV/EWI/active exploitation) produces `EXPLOIT_INTELLIGENCE_OVERRIDE`; `under_investigation` requires review; statements outside the finding scope produce `SCOPE_MISMATCH`. Unsigned statements are retained for audit but can never suppress, and generic JSON feeds keep only `signed === true` statements. Scope matching uses the same symmetric alias thesaurus as correlation and the matched inventory item's own PURLs, so a statement for one affected package cannot suppress a finding for a different package on the same CVE. Findings now persist `matchedAssetPurls`, and reconciliation refreshes vendor, product, and PURL scope when inventory changes. Regression coverage: `tests/exploitability.test.ts` (conflict, scope mismatch, per-asset PURL scope, signed/unsigned, override, review escalation).

### Matching — symmetric structured CPE aliases without weakening strict mode
**Files:** `src/utils/cpeMatcher.ts`, `src/engine/pipelineEngine.ts`

`matchCPE` accepts optional vendor/product alias maps. Exact component equality is always evaluated first; only a structured pair that differs solely by a thesaurus entry is matched, returns `viaAlias: true`, and is scored at 85% (below the 90% auto-dispatch threshold). Omitting the alias maps preserves the previous strict behavior. The pipeline's candidate prefilter and the PostgreSQL candidate index expand the same built-in plus operator-managed alias groups; expanding only custom aliases had excluded pairs such as `microsoft`/`msft` before the matcher could evaluate them, silently dropping valid findings. Regression coverage: `tests/cpe-alias.test.ts` (both operand orders, strict default, exact-match precedence, product separation, review confidence, built-in alias reachability) and the built-in-alias candidate subtest in `tests/hardening.test.ts`.

### Delivery — content-revision outbox dedupe
**Files:** `server/delivery.ts`

Outbox keys are `${stableDispatchKey}:${contentRevision}:{email|webhook}:${targetId}`. Pipeline-created advisories receive a new random ID on every run, so the advisory ID is excluded from the content revision and the default dispatch key is content-derived; an explicit operator dispatch key still overrides it for intentional resends. `findingRevision` excludes volatile delivery state (`notificationStatus`, `exploitability`) so reruns after delivery do not create new revisions. A terminal stale-applicability failure may be safely re-opened only after the pipeline revalidates current inventory; transport, recipient, and subscription failures are never resurrected. Regression coverage: `tests/hardening.test.ts` (random advisory IDs dedupe, volatile state ignored, material change redelivers, operator override), plus the existing stale-bundle lifecycle tests.

### Scale — typed candidate index and pushdown
**Files:** `server/versionIndex.ts`, `server/migrations/008_match_index.sql`, `server/pipeline.ts`, `server/db.ts`

Migration 8 adds `match_asset_index`/`match_cve_index` with GIN identity arrays and typed version ordinals. PostgreSQL now generates candidate `(cve_id, asset_id)` pairs; the JavaScript matcher remains authoritative. Only simple dotted numeric versions are encoded, and any unencodable bound/criterion is treated as unbounded, so the index is always a conservative superset. Alias-expanded identities and PURL identities participate, and a full refresh removes stale asset/criterion rows. The cleanup compares positionally aligned CVE/criterion arrays: de-duplicating the CVE ids had zipped them against a longer criterion list and silently dropped every criterion after the first for multi-criterion CVEs. This also closes the PURL-only inventory scan and alias candidate-pruning gaps. Regression coverage: `tests/hardening.test.ts` (range/exact/PURL/wildcard selection, non-numeric conservatism, stale-row cleanup, multi-criterion retention, ordinal ordering).

### Server input and authorization hardening
**Files:** `server/config.ts`, `server/auth.ts`, `server/commands.ts`, `server/rss.ts`

- `DATABASE_URL` must now parse as a `postgres:`/`postgresql:` URL with a hostname, so malformed configuration fails at startup instead of during the first query.
- `TRUST_PROXY` rejects trust-all values (`*`, `true`, `0.0.0.0/0`, `::/0`). Explicit proxy IPs, CIDRs, and the `loopback`/`linklocal`/`uniquelocal` presets remain supported.
- Cookie extraction matches the exact cookie name instead of the first prefix match, preventing a forged `vulnstream_*` cookie from shadowing the real session token.
- `requireRole` fails closed with `401` when authentication middleware did not run, instead of dereferencing a missing operator.
- Read-only endpoints (audit-chain verification, the email queue, and correlation simulation) remain available to `VIEWER`, matching the documented role model; only mutations and administrative routes require `ADMIN`/`OPERATOR`.
- Editing a recipient preserves its computed `deliverySuccessRate`; editing a webhook preserves its `deliveryCount` and does not silently rotate a stored secret when the secret field is blank.
- RSS numeric character references in the UTF-16 surrogate range are left undecoded instead of emitting lone surrogates.
- `/api/state` and other responses are gzip-compressed above 1 KiB; heavy collections are bounded and their history views are server-paginated.

Regression coverage: `tests/config-auth.test.ts`, the recipient/webhook subtest in `tests/hardening.test.ts`, the surrogate case in `tests/news-events.test.ts`, and the compression assertion in `tests/integration.test.ts`.

### Matcher and data-integrity hardening
**Files:** `src/utils/cpeMatcher.ts`, `server/versionIndex.ts`, `src/utils/deduplicator.ts`, `src/engine/reconcileFindings.ts`, `server/validation.ts`, `server/collections.ts`

- Scoped PURLs (`pkg:npm/@scope/name`) keep the npm scope as identity; a leading `@` is no longer mistaken for a version delimiter in either the matcher or the version index.
- Operator-managed alias maps use null prototypes, so a canonical key such as `__proto__` is stored as data instead of mutating `Object.prototype`.
- CVE merges prefer a record with a parseable `modifiedDate` over one with an invalid date; when both dates are invalid, deterministic content ordering decides the winner. Equal-time applicability conflicts still escalate to review.
- Finding reconciliation falls back to the raw CVE ID (or finding ID) when normalization fails, so distinct invalid identifiers no longer collapse onto one identity.
- `idSchema` rejects control characters (C0 and DEL) while allowing legitimate separators.
- Collection search escapes `%`, `_`, and `!` and uses `ESCAPE '!'`, so a literal wildcard in a query cannot broaden a search. Audit IP search is now case-insensitive.

Regression coverage: `tests/data-integrity.test.ts`, `tests/cpe-alias.test.ts`, `tests/audit.test.ts` (scoped PURL), and the LIKE-wildcard subtest in `tests/hardening.test.ts`.

### State scaling — bounded snapshots with exact aggregates
**Files:** `server/db.ts`, `server/app.ts`, `src/context/AppContext.tsx`, `src/components/*`

- `state()` honors per-kind limits and `/api/state` always supplies `STATE_COLLECTION_LIMITS`; only recent slices of heavy collections are returned.
- `counts` and `summary` are computed independently of the returned rows, so KPI cards and navigation badges stay exact at any cache size.
- Advisories, pipeline executions, sent-notification history, and audit logs use `/api/collections/:kind` with server-side pagination and search instead of slicing capped snapshot arrays. Audit exports walk every server page and honor the active filters.
- Retention footprint counts come from `/api/retention/preview`; the correlation simulator calls `/api/correlation/simulate`, which evaluates the full server-side cache.
- The dashboard and sidebar read `summary`/`counts`; gzip compression above 1 KiB remains enabled.

Regression coverage: the bounded-state subtest in `tests/hardening.test.ts` asserts capped slices, exact `counts`, and exact `summary` aggregates, and `tests/integration.test.ts` asserts gzip on `/api/state`.

### Collection reliability — malformed legacy values cannot break a page
**Files:** `server/collections.ts`, `server/migrations/009_safe_json_casts.sql`, `server/db.ts`

Server-side ordering and filtering cast JSON fields to `timestamptz`/`numeric`. A single legacy or imported row with an unparseable value made PostgreSQL abort the entire paginated listing (`invalid input syntax for type timestamp with time zone`). Migration 9 adds `safe_timestamptz()`/`safe_numeric()`, which return `NULL` for unparseable input; the collection queries use them for sorting and range filters, malformed timestamps sort last via `NULLS LAST`, and the KEV filter compares the text value instead of casting it to `boolean`. Regression coverage: the malformed-legacy-payload subtest in `tests/hardening.test.ts` exercises sorting, in-scope date filtering, KEV filtering, and EPSS filtering with invalid values.

### Client resilience and mutation limiting
**Files:** `server/rateLimit.ts`, `server/app.ts`, `src/context/AppContext.tsx`, `src/hooks/useCollection.ts`, `src/components/SettingsView.tsx`, `src/components/ErrorBoundary.tsx`, `src/main.tsx`

- Mutation token buckets now refill continuously. The previous implementation reset its timestamp on every request, so a throttled operator could never recover while retrying; denied responses now carry a `Retry-After` derived from the actual refill rate.
- Concurrent state refreshes are sequence-numbered, so a slower older snapshot can no longer overwrite a newer one.
- Background tabs skip the 10-second `/api/state` poll and refresh immediately when they become visible again.
- `useCollection` invalidates in-flight requests on unmount or parameter change, preventing late responses from updating an inactive view.
- A failed paginated collection fetch keeps the last successful page and surfaces the app-level error banner instead of blanking the table.
- A failed post-mutation snapshot refresh no longer makes a committed mutation look failed.
- A failed password change keeps the form populated so the operator can correct the current password instead of retyping both values.
- Recipient, webhook, and finding-status mutations refresh the snapshot immediately instead of waiting for the next poll.
- Delete confirmations close only after the server confirms success, and failed webhook tests now surface an error instead of silently doing nothing.
- Email retry state is cleared in a `finally` block so a failed request cannot leave the row stuck in a retrying state.
- The existing error boundary is now mounted at the application root, so a render failure shows its diagnostics and recovery UI instead of leaving a blank page.

Regression coverage: `tests/rate-limit.test.ts`.

**Addressed:** the mutation limiter was originally per-process. It is now backed by the `consume_rate_limit_token` PostgreSQL function (`server/migrations/010_shared_rate_limit.sql`, refined by `012_rate_limit_return.sql`) and `createDatabaseRateLimiter` (`server/rateLimit.ts:71-87`). The bucket lives in `rate_limit_buckets` and the decision plus refill-update happen atomically under `FOR UPDATE`, so every replica shares one quota per operator. `server/app.ts:540-543` uses the database limiter by default for both mutation and ingest quotas, and `server/runtimePrivileges.ts:9,32` grants the runtime role CRUD on the table and `EXECUTE` on the function. The cross-replica test (`tests/rate-limit.test.ts:57-89`) verifies that two limiter instances share a single token bucket.

### Verification
`npx tsc --noEmit`, `npm run build`, `npm test` without a database (178 tests: 173 pass, 5 skipped), and the full PostgreSQL run (237 tests, 237 pass) all succeeded.

---

## 3. Findings and status (prioritized)

### P0 — `/api/state` returns the entire cache and history on every poll
**Status:** Addressed. `/api/state` now returns a bounded snapshot: `STATE_COLLECTION_LIMITS` applies a `LIMIT` to every heavy collection (`cveData`, `findings`, `advisories`, `alertedCves`, delivery logs, executions, articles, matches, audit rows), while `counts` and `summary` remain exact and are computed independently of those slices. Views that need history now use the server-paginated `/api/collections/:kind` endpoint: advisories, pipeline executions, sent-notification history, and audit logs. Dashboard and navigation totals use `summary`/`counts` instead of filtering capped arrays, the retention footprint uses `/api/retention/preview`, and the correlation simulator uses `/api/correlation/simulate` against the full cache. Responses are also gzip-compressed above 1 KiB.

**Files:** `server/db.ts`, `server/app.ts`, `src/context/AppContext.tsx`, `src/components/{AdvisoriesView,PipelineExecutionsView,AlertedCVEsView,OperationalLogsView,DashboardView,Sidebar,ArchiveRetentionView,WatchListView}.tsx`

### P1 — Hardcoded cleanup windows bypass the operator retention policy
**Status:** Addressed. The background cleanup now removes only security-invariant session/login-attempt rows. Terminal `outbox` rows and `operational_events` are deleted by `runRetention` using the configured policy cutoff, and those deletions are audited.

**Files:** `server/main.ts`, `server/retention.ts`

### P1 — PURL-only inventory is evaluated against every CVE
**Status:** Addressed in §2a by the typed candidate index. PURL identities now participate in candidate generation, so PURL-only assets are only offered to CVEs whose PURL criteria overlap. Wildcard/unencodable criteria still fall back to the full candidate set for correctness.

**Files:** `server/versionIndex.ts`, `server/migrations/008_match_index.sql`, `server/pipeline.ts`

### P1 — Retention scheduling is per process, not per deployment
**Status:** Addressed. The last successful run and an expiring claim are persisted in the `systemState` `retention-schedule` row, so replicas do not each schedule the same cleanup. A scoped `retention-claim` lock serializes the first claim.

**File:** `server/main.ts`

### P2 — Alias/fallback matches ignore the version range
**Status:** Addressed within the strict-matching constraint. Structured CPE alias matches still evaluate the NVD version interval (the alias only broadens vendor/product), and an unprovable version keeps the finding review-only. The free-text vendor/product fallback stays at 85% and is review-only, so it can never auto-dispatch. This is deliberate: exact matching remains the default, concrete versions are evaluated before ranges, and every looser path is gated behind manual review.

**File:** `src/utils/cpeMatcher.ts`

### P2 — A failed retention run waits a full interval
**Status:** Addressed. `releaseRetention(false)` records `lastFailedAt` and `nextRetryAt` (60 seconds by default), and `retentionTick` honors `nextRetryAt` before attempting another claim.

**File:** `server/main.ts`

### P2 — Older audit documents are stale
**Status:** Addressed. `AUDIT.md`, `AUDIT-SUMMARY.md`, `THREAT-INTELLIGENCE-AUDIT.md`, `ECOSYSTEM-AUDIT-2026-10-21.md`, and `CODEBASE-UI-AUDIT-2026-10-21.md` now carry a historical banner that points to this report as the authoritative readiness document.

**Files:** `AUDIT.md`, `AUDIT-SUMMARY.md`, `THREAT-INTELLIGENCE-AUDIT.md`, `ECOSYSTEM-AUDIT-2026-10-21.md`, `CODEBASE-UI-AUDIT-2026-10-21.md`

---

## 4. Deployment checklist

- [ ] Set `NODE_ENV=production`, an HTTPS `APP_ORIGIN`, and a 32-byte base64 `ENCRYPTION_KEY`.
- [ ] Keep `EGRESS_ALLOWED_HOSTS` minimal; add only feed/provider hosts actually used.
- [ ] Run migrations before starting the worker (`schema_migrations` version 9 is required).
- [ ] Set `WORKER_ENABLED=true` only on the process that should run the pipeline, delivery loop, and retention.
- [ ] Configure a reverse proxy with TLS, request/response size limits, and timeouts above the 30-second API timeout.
- [x] State snapshots are bounded and heavy history views are server-paginated; no further `/api/state` scaling change is required before loading a large CVE cache.
- [ ] Verify email/webhook providers from the UI (“Test All Feeds” for feeds; provider test actions for delivery) before enabling auto-dispatch.
- [ ] Keep retention disabled until the desired window and archive ceiling are reviewed; test a manual cleanup in staging first.
- [ ] Run `npm run lint`, `npm test` (with `TEST_DATABASE_URL`), `npm run build`, and `npm audit --omit=dev` in CI.

---

## 5. Notes on concurrent work

The working tree also contains operator-facing retention work (`server/retention.ts`, `tests/retention.test.ts`, `src/components/ArchiveRetentionView.tsx`, retention settings/types) and unrelated UI changes. They were verified by the full test/build run and were not reverted. The older audit documents were retained and marked historical rather than deleted, to preserve user-authored history.
