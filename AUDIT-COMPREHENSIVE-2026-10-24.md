# Comprehensive Codebase Audit Report — BA Threat Intel

**Date:** 2026-10-24
**Scope:** Full codebase — server (40+ files), client (30+ components), shared modules, engine, utils, tests, migrations, deployment
**Methodology:** Line-by-line review across 4 parallel audit domains (server core, server pipeline, server network/commands, client context/views/utils)

---

## Executive Summary

The codebase demonstrates strong security engineering: scrypt password hashing, AES-256-GCM secrets, SSRF-hardened egress, advisory-locked transactions, SHA-256 audit chains, Zod validation at all boundaries, and non-root Docker deployment. No CRITICAL vulnerabilities were found. However, several HIGH and MEDIUM severity issues should be addressed for enterprise-grade reliability.

**Findings: 12 HIGH, 38 MEDIUM, 25 LOW, 0 CRITICAL**

> **Remediation status (2026-10-25):** This document is retained as the historical baseline for the original review. The authoritative current readiness decision and verification counts are in `PRODUCTION-READINESS-AUDIT.md`. The following items were implemented and verified in the 2026-10-25 hardening pass:
>
> | Finding | Status | Implementation |
> |---|---|---|
> | H1 — audit-chain race | Fixed | `appendAudit` acquires the scoped `audit-chain` advisory lock itself and wraps non-transaction callers in a transaction. |
> | H5 — email header injection | Fixed | `advisoryEmail` strips CR/LF from ID, severity, and title before building the subject. |
> | H6 — CPE delimiter escaping | Fixed | `generateCPE23` escapes `\` and `:`; `buildStrictCpe23` does the same. |
> | H7 — wildcard CPE ReDoS | Fixed | Wildcard expansion is capped; wildcard-vs-wildcard comparison uses memoized glob intersection. |
> | H8 — alias candidate pruning | Fixed | Candidate generation expands alias identities, and the PostgreSQL match index carries the same alias-expanded keys. |
> | M — cookie prefix shadowing | Fixed | Cookie extraction matches the exact cookie name. |
> | M — `requireRole` missing-operator dereference | Fixed | Returns `401` when authentication middleware did not run. |
> | M — `TRUST_PROXY` / `DATABASE_URL` validation | Fixed | Trust-all proxy values and malformed database URLs are rejected at startup. |
> | M — recipient/webhook save resets delivery metrics | Fixed | Edits preserve `deliverySuccessRate`/`deliveryCount` and existing webhook secrets. |
> | M — RSS numeric entity lone surrogates | Fixed | Surrogate-range references are left undecoded. |
> | M — large state transfer size | Fixed | Bounded snapshot slices, exact `counts`/`summary`, server-side pagination for heavy views, and gzip above 1 KiB. |
> | M — scoped PURL identity | Fixed | A leading `@` is treated as the npm scope in the matcher and version index. |
> | M — alias-map prototype pollution | Fixed | Alias maps use null prototypes and store `__proto__` as ordinary data. |
> | M — invalid revision dates in CVE merges | Fixed | A parseable date wins; two invalid dates resolve deterministically. |
> | M — invalid CVE identity collisions | Fixed | Reconciliation falls back to the raw CVE ID or finding ID. |
> | M — LIKE wildcards in collection search | Fixed | `%`, `_`, and `!` are escaped with `ESCAPE '!'`; audit IP search is case-insensitive. |
> | M — identifier control characters | Fixed | `idSchema` rejects C0 and DEL control characters. |
> | M — mutation limiter never refilled | Fixed | Continuous token refill with an accurate `Retry-After`. |
> | M — stale snapshot / unmounted collection updates | Fixed | Refresh sequencing and in-flight request invalidation. |
> | M — failed post-mutation refresh reported as failure | Fixed | The committed mutation result survives a snapshot-refresh error. |
> | M — blank page on render error | Fixed | Top-level error boundary with a reload path. |
>
> The same pass added an explicit VEX conflict/scope lattice, symmetric structured CPE aliases, content-revision outbox dedupe, scoped named locks plus row-level locks, a typed candidate-pair index (migration 8), and safe JSON casts (migration 9). Regression coverage lives in `tests/exploitability.test.ts`, `tests/cpe-alias.test.ts`, `tests/config-auth.test.ts`, `tests/data-integrity.test.ts`, `tests/rate-limit.test.ts`, and `tests/hardening.test.ts`. Full verification: type check and production build pass; 237/237 PostgreSQL tests pass; 173/178 tests pass without a database with 5 database suites skipped.

---

## HIGH Severity Findings

### H1. Audit-chain race condition — `server/db.ts:121-149`
**Status: Fixed (2026-10-25).** `appendAudit` now acquires the scoped `audit-chain` advisory lock for the read/insert pair and wraps non-transaction callers in a transaction, so callers no longer need to hold a global mutation lock.

### H2. Missing global rate limiting — `server/auth.ts:104-120`
Only `/api/login` is throttled. No throttling on `/api/commands`, `/api/pipeline`, feed tests, password changes, or delivery retries. Brute-force and DoS vectors exist on all mutation endpoints.
**Fix:** Add a shared per-IP/per-user rate limiter middleware in front of all mutation routes.

### H3. Retention retry bug — `server/main.ts:88-106`
`claimRetention` gates retries on `lastRun` interval even after a failed run. `releaseRetention(false)` keeps the old `lastRun`, so a failed retention run cannot be retried until `cleanupIntervalMinutes` elapses, despite comments claiming immediate retry.
**Fix:** On failure, reset `lastRun` or set a shorter retry backoff.

### H4. Shutdown doesn't await retention — `server/main.ts:157-169`
Shutdown awaits `pipeline` and `outbox` but never awaits the in-flight retention run (`retentionRunning` is only a boolean). Process can exit mid-retention transaction.
**Fix:** Track the retention promise and include it in `Promise.allSettled` during shutdown.

### H5. Email header injection — `server/advisoryEmail.ts:16`
The email subject is built from raw `advisory.id` and `advisory.title` without CR/LF sanitization. A CVE title containing newlines can create an email header-injection vector.
**Fix:** Strip CR/LF from subject components before constructing the email.

### H6. CPE generation doesn't escape delimiters — `src/utils/cpeMatcher.ts:690-709`
`generateCPE23` does not escape CPE token delimiters (`:` and `\`) in vendor/product/version/targetHw, unlike `buildStrictCpe23`. Inputs containing `:` or `\` produce malformed CPE strings.
**Fix:** Apply the same escaping as `buildStrictCpe23`.

### H7. ReDoS via wildcard CPE patterns — `src/utils/cpeMatcher.ts:131-155`
`cpeComponentPattern` expands `*` to `.*` and builds a `RegExp` without guarding against nested quantifiers. Attacker-controlled CPE values with repeated wildcards can cause catastrophic backtracking.
**Fix:** Limit wildcard expansion depth or use a non-backtracking regex engine.

### H8. Alias candidate pruning false negatives — `src/engine/pipelineEngine.ts:132-161`
**Status: Fixed (2026-10-25).** Candidate keys are expanded through the alias maps, and the PostgreSQL match index (`server/versionIndex.ts`) uses the same alias-expanded identities, so alias-only correlations are no longer pruned.

### H9. Unvalidated URL in href (XSS) — `src/components/ThreatDataView.tsx:838`
`href={article.url}` renders an unvalidated URL in a new tab. A malicious/compromised feed article with a `javascript:` URL can execute script when clicked.
**Fix:** Validate/allow only `http:`/`https:` schemes before rendering.

### H10. Unhandled promise in resend — `src/components/AlertedCVEsView.tsx:39-45`
`handleConfirmResend` calls `resendNotification(...)` without `await`/error handling and never reloads state. Floating promise can reject unhandled; UI shows stale dispatch history.
**Fix:** `await`, check result, then reload.

### H11. Missing try/finally on refresh — `src/components/EmailQueueView.tsx:48-58`
`refresh()` has no `try/finally`; if `listEmailQueue()` rejects, `setLoading(false)` is never reached and the queue stays in loading state. `useEffect` invokes without cleanup.
**Fix:** Wrap in `try/finally`, add disposed guard.

### H12. Unhandled promise in test all — `src/components/ThreatFeedsView.tsx:83-106`
`handleTestAll()` awaits `Promise.all(...)` with no `try/catch`. If any `testFeedConnectivity` rejects, `testingAll` is never reset.
**Fix:** Wrap worker loop in `try/finally`.

---

## MEDIUM Severity Findings (selected)

### Server Core
- **`server/auth.ts:37-42`** — Cookie token extraction uses `find(startsWith(prefix))`; malformed/extra cookie could shadow real session token. Parse cookies into a map.
- **`server/auth.ts:69-71`** — `requireRole` dereferences `req.operator!` without guard; misordered middleware → 500/crash instead of 401.
- **`server/auth.ts:138-144`** — `secure` cookie flag tied solely to `NODE_ENV === 'production'`; HTTPS non-production deployments send non-Secure cookies.
- **`server/config.ts:9`** — `TRUST_PROXY` accepts any string; `true`/`*` trusts all proxies, enabling IP spoofing and rate-limit bypass.
- **`server/config.ts:5`** — `DATABASE_URL` only checked for non-empty; malformed URLs surface late.
- **`server/migrate.ts:7-13`** — Hardcoded `vulnstream_app` role; if absent migration fails, if unintended role exists privileges leak.
- **`server/secrets.ts:45-61`** — `decrypt` base64 canonicality check can reject valid inputs lacking padding.
- **`server/secrets.ts:62-64`** — `secureEqual` hashes unbounded input; CPU DoS vector.
- **`server/validation.ts:27-35`** — Secret query-param blocklist misses variants (`access_token`, `client_secret`, `auth`, `credential`).
- **`server/validation.ts:194-247`** — `emailConfigSchema` doesn't enforce egress allowlist on `apiEndpoint`.
- **`server/validation.ts:5`** — `idSchema` permits control characters/path separators.
- **`server/db.ts:276-291`** — `pipelineState` skips `orderWatchlist`, counts, full collection ordering.
- **`server/db.ts:108-110`** — `get<T>` casts unvalidated JSON to `T`; type-safety gap.

### Server Pipeline
- **`server/ingestion.ts:193-200`** — Feed timeout overrides pipeline duration budget instead of bounding it.
- **`server/delivery.ts:416-422`** — Non-transient delivery failures (decryption, SSRF, config errors) retried as transient.
- **`server/pipeline.ts:657-663`** — Stale-bundle recovery depends on exact error wording (`LIKE '%no longer applicable%'`).
- **`server/ingestion.ts:405`** — EPSS length guard checks wrong value (individual CVE id, not batch).
- **`server/pipeline.ts:415`** — `Promise.allSettled` with zero concurrency when no sources.
- **`server/mitre.ts:57-60,73`** — Unbounded in-memory index parsing (64 MiB allowed).
- **`server/pipeline.ts:686`** — Intelligence-match cleanup deletes all rows when new set is empty.

### Server Network/Commands/Retention
- **`server/events.ts:5`** — Sensitive-key redaction misses common secret-bearing names (`credential`, `passphrase`, `privateKey`, `jwt`, `authorizationHeader`).
- **`server/commands.ts:177`** — `recipient.save` always sets `deliverySuccessRate: 0`, discarding computed metric.
- **`server/commands.ts:186`** — `webhook.save` always resets `deliveryCount: 0`, discarding delivery history.
- **`server/commands.ts:280`** — `finding.status` spreads `f.timeline` without null guard.
- **`server/retention.ts:245-251`** — Outbox and operational-event deletions not audited unless records also deleted.
- **`server/retention.ts:11-17`** — `intelligenceArticles` eligible for retention while `intelligenceMatches` is not; dangling references.
- **`server/advisoryEmail.ts:16`** — Email subject built from raw advisory.id/title without CR/LF sanitization.
- **`server/collections.ts:59-60`** — `likeValue()` doesn't escape SQL LIKE wildcards.
- **`server/collections.ts:213`** — Audit-log IP search case-sensitive while other fields lower-cased.
- **`server/rss.ts:29-34`** — Numeric entity decoding can emit lone surrogates.

### Client Context/Hooks
- **`src/context/AppContext.tsx:82-87`** — Race condition: concurrent `refresh()` calls can apply stale snapshot.
- **`src/context/AppContext.tsx:383-384`** — Unmemoized context value causes global re-render storms.
- **`src/context/AppContext.tsx:119-130`** — `safely` clears shared error banner for concurrent operations.
- **`src/context/AppContext.tsx:323-330`** — Mutation commands that don't refresh leave collection views stale.
- **`src/context/AppContext.tsx:207-212`** — `call()` reports failure even when mutation succeeded.
- **`src/context/AppContext.tsx:181-188`** — `login` partially commits state on refresh failure.
- **`src/context/AppContext.tsx:100-101`** — No upper bound on `page`/`pageSize`.
- **`src/hooks/useCollection.ts:76-82`** — `catch` clears page despite comment claiming to keep it.
- **`src/hooks/useCollection.ts:56-85`** — No request cancellation; setState can run after unmount.
- **`src/main.tsx:5`** — No error boundary around app tree.

### Client Views
- **`src/components/AdvisoriesView.tsx:82`** — `adv.severity` interpolated unescaped in HTML download (XSS).
- **`src/components/FindingsView.tsx:65-74`** — Optimistic state update can show stale/inconsistent drawer.
- **`src/components/FindingsView.tsx:193-305`**, **`OperationalLogsView.tsx:269,574`** — Clickable table rows lack keyboard accessibility.
- **`src/components/FindingsView.tsx:516-570`** and similar modals — Missing `role="dialog"`, `aria-modal`, `aria-labelledby`.
- **`src/components/EmailHistoryView.tsx:25-35`** — Floating promises in retry/refresh.
- **`src/components/EmailQueueView.tsx:97-108`** — Concurrent review actions can desync queue.
- **`src/components/RecipientsView.tsx:139-148`** — Webhook test ignores failures.
- **`src/components/RecipientsView.tsx:693-702,722-731`** — Delete handlers don't await success before closing modal.
- **`src/components/SettingsView.tsx:46`** — Form not resynced when settings change.
- **`src/components/SettingsView.tsx:221-226`** — Password change doesn't check result.
- **`src/components/AliasesView.tsx:329-333`** — Delete doesn't await success.
- **`src/components/OperationalLogsView.tsx:383`** — `error.message` assumes Error type.
- **`src/components/WatchListView.tsx:423-480`** — Bulk import lacks client-side shape validation.
- **`src/components/ThreatFeedsView.tsx:80`**, **`WatchListView.tsx:468`**, **`AdvisoryTemplateView.tsx:146`** — `setTimeout` not cleared on unmount.
- **`src/components/SystemHealthView.tsx:74-76`**, **`SettingsView.tsx:62-64`** — useEffect async without unmount guards.
- **`src/components/AdvisoryTemplateView.tsx:827-841`** — Preview iframe sandbox policy.

### Client Utils/Engine
- **`src/utils/cpeMatcher.ts:690-709`** — CPE generation doesn't escape delimiters (HIGH).
- **`src/utils/cpeMatcher.ts:131-155`** — ReDoS via wildcard CPE patterns (HIGH).
- **`src/engine/pipelineEngine.ts:132-161`** — Alias candidate pruning false negatives (HIGH).
- **`src/utils/deduplicator.ts:46-48`** — NaN date comparison silently retains stale records.
- **`src/utils/cpeMatcher.ts:352-361,366-377`** — Prototype pollution via alias keys.
- **`src/utils/versionComparator.ts:39-44`** — Misleading version ordering for non-numeric cores.
- **`src/utils/watchlist.ts:12-26`** — Mixed-case CPE fields always treated as changed.
- **`src/utils/cryptoChain.ts:11-13`** — `sha256` returns sync but typed as Promise.
- **`src/engine/reconcileFindings.ts:3`** — Null CVE IDs collapse to same key.
- **`src/utils/cpeMatcher.ts:434-446`** — PURL parsing misparses scoped packages.
- **`server/advisoryEmail.ts:9`** — Injection of advisory ID skipped on coincidental match.
- **`src/engine/pipelineEngine.ts:86`** — Duplicate count undercounts invalid CVE IDs.

---

## Recommendations by Priority

### P0 — Fix immediately (security/correctness)
1. H5: Email header injection (advisoryEmail.ts)
2. H9: XSS via unvalidated URL (ThreatDataView.tsx)
3. H1: Audit-chain race (db.ts)
4. H6/H7: CPE injection + ReDoS (cpeMatcher.ts)

### P1 — Fix soon (reliability)
5. H2: Global rate limiting (auth.ts)
6. H3/H4: Retention retry + shutdown (main.ts)
7. H8: Alias candidate pruning (pipelineEngine.ts)
8. H10-H12: Unhandled promises in views
9. M: Mutation commands not refreshing (AppContext)
10. M: Non-transient delivery failures retried (delivery.ts)

### P2 — Harden (enterprise quality)
11. M: All remaining medium findings
12. L: All low findings
13. Accessibility improvements
14. Error boundary + StrictMode (main.tsx)

---

## Positive Findings (Enterprise-Grade Practices Already in Place)

- Scrypt password hashing with salt, no default accounts
- AES-256-GCM with record-specific AAD for secrets
- SSRF-hardened egress: hostname allowlist, DNS pinning, IP screening, HTTPS-only, redirect rejection
- PostgreSQL advisory locks with schema-scoping
- SHA-256 chained audit logs with content/link verification
- Transactional outbox for delivery with atomic claims and lease tokens
- Zod validation at all API boundaries
- Non-root Docker with read-only filesystem, health checks, graceful shutdown
- CSRF tokens with exact-origin enforcement
- Comprehensive test suite (237 tests with PostgreSQL; database suites skip cleanly without it)
- Retention policy with dry-run preview
- Circuit breaker for feeds
- Delivery retry with exponential backoff
- Webhook HMAC signing with timestamp validation
- Formula-safe CSV export
- Sandboxed HTML preview
- Cryptographic chain verification UI
- Rate limiting on login
- Login throttling stored in PostgreSQL
- Session revocation on password change
- Idle/absolute session expiry
- Encrypted secrets with redaction from API responses
- Feed credential clearing on URL/auth change
- No seeded runtime cache
- Explicit version exclusions in matching
- Per-CPE range matching
- Unknown/unsupported version review gates
- Unsigned VEX cannot suppress findings
- Worker recovery with idempotent re-runs
- Disabled-target delivery checks
- Provider acceptance recorded separately from inbox delivery
- Constrained template customization
- Full history retained in PostgreSQL
- Separate owner and restricted runtime DB roles
- Migration job separate from app
- Caddy HTTPS proxy
- Backup/restore documentation

---

## Files Audited

**Server (42 files):** db.ts, auth.ts, config.ts, main.ts, migrate.ts, secrets.ts, validation.ts, pipeline.ts, ingestion.ts, ingestionState.ts, feedRecovery.ts, delivery.ts, concurrency.ts, mitre.ts, rss.ts, network.ts, events.ts, collections.ts, commands.ts, retention.ts, advisoryEmail.ts, recommendedFeeds.ts, emailProviders.ts, app.ts, advisoryEmail.ts, + 4 migration SQL files

**Client (35+ files):** AppContext.tsx, useCollection.ts, all 18 *View.tsx components, EmailProviderSettings.tsx, LogDetailModal.tsx, Sidebar.tsx, TopHeader.tsx, LoginView.tsx, ErrorBoundary.tsx, main.tsx, all utils/, engine/, types/

**Shared:** state.ts, types/index.ts

**Tests:** 25+ test files reviewed for coverage patterns

**Deployment:** compose.yaml, Dockerfile, init-db.sh, Caddyfile

**Documentation:** README.md, OPERATIONS.md, 5 audit docs
