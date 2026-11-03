# AI Audit Prompt — VulnStream-Enterprise (All Features)

You are a senior security engineer, architect, and code reviewer performing a comprehensive production-readiness and feature-correctness audit of the VulnStream-Enterprise codebase. This is a vulnerability intelligence platform: it ingests CVE feeds, correlates them with CPE/PURL inventory, generates advisories, and delivers notifications via email/webhooks, with an autonomous offline ML subsystem.

## Repository Context
- Stack: React 19 + Vite (client), Node.js 22 + Express (server), PostgreSQL 17, Docker/Caddy.
- Entry: `server/main.ts` (bootstrap), `server/app.ts` (router, ~2200 lines), `src/App.tsx` (SPA shell).
- Config: `kilo.json`, `AGENTS.md`. Lint: `npm run lint` (tsc --noEmit). Tests: `npm test`, `npm run test:unit`.

## Scope: Audit ALL features listed below. For each, verify implementation correctness, security, data integrity, error handling, concurrency, performance, and test coverage.

### A. Authentication & Authorization
Files: `server/auth.ts`, `server/secrets.ts`, `server/rateLimit.ts`, `server/config.ts`, `src/components/LoginView.tsx`.
- Opaque server sessions, CSRF/origin checks, password hashing (argon/bcrypt?), token expiry/refresh.
- RBAC: ADMIN / OPERATOR / VIEWER enforced on every endpoint.
- Persistent login throttling shared across replicas (DB-backed rate limiter).
- Password reset flow (`/api/password-reset/*`): request/verify/complete, quotas, code exposure only in test.
- Secrets encryption at rest (ENCRYPTION_KEY), masking in API responses.
- Session isolation, logout invalidation, concurrent session handling.

### B. Ingestion & Feeds
Files: `server/ingestion.ts`, `server/ingestionState.ts`, `server/mitre.ts`, `server/rss.ts`, `server/recommendedFeeds.ts`, `server/feedRecovery.ts`, `server/cvss.ts`, `src/components/ThreatFeedsView.tsx`.
- MITRE CVE JSON 5, NVD API, CISA KEV, FIRST EPSS, OpenCVE v2, VulnCheck KEV, RSS/Atom news, schema-validated JSON feeds.
- Incremental checkpoints with 10-min overlap; initial sync capped 24h; daily slices for catch-up.
- MITRE/OpenCVE skip unchanged revisions; EPSS caches scores 1h.
- RSS: ingestion window, XML validation, DTD/entity rejection, quarantine malformed/future-dated entries, canonical URLs strip tracking params.
- Feed recovery backoff, circuit breaker, retry.
- Provider tokens required; seeded disabled until configured.
- Feed CRUD, connectivity test, egress allowlist enforcement.

### C. Correlation Engine
Files: `server/correlation/*` (engine, clusters, pending, runtime, supervisor, inventory, extraction, validation, notifications, notificationEvidence, metrics, heartbeat, telemetry, operations, ingest, stream, query, deadLetter, boundedJson, version, preflight), `src/components/CorrelationDashboard.tsx`, `CorrelationOperations.tsx`, `CpeMatcherView.tsx`, `AliasesView.tsx`.
- CPE/PURL matching with version exclusions.
- Strict-first tiers: PURL → strict CPE → alias thesaurus → whole-word vendor/product prose.
- Only structured tiers can auto-dispatch; alias/prose review-only.
- Unknown versions / complex NVD applicability require review.
- Unsigned VEX cannot suppress findings.
- Vendor/product aliases: self-maintaining, bounded, learned only from confirmed findings, 30-day expiry, promote/revoke.
- Concurrency: advisory locks, lease ownership, shared correlation concurrency, dead-letter handling.
- Metrics endpoint `/metrics` auth, heartbeat hang detection.

### D. Pipeline & Findings
Files: `server/pipeline.ts`, `src/engine/pipelineEngine.ts`, `src/engine/reconcileFindings.ts`, `src/components/PipelineExecutionsView.tsx`, `FindingsView.tsx`, `AlertedCVEsView.tsx`.
- Pipeline run lifecycle, scheduling, catch-up.
- Findings stable IDs and history as applicability changes.
- Per-execution filtering via executionId; new detection reporting per execution.
- Reconciliation of current inventory against cached CVEs.
- Finding importance ranking, severity tiering.
- Archive retention.

### E. Advisories & Templates
Files: `server/advisoryRender.ts`, `server/advisoryEmail.ts`, `server/advisoryRebuild.ts`, `server/pdf.ts`, `src/components/AdvisoriesView.tsx`, `AdvisoryTemplateView.tsx`.
- Advisory generation, rendering, PDF export.
- Template editing, live preview.
- Rebuild on demand.
- Advisory remediation helper (ML).

### F. Delivery & Notifications
Files: `server/delivery.ts`, `server/digest.ts`, `server/dailyDigest.ts`, `server/emailProviders.ts`, `server/commands.ts`, `src/components/EmailHistoryView.tsx`, `EmailQueueView.tsx`, `RecipientsView.tsx`, `DailyDigestView.tsx`, `EmailProviderSettings.tsx`.
- Durable PostgreSQL outbox with retries/recovery.
- SMTP and Email API providers, encrypted credentials, leave-blank keeps.
- At-least-once delivery; stable Message-ID; webhook idempotency keys.
- Digest combining threats into one email per recipient per tier; digest state in PG.
- Retry policy: enabled flag, attempts, initial/max delay; Retry-After honor.
- Content deduplication; rerun/retry/restart no duplicate.
- Recipient subscriptions tiers; per-recipient filtering.
- Command authorization fail-closed co-located with dispatcher.
- Manual retry, queue test email.

### G. ML Subsystem
Files: `server/ml/*`, tests `tests/ml-*.test.ts`.
- 17 models (list in `server/ml/models/`), base model, factory, runtime, integration, defaults.
- Algorithms: GBDT, scaler, isolation forest, logistic regression, RNG.
- Training: orchestrator, data provider, evaluation, quality gates, drift detection, cron.
- Fallback when untrained; training never overwrites active model on failure.
- Quality gates thresholds; PSI/concept drift.
- Memory leaks in history buffers; type safety (no `any`).
- Cron training script standalone.

### H. Analytics, Health, Ops
Files: `server/analytics.ts`, `server/events.ts`, `server/retention.ts`, `src/components/ThreatAnalyticsView.tsx`, `SystemHealthView.tsx`, `OperationalLogsView.tsx`, `ArchiveRetentionView.tsx`.
- Threat analytics, operational events (category/level/full-text/cursor pagination).
- Health `/live`, `/ready`, `/metrics` actual measurements.
- Archive retention policies.
- Dashboard.

### I. Threat Intelligence Search & Data
Files: `server/threatSearch.ts`, `server/cpeSearch.ts`, `src/components/ThreatIntelligenceSearch.tsx`, `ThreatDataView.tsx`, `ThreatAnalyticsView.tsx`.
- Search, CPE simulation, intelligence matcher, severity classifier.

### J. Settings & Configuration
Files: `src/components/SettingsView.tsx`, `server/config.ts`, settings.css.
- Processing/dispatch settings, email delivery, recipients, aliases.
- Environment variables documented; defaults safe.

### K. Frontend/UI
Files: `src/components/*`, `src/index.css`, css files.
- Table styling consolidation (`.ui-main table` canonical).
- ErrorBoundary, pagination, dialogs, modals.
- Dark/light theme.
- Recent changes: divide-y removal, per-component CSS removal.

### L. Database & Migrations
Files: `server/db.ts`, `server/migrate.ts`, `server/migrations/*`.
- Idempotent/reversible migrations, transactions, pooling, indexes, constraints, backup/restore.

### M. Security Cross-Cutting
- SQL injection, XSS, CSRF, authn/authz, secrets, input validation, rate limiting, CORS, SSRF, path traversal, dependency CVEs.

### N. Testing
- `tests/*.test.ts`, vitest. Coverage gaps, isolation, mocks, edge cases, flaky.

### O. Vulnerability Search & OSINT
Files: `server/vulnerabilitySearch.ts`, `server/googleCse.ts`, `shared/vulnerability.ts`, `src/components/VulnerabilitySearchView.tsx`, `src/types/index.ts`.
- OSV/NVD/CISA KEV vulnerability search with live OSINT panel.
- Google CSE integration (API key handling, quota, egress allowlist).
- Shared vulnerability types between server/client.
- Input validation, rate limiting, SSRF protection on search endpoints.
- Caching, pagination, error handling, empty states.

### P. System Uptime & Health
Files: `server/app.ts` (`/api/system-uptime`), `src/components/TopHeader.tsx`, `src/context/AppContext.tsx`.
- Public uptime endpoint (moved before requireAuth); no sensitive data leakage.
- Frontend fetch from API (no missing request export).
- Memory-shedding HIGH-lane floor; DB severance detection.

### Q. Pipeline Hardening & Concurrency (recent)
Files: `server/pipeline.ts`, `server/commands.ts`, `server/correlation/supervisor.ts`, `server/delivery.ts`, `server/correlation/query.ts`.
- Transaction-scoped advisory locks for watchlist/recipients.
- Pipeline stop via shared worker connection.
- DB severance detection; memory-shedding.
- Dedupe news notifications by asset identity.
- Duplicate symbol/syntax resolution.

## Audit Instructions
1. Read the relevant files for each feature before judging.
2. Verify against README supported behavior and migrations.
3. Run verification commands:
   - `npm run lint`
   - `npm test`
   - `npm run test:unit`
   - `npm run build`
4. Do not modify code; report findings only.
5. For each finding output:
   - File: path:line
   - Severity: CRITICAL/HIGH/MEDIUM/LOW
   - Category: Security/Performance/Reliability/Maintainability/Testing/Styling/Functional
   - Feature: which feature area
   - Description
   - Impact
   - Fix
   - Effort: S/M/L/XL
6. Prioritize: Security → Data loss → Availability → Performance → Quality → Coverage → Styling.

## Exclusions
- `node_modules/`, `dist/`, `server-dist/`.
- Style/formatting handled by linter.
- Skip generated migration content.
- Do not report missing features; focus on existing code quality and correctness.

## Recent Changes to Verify (regression focus)
- Commit 6f70f4e: table styling consolidation; verify no `divide-y` on tbody; no per-component overrides; `.feeds-table`, `audit-actions-table`, `ml-logs-table`, `cr-match-table`, `threat-results-table` still function.
- Commit 9f06baa: report new detections not whole corpus per execution; verify `executionId` filtering and detection counts.
- Commit 4d06be3/4f8958f: fail-closed command authorization co-located with dispatcher; verify HTTP boundary tests.
- Commit 201c57f: executionId on findings for per-execution filtering.
- ML audit trail training data collection and cron training (07223b7, f7f4904, c247031, 1634383, c1483f7, 39573ac).
- Correlation schema contracts and hardening (023, 024, 025, 027, 028).

Produce a final audit report grouped by feature area with a summary table of counts by severity.
