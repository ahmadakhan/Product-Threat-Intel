# AI Audit Prompt — Production-Ready Code (VulnStream-Enterprise)

You are a senior SRE, security engineer, and production-readiness reviewer. Audit the VulnStream-Enterprise codebase to determine whether it is safe to deploy and operate in production. Focus on deployability, operability, resilience, security, data integrity, and observability. Do not report missing features; evaluate existing code quality.

## System Overview
- React 19 + Vite SPA (`src/`), Node.js 26 + Express API/worker (`server/`), PostgreSQL 17, Docker Compose + Caddy TLS proxy.
- Bootstrap: `server/main.ts`; router: `server/app.ts`; health: `/live`, `/ready`, `/metrics`.
- Migrations: `server/migrate.ts`, `server/migrations/001..034` + indexes.
- Env: `.env.example`; secrets encrypted at rest with ENCRYPTION_KEY.

## Production-Readiness Dimensions

### 1. Boot & Lifecycle
- `server/main.ts`: graceful startup, migration ownership, DB role privileges, signal handling (SIGTERM/SIGINT), connection pool close, worker pool drain, hang timer unref.
- Readiness `/ready`: DB latency, supervisor health, backpressure; must fail closed when DB/severance.
- Liveness `/live`: event-loop hang detection threshold.
- Graceful degradation when optional services missing.
- Process global handlers: uncaughtException, unhandledRejection; structured logging.

### 2. Configuration & Secrets
- All required env vars documented (README, .env.example); defaults safe for production.
- No hardcoded secrets; ENCRYPTION_KEY handling; credential blank-keeps behavior.
- Egress allowlist `EGRESS_ALLOWED_HOSTS` enforcement in network.ts.
- CORS restrictive, origin validation, CSRF.
- Rate limiters DB-backed shared across replicas (reset quotas).

### 3. Database & Migrations
- Migration job owns DDL; runtime role no DDL; idempotent migrations; reversible where feasible.
- Connection pooling: size, timeout, leak prevention, release() in finally.
- Transactions for critical ops (outbox, findings, aliases).
- Index coverage for hot queries; CONCURRENTLY migrations (026).
- Backup/restore procedures in OPERATIONS.md; test with TEST_DATABASE_URL.
- No N+1 in loops; batch queries.

### 4. Security
- SQL injection: parameterized queries only.
- XSS: escaped HTML in advisory/email templates.
- CSRF/origin on state-changing endpoints.
- Auth: opaque sessions, password hashing, expiry, reset quotas.
- RBAC on every route.
- Input validation (zod) on all endpoints.
- SSRF: URL validation in fetchers/webhooks.
- Path traversal in file ops.
- Dependency audit (`npm audit`).

### 5. Resilience & Concurrency
- Retry with exponential backoff + jitter for external calls; Retry-After honor.
- Circuit breakers for feeds/pipeline; feed recovery.
- Worker coordination: dedup, advisory locks, lease ownership, dead-letter.
- Shared state safety; cache invalidation.
- Outbox at-least-once; content dedup; stable Message-ID/idempotency keys.
- Digest state durable in PG.

### 6. Performance & Scale
- Memory leaks: listeners, timers, buffers, model history.
- Bundle size; code splitting.
- Pagination on all list endpoints; cursor pagination for logs.
- Query performance; indexes.
- Concurrency limits (workLimiter).

### 7. Observability
- Structured logging with levels; operational events (category/level/full-text).
- Hash-chain audit trail immutability (runtime role cannot update/delete).
- Metrics endpoint auth.
- Health reflects actual DB/process/worker measurements (no inferred external).

### 8. Delivery & Email
- SMTP/API providers; encrypted creds; leave-blank keeps.
- Retry policy defaults (6 attempts, 1m initial, 1h cap); max attempts 1 disables retries.
- Provider acceptance recorded as ACCEPTED (not inbox proof).
- Digest combining; per-recipient tier filtering.
- Manual retry; queue test email.

### 9. ML Subsystem
- Offline-only; fallback when untrained.
- Training never overwrites active model on failure; quality gates.
- Drift detection (PSI, concept drift).
- Cron training script; data provider matches schema.
- Memory in history buffers; type safety.

### 10. Frontend Production
- ErrorBoundary; loading states; empty states.
- Theme compatibility; responsive tables; modal focus management.
- No console errors; accessibility basics.

### 11. Deployment
- Dockerfile security (non-root, minimal); docker-compose; Caddy TLS.
- Migration service before app.
- Healthchecks in compose.
- Ports not published directly.
- Backup/restore tested.

### 12. Vulnerability Search & OSINT (new)
- `server/vulnerabilitySearch.ts`, `server/googleCse.ts`, `shared/vulnerability.ts`, `src/components/VulnerabilitySearchView.tsx`.
- External API calls (OSV/NVD/CISA KEV/Google CSE) must have timeouts, retries, egress allowlist, rate limits.
- Input validation and SSRF protection on search queries.
- Caching bounded (CPE cache DoS fix); memory shedding under load.
- Secrets (API keys) encrypted/not leaked.

### 13. System Uptime & Health (new)
- `/api/system-uptime` public; verify no sensitive data; frontend fetch robust.
- DB severance detection; memory-shedding HIGH-lane floor; hang detection.

### 14. Pipeline Hardening (new)
- Transaction-scoped advisory locks; shared worker connection stop; news dedup by asset identity.
- Verify no race conditions in watchlist/recipients mutations.

## Verification Commands
- `npm run lint`
- `npm test` (without TEST_DATABASE_URL skips DB suite — not full validation)
- `TEST_DATABASE_URL=... npm run test:integration`
- `npm run build`
- `npm audit`
- `npm run matching:evaluate`

## Regression Focus (recent commits)
- Vulnerability search (2063c2e): security (SQLi/XSS/SSRF), rate limits, egress, caching, DoS.
- Security fixes (5bb18e0): parameterized queries, XSS escaping, bounded CPE cache.
- ML quality gate (9ce408e): thresholds, type safety, audit logging.
- System uptime (e999559/94746dd/c4615a9/0fa1226/027ef7b): public endpoint, no leakage.
- Pipeline hardening (2063c2e): advisory locks, shared worker stop, DB severance, memory-shedding, news dedup.
- Table styling consolidation (6f70f4e).
- New-detection reporting per execution (9f06baa/201c57f).
- Fail-closed command authorization (4d06be3/4f8958f).
- ML audit trail + cron training; correlation contracts (023-028).
- Hang detection / readiness.

## Output Format
For each finding:
- File: path:line
- Severity: CRITICAL/HIGH/MEDIUM/LOW
- Category: Security/Resilience/Performance/Operability/DataIntegrity/Testing/Deployment
- Description
- Impact
- Fix
- Effort: S/M/L/XL

## Priority Order
1. Security vulnerabilities
2. Data loss/corruption
3. Availability/reliability
4. Operational gaps (health, logging, shutdown)
5. Performance
6. Deployment/config
7. Test coverage

## Exclusions
- `node_modules/`, `dist/`, `server-dist/`.
- Linter-handled style.
- Generated migration content.
- Missing features.

Produce a final report grouped by dimension with a severity count summary.
