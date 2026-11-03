# Production-Ready Codebase Audit Prompt — VulnStream-Enterprise

You are a senior SRE, security engineer, and production-readiness reviewer. Audit the VulnStream-Enterprise codebase to determine whether it is safe to deploy and operate in production. Focus on deployability, operability, resilience, security, data integrity, observability, and feature completeness. Do not report missing features; evaluate existing code quality and completeness of implemented features.

## System Overview

- **React 19 + Vite SPA** (`src/`), **Node.js 22 + Express API/worker** (`server/`), **PostgreSQL 17**, Docker Compose + Caddy TLS proxy
- **Bootstrap**: `server/main.ts`; router: `server/app.ts`; health: `/live`, `/ready`, `/metrics`
- **Migrations**: `server/migrate.ts`, `server/migrations/001..034` + `migrations/indexes/`
- **Env**: `.env.example`; secrets encrypted at rest with `ENCRYPTION_KEY`
- **ML subsystem**: `server/ml/` (algorithms, models, runtime, train, integration)
- **Email delivery**: `server/delivery.ts`, `server/emailProviders.ts`
- **Vulnerability search**: `server/vulnerabilitySearch.ts`, `server/googleCse.ts`
- **Correlation engine**: `server/correlation/`
- **Pipeline engine**: `server/pipeline.ts`, `src/engine/pipelineEngine.ts`
- **Frontend**: `src/components/` (48 views), `src/context/`, `src/hooks/`, `src/utils/`, `src/engine/`

## Production-Readiness Dimensions

### 1. Boot & Lifecycle

- `server/main.ts`: graceful startup, migration ownership, DB role privileges, signal handling (SIGTERM/SIGINT), connection pool close, worker pool drain, hang timer unref
- Readiness `/ready`: DB latency, supervisor health, backpressure; must fail closed when DB/severance
- Liveness `/live`: event-loop hang detection threshold
- Graceful degradation when optional services missing
- Process global handlers: uncaughtException, unhandledRejection; structured logging
- Worker tick loop: stuck-promise detection, generation tracking, non-overlapping execution
- Retention, daily digest, and ML training schedulers: claim/release, stuck detection
- Session/login-attempt cleanup: interval, expiry enforcement
- Shutdown deadline: 30s forced exit vs graceful pool close

### 2. Configuration & Secrets

- All required env vars documented (README, `.env.example`); defaults safe for production
- No hardcoded secrets; `ENCRYPTION_KEY` validation (base64 32-byte); credential blank-keeps behavior
- Egress allowlist `EGRESS_ALLOWED_HOSTS` enforcement in `network.ts`; redirect target SSRF re-validation
- CORS restrictive, origin validation, CSRF
- Rate limiters DB-backed shared across replicas (reset quotas, mutation quota, ingest quota)
- SMTP/API provider config validation; encrypted creds at rest; `decrypt()` failure handling
- `FAULT_SIMULATION_ENABLED` blocked in production; `HEARTBEAT_URL` https-only in production
- `TRUST_PROXY` rejects trust-all values

### 3. Database & Migrations

- Migration job owns DDL; runtime role no DDL; idempotent migrations; reversible where feasible
- `REQUIRED_SCHEMA_VERSION = 34` enforced at production startup
- Connection pooling: size, timeout, leak prevention, `release()` in finally with failure flag
- Transactions for critical ops (outbox, findings, aliases); advisory locks scoped per schema
- Index coverage for hot queries; `CREATE INDEX CONCURRENTLY` outside transaction
- Invalid index detection and rebuild before concurrent build
- No N+1 in loops; batch queries (`putMany`, `removeMany`, `getMany`)
- `FOR UPDATE` row locks for read-modify-write; alphabetical lock ordering to prevent deadlocks
- Audit chain: tamper-evident hash chain, runtime role cannot update/delete
- `statement_timeout` per pool (15s default); migrations use 300s local timeout

### 4. Security

- SQL injection: parameterized queries only; no string interpolation in SQL
- XSS: escaped HTML in advisory/email templates (`escapeHtml`)
- CSRF/origin on state-changing endpoints; `__Host-` cookie prefix in production
- Auth: opaque sessions, password hashing (scrypt), expiry, reset quotas, login throttling
- RBAC on every route (`requireRole`); `requireAuth` fail-closed
- Input validation (zod) on all endpoints; strict schemas; no implicit any
- SSRF: URL validation in `resolvePublic`; public IP check; port 443 only; no URL credentials
- Path traversal in file ops (`disableFileAccess`, `disableUrlAccess` in nodemailer)
- Dependency audit (`npm audit`)
- Sensitive data redaction in events (`describeError` context redaction)
- Password reset: per-IP and per-account quotas; code expiration; consume-once; account disabled check
- Session renewal rotates CSRF token; logout clears `__Host-` cookie with matching attributes

### 5. Resilience & Concurrency

- Retry with exponential backoff + jitter for external calls; `Retry-After` honor
- Circuit breakers for feeds/pipeline; feed recovery; dead-letter queue
- Worker coordination: dedup, advisory locks, lease ownership, dead-letter
- Shared state safety; cache invalidation
- Outbox at-least-once; content dedup; stable Message-ID/idempotency keys
- Digest state durable in PG
- AbortController for retention/digest; `cancelBackend` for stuck statements
- Pool connection destroy on failure flag; broken connections not recycled
- Stuck promise detection (15 min backstop) for pipeline/outbox/digest/retention/training
- ML training never overwrites active model on failure; quality gates
- `ERROR` handling: `allSettled` for partial source failures; non-blocking writes

### 6. Performance & Scale

- Memory leaks: listeners, timers, buffers, model history; `timer.unref()` on interval timers
- Bundle size; code splitting; Vite build
- Pagination on all list endpoints; cursor pagination for logs
- Query performance; indexes; `ROW_NUMBER()` window for bounded heavy collections
- Concurrency limits (`workLimiter`); mutation rate limiter shared across replicas
- CPE cache bounded (DoS fix); memory shedding under load
- Feed max duration; request timeouts; socket timeouts
- `unref()` on non-critical timers to allow process exit

### 7. Observability

- Structured logging with levels; operational events (category/level/full-text)
- Hash-chain audit trail immutability (runtime role cannot update/delete)
- Metrics endpoint auth (`METRICS_TOKEN`, 32+ chars)
- Health reflects actual DB/process/worker measurements (no inferred external)
- `describeError` with stack, cause, code, detail; bounded text
- Event log pagination; cursor-based; category filtering
- `/api/system-uptime` public endpoint; no sensitive data leakage

### 8. Delivery & Email

- SMTP/API providers; encrypted creds; leave-blank keeps
- Retry policy defaults (6 attempts, 1m initial, 1h cap); max attempts 1 disables retries
- Provider acceptance recorded as `ACCEPTED` (not inbox proof)
- Digest combining; per-recipient tier filtering
- Manual retry; queue test email
- PDF attachment: graceful degradation on render failure
- Prior-delivery confirmation to prevent duplicates; `transportRejected` flag
- Content revision for dedupe; `deliveryRevisionEvidence` canonical builder
- Everyone-group deferral until Security-team delivery confirmed

### 9. ML Subsystem

- Offline-only; fallback when untrained
- Training never overwrites active model on failure; quality gates
- Drift detection (PSI, concept drift)
- Cron training script; data provider matches schema
- Memory in history buffers; type safety
- `initMlRuntime` failure does not block server start
- Scheduled training interval; last-run dedup

### 10. Frontend Production

- ErrorBoundary; loading states; empty states
- Theme compatibility; responsive tables; modal focus management
- No console errors; accessibility basics
- React 19; strict mode considerations
- CSRF token handling on mutation endpoints
- Session expiry handling (401 → login flow)
- Cursor pagination in UI tables

### 11. Deployment

- Dockerfile security (non-root, minimal); docker-compose; Caddy TLS
- Migration service before app
- Healthchecks in compose
- Ports not published directly (app on internal network)
- Backup/restore tested (`OPERATIONS.md`)
- `ATTACH_ADVISORY_PDF` toggle; Chrome executable path
- `server-dist/` build output; `build-server.mjs` bundling

### 12. Vulnerability Search & OSINT

- `server/vulnerabilitySearch.ts`, `server/googleCse.ts`, `shared/vulnerability.ts`
- External API calls (OSV/NVD/CISA KEV/Google CSE) must have timeouts, retries, egress allowlist, rate limits
- Input validation and SSRF protection on search queries
- Caching bounded (CPE cache DoS fix); memory shedding under load
- Secrets (API keys) encrypted/not leaked
- NVD key rejection caching (10 min TTL); anonymous fallback
- CISA KEV cache with in-flight dedup; 10 min TTL
- OSV 404 = empty answer, not failure; NVD 404 = empty answer
- Partial results via `Promise.allSettled`; one slow source must not hold page hostage

### 13. System Uptime & Health

- `/api/system-uptime` public; verify no sensitive data; frontend fetch robust
- DB severance detection; memory-shedding HIGH-lane floor; hang detection
- Readiness fail-closed on `RECOVERING_DB_SEVERANCE`

### 14. Pipeline Hardening

- Transaction-scoped advisory locks; shared worker connection stop; news dedup by asset identity
- Verify no race conditions in watchlist/recipients mutations
- Alias lifecycle: self-maintaining but bounded; 30-day expiry for automatic rows
- Correlation schema contract (migrations 023-028)
- Match quality gate; precision/recall regression test

## Output Format

For each finding:

- **File:** `path:line`
- **Severity:** CRITICAL/HIGH/MEDIUM/LOW
- **Category:** Security/Resilience/Performance/Operability/DataIntegrity/Testing/Deployment
- **Description**
- **Impact**
- **Fix**
- **Effort:** S/M/L/XL

## Priority Order

1. Security vulnerabilities
2. Data loss/corruption
3. Availability/reliability
4. Operational gaps (health, logging, shutdown)
5. Performance
6. Deployment/config
7. Test coverage

## Exclusions

- `node_modules/`, `dist/`, `server-dist/`
- Linter-handled style (prettier)
- Generated migration content
- Missing features not in the codebase

## Verification Commands

- `npm run lint` — `tsc --noEmit`
- `npm test` — `node --import tsx --test` (all tests)
- `npm run test:unit` — `vitest run`
- `npm run build` — client + server build
- `npm audit` — dependency vulnerabilities

## Deliverable

Produce a final audit report grouped by dimension with a severity count summary, then implement all CRITICAL and HIGH fixes. After implementing, run `npm run lint` and `npm test` to verify no regressions.
