# Requirements Registry

Each requirement carries a stable `REQ-####` id. Requirements are the single source
of truth for what "verified" means; see VERIFICATION-FRAMEWORK.md. Every requirement
must be referenced by at least one test, recorded in docs/TRACEABILITY.csv.

## Functional correctness

REQ-0001 — Correlation drain guard cancellation
A drain pass cancelled before it starts takes no work and issues no database query.
A pass cancelled part-way runs no further stage after the cancellation point.
Cancellation observed before a claim means no batch is claimed and nothing is ingested.
The running pass exposes `cancelDrain` and clears it on exit.
Pinned by tests/correlation-drain-guard.test.ts.

REQ-0002 — Bounded statement timeout
Every pooled query carries a statement timeout applied through libpq options
(`-c statement_timeout=...`), never the unsupported pg `statement_timeout` pool property.
No query is unbounded. See server/db.ts.

REQ-0003 — Schema version gate
`REQUIRED_SCHEMA_VERSION` in server/db.ts equals the number of the newest migration
file in server/migrations/. tests/migrations.test.ts fails if it lags.
Every migration records itself in `schema_migrations(version)`.

REQ-0004 — Idempotent pipeline start
Repeated POST /api/pipeline while a run is QUEUED/RUNNING returns the active
execution without draining the mutation quota or creating a duplicate run.

REQ-0005 — Delivery claims lifecycle
A claimed delivery cannot be re-claimed by another job; claim expiry follows the
outbox lifecycle; `releaseClaims` deletes only claims owned by the given job;
an UNKNOWN terminal outcome is never reopened without confirmation.

REQ-0006 — Retention safety
Records with missing or unparseable timestamps are never deleted. Strict mode
deletes only data older than the window and keeps the boundary. Audit history is
excluded because hash-chain integrity depends on retained links.

REQ-0007 — Version range evaluation
CPE 2.3 / PURL / semver bounds (start-including/excluding, end-including/excluding)
are evaluated per the specification; "through" bands are inclusive bands, not
single <= bounds. Deterministic alias-stable VulXXXXX identifiers.

REQ-0008 — Email template rendering
Nested block depth is capped; stray braces scan in linear time; block keywords are
case-insensitive; negation is whole-word and sentence-scoped; HTML with unclosed
tags renders without CPU exhaustion.

REQ-0009 — Feed ingestion resilience
429 with Retry-After defers the run; pagination cursor loops are detected;
malformed CVE records are rejected without committing partial data; upstream
failure on every path is an upstream error, never an empty result.

## Security compliance

SEC-0001 — Authentication required on /api
Every route registered under /api is behind `requireAuth` (global mount at
server/app.ts:997). Public auth-adjacent routes (/api/login, /api/password-reset/*)
are exempt by design.

SEC-0002 — Explicit role authorization on /api
Every authenticated /api route carries at least one `requireRole(...)` using only
ADMIN, OPERATOR, VIEWER. Management actions (bulk retry/cancel/send-now,
correlation fault, retention run, dead-letter decisions) require ADMIN or OPERATOR.

SEC-0003 — Role set is closed
Roles are exactly ADMIN, OPERATOR, VIEWER (shared/state.ts). No new roles are
introduced; requireRole never accepts a role outside this set.

SEC-0004 — Boundary validation (Zod 4)
Environment is validated at startup (server/config.ts). Every HTTP request body
and query is validated by a Zod schema before reaching business logic
(server/validation.ts). Shapes are not re-validated deep inside logic.

SEC-0005 — CSRF protection
Mutations under /api require an Origin header; state-changing POSTs require a
matching X-CSRF-TOKEN cookie/header pair. Read-only POSTs are allow-listed by
exact route, never by prefix.

SEC-0006 — Password policy
Minimum password length enforced from settings securityPolicy (default 14).
Password reset uses a 6-digit OTP, 10-minute expiry, single-consumption, and
never reveals whether a username exists.

SEC-0007 — Secrets handling
No .env / .env.production / .env.test is read, modified, or committed. Only
.env.example is tracked. Secrets flow through server/secrets.ts and
server/runtimePrivileges.ts and are never logged. Tests use fixture keys only.

SEC-0008 — Audit log tamper evidence
Append-only audit log with hash/Merkle chain (src/utils/cryptoChain.ts). Chain
validity is re-verified by test; tampering is detectable.

SEC-0009 — Error responses leak no secrets
Zod validation failures and HttpError map through the single error middleware
(server/app.ts). Error bodies name the field and rule only, never the rejected
value or credentials.

## Architectural integrity

ARC-0001 — Layering
server/* never imports from src/components/ or src/context/.
src/utils/* imports only src/types/, shared/, or node stdlib.
Dependencies flow downhill: components → context → engine → utils → types/shared.

ARC-0002 — Persistence through db.ts helpers
Routes persist via server/db.ts helpers (`get`, `put`, `list`, `transaction`,
`appendAudit`), not ad-hoc SQL, unless a helper is genuinely missing.

ARC-0003 — Migration governance
Migrations are transactional SQL with unique gap-free numeric prefix; each records
itself in schema_migrations. Index DDL on populated relations lives in
server/migrations/indexes/ as CREATE INDEX CONCURRENTLY outside a transaction.
Never edit applied migrations or server/migrations/retired/.

ARC-0004 — Single-component monolith
The SPA and API are served from one Express process; no package split without a
strong technical reason. The UI has no URL router: pages are tabs (activeTab)
rendered by src/App.tsx, labelled/grouped by src/design/pages.ts and
src/components/Sidebar.tsx.

ARC-0005 — Concurrency invariants
Correlation drain supervisor, leadership election, and dead-letter budget uphold
their invariants under concurrency; pinned by deterministic stubbed-pool tests
and npm run correlation:preflight.

ARC-0006 — Deterministic, hermetic tests
Tests use injected clocks and fixed seeds; no Date.now()/Math.random() assertions
without injection; no test reaches the network or a real database unless opted in
via TEST_DATABASE_URL; suites run with --test-concurrency=1.

ARC-0007 — Regression testing
Every bug fix ships a regression test named <area>-regressions.test.ts that fails
on pre-fix code and passes on post-fix code.

ARC-0008 — Type soundness
tsc --noEmit passes with zero errors; no `any` in new code; no @ts-ignore /
@ts-expect-error / `as any` without an inline justification.
