> **Historical document.** This report reflects the codebase as of its original date and has been
> superseded by [`PRODUCTION-READINESS-AUDIT.md`](./PRODUCTION-READINESS-AUDIT.md), which is the
> authoritative readiness report. Findings here may already be fixed; do not use this file to make
> current readiness decisions.

# Production implementation audit — 21 October 2026

## Scope and outcome

The original browser simulation has been replaced with a Node.js API and worker, PostgreSQL persistence, server-side accounts, real transport implementations and a Docker deployment. This report supersedes the earlier simulation audit. Reviewed application source, matching, authentication/authorization, persistence, ingestion, delivery, rendering/export, dependencies and deployment configuration. No Git metadata was supplied, so there is no commit/diff baseline.

## Applied corrections and safeguards

| Area | Implemented behavior |
| --- | --- |
| Authentication | Server-side scrypt password hashes, no default account, opaque hashed session tokens, HttpOnly/Secure/SameSite cookies in production, idle/absolute expiry, revocation after password changes, database-backed login throttling |
| Authorization | ADMIN/OPERATOR/VIEWER checks at the API, exact-origin and CSRF enforcement on mutations, validated inputs and redacted API errors |
| Persistence | PostgreSQL migrations, atomic record/audit/outbox writes, serialized mutations, separate owner and restricted runtime roles |
| Secrets | AES-256-GCM with record-specific authenticated context, redaction from responses, no browser credential persistence; changing a feed URL/auth method clears retained credentials |
| Outbound requests | Exact hostname allowlist, public-address DNS validation including mixed resolutions, pinned IP connection with TLS hostname verification, HTTPS/443 only, redirects rejected, bounded DNS/connection/body sizes |
| Ingestion | NVD, CISA KEV, EPSS and normalized JSON adapters, validated pagination and data, explicit failures, measured telemetry, no seeded runtime cache |
| Matching | Exact structured identities, explicit version exclusions, per-CPE ranges, unknown/unsupported version and complex applicability review gates; unsigned VEX cannot suppress findings |
| Worker recovery | Database advisory lock ownership retained on the same connection as pipeline write transactions; interrupted runs recover idempotently; failed scheduled attempts advance last-run time |
| Delivery | Transactional outbox, atomic claims with lease tokens, retry/backoff, disabled-target checks, HMAC webhook signatures, provider acceptance recorded separately from inbox delivery |
| Rendering/export | Escaped advisory content, constrained template customization, sandboxed preview, formula-safe CSV, neutral preview-only sample text |
| Audit | Canonical SHA-256 chaining, content/link verification, append-only database trigger and runtime permissions, full history retained in PostgreSQL |
| UI | Authenticated server snapshots, real health measurements, truthful queued/accepted statuses, actual scheduler/dispatch state, no fabricated NTP or delivery confirmation |
| Deployment | Non-root multi-stage image, read-only runtime, internal database network, Caddy HTTPS proxy, migration job, health checks, graceful shutdown, CI validation and backup/restore guide |

## Verification

- Regression and PostgreSQL integration tests cover matching boundaries, cryptographic vectors, audit tampering, input validation, RBAC, CSRF/origin, encrypted/redacted secrets, changed endpoint credential removal, pipeline/outbox atomicity, retries and provider acceptance, webhook signing, crash recovery, concurrent delivery claims, disabled recipients, password/session expiry and login throttling.
- Docker Compose database, migration job and production application started successfully in an isolated project. `/ready` returned 200; anonymous `/api/state` returned 401. Production sign-in and secure cookie flags verified.
- Runtime connected as `vulnstream_app`; schema CREATE and audit UPDATE/DELETE privileges all false.
- PostgreSQL custom-format backup restored successfully into a separate test database, preserving the test account and audit records. This verifies the local dump/restore mechanism, not an off-site disaster-recovery objective.
- Built application browser smoke checks passed for all 14 navigation views. Operator sign-in, inventory import, persistence after reload and expired-session rejection verified. Evidence: [production-verification.png](production-verification.png). The previous `audit-verification.png` depicts the obsolete simulation.
- Final `npm test` against PostgreSQL: **37 passed, 0 failed, 0 skipped**. TypeScript checking and client/server production builds passed. Final Docker image build passed. `npm audit --audit-level=low` reported **0 vulnerabilities** at verification time; this is not a guarantee of absence of vulnerabilities.

## Deployment acceptance boundaries

This is a source and local runtime audit, not a penetration test or certification of a deployed service. Live feeds and mail/webhook providers were not contacted during transport tests: deterministic injected responses verify behavior, not provider credentials or current service availability. Configure and test the intended domain, TLS, egress, SMTP and recipients before enabling scheduling/dispatch.

Delivery is at least once; remote acceptance immediately before a crash can duplicate a notification. Stable IDs support deduplication. Database-owner compromise can rewrite audit history; independently anchored immutable exports are needed for stronger evidence. Matching intentionally requires review for unsupported applicability/version ordering and does not implement all NIST/vendor semantics.

The snapshot architecture and serialized writes have not been load-tested for a full historical vulnerability mirror or high operator concurrency. Feed/body caps fail explicitly, and capacity must be measured against the deployment's inventory and ingestion window. No automatic business-data retention policy is applied. See [OPERATIONS.md](OPERATIONS.md) for capacity, backup, restore and key-rotation boundaries. These are explicit operating limits, not claims of unlimited production readiness.

## Follow-up page and watchlist verification

The 21 October follow-up tested populated pages and a persisted CPE/PURL matrix, fixed additional matching and inventory UI defects, and passed 42 tests. See [PAGE-VERIFICATION.md](PAGE-VERIFICATION.md) for the precise cases, page coverage and limits.

## Pipeline lifecycle follow-up

The pipeline/matching follow-up added reconciliation, pre-send applicability checks, safe stale-bundle recovery and accurate execution phases. All 51 tests passed. See [PIPELINE-FIXES.md](PIPELINE-FIXES.md) for changes and verification evidence.
