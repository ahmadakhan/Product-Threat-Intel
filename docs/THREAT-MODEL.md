# Threat Model

**System:** VulnStream-Enterprise — single-component monolith (Express API + React SPA)
serving vulnerability ingestion, correlation, advisory email delivery, and operations.
**Reviewed:** 2026-11-25
**Owner:** Security

## 1. Assets

- Vulnerability findings, advisories, and CVE data (confidentiality/integrity).
- Operator sessions and credentials (confidentiality/integrity).
- Email delivery logs, recipients, and advisory content (confidentiality/integrity).
- Audit log (integrity / non-repudiation).
- Database schema and migration state (integrity/availability).

## 2. Trust boundaries

- Browser ↔ Express API over `/api` (mutations require Origin + CSRF token).
- Express ↔ PostgreSQL (pg pool, statement timeout via libpq).
- Express ↔ upstream feeds (NVD, VulnCheck, OTX, OSV, CISA KEV) — untrusted input.
- Client SPA ↔ server state snapshot via `/api/state`.

## 3. Threats and controls

| Threat | Asset | Control | Requirement | Evidence |
|---|---|---|---|---|
| Unauthenticated access to /api | sessions, findings | Global `requireAuth` mount on `/api` (app.ts:997) | SEC-0001 | route-authorization test |
| Privilege escalation (VIEWER → admin action) | all | `requireRole(ADMIN\|OPERATOR\|VIEWER)` per route; closed role set | SEC-0002, SEC-0003 | route-authorization test |
| CSRF on state-changing POST | sessions | Origin header + X-CSRF-TOKEN cookie/header match | SEC-0005 | CSRF checks in app.ts |
| Malformed request bypassing validation | findings, config | Zod 4 boundary schemas (config.ts, validation.ts) | SEC-0004 | config-auth test |
| Injection via SQL | database | pg parameterized queries; `db.ts` helpers; outbox id parsed as uuid | ARC-0002 | db helper usage |
| Unbounded / slow query DoS | availability | Statement timeout via libpq (`-c statement_timeout=...`) | REQ-0002 | server/db.ts |
| Credential in query params / logs | feed secrets | feedSchema rejects token/password/secret keys in URL query | SEC-0004 | feedSchema |
| Password spraying / weak passwords | credentials | Min length 14, max login attempts, lockout, OTP reset | SEC-0006 | auth.ts password policy |
| Audit log tampering | audit log | Append-only hash/Merkle chain; chain re-verified by test | SEC-0008 | cryptoChain.ts + audit test |
| Secret leakage in error output | credentials, config | Single error middleware; errors name field/rule only, never values | SEC-0009 | app.ts error middleware |
| Hardcoded / committed secrets | credentials | .env* gitignored; only .env.example tracked; fixture keys in tests | SEC-0007 | repo scan |
| Migration drift / lost schema | database schema | `REQUIRED_SCHEMA_VERSION` gate; migrations record in schema_migrations | REQ-0003, ARC-0003 | migrations test |
| Concurrency race (double-claim, double-run) | findings, outbox | Deterministic stubbed-pool drain guard tests; idempotent pipeline start | REQ-0001, REQ-0004, ARC-0005 | correlation-drain-guard test |
| Dependency-layer violation | code integrity | server never imports client components; utils import only types/shared/stdlib | ARC-0001 | architecture-deps test |

## 4. Residual risks (accepted, tracked)

- Feed upstream compromise: upstream data is treated as untrusted; normalization and
  CPE validation run before correlation. Residual risk of false positives accepted;
  operator review queue is the compensating control.
- Email delivery to wrong recipient: transport re-validates recipient subscription
  at send time (`recipientAllows`). Residual risk of stale recipient data accepted;
  recipient management is operator-gated (ADMIN/OPERATOR).

## 5. Review cadence

Reviewed each release alongside docs/TRACEABILITY.csv and docs/RISK-ACCEPTANCE.md.
Sign-off required from security for any new threat, control change, or risk
acceptance.
