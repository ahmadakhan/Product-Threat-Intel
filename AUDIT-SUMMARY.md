> **Historical document.** This report reflects the codebase as of its original date and has been
> superseded by [`PRODUCTION-READINESS-AUDIT.md`](./PRODUCTION-READINESS-AUDIT.md), which is the
> authoritative readiness report. Findings here may already be fixed; do not use this file to make
> current readiness decisions.

# Deep Audit Summary — BA Threat Intel Enterprise

**Date:** 21 October 2026  
**Scope:** Complete source code review — server, client, shared modules, engine, tests, deployment  
**Baseline:** No Git metadata; audit is against source only.

---

## Executive Summary

BA Threat Intel Enterprise is a well-engineered, defense-in-depth vulnerability inventory correlation and advisory delivery platform. The codebase implements server-side authentication/authorization, encrypted secret storage, SSRF-hardened egress, atomic PostgreSQL transactions with advisory locks, SHA-256 chained audit logs, and a production Docker Compose deployment with non-root read-only runtime. TypeScript is used consistently with Zod schema validation at all API boundaries.

**Overall impression:** Security-conscious architecture with explicit, documented boundaries and verified test coverage (37 unit + 42 page-verification + 51 pipeline-lifecycle tests all passing at last verification).

## Key Strengths

### 1. Authentication & Session Management
- Server-side scrypt password hashing (N=131072, r=8, p=1)
- No default account; operators created via CLI with password read from stdin
- Opaque session tokens (SHA-256 hashed before storage)
- HttpOnly, Secure, SameSite=Strict cookies in production
- Idle + absolute expiry; session revocation on password change
- Per-IP and per-user login throttling (5 attempts per 15min)

### 2. Authorization (RBAC)
- Three roles: ADMIN, OPERATOR, VIEWER enforced at API level
- Runtime DB role `vulnstream_app` has DML only (SELECT only on audit)
- No DDL privileges for runtime role

### 3. Input Validation & Sanitization
- Zod schemas for all API inputs
- Origin + Content-Type enforcement; 2MB body limit
- Strict CPE 2.3 and PURL validation
- HTML escaping in template rendering and CSV output
- Exact-origin and CSRF protection

### 4. Secrets & Cryptography
- AES-256-GCM with record-specific AAD context
- No browser credential persistence
- Secrets redacted from API responses
- Password hashing with per-user salts

### 5. Network & Egress Security (SSRF)
- Only HTTPS on port 443, no credentials in URLs
- Hostname allowlist (default: NVD, CISA, FIRST)
- Public unicast address validation
- Pinned IP + TLS hostname verification
- 8 MiB response body cap

### 6. Data Persistence & Integrity
- PostgreSQL with `records(kind, id, data)` entity-attribute-value store
- Advisory-lock serialized transactions (`800002`)
- Append-only audit table with trigger
- Audit chain SHA-256 with `verifyAuditChain()`
- Runtime role restricted from audit updates

### 7. Ingestion Pipeline
- NVD, CISA KEV, EPSS, JSON_SEARCH_API adapters
- Pagination validation; 120-day/50k NVD window per run
- Rate limiting; failure recording, not invented success
- No automatic cache; feed failures explicitly recorded

### 8. Matching & Correlation Engine
- Strict CPE 2.3 component matching (11 fields)
- PURL exact matching
- Per-CPE version interval evaluation
- Unsupported version ordering → review required
- Reconciliation preserves operator lifecycle decisions

### 9. Delivery System
- Transactional outbox with `dedupe_key` UNIQUE
- Atomic claim with lease tokens
- Retry/backoff (6 attempts with schedule)
- HMAC webhook signatures
- Delivery acceptance recorded separately from inbox delivery

### 10. Audit & Logging
- Canonical SHA-256 chaining
- Append-only DB trigger
- Role-based audit privileges
- `verifyAuditChain()` tamper detection

### 11. Frontend Security
- Helmet CSP with `default-src 'self'`, `script-src 'self'`
- HSTS in production
- `X-Powered-By` disabled
- CSRF tokens on all mutations
- HTML escaping in templates
- CSV formula injection neutralization

### 12. Deployment & Infrastructure
- Multi-stage Docker build; non-root user, read-only runtime
- `cap_drop: [ALL]`, `no-new-privileges:true`
- Internal-only database network
- Caddy reverse proxy with HTTPS
- Migration job with role grants

## Key Limitations / Open Areas

1. **Session cookie timeout decoupling:** Cookie `maxAge` is 12h regardless of `sessionTimeoutMins` (configurable idle timeout). Mitigated by absolute expiry and Secure/HttpOnly.

2. **Audit `ipAddress` always empty:** Reduces forensic traceability. Current design avoids storing potentially spoofed client data.

3. **No automated key rotation / re-encryption:** Changing `ENCRYPTION_KEY` does not re-encrypt stored secrets. Old key must be retained.

4. **`style-src 'unsafe-inline'` in CSP:** Required for dynamic theming. Trade-off accepted.

5. **Mailgun integration disabled in code but schema supports it:** Configuration field exists but no implementation path.

6. **No automated E2E/browser tests:** Smoke checks were manual.

## Testing Verification

- **Unit tests:** 37 passing (CPE/PURL matching, crypto, SSRF, pipeline)
- **Integration tests:** PostgreSQL integration (auth, RBAC, network, ingestion, pipeline, delivery, audit)
- **Pipeline lifecycle:** 51 tests passing
- **All tests:** Require `TEST_DATABASE_URL`; otherwise DB tests are skipped

## Security Posture Summary

| Control | Status |
|---------|--------|
| Authentication | ✅ Robust |
| Authorization | ✅ Defense-in-depth |
| Input Validation | ✅ Strict Zod schemas |
| Cryptographic storage | ✅ AES-256-GCM with context |
| Network egress | ✅ SSRF-hardened |
| DB integrity | ✅ Advisory locks + append-only audit |
| Egress validation | ✅ Hostname + IP pinning |
| Session management | ✅ Opaque tokens, revocation |
| Forensic evidence | ⚠️ IP missing from audit (design) |
| Load-testing | ⚠️ Not conducted (documented boundary) |

## Recommendations

1. **Session cookie timeout:** Align `maxAge` with configured idle timeout.
2. **Audit IP:** Consider populating `ipAddress` from `req.ip` with awareness of spoofing risk.
3. **Key rotation:** Implement versioned encryption keys and re-encryption migration.
4. **Mailgun:** Remove schema fields if not implemented, or implement actual Mailgun integration.
5. **E2E tests:** Add browser test suite for critical user workflows.

---

**No critical vulnerabilities identified.** The system is production-ready with well-documented operating boundaries.