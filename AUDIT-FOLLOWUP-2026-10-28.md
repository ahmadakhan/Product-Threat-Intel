# Code audit and verified fixes — 2026-10-28

Scope: focused source review of authentication and password recovery, account mutations, collection API boundaries, configuration, and advisory rendering, supported by the complete automated test suite. This report records verified defects; it does not certify that every code path is free of vulnerabilities.

## Fixed findings

| Severity | Finding | Fix |
| --- | --- | --- |
| Critical | Password-reset completion selected an account using only the six-digit code hash. The supplied username was used for deletion instead of account selection, allowing a code to change another account and remain reusable. | Bind lookup and consumption to username and code, lock the account, and consume the code within the same transaction as password replacement and session revocation. Concurrent completions have exactly one winner. |
| High | Public reset routes had no rate limiting; verification allowed unlimited guesses and completion performed scrypt before rejecting invalid codes. | Shared database quotas cover request IPs and normalized usernames. Verification and completion share their guessing budget. Invalid codes fail before password hashing, and throttling returns 429 with Retry-After. |
| High | Development reset responses disclosed the code directly, bypassing mailbox ownership. Missing production SMTP configuration was detected only after a code had been stored. | Return codes only in automated test mode. Require deployment SMTP in development and production before account lookup or token issuance. |
| Medium | Outstanding reset codes survived mailbox changes, account deletion, and administrative or authenticated password replacement. Concurrent requests could also leave multiple valid codes. | Serialize issuance with account mutations and completion; revoke outstanding codes on relevant account/password changes; expire stored tokens through scheduled cleanup. |
| Medium | Account changes committed before session revocation and auditing. A later failure could leave a changed account without the corresponding session cleanup or audit entry. | Perform the edit, reset-code invalidation, session revocation, and audit append in one transaction. Email-only edits continue to preserve sessions. |
| Medium | Collection endpoints exposed encrypted feed credentials, webhook URLs, and webhook signing tokens, although the state endpoint redacted them. Generic search also matched hidden stored values. | Apply equivalent redaction in SQL projections and search predicates, including total-count queries. Credentials remain encrypted in storage. |
| Low | Sort keys such as constructor and toString resolved inherited Object properties and produced invalid SQL. | Accept only own properties of the explicit sort mapping; otherwise use the default ordering. |

## Validation

- Baseline: TypeScript passed; 379 tests passed and 26 database-backed tests were skipped without a configured test URL.
- Final complete suite: **495 tests passed, 0 failed, 0 skipped**, using the existing isolated test PostgreSQL service. Suites created and removed dedicated schemas; the production database was not used.
- New recovery regression suite: 12 tests passed, including cross-account rejection, concurrent completion and issuance across app instances, expiry, invalidation after account/password changes, shared throttling, and rollback when audit insertion fails.
- Existing integration scenarios now verify collection credential redaction, hidden-value search counts, and prototype-property sort keys.
- TypeScript (`npm run lint`), client/server production build (`npm run build`), final server rebuild, and whitespace checks passed.

## Operational impact and limits

Self-service password recovery now requires deployment SMTP settings in development as well as production. Reset mail goes to each account's configured email address. Test-mode code disclosure is retained for automated tests only.

Reset request buckets allow an initial burst of 3 requests per account and 15 per IP, continuously refilling those capacities over ten minutes. Verification and completion share bursts of 10 per account and 50 per IP with the same refill period. Quotas span application replicas.

No schema migration is required. Changes are local source and build artifacts; running services have not been redeployed. Real SMTP delivery and production load behavior were not exercised by this audit.
