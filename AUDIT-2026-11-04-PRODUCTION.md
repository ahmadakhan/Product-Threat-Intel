# Production Readiness and Security Audit

Date: 4 November 2026

## Verdict and scope

Confirmed production defects were fixed and the complete isolated CI suite passed **991 tests, zero failures, zero skips**. PostgreSQL integration, restricted-role operations, real TCP disconnection/recovery, actual Chrome sanitization/PDF checks, matching, delivery and fault-injection tests were enabled. No source file changed during that test run, and its disposable database was removed.

The source inventory covers **362 files and 118,463 lines**, including application code, shared contracts, tests, SQL migrations, deployment files and scripts. A static scan identified 68 literal Express route/mount registrations. This is a coverage/inventory statement, not a claim that every route was proven secure by a parser or that every source line received an independent manual review. Manual review targeted security-critical control paths listed below; existing regression suites covered the wider codebase.

The durable [coverage artifact](AUDIT-2026-11-04-coverage.json) contains tested file hashes, route locations, four supplemental shell/Python/service-file inventory entries and post-CI changes. The redacted heuristic secret-pattern scan reported no candidates in these scanned files; it did not inspect protected environment secrets or certify Git history as secret-free. Previously reported DB-severance and self-healing regression failures are resolved by this pass.

**This is not an unconditional production certification or a guarantee of zero bugs, false positives, false negatives, races or inbox-delivery failures.** The container configuration changes require target-host validation because Docker is unavailable on the audit machine. The running API and live database were not migrated/restarted by this pass.

## Newly confirmed findings

Prior fixes are not counted again. This pass identified seven HIGH and five MEDIUM root-cause groups; all were patched, with the container-only change still awaiting runtime verification.

| ID | Severity | Area | Confirmed defect and correction |
| --- | --- | --- | --- |
| SEC-01 | HIGH | Authenticated HTML preview | Regex sanitization did not parse numeric/control-character encoded schemes. Replaced with DOMPurify plus a restricted presentation-style policy, safe links, embedded-raster-only images and blocked forms/SVG/event handlers/overlay styles. Real Chrome regressions exercise malicious markup and preserved advisory content. |
| REL-01 | HIGH | Prior delivery confirmation | A failed SMTP or custom HTTP send was assumed unsent based on provider type. SMTP can be accepted before its final reply is lost. Proven pre-submission failures retain retries; ambiguous DATA/API outcomes are not blindly resent. Tests distinguish both stages. |
| REL-02 | HIGH | Self-healing alert admission | Cooldown admission committed before queueing, and all recipients shared one synthetic outbox target/address list. Admission and per-recipient jobs now commit atomically, recipient lists are not exposed in events, and failed queueing can retry despite an already-created recovery run. |
| REL-03 | HIGH | Recovery state and operator changes | Initial recovery state used UPDATE against an absent row, and feed rearming could overwrite concurrent operator state. Recovery claims now upsert; feed state is reread under a row lock and live circuit/disable decisions are preserved. Scheduler disablement is respected. |
| REL-04 | HIGH | Database severance | Supervisor classification missed real socket/DNS reset/unreachable errors. Shared classification now recognizes explicit transport codes while keeping constraint/schema/SQL statement complaints out of DB-severance recovery. Real TCP-severance and SQLSTATE regression suites pass. |
| SEC-02 | HIGH | Encryption-key rotation | Retained key configuration was stripped, the current key could remain behind a retired one, and index-zero ciphertext never tried retained keys. Validated retained keys now survive configuration and reach correlation recovery; current writes and authenticated fallback decryption preserve legacy envelopes and context binding. |
| REL-05 | HIGH | Concurrent dead-letter replay | Independent flushers read/deleted the same spool file, producing Windows EPERM and interrupting replay/retention workflows. Renewable cross-process per-file leases now protect replay; lease loss preserves evidence; database writes remain idempotent. Shared-flusher and persistence-failure regressions pass. |
| DEL-01 | MEDIUM | Password reset delivery | Reset requests depended on deployment SMTP even when the workspace used an API provider. Reset mail now uses the configured sender and master switch, without advisory PDF attachments or raw reset codes in the general outbox. Mocked-provider tests verify delivery and hash-only storage. |
| CFG-01 | MEDIUM | Startup egress intent | Recommended feeds were unconditionally seeded despite the bootstrap opt-in flag. Startup now adds feeds only when enabled while repairing known catalog URLs without overwriting disabled state or credentials; obsolete source validators/cooldowns are invalidated. |
| OBS-01 | MEDIUM | Watchdog load and memory alarms | Every tick loaded all retained executions and measured memory against allocated heapTotal. Reads are restricted to active/recent-failure state and memory pressure uses actual V8/process limits. |
| OBS-02 | MEDIUM | Suppression and spool telemetry | Disabled-mail/no-recipient cases could spam events or lose alert eligibility; file leases polluted spool capacity and post-flush gauges could remain stale. Suppression is bounded and distinguishable from a delivered-alert claim; lease directories are excluded and successful flushes refresh the gauge. |
| DEP-01 | MEDIUM | Read-only container | Scheduled ML model persistence had no writable mounted path. Added runtime-user-owned `/var/lib/vulnstream/ml` and a named Compose model volume. Static diff checked; Docker build/startup remains unverified. |

## Reviewed control paths and tested contracts

### Authentication, authorization and request handling

- Reviewed exact cookie parsing, opaque session token hashing, expiry/disabled-account checks, production `__Host-` attributes, SameSite/HttpOnly/Secure settings and matching logout attributes.
- Reviewed origin/JSON enforcement, CSRF verification, global API authentication ordering, route-level roles, command-role fail-closed checks and PostgreSQL-backed mutation/login/reset quotas.
- Checked password hashing admission limits, dummy-hash login work, reset token expiry/consumption, session revocation and no reset-code disclosure outside automated test mode.
- Read-only public health/uptime endpoints are distinct from authenticated state-bearing endpoints. Route inventory is supporting evidence, not a substitute for authorization tests.

### Product matching and confidence

- Re-executed the full matching/registration/version and pipeline suites, including distinct product identities, CPE/PURL contradictions, version intervals, wildcard intersections, unknown platform constraints, alias lifecycle, source review holds, withdrawals and changed inventory.
- Preserved the approved all-version registration policy. Explicit product-level `*` registrations cover all versions; partial patterns and unsupported concrete ordering retain their checks. This policy intentionally does not prove which version is installed.
- Rechecked saved queued/review minimums, trained ML unable to override the configured queue threshold, per-recipient subscriptions and stale-review rejection.
- The curated matching corpus has 30 cases; target-environment labelled data is still needed for a statistically meaningful precision/recall estimate.

### Email, advisories and previews

- Re-executed provider confirmation, safe retry budgets, idempotency, recipient subsets, review admission/acceptance, digest payloads and rendered-advisory escaping tests.
- Retained professionally styled linked-CVE review mail and its criterion-specific ranges. Previous desktop/mobile design checks are documented in the pipeline audit; this pass did not redesign the SPA.
- Reviewed and tested the sole raw HTML preview sink and offline PDF resource policy. No real outbound advisories or reset emails were sent by this audit.
- A provider's ACCEPTED receipt is not inbox delivery/read proof. Explicit operator approval and unknown-outcome recovery require operational care.

### Database, recovery and deployment

- Re-executed migrations through 036, state counter/backfill/rollback tests, audit chain/context tamper checks, restricted-role tests, claim/lease workflows and cancellation/recovery paths.
- Reviewed startup schema gating, signal/shutdown handling, feed reconciliation, durable outbox/dead letters, writable runtime paths, non-root/read-only Compose settings and supported egress configuration.
- Checked DNS/public-address validation, per-hop redirect revalidation, credential stripping on cross-origin redirects, DNS-pinned sockets, request cancellation and size/time limits.
- Rechecked retained key parsing, AES-GCM context authentication, invalid envelope rejection, legacy decryption, tampered-tag rejection and no implicit data re-encryption during rotation.

## Verification

| Gate | Result |
| --- | --- |
| Complete `npm run test:ci`, fresh disposable PostgreSQL database | 991 passed, 0 failed, 0 skipped |
| Source stability during complete CI | No source hash changes |
| Disposable audit database teardown | Confirmed removed |
| TypeScript `npm run lint` | Passed |
| Client/server `npm run build` | Passed; existing large-client-chunk warning |
| Browser sanitizer regression | Passed in real Chrome |
| DB-severance/reconnect, replay, retention and self-healing | Passed, including previously failing scenarios |
| Dependency audit after added maintained sanitizer/lease libraries | Zero known vulnerabilities |
| Docker image/startup/Compose runtime | Unavailable: Docker CLI not installed |

The small deployment-only model-volume correction followed the full CI freeze. Application source remained unchanged; image/volume behavior cannot be validated by Node tests. The generated coverage artifact records the tested hashes and any post-CI changes.

## Remaining release requirements

1. Apply migration 036 with the migration-owner connection in a maintenance window, grant the runtime role, and deploy the tested server/client together. Existing context-aware audit writers/verifiers must be compatible.
2. Build/start the image on the target Docker host and verify persistent-volume ownership, two-replica file-lease behavior, resource limits, probes and graceful shutdown. Validate Node 26 runtime behavior there; audit tests also ran on Node 26.
3. Perform a backup/restore drill with protected encryption keys and shared dead-letter/model data. Do not drop retained keys until all protected records, spools and required backups are migrated.
4. Perform controlled provider sandbox/staging delivery tests and confirm inbound provider telemetry. Automated CI uses mocks/local transports and does not certify external delivery or TLS/account configuration.
5. Load-test representative retained history, inventory/CVE volume and concurrent operators. The full suite and curated corpus are not a capacity or fuzzing certification.
6. Re-test browser/client compatibility and previews in supported mail clients. Professional-format snapshots and Chrome sanitization checks are not Outlook/Gmail rendering certification.

No live schema migration, API restart, production deployment or real outbound email was performed by this audit.