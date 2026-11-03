> **Historical document.** This report reflects the codebase as of its original date and has been
> superseded by [`PRODUCTION-READINESS-AUDIT.md`](./PRODUCTION-READINESS-AUDIT.md), which is the
> authoritative readiness report. Findings here may already be fixed; do not use this file to make
> current readiness decisions.

# Codebase and UI verification — 2026-10-21

This follow-up builds on ECOSYSTEM-AUDIT-2026-10-21.md. Existing feed, matching, withdrawal, de-duplication and delivery regression coverage remains passing. This is verified development evidence, not a certification of a production deployment.

## Findings corrected

- Execution telemetry previously appeared only after completion, with no persisted active phases. The worker now stores pending/running phases, source progress and measured ingestion duration. A dependency graph renders ingestion → structured correlation → delivery queue, including before the first execution. Source retrieval can run concurrently inside ingestion. Delivery transport remains a separate worker; a queued job is not represented as delivered.
- Replaced disconnected cards, hard-coded connector count, unconditional success icons and global active-run highlighting with accessible stage buttons, real per-execution statuses, directional connectors, selected-stage details and measured metrics. Selecting an old execution never borrows a current run's progress. History displays dates and accurate failure/cancellation colors. The graph stacks vertically on mobile and supports both themes and reduced-motion preferences.
- Added authenticated, CSRF-protected ADMIN/OPERATOR POST /api/pipeline/:id/stop. Queued runs cancel immediately. Running requests persist a stop flag; checkpoints prevent further requests or commit after cancellation is observed. Retry/pacing sleeps check every 500 ms. Active requests finish within their configured timeout before the checkpoint. All concurrent workers settle before the execution lock is released. Stop is idempotent and survives worker restart.
- Cancellation discards uncommitted intelligence, findings and notification jobs, retains an audit event and terminal CANCELLED execution, and releases the worker lock. It does not retract already committed mail or disable future scheduled runs. If the final serialized commit has already begun, it completes atomically; a concurrent stop request then returns the completed execution. Cancellation is cooperative, not a hard process kill.
- Fixed light-theme styling in System Health and added accessible names/current-page semantics to shared pagination. JSON report download uses a Blob URL rather than an oversized data URL.

## Verification

- TypeScript check and client/server production builds pass.
- PostgreSQL-backed suite: 75 passed, zero failed/skipped. Includes queued cancellation, stop during retrieval, zero partial writes, released lock, and authentication/CSRF/role enforcement for stop.
- Browser smoke: all 14 authenticated pages at 1440px and 390px in dark/light themes (56 combinations); no uncaught page exceptions or document overflow. Run → stop → CANCELLED succeeds against a disposable local fixture database with background workers disabled.
- Visual inspection of pipeline desktop/mobile screenshots. Navigation smoke verifies page rendering, not every possible form/data combination.
- npm audit --omit=dev reports zero known production dependency vulnerabilities at inspection time.
- git diff --check passes.

## Production acceptance still required

The earlier ecosystem report's limitations remain: production-sized corpus/load testing, database recovery/HA validation, actual SMTP deliverability and supported feed coverage, source catch-up/backfill, retention, and conservative complex applicability handling. Correlation and outbox creation remain one atomic serialized transaction; brief stages can finish between browser polls (five seconds). Stop acknowledgement can wait behind that transaction and does not preempt CPU-bound synchronous correlation. An active NVD request can take up to its configured 60-second timeout. Live infrastructure settings and production data were not altered, and no external messages were sent.
