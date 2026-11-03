# Pipeline audit — 29 October 2026

Focused review of pipeline scheduling, execution persistence, feed ingestion, cached-match reuse, cancellation, and interrupted-worker recovery. This report records reproduced defects and fixes; it is not a certification that every possible failure mode has been eliminated.

## Fixed: confidence policy bypass during cached-match reuse

**Severity: High.** The preliminary matching pass used `DEFAULT_SETTINGS`, including its 90% dispatch threshold. When the final pass reused these matches, it retained their notification eligibility even if the workspace required a higher threshold. A 90%-confidence match could therefore enter the delivery queue despite a configured threshold of 99%.

Preliminary matching now uses the workspace policy. The final transaction compares that policy with the current threshold and recomputes matching if it changed during EPSS enrichment. Regression checks cover both a stricter initial policy and an edit during enrichment, including the absence of outbox jobs when review is required. A deliberate reduction to 90% still permits eligible delivery.

## Fixed: cancellation overwritten by worker progress

**Severity: High.** The worker checked for a stop, then wrote its earlier execution snapshot with an unconditional upsert. A stop committed between these operations could be erased; a reproduction showed the execution finishing as `COMPLETED` instead of `CANCELLED`.

Every active progress/final execution write now uses an atomic database condition requiring an active status and no stop request. A rejected write aborts the transaction and enters cancellation handling. Cancellation preserves the durable stop timestamp and operator log entry. Recovery locks and re-reads each interrupted execution, terminalizing outstanding stop requests without restarting them.

## Stale-bundle recovery reason

The outbox error `Some advisory findings are no longer applicable; rebuild from current inventory. Reason: current applicability or confidence policy requires review.` is the delivery worker's pre-transport revalidation rejecting a queued bundle. It is raised when a finding still matches current inventory but the workspace confidence policy now holds it in `REVIEW_REQUIRED` rather than `QUEUED_FOR_DISPATCH`. It does not mean the finding was sent.

The worker marks the whole bundle `FAILED` with that reason, fails the sibling jobs and calls `rebuildFromCurrentInventory()`, which queues an immediate run. The rebuild reconciles against current inventory and the current policy; the held finding is retained as `REVIEW_REQUIRED` and is not placed in a new advisory, so no rebuild can re-queue or re-send it. Sending still requires the policy to admit the finding, or review to be completed so it is dispatched within the team's review workflow.

## Validation

The four new scenarios were run against a temporary copy of the original pipeline implementation: all four failed. The same scenarios pass against the corrected implementation. All database work used dedicated schemas in the isolated test database; no production pipeline or email transport was invoked.

The broader test suite also exposed a pre-existing fixture issue: the session-renewal scenario expected an administrator session after an earlier password-change scenario had revoked it. The test now establishes a fresh session before explicitly invalidating it. No authentication behavior was changed as part of this fixture correction.

The focused pipeline lifecycle, integration, and new regression suites passed 75 tests. Typechecking and the client/server production build passed. The complete database-backed suite passed **514 tests, with 0 failures and 0 skips**.

No schema migration is required. Source changes and build artifacts are local; running services have not been redeployed.
