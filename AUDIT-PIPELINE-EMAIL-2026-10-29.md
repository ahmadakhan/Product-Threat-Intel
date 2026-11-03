# Pipeline and email delivery audit — 29 October 2026

The audit covered correlation-to-queue handoff, subscription filtering, daily digests, review approval, retry budgets, stale payload recovery, delivery leases, and delivery-log consistency. All delivery tests use mock transports and an isolated PostgreSQL database. No live email was sent and no deployment was changed.

## Defects fixed

- **Daily digest subscription scope:** the scheduler previously rendered the complete findings list for every opted-in recipient. Delivery then rejected entire digests for restricted subscribers. Each recipient now receives its permitted subset in HTML, plain text, CVE IDs, and revision evidence. An explicitly empty health-only subset stays empty during delivery validation.
- **Unsafe inventory markup:** the appended daily summary inserted inventory names directly into HTML. Inventory text is now escaped before rendering.
- **Current review policy:** a digest key previously exempted stored review-held findings from the applicability gate. Digests now reassess current inventory, withdrawals, and confidence policy; delivery rechecks the verdict without a digest exemption. Resolved, dismissed, patched, and VEX-suppressed findings stay excluded.
- **Approval and retries:** approval now starts a fresh transport attempt budget. Approved messages remain subject to retry limits and recovery checks; approval cannot bypass a newly tightened applicability policy.
- **Legacy and stale content:** recovery previously attached current fingerprints to old rendered content. It now reconstructs subject, text, HTML, affected systems, remediation, and revision evidence from current applicable findings. A changed body invalidates the previous approval.
- **Recovery concurrency and partial bundles:** recovery now runs after the claiming worker commits its result. It leaves other workers' sending leases intact. Valid portions of mixed bundles are rebuilt while withheld portions remain unsent. The failed attempt is retained, and deterministic replacement keys prevent duplicate rebuild deliveries or orphan advisory bindings.
- **Delivery-log consistency:** invalidating queued siblings updates their delivery logs in the same transaction as the queue state.

## Verification

Six initial regression scenarios failed before their corresponding fixes. Focused coverage also checks health-only subscriptions, resolved findings, concurrent sending leases, repeated recovery after acceptance, and queue/log consistency. The existing lifecycle tests were corrected to model explicit approval, disabled automatic dispatch, independent inventory correlations, and actual CVE withdrawals.

Verification completed: the full suite passed 542 tests with zero failures or skips; the final focused delivery and pipeline run passed 95 tests with zero failures or skips. Type checking, client and server production builds, and diff checks passed.
