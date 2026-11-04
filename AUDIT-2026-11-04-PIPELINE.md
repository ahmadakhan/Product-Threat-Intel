# Pipeline Matching and Review Delivery Audit

Date: 4 November 2026

## Scope and conclusion

Reviewed matching classification, configured confidence thresholds, registered-product matching, source review holds, subscription filtering, review queue admission, pre-transport validation, acceptance bookkeeping, Settings persistence and review-email presentation.

The focused audit gate passed 368 tests in 24 files with PostgreSQL-backed tests enabled and zero skips. This is evidence for the tested contracts, not proof that arbitrary vendor data cannot produce false positives, false negatives or races. Source completeness, vendor version semantics and external transport acceptance remain independent boundaries.

## Fixed defects

| Area | Defect | Correction |
| --- | --- | --- |
| Confidence policy | A trained model could replace the operator's saved dispatch threshold. | The saved threshold is authoritative; trained model thresholds are recommendations only. Invalid/non-finite confidence cannot dispatch. |
| Confidence classification | Every uncertain match was forced to zero, making nonzero thresholds ineffective. | Version-uncertain matches retain measured confidence. Hard source, complex-applicability and contradictory-identifier holds remain protected. |
| Review selection | Only confidence-zero findings were eligible for review notices. | An independent review-email minimum applies to all findings still held for review. Findings below it remain visible without automatic review email. |
| Recipient governance | Review batches could contain findings outside a recipient's subscription. | Each Security-team recipient receives only their own eligible severity/KEV subset. Everyone-group recipients are excluded. |
| Stale review jobs | Review notifications bypassed current applicability and policy checks. | Before sending, the worker verifies current recipient identity/tier, findings, inventory, source revisions, withdrawal state, confidence policy and rendered evidence. |
| Concurrent batches | Overlapping pending batches could notify a finding twice. | Transaction-scoped admission and recipient-specific reservations prevent overlap, including concurrent producers. Pending reservations and acceptance markers are read in one database snapshot. |
| Concurrent updates | Acceptance bookkeeping rewrote complete findings from stale snapshots. | An atomic JSON-field update stamps review acceptance without overwriting concurrent operator decisions. |
| Recovery | A policy-blocked review job could remain permanently blocked after eligibility was restored. | Deterministic pre-transport review failures can resume after revalidation, without reopening transport failures or adding duplicate jobs. |
| Settings safety | Validated Settings saves omitted the master email-delivery switch. | `emailEnabled` is validated and persisted, including an explicit false. Confidence edits do not re-enable disabled transport. |
| Input safety | Empty confidence inputs were coerced to zero. | String drafts preserve empty input; inline integer/range validation blocks saving invalid values while allowing an explicit zero. |
| Email evidence | CVEs were not linked, and version labels/ranges could imply evidence the matcher had not established. | CVEs link to credential-free HTTPS source guidance with NVD fallback; matched CPE versions and criterion-specific ranges are labelled accurately. All HTML data is escaped. |

## Confidence contract

- `autoDispatchConfidenceThreshold` is the queued-email minimum, inclusive, from 0 to 100. Existing default: 90.
- `reviewConfidenceThreshold` is the review-email minimum, inclusive, from 0 to 100. Backward-compatible default: 0.
- `QUEUED_FOR_DISPATCH` means the finding is eligible under matching policy. Actual automated transport also requires automatic dispatch and master email delivery to be enabled, plus recipient eligibility.
- A version-uncertain match remains `REVIEW_REQUIRED` unless `autoDispatchUnverifiableMatches` permits it and its measured confidence reaches the queued minimum.
- A review notice requires `reviewUnverifiableMatches`, `REVIEW_REQUIRED`, the review minimum, an active/non-dismissed finding and an eligible Security-team recipient. Below-minimum findings are not deleted.
- Numeric thresholds do not release review-only source evidence, unresolved complex applicability or contradictory package evidence.
- Explicit all-version product registrations retain the previously approved automatic-dispatch policy. Partial-version patterns and unsupported concrete ordering retain their evidence checks.

Example: with queue minimum 85 and review minimum 65, an eligible 90-confidence finding queues, a held 70-confidence finding can generate a review notice, and a 60-confidence finding remains visible without an automatic review notice. The review toggle and recipient subscription still apply.

## Verification

- 368 focused matching, registration, pipeline, delivery and ML integration tests passed; zero failed and zero skipped.
- TypeScript lint and both production builds passed. The existing main-client-chunk size warning remains.
- The labelled benchmark passed all 30 cases: TP=13, TN=17, FP=0, FN=0; precision and recall were 100% on this curated corpus only.
- Tests cover confidence boundaries, a trained model unable to override settings, source holds, incompatible identifiers, historical/new inventory, withdrawal and changed-source rejection, overlapping producers, concurrent workers, multi-recipient acceptance, subscription subsets and policy-restoration recovery.
- Browser verification used an isolated database, disposable account, disabled worker, disabled scheduler and disabled email transport. No live messages were sent.
- Settings round-trip persisted queue/review values 85/65 while keeping `emailEnabled=false`.
- Browser checks confirmed empty/decimal/out-of-range input blocks saving, explicit zero is valid, accessible errors are associated with fields, and disabled review fields explain their prerequisite.
- Settings and email were measured at 1440px and 390px with no document overflow. Screenshots were inspected. An independent design review passed after refinement.
- Review email source links are HTTPS, CVEs are ordered by severity, badges have contrast-safe text, and the document has no scripts or externally loaded visual assets.

## Operational limits

- Confidence is a policy score, not a statistically calibrated guarantee that a system is affected. Validate precision and recall on representative labelled deployment data, not only the repository corpus.
- Vendor feeds can be incomplete, late or internally inconsistent. Ambiguous source evidence must remain reviewable.
- A provider can accept mail immediately before a database commit is lost. At-least-once delivery and provider-confirmation limits still apply; do not promise exactly-once inbox delivery.
- A policy or inventory change after the final check and after transport submission cannot retract an accepted email. The checks reject known stale queued content, but cannot atomically transact with an external mail provider.
- Already-queued legacy review payloads without current revision evidence are held rather than trusted; run correlation to generate a refreshed review notification.
- Independent repository-wide DB-severance/self-healing test failures reported in the earlier full-CI pass are outside this focused gate. This report does not certify the entire deployment.
- Migration 036 from the earlier production-hardening change remains a prerequisite for this working tree's state-counter code. This audit did not apply schema changes to the live database.