import type { Finding } from '../types';
import { normalizeCveId } from '../utils/deduplicator';
/** Stable identity shared by reconciliation, matching and detection counts. */
export const findingIdentity = (f: Finding) =>
  `${normalizeCveId(f.cveId) ?? `raw:${f.cveId || f.id}`}:${f.matchedAssetId}`;
/**
 * Count candidates whose (CVE, asset) identity was not present in the previous
 * finding set. The pipeline re-derives every current match on each run so it
 * can refresh applicability; only identities absent from the previous set are
 * genuinely new detections. Repeated candidates within the run count once.
 */
export function countNewFindings(existing: readonly Finding[], candidates: readonly Finding[]): number {
  const known = new Set(existing.map(findingIdentity));
  const detected = new Set<string>();
  for (const candidate of candidates) {
    const id = findingIdentity(candidate);
    if (!known.has(id)) detected.add(id);
  }
  return detected.size;
}
/**
 * How long a finding normally stays parked as DELIVERY_FAILED before a later run
 * may re-queue it.
 *
 * A delivery failure is an operator-visible outcome, not an automatic-resend
 * trigger, so a failure is NOT cleared by the next run (that would re-send after
 * every transient failure). It has to be eventually recoverable, though: the
 * dead-letter retry sweep gives up after its own bounded budget, and without a
 * time-based window after that a finding whose only problem was a provider
 * outage stayed parked forever unless an operator noticed it.
 *
 * This bounds failures that carry a delivery timestamp. A failure with no
 * timestamp at all is retried on the next run: the alternative is a finding that
 * can never be recovered, and the per-recipient `delivery_claims` receipt still
 * prevents a mailbox from being told twice.
 */
export const DELIVERY_FAILED_RETRY_HOURS = 24;

/** Run-level policy for {@link reconcileFindings}. */
export interface ReconcileOptions {
  /** Operator override for the DELIVERY_FAILED retry window, in hours. */
  deliveryFailedRetryHours?: number;
}

/** Preserve finding identity, operator lifecycle decisions and delivery history while refreshing applicability. */
export function reconcileFindings(
  existing: Finding[],
  candidates: Finding[],
  now = new Date().toISOString(),
  options: ReconcileOptions = {},
): Finding[] {
  const previous = new Map(existing.map((f) => [findingIdentity(f), f]));
  const uniqueCandidates: Finding[] = [];
  {
    const seen = new Set<string>();
    const dupes: Finding[] = [];
    for (const candidate of candidates) {
      const id = findingIdentity(candidate);
      if (seen.has(id)) {
        dupes.push(candidate);
        continue;
      }
      seen.add(id);
      uniqueCandidates.push(candidate);
    }
    if (dupes.length)
      console.warn(
        `[reconcileFindings] dropped ${dupes.length} duplicate candidate(s) with identities already present in the candidate set`,
      );
  }
  const current = new Set(uniqueCandidates.map(findingIdentity));
  const result = uniqueCandidates.map((candidate) => {
    const old = previous.get(findingIdentity(candidate));
    if (!old) return candidate;
    let notificationStatus = candidate.notificationStatus;
    // A zero-day withheld by the run's rate cap is delivered only through its
    // digest. That decision belongs to *this* run: the matcher rebuilds a fresh
    // `QUEUED_FOR_DISPATCH` candidate, so carrying the stored `DIGEST_BATCHED`
    // forward would silence the finding permanently once the cap no longer
    // applies. It must be carried through only when this run's cap withheld it
    // again (the same reason `DIGEST_BATCHED` is not part of the branches below).
    const digestBatchedNow = notificationStatus === 'DIGEST_BATCHED';
    // A stored delivery failure keeps its own branch, ahead of the advisory branch
    // below: that branch reported a FAILED status verbatim, so a finding whose
    // advisory never cleared stayed parked forever once the dead-letter budget
    // was spent.
    const failedNow = old.notificationStatus === 'DELIVERY_FAILED' && notificationStatus !== 'REVIEW_REQUIRED';
    if (digestBatchedNow) {
      // Keep this run's verdict.
    } else if (failedNow) {
      // A delivery failure is an operator-visible outcome, so it is not cleared by
      // the very next run (that would re-send after every transient failure). It
      // becomes dispatchable again once the recovery window has elapsed, and
      // immediately when the pipeline cleared the advisory (`advisoryId === null`
      // is its explicit "this bundle was wholly rejected, rebuild it" signal).
      //
      // `autoDispatchedAt` is NOT proof of delivery here. It is stamped by the
      // *first* successful acceptance, so using it as the recovery test (the old
      // `autoDispatchedAt || advisoryId === null` form) re-queued unchanged
      // content after a later failed re-delivery. It is only the "when did we last
      // hear anything" timestamp for the window.
      const retryAfterHours =
        typeof options.deliveryFailedRetryHours === 'number' &&
        Number.isFinite(options.deliveryFailedRetryHours) &&
        options.deliveryFailedRetryHours > 0
          ? options.deliveryFailedRetryHours
          : DELIVERY_FAILED_RETRY_HOURS;
      const lastAttempt = old.autoDispatchedAt ?? null;
      const lastAttemptAt = lastAttempt ? Date.parse(lastAttempt) : NaN;
      const nowAt = Date.parse(now);
      const retryDue =
        !lastAttempt ||
        !Number.isFinite(lastAttemptAt) ||
        !Number.isFinite(nowAt) ||
        nowAt - lastAttemptAt >= retryAfterHours * 3_600_000;
      notificationStatus = old.advisoryId === null || retryDue ? candidate.notificationStatus : 'DELIVERY_FAILED';
    } else if (notificationStatus !== 'REVIEW_REQUIRED' && old.advisoryId) {
      notificationStatus = old.autoDispatchedAt
        ? 'AUTO_DISPATCHED'
        : ['QUEUED_FOR_DISPATCH', 'DELIVERY_FAILED', 'SECURITY_REJECTED'].includes(old.notificationStatus)
          ? old.notificationStatus
          : 'DELIVERY_FAILED';
    } else if (notificationStatus !== 'REVIEW_REQUIRED' && old.reviewNotifiedAt) {
      // The finding was announced in a consolidated email, so report that lifecycle
      // instead of leaving it looking unused. This is NOT the Finding 1 bug: that
      // bug filtered the dispatch set on this global stamp, so recipients who were
      // never told got nothing. `AUTO_DISPATCHED` is admitted by the dispatch
      // filter, and the per-recipient `delivery_claims` receipt still decides
      // whether a given mailbox needs this finding.
      //
      // The stamp is used rather than `autoDispatchedAt` because it is set
      // unconditionally on transport acceptance; `autoDispatchedAt` is null for a
      // finding released from REVIEW_REQUIRED.
      notificationStatus = 'AUTO_DISPATCHED';
    }
    const changed =
      old.matchingEvidence !== candidate.matchingEvidence ||
      old.matchedCpe !== candidate.matchedCpe ||
      old.matchedAssetVendor !== candidate.matchedAssetVendor ||
      old.matchedAssetProduct !== candidate.matchedAssetProduct ||
      old.wildcardScopeMatch !== candidate.wildcardScopeMatch ||
      JSON.stringify(old.matchedAssetPurls ?? []) !== JSON.stringify(candidate.matchedAssetPurls ?? []) ||
      old.notificationStatus !== notificationStatus;
    return {
      ...old,
      cve: candidate.cve,
      // A deferral is an operator/policy decision already recorded against this
      // finding, not a property the matcher re-derives. The matcher rebuilds a
      // candidate with `dispatchDeferred: false`, so taking the candidate's value
      // here silently un-deferred a finding that policy had held — the next run
      // then dispatched it. Keep the stored decision and fall back to the fresh
      // candidate only when the finding had none.
      dispatchDeferred: old.dispatchDeferred ?? candidate.dispatchDeferred,
      matchedAssetName: candidate.matchedAssetName,
      matchedAssetVendor: candidate.matchedAssetVendor,
      matchedAssetProduct: candidate.matchedAssetProduct,
      matchedAssetPurls: candidate.matchedAssetPurls,
      matchedCpe: candidate.matchedCpe,
      matchingMethod: candidate.matchingMethod,
       matchingEvidence: candidate.matchingEvidence,
       wildcardScopeMatch: candidate.wildcardScopeMatch,
       confidence: candidate.confidence,
       exposure: candidate.exposure,
       // Announcement state is never reset by a re-evaluation: it records
       // what was *sent*, not what currently applies.
       reviewNotifiedAt: old.reviewNotifiedAt ?? candidate.reviewNotifiedAt ?? null,
      // The dead-letter retry budget is spent, not reset: a requeue that cleared
      // it would make the cap meaningless (the sweep would retry forever).
      deadLetterCount: old.deadLetterCount ?? candidate.deadLetterCount,
      exploitRisk: candidate.exploitRisk,
      mlAssessment: candidate.mlAssessment,
      notificationStatus,
      timeline: changed
        ? [
            ...(old.timeline ?? []),
            {
              timestamp: now,
              action: 'Applicability re-evaluated',
              system: 'Server correlation engine',
              details: candidate.matchingEvidence,
            },
          ]
        : old.timeline,
    };
  });
  for (const old of existing)
    if (!current.has(findingIdentity(old)))
      result.push(
        old.notificationStatus === 'NOT_APPLICABLE'
          ? old
          : {
              ...old,
              notificationStatus: 'NOT_APPLICABLE',
              matchingEvidence:
                'No current match: inventory is inactive, removed, or outside the cached vulnerability criteria.',
              timeline: [
                ...(old.timeline ?? []),
                {
                  timestamp: now,
                  action: 'Applicability re-evaluated',
                  system: 'Server correlation engine',
                  details: 'No current inventory match; excluded from notification.',
                },
              ],
            },
      );
  return result;
}
