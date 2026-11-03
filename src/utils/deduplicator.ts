/**
 * CVE ID Normalization and Deduplication Engine
 * Enforces canonical CVE-YYYY-NNNN+ format and O(1) tracking.
 */

import type { NormalizedCVE } from '../types';

const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;

export function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object')
    return `{${Object.entries(value)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, v]) => `${JSON.stringify(key)}:${stableJson(v)}`)
      .join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}

/** Select a complete source revision; never combine applicability ranges from unrelated revisions. */
export function mergeCveRecords(records: NormalizedCVE[]): Map<string, NormalizedCVE> {
  const merged = new Map<string, NormalizedCVE>();
  const applicability = (cve: NormalizedCVE) =>
    stableJson({
      cpes: [...cve.cpeMatches].sort(),
      details: cve.cpeMatchDetails?.map(stableJson).sort(),
      range: cve.versionRange,
      purls: cve.purls ? [...cve.purls].sort() : undefined,
    });
  const content = ({ sourceFeeds: _sources, applicabilityRequiresReview: _review, ...cve }: NormalizedCVE) =>
    stableJson(cve);
  const detailsFor = (cve: NormalizedCVE) =>
    cve.cpeMatchDetails?.length
      ? cve.cpeMatchDetails
      : cve.cpeMatches.map((criteria) => ({ criteria, range: cve.versionRange }));
  for (const raw of records) {
    const cveId = normalizeCveId(raw.cveId);
    if (!cveId) continue;
    const candidate = { ...raw, cveId };
    const old = merged.get(cveId);
    if (!old) {
      merged.set(cveId, candidate);
      continue;
    }
    const candidateTime = Date.parse(candidate.modifiedDate);
    const oldTime = Date.parse(old.modifiedDate);
    const candidateValid = Number.isFinite(candidateTime);
    const oldValid = Number.isFinite(oldTime);
    const delta = candidateTime - oldTime;
    const contentWins = content(candidate) > content(old);
    // A missing or unparseable revision date must not silently make an older
    // record win. Prefer the record with a usable date; when both are unusable,
    // fall back to deterministic content ordering.
    const winner =
      candidateValid && !oldValid
        ? candidate
        : oldValid && !candidateValid
          ? old
          : candidateValid && oldValid
            ? delta > 0 || (delta === 0 && contentWins)
              ? candidate
              : old
            : contentWins
              ? candidate
              : old;
    const applicabilityConflict =
      candidateValid && oldValid && delta === 0 && applicability(old) !== applicability(candidate);
    const mergedDetails = applicabilityConflict
      ? [...new Map([...detailsFor(old), ...detailsFor(candidate)].map((detail) => [stableJson(detail), detail])).values()]
          .sort((a, b) => stableJson(a).localeCompare(stableJson(b)))
      : winner.cpeMatchDetails;
    merged.set(cveId, {
      ...winner,
      ...(applicabilityConflict
        ? {
            cpeMatches: [...new Set([...old.cpeMatches, ...candidate.cpeMatches])].sort(),
            cpeMatchDetails: mergedDetails,
            purls: [...new Set([...(old.purls || []), ...(candidate.purls || [])])].sort(),
            // The top-level range cannot safely describe conflicting source
            // applicability. Preserve candidates and require operator review.
            versionRange: undefined,
          }
        : {}),
      sourceFeeds: [...new Set([...old.sourceFeeds, ...candidate.sourceFeeds])].sort(),
      applicabilityRequiresReview: winner.applicabilityRequiresReview || applicabilityConflict,
    });
  }
  return merged;
}

/**
 * Normalizes any CVE string into canonical uppercase, trimmed format.
 * Returns null if not a valid CVE ID.
 */
export function normalizeCveId(rawId: string): string | null {
  if (!rawId || typeof rawId !== 'string') return null;

  const trimmed = rawId.trim().toUpperCase();
  if (CVE_REGEX.test(trimmed)) {
    return trimmed;
  }
  return null;
}

/**
 * Checks if a CVE falls within the processing window based on scope_hours
 */
export function isWithinTimelineScope(
  publishedDate: string,
  modifiedDate: string,
  scopeHours: number,
  now: Date = new Date(),
): boolean {
  if (!scopeHours || scopeHours <= 0) return true; // If 0, no filter

  const windowMillis = scopeHours * 60 * 60 * 1000;
  const cutoffTime = now.getTime() - windowMillis;

  const pubTime = new Date(publishedDate).getTime();
  const modTime = new Date(modifiedDate).getTime();

  const latestActivity = Math.max(isNaN(pubTime) ? 0 : pubTime, isNaN(modTime) ? 0 : modTime);

  return latestActivity >= cutoffTime;
}

/**
 * Deduplicator class for in-run O(1) deduplication
 */
export class InRunDeduplicator {
  private seenInRun = new Set<string>();
  private previouslyAlerted = new Set<string>();

  constructor(previouslyAlertedIds: string[] = []) {
    for (const id of previouslyAlertedIds) {
      const norm = normalizeCveId(id);
      if (norm) {
        this.previouslyAlerted.add(norm);
      }
    }
  }

  /**
   * Evaluates if a CVE is new or duplicate
   */
  public evaluate(rawCveId: string): {
    canonicalId: string | null;
    isDuplicateInRun: boolean;
    isPreviouslyAlerted: boolean;
    isProcessable: boolean;
  } {
    const canonical = normalizeCveId(rawCveId);
    if (!canonical) {
      return {
        canonicalId: null,
        isDuplicateInRun: false,
        isPreviouslyAlerted: false,
        isProcessable: false,
      };
    }

    if (this.seenInRun.has(canonical)) {
      return {
        canonicalId: canonical,
        isDuplicateInRun: true,
        isPreviouslyAlerted: this.previouslyAlerted.has(canonical),
        isProcessable: false,
      };
    }

    this.seenInRun.add(canonical);

    const isPrevAlerted = this.previouslyAlerted.has(canonical);

    return {
      canonicalId: canonical,
      isDuplicateInRun: false,
      isPreviouslyAlerted: isPrevAlerted,
      isProcessable: true,
    };
  }

  public getSeenCount(): number {
    return this.seenInRun.size;
  }
}
