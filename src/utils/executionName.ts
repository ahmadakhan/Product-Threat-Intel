/** Build a short, human-friendly display name for a pipeline execution from its id.
 *
 * Executions are keyed by an opaque UUID, but the Execution history list renders a
 * readable label (e.g. `Run 3add6860`) instead of the raw identifier. Legacy rows
 * stored before this name was persisted fall back to this helper on read. */
export const formatExecutionName = (id: string): string => `Run ${id.slice(0, 8)}`;

/** In-memory counter keyed by `prefix|datePart` for sequential daily advisory IDs. */
const advisoryCounter = new Map<string, number>();

/** Reset the in-memory counter for a prefix/date — used by tests to force a known
 * sequence number without spawning across multiple days. */
export const resetAdvisoryCounterForTest = (prefix: string, datePart: string): void => {
  advisoryCounter.delete(`${prefix}|${datePart}`);
};

/**
 * `ddmmyy` date component of a finding-advisory identifier.
 *
 * Built from the local calendar parts in UTC-agnostic form rather than
 * `toLocaleDateString`, which is locale- and ICU-dependent: the same instant could
 * produce `12/02/2026`, `2026-12-02` or `2 Dec 2026` on different hosts, and the
 * identifier appears in email subjects and attachment filenames that must be
 * reproducible across deployments.
 */
export function advisoryDatePart(now: Date = new Date()): string {
  const day = String(now.getDate()).padStart(2, '0');
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const year = String(now.getFullYear() % 100).padStart(2, '0');
  return `${day}${month}${year}`;
}

/**
 * Format a finding-advisory identifier: `PREFIX-ddMMyy-N` (e.g. `ADV-021226-1`).
 *
 * The date is the local calendar date, and the sequence restarts at `1` each day
 * and increments once per identifier issued. The sequence is NOT zero-padded: the
 * agreed format is `ADV-021226-1`, not `ADV-021226-001`.
 *
 * The sequence is process-local. That is deliberate for the finding-email path,
 * whose identifier must be stable for the same batch on retry (it is derived from
 * the batch fingerprint by the caller, not re-minted per delivery). Callers that
 * need a globally unique, restart-safe number should pass an explicit `sequence`
 * obtained from durable storage.
 */
export const formatAdvisoryId = (prefix: string, now: Date = new Date(), sequence?: number): string => {
  const datePart = advisoryDatePart(now);
  let ordinal: number;
  if (sequence !== undefined) {
    ordinal = Math.max(1, Math.floor(sequence));
  } else {
    const key = `${prefix}|${datePart}`;
    const count = (advisoryCounter.get(key) ?? 0) + 1;
    advisoryCounter.set(key, count);
    ordinal = count;
  }
  return `${prefix}-${datePart}-${ordinal}`;
};
