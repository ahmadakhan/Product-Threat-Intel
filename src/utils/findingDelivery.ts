/**
 * Identifies deliveries that represent a vulnerability advisory bundle.
 *
 * The Action Center's follow-up workflow re-renders an advisory and re-queues
 * it for an operator-selected audience. That is only meaningful for finding
 * advisories: daily digests, threat-intelligence news, zero-day digests and
 * unverifiable-applicability notices are generated summaries with no advisory
 * row to re-render, so they must not appear as pending follow-up actions.
 *
 * The advisory prefix is configurable, so this matches the fixed synthetic
 * prefixes and the `DAILY_<YYYYMMDD>` suffix rather than assuming `ADV-`.
 */
const NON_ADVISORY_PREFIXES = ['NEWS:', 'ZERODAY:', 'UNVERIFIABLE:'] as const;

export function isFindingDelivery(advisoryId: string | null | undefined): boolean {
  if (!advisoryId || advisoryId === 'TEST') return false;
  if (NON_ADVISORY_PREFIXES.some((prefix) => advisoryId.startsWith(prefix))) return false;
  return !/DAILY[_-]/i.test(advisoryId);
}
