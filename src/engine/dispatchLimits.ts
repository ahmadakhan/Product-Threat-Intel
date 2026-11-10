import type { AppSettings, Finding } from '../types/index.ts';

/** Apply finding quotas to the actual dispatch set, including low-confidence findings. */
export function limitFindingDispatches(findings: Finding[], settings: AppSettings): Finding[] {
  const cap = Math.min(settings.maxFindingsPerRun ?? 10000, settings.maxTotalFindingsPerRun ?? 50000);
  const perFeed = settings.maxDispatchesPerRunPerFeed ?? 10000;
  const counts = new Map<string, number>();
  const admitted: Finding[] = [];
  for (const finding of findings) {
    if (finding.dispatchDeferred || admitted.length >= cap) continue;
    const sources = [...new Set(finding.cve.sourceFeeds ?? [])];
    if (sources.some((source) => (counts.get(source) ?? 0) >= perFeed)) continue;
    admitted.push(finding);
    for (const source of sources) counts.set(source, (counts.get(source) ?? 0) + 1);
  }
  return admitted;
}
