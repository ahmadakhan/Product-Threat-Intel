import type { AppSettings, Finding } from '../types/index.ts';

/** All findings dispatch; no quotas or caps. Returns findings unchanged. */
export function limitFindingDispatches(findings: Finding[], settings: AppSettings): Finding[] {
  return findings;
}
