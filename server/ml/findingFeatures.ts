import type { Finding } from '../../src/types/index.ts';
import { parseCPE23 } from '../../src/utils/cpeMatcher.ts';
import type { FindingFeatures } from './models/reviewRanker.ts';

const finite = (value: unknown) =>
  typeof value === 'number' && Number.isFinite(value) ? value : 0;

export function findingFeatures(finding: Finding): FindingFeatures {
  const cve = finding.cve;
  const parsed = parseCPE23(finding.matchedCpe || '');
  const published = Date.parse(cve.publishedDate || '');
  return {
    matchConfidence: finite(finding.confidence),
    cvssScore: finite(cve.cvss?.score),
    epssScore: finite(cve.epss?.score),
    cisaKev: cve.cisaKev?.isKev === true,
    exploitStatus: Math.max(0, ['None', 'Reported In Wild', 'POC Available', 'Active Weaponized'].indexOf(cve.exploitStatus)),
    cweRiskLevel: 0,
    signalDensity: 0,
    matchMethod: finding.matchingMethod,
    sourceFeedWeight: 0,
    assetCriticality: 0,
    hasVersionEvidence: parsed.isValid && !['*', '-'].includes(parsed.version) && !/[?*]/.test(parsed.version),
    daysSincePublished: Number.isFinite(published) ? Math.max(0, (Date.now() - published) / 86400000) : 0,
    negated: false,
  };
}
