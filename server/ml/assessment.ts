import type { AppSettings, FeedType, Finding } from '../../src/types/index.ts';
import { findingFeatures } from './findingFeatures.ts';
import {
  cpePreFilter, isMlModelTrained, predictAliasConfidence, predictExploitRisk, predictMatchConfidence,
  predictRemediation, predictSeverityTier, rankReviewFindings,
} from './integration.ts';

/** The engine's exact wording for a hold caused only by the confidence policy. */
const POLICY_CONFIDENCE_HOLD = /confidence is below the .*auto-dispatch threshold/i;

export function assessFinding(
  finding: Finding,
  feedTypesById?: ReadonlyMap<string, FeedType>,
): Finding {
  const cve = finding.cve;
  const common = findingFeatures(finding, feedTypesById);
  // Recommendations never replace the parser's applicability, VEX, or operator dispatch policy.
  return {
    ...finding,
    mlAssessment: {
      assessedAt: new Date().toISOString(),
      cpeParseRecommended: cpePreFilter(finding.matchedCpe),
      matchConfidence: predictMatchConfidence({ ...common, matchMethod: finding.matchingMethod, negated: false }),
      aliasConfidence: predictAliasConfidence({
        ...common,
        matchMethod: finding.matchingMethod,
      }),
      exploitRisk: predictExploitRisk({
        ...common, exploitStatus: cve.exploitStatus, exploitationSourcesCount: cve.exploitationSources?.length ?? 0,
      }),
      severityTier: predictSeverityTier({ ...common, exploitStatus: cve.exploitStatus, cweRiskLevel: 0, cvssSeverity: cve.cvss.severity }),
      remediationCompleteness: predictRemediation({
        ...common,
      }, cve.remediation).recommendation,
    },
  };
}

/**
 * ML review routing pass-through.
 *
 * All findings dispatch; no review queue exists. ML routing is informational
 * only and does not gate delivery. The finding is returned unchanged so that
 * callers can rely on a stable signature while ML assessment results live in
 * `finding.mlAssessment` (populated by `assessFinding`).
 */
export function applyMlReviewRouting(finding: Finding, settings?: AppSettings): Finding {
  return finding;
}

export function assessFindings(
  findings: Finding[],
  feedTypesById?: ReadonlyMap<string, FeedType>,
  settings?: AppSettings,
): Finding[] {
  return rankReviewFindings(
    findings
      .map((finding) => applyMlReviewRouting(assessFinding(finding, feedTypesById), settings)),
    feedTypesById,
  );
}
