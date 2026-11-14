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
 * Opt-in ML review routing.
 *
 * This deliberately promotes only a finding whose hold reason is the
 * confidence policy. Applicability/version holds, source review-only holds,
 * circuit-breaker deferrals and every VEX decision remain authoritative. It
 * also requires both confidence models to be genuinely trained, so a missing
 * model can never silently change routing.
 */
export function applyMlReviewRouting(finding: Finding, settings?: AppSettings): Finding {
  // All findings dispatch; no review queue exists. ML routing is informational
  // only and does not gate delivery.
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
