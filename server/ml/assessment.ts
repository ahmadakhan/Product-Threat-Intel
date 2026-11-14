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
  if (!settings?.mlReviewRoutingEnabled) return finding;
  if (finding.notificationStatus !== 'REVIEW_REQUIRED' || finding.dispatchDeferred) return finding;
  if (!POLICY_CONFIDENCE_HOLD.test(finding.matchingEvidence)) return finding;
  if (!isMlModelTrained('match-confidence-model') || !isMlModelTrained('alias-confidence-model')) {
    return finding;
  }
  const assessment = finding.mlAssessment;
  if (!assessment) return finding;
  const threshold = settings.confirmedFindingThreshold ?? 90;
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) return finding;
  if (!Number.isFinite(assessment.matchConfidence) || assessment.matchConfidence < threshold) return finding;
  if (!Number.isFinite(assessment.aliasConfidence) || assessment.aliasConfidence < 0.65) return finding;
  return {
    ...finding,
    notificationStatus: 'QUEUED_FOR_DISPATCH',
    matchingEvidence: `${finding.matchingEvidence}; promoted by ML review routing (match ${Math.round(assessment.matchConfidence)}%, alias ${Math.round(assessment.aliasConfidence * 100)}% confidence)`,
  };
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
