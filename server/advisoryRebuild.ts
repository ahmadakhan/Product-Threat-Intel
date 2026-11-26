import type { Advisory, Finding } from '../src/types/index.ts';
import { get, type Db } from './db.ts';
import { advisoryEmail } from './advisoryEmail.ts';
import { renderAdvisory } from './advisoryRender.ts';
import { mlComposeAdvisoryEmail } from './ml/integration.ts';
import { resolveAdvisoryTemplate, type SavedTemplateRecord } from './deliveryDocument.ts';

/** Rebuilt content must describe current findings, never an old rendered body. */
export function currentAdvisoryView(original: Advisory, findings: Finding[]): Advisory {
  const unique = (values: string[]) => [...new Set(values.filter(Boolean))].sort();
  const ranks: Advisory['severity'][] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const links = unique(
    findings.flatMap((f) => [f.cve.remediation?.vendorAdvisoryRef || '', f.cve.remediation?.patchUrl || '']),
  );

  // ML-guided email composition with rule-based fallback when untrained.
  const { subject, executiveSummary, remediationInstructions, severitySummary } = mlComposeAdvisoryEmail(findings, original);

  return {
    ...original,
    severity: findings.reduce(
      (severity, f) =>
        ranks.indexOf(f.cve.cvss.severity) > ranks.indexOf(severity) ? f.cve.cvss.severity : severity,
      'UNKNOWN' as Advisory['severity'],
    ),
    title: subject,
    cveIds: unique(findings.map((f) => f.cveId)),
    findingIds: findings.map((f) => f.id),
    affectedSystems: unique(findings.map((f) => f.matchedAssetName)),
    executiveSummary,
    remediationInstructions,
    vendorLink: links[0] || '',
  };
}

export async function currentAdvisoryBody(db: Db, view: Advisory, findings: Finding[]) {
  const record = await get<SavedTemplateRecord>(db, 'template', 'main');
  const html = renderAdvisory(resolveAdvisoryTemplate(record), view, findings);
  return advisoryEmail(
    view,
    html,
    findings.map(
      (f) =>
        `${f.cveId} | ${f.cve.cvss.severity}${f.cve.cisaKev?.isKev ? ' | CISA KEV' : ''} | ${f.matchedAssetName}`,
    ),
    { findings },
  );
}
