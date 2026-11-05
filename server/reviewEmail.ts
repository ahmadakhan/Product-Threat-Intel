import type { Finding, Severity } from '../src/types/index.ts';
import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
import { formatDateTime } from '../src/utils/dateTime.ts';
import { escapeHtml } from './emailEdits.ts';

const SEVERITIES: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const BADGES: Record<Severity, { background: string; color: string }> = {
  CRITICAL: { background: '#991b1b', color: '#ffffff' },
  HIGH: { background: '#c2410c', color: '#ffffff' },
  MEDIUM: { background: '#fde68a', color: '#854d0e' },
  LOW: { background: '#dbeafe', color: '#1e40af' },
  UNKNOWN: { background: '#e5e7eb', color: '#374151' },
};
const WRAP = 'overflow-wrap:anywhere;word-wrap:break-word;word-break:break-word;';

function severityOf(finding: Finding): Severity {
  return SEVERITIES.includes(finding.cve.cvss.severity) ? finding.cve.cvss.severity : 'UNKNOWN';
}

function sourceUrl(finding: Finding): string {
  for (const candidate of [finding.cve.remediation?.vendorAdvisoryRef, finding.cve.remediation?.patchUrl]) {
    if (!candidate) continue;
    try {
      const url = new URL(candidate);
      if (url.protocol === 'https:' && !url.username && !url.password) return url.href;
    } catch {
      continue;
    }
  }
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(finding.cveId)}`;
}

function finiteScore(value: number | undefined, maximum: number, suffix: string): string {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= maximum
    ? `${Number(value.toFixed(1))}${suffix}`
    : 'Not available';
}

function dualTimestamp(value: string | undefined, timezone?: string): string {
  const date = value ? new Date(value) : undefined;
  if (!date || !Number.isFinite(date.getTime())) return 'Not available';
  const utc = date.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
  return `${formatDateTime(date, timezone)} | ${utc}`;
}

function rangeLabel(range: Finding['cve']['versionRange']): string {
  if (!range) return '';
  return [
    range.versionStartIncluding ? `>= ${range.versionStartIncluding}` : '',
    range.versionStartExcluding ? `> ${range.versionStartExcluding}` : '',
    range.versionEndIncluding ? `<= ${range.versionEndIncluding}` : '',
    range.versionEndExcluding ? `< ${range.versionEndExcluding}` : '',
  ].filter(Boolean).join(' and ');
}

function affectedRange(finding: Finding): string {
  const matchingDetails = finding.cve.cpeMatchDetails?.filter((detail) => detail.criteria === finding.matchedCpe);
  if (matchingDetails?.length) {
    const labels = matchingDetails.map((detail) => {
      const range = rangeLabel(detail.range);
      if (range) return range;
      const parsed = parseCPE23(detail.criteria);
      return parsed.isValid && parsed.version !== '*' && parsed.version !== '-' ? parsed.version : '';
    }).filter(Boolean);
    return labels.length ? [...new Set(labels)].join('; ') : 'No version bounds specified for the matched criterion';
  }
  return rangeLabel(finding.cve.versionRange);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function renderUnverifiableReviewEmail(
  findings: readonly Finding[],
  timezone?: string,
): { subject: string; text: string; html: string } {
  const ordered = [...findings].sort((left, right) =>
    SEVERITIES.indexOf(severityOf(left)) - SEVERITIES.indexOf(severityOf(right)) ||
    compareText(left.cveId, right.cveId) ||
    compareText(left.matchedAssetName, right.matchedAssetName) ||
    compareText(left.id, right.id),
  );
  const count = findings.length;
  const countLabel = `${count} ${count === 1 ? 'finding' : 'findings'}`;
  const subject = `[Threat intelligence] for Review - Unverifiable matches (${countLabel})`;
  const summary = count
    ? 'Inventory correlations need an applicability review. Check the evidence, affected versions, platform, and source guidance before deciding on remediation.'
    : 'No findings were included in this review bulletin.';
  const footer = 'A correlation is not confirmation of applicability or exploitation. Record the review outcome in VulnStream Enterprise.';
  const textBlocks: string[] = [];
  const htmlBlocks = ordered.map((finding, index) => {
    const severity = severityOf(finding);
    const badge = BADGES[severity];
    const url = sourceUrl(finding);
    const asset = finding.matchedAssetName || finding.matchedAssetProduct || finding.matchedAssetVendor || 'Unknown asset';
    const parsedAsset = parseCPE23(finding.matchedCpe);
    const criterionVersion = parsedAsset.isValid && parsedAsset.version !== '*' && parsedAsset.version !== '-'
      ? parsedAsset.version : '';
    const range = affectedRange(finding);
    const description = finding.cve.description || 'No description supplied by the source.';
    const evidence = finding.matchingEvidence || 'No matching evidence supplied. Verify this correlation against the source guidance.';
    const cvss = finiteScore(finding.cve.cvss.score, 10, ' / 10');
    const confidence = finiteScore(finding.confidence, 100, '%');
    const fields: [string, string][] = [
      ['Asset', asset],
      ...(finding.matchedAssetVendor ? [['Vendor', finding.matchedAssetVendor] as [string, string]] : []),
      ...(finding.matchedAssetProduct ? [['Product', finding.matchedAssetProduct] as [string, string]] : []),
      ...(criterionVersion ? [['Matched CPE version', criterionVersion] as [string, string]] : []),
      ['Affected range', range || 'Not specified; verify against source guidance'],
      ['CVE published', dualTimestamp(finding.cve.publishedDate, timezone)],
      ['Source updated', dualTimestamp(finding.cve.modifiedDate, timezone)],
    ];
    textBlocks.push([
      `${index + 1}. ${finding.cveId} | ${severity}`,
      `Source: ${url}`,
      `CVSS: ${cvss} | Match confidence: ${confidence}`,
      ...fields.map(([label, value]) => `${label}: ${value}`),
      `Description: ${description}`,
      `Evidence: ${evidence}`,
    ].join('\n'));
    const fieldHtml = fields.map(([label, value]) =>
      `<tr><td valign="top" width="108" style="width:108px;padding:5px 12px 5px 0;color:#52606d;font-size:13px;line-height:19px;">${escapeHtml(label)}</td>` +
      `<td valign="top" style="padding:5px 0;color:#17212b;font-size:13px;line-height:19px;${WRAP}">${escapeHtml(value)}</td></tr>`,
    ).join('');
    return `<tr class="vulnstream-pdf-card" data-pdf-accent="${badge.background}"><td style="padding:24px 24px 26px;border-top:1px solid #dfe4e8;border-left:4px solid ${badge.background};${WRAP}">` +
      `<p style="margin:0 0 8px;font-size:12px;line-height:18px;color:#52606d;">FINDING ${index + 1} OF ${count}</p>` +
      `<h2 style="margin:0 0 4px;font-size:20px;line-height:28px;font-weight:700;${WRAP}"><a href="${escapeHtml(url)}" style="color:#155e75;text-decoration:underline;${WRAP}">${escapeHtml(finding.cveId)}</a></h2>` +
      `<p style="margin:0 0 12px;font-size:13px;line-height:19px;color:#52606d;${WRAP}">Source: ${escapeHtml(new URL(url).hostname)}</p>` +
      `<p style="margin:0 0 8px;"><span style="display:inline-block;padding:3px 8px;border-radius:4px;background:${badge.background};color:${badge.color};font-size:12px;line-height:18px;font-weight:700;">${escapeHtml(severity)}</span></p>` +
      `<p style="margin:0 0 16px;font-size:13px;line-height:21px;color:#374151;">CVSS <strong>${escapeHtml(cvss)}</strong><br>Match confidence <strong>${escapeHtml(confidence)}</strong></p>` +
      `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;table-layout:fixed;">${fieldHtml}</table>` +
      `<p style="margin:16px 0 6px;font-size:13px;line-height:19px;font-weight:700;color:#17212b;">Description</p>` +
      `<p style="margin:0;font-size:13px;line-height:21px;color:#374151;${WRAP}">${escapeHtml(description).replace(/\r?\n/g, '<br>')}</p>` +
      `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin-top:16px;border-collapse:collapse;table-layout:fixed;"><tr><td style="padding:12px 14px;background:#f7f8fa;border-left:3px solid #b7791f;${WRAP}">` +
      `<p style="margin:0 0 5px;font-size:13px;line-height:19px;font-weight:700;color:#17212b;">Matching evidence</p>` +
      `<p style="margin:0;font-size:13px;line-height:21px;color:#374151;${WRAP}">${escapeHtml(evidence).replace(/\r?\n/g, '<br>')}</p></td></tr></table>` +
      `</td></tr>`;
  }).join('');
  const text = ['VulnStream Enterprise | Security Review', 'Unverifiable Matches', 'Review Required', countLabel, summary, ...textBlocks, footer].join('\n\n');
  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Unverifiable Matches</title></head>' +
    '<body style="margin:0;padding:0;background:#f1f3f5;color:#17212b;font-family:Arial,Helvetica,sans-serif;">' +
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f1f3f5;border-collapse:collapse;"><tr><td align="center" style="padding:24px 8px;">` +
    '<!--[if mso]><table role="presentation" width="640" align="center"><tr><td><![endif]-->' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:640px;table-layout:fixed;background:#ffffff;border:1px solid #dfe4e8;border-top:4px solid #155e75;border-collapse:collapse;">' +
    '<tr><td style="padding:20px 24px;border-bottom:1px solid #dfe4e8;"><p style="margin:0;font-size:14px;line-height:20px;font-weight:700;color:#17212b;">VulnStream Enterprise</p><p style="margin:3px 0 0;font-size:12px;line-height:18px;color:#52606d;">THREAT INTELLIGENCE / SECURITY REVIEW</p></td></tr>' +
    '<tr><td style="padding:26px 24px 24px;">' +
    '<p style="margin:0 0 12px;"><span style="display:inline-block;padding:4px 9px;border:1px solid #92400e;border-radius:4px;background:#ffffff;color:#78350f;font-size:12px;line-height:18px;font-weight:700;">Review Required</span></p>' +
    '<h1 style="margin:0 0 12px;font-size:26px;line-height:34px;font-weight:700;color:#17212b;">Unverifiable Matches</h1>' +
    `<p style="margin:0 0 8px;font-size:16px;line-height:24px;font-weight:700;color:#17212b;">${escapeHtml(countLabel)} to review</p>` +
    `<p style="margin:0;font-size:14px;line-height:23px;color:#374151;">${escapeHtml(summary)}</p></td></tr>` +
    htmlBlocks +
    `<tr><td style="padding:18px 24px;border-top:1px solid #dfe4e8;background:#fafbfc;"><p style="margin:0;font-size:13px;line-height:20px;color:#52606d;">${escapeHtml(footer)}</p></td></tr>` +
    '</table><!--[if mso]></td></tr></table><![endif]--></td></tr></table></body></html>';
  return { subject, text, html };
}