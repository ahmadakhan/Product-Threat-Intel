import type { Advisory, Finding, ReviewEdits } from '../src/types/index.ts';
import { mlComposeAdvisoryEmail } from './ml/integration';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f59e0b',
  MEDIUM: '#eab308',
  LOW: '#10b981',
  UNKNOWN: '#6b7280',
};
const SEVERITY_BADGE = (severity: string, suffix = '') => {
  const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN;
  const label = severity || 'UNKNOWN';
  const escapedLabel = label.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);
  return `<span style="display:inline-block;padding:4px 10px;border-radius:4px;background:${color};color:#ffffff;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px;">${escapedLabel}${suffix}</span>`;
};

/**
 * Validates that all required advisory fields needed by the email template
 * are populated. Called by renderAdvisory to prevent emails with empty
 * content from being queued for delivery.
 */
export function validateAdvisoryFields(advisory: Advisory): AdvisoryFieldValidation {
  const missingFields: string[] = [];
  if (!advisory.id || !advisory.id.trim()) missingFields.push('id');
  if (!advisory.title || !advisory.title.trim()) missingFields.push('title');
  if (!advisory.severity) missingFields.push('severity');
  if (!advisory.executiveSummary || !advisory.executiveSummary.trim())
    missingFields.push('executiveSummary');
  if (!advisory.remediationInstructions || !advisory.remediationInstructions.trim())
    missingFields.push('remediationInstructions');
  if (!advisory.affectedSystems || advisory.affectedSystems.length === 0)
    missingFields.push('affectedSystems');
  return { valid: missingFields.length === 0, missingFields };
}

export interface AdvisoryFieldValidation {
  valid: boolean;
  missingFields: string[];
}

/**
 * Renders the operator-managed advisory template for one advisory view.
 *
 * A digest is rendered from a recipient-specific advisory view (a subset of the
 * findings in the combined advisory), so the rendered HTML can never disclose a
 * finding that the recipient is not subscribed to.
 *
  * Throws if any required advisory field is empty, preventing emails with
  * missing content from being queued for delivery.
  *
  * `findings`, when provided, supplies each CVE's own severity and CVSS score
  * for the {{cve_details}} block. Without it, every CVE badge falls back to
  * the advisory's single aggregate severity (its highest-ranked finding),
  * which is correct for the overall advisory badge but misrepresents any
  * lower-severity CVE bundled alongside a higher one.
  */

/**
 * Feed-controlled URL guard for rendered advisory links. Vendor links come from
 * CVE feeds (not from operators), so a hostile record must not become a
 * `javascript:`/`data:` target inside the delivered email or PDF. Only http(s)
 * URLs without embedded credentials are renderable; anything else renders as
 * plain text.
 */
function safeHttpHref(value: string): string {
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return '';
    return url.href;
  } catch {
    return '';
  }
}

const SEVERITY_RANK: Record<string, number> = {
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};
function cveSeverity(cve: string, advisory: Advisory, findings?: Finding[]): string {
  const cveFindings = findings?.filter((f) => f.cveId === cve) || [];
  if (cveFindings.length) {
    return cveFindings.reduce(
      (current, f) =>
        (SEVERITY_RANK[f.cve.cvss.severity] || 0) > (SEVERITY_RANK[current] || 0) ? f.cve.cvss.severity : current,
      'UNKNOWN' as string,
    );
  }
  return advisory.severity || 'UNKNOWN';
}
function severityRank(cve: string, advisory: Advisory, findings?: Finding[]): number {
  return SEVERITY_RANK[cveSeverity(cve, advisory, findings)] || 0;
}

export function renderAdvisory(template: string, advisory: Advisory, findings?: Finding[]): string {
  const validation = validateAdvisoryFields(advisory);
  if (!validation.valid) {
    throw new Error(
      `Cannot render advisory email with empty required fields: ${validation.missingFields.join(', ')}`,
    );
  }
  const escape = (v: string) =>
    v.replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
    );
  const edits: ReviewEdits = advisory.edits || {};
  // ML-guided prose. The composer rewrites the executive summary and
  // remediation guidance for the actual finding mix (severity weighting, KEV
  // emphasis, exploitation context). It falls back to the stored text when the
  // model is untrained, so this cannot blank a field — and an operator's
  // explicit edit always wins.
  let composedSummary = advisory.executiveSummary;
  let composedRemediation = advisory.remediationInstructions;
  if (findings?.length) {
    try {
      const composed = mlComposeAdvisoryEmail(findings, advisory);
      if (!edits.customBodyOverride && composed.executiveSummary)
        composedSummary = composed.executiveSummary;
      if (composed.remediationInstructions) composedRemediation = composed.remediationInstructions;
    } catch {
      // Rendering must never fail because the ML layer is unavailable.
    }
  }
  const values: Record<string, string> = {
    severity: advisory.severity,
    advisory_id: advisory.id,
    advisory_title: advisory.title,
    dispatch_date: new Date().toLocaleString('en-GB', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }),
    executive_summary: escape(composedSummary),
    cve_ids: advisory.cveIds.join(', '),
    affected_systems: advisory.affectedSystems.join('\n'),
    affected_systems_html: advisory.affectedSystems
      .map((sys: string) => `<div style="margin:0 0 4px;padding-left:0;font-size:12px;line-height:18px;color:#334155;">${escape(sys)}</div>`)
      .join('\n'),
    vendor_products: findings
      ? Array.from(
          findings.reduce((acc, f) => {
            const vendor = f.matchedAssetVendor || '';
            const product = f.matchedAssetProduct || '';
            if (vendor && product) acc.add(`${vendor} - ${product}`);
            return acc;
          }, new Set<string>())
        ).join('\n')
      : advisory.affectedSystems.join('\n'),
    vendor_products_html: findings
      ? Array.from(
          findings.reduce((acc, f) => {
            const vendor = f.matchedAssetVendor || '';
            const product = f.matchedAssetProduct || '';
            if (vendor && product) acc.add(`${vendor} - ${product}`);
            return acc;
          }, new Set<string>())
        ).map((pair: string) => `<div style="margin:0 0 4px;font-size:12px;line-height:18px;color:#334155;">${escape(pair)}</div>`).join('\n')
       : advisory.affectedSystems.map((sys: string) => `<div style="margin:0 0 4px;font-size:12px;line-height:18px;color:#334155;">${escape(sys)}</div>`).join('\n'),
    remediation_steps: escape(composedRemediation),
    vendor_link: safeHttpHref(advisory.vendorLink || ''),
    remediation_link:
      safeHttpHref(
        findings?.find((f) => f.cve?.remediation?.patchUrl)?.cve?.remediation?.patchUrl || '',
      ),
    references_link:
      safeHttpHref(
        findings?.find((f) => f.cve?.remediation?.vendorAdvisoryRef)?.cve?.remediation?.vendorAdvisoryRef || '',
      ),
    cve_id_links: [...advisory.cveIds]
      .sort((a: string, b: string) => severityRank(b, advisory, findings) - severityRank(a, advisory, findings) || a.localeCompare(b))
      .map(
        (cve: string) =>
          `<a href="https://nvd.nist.gov/vuln/detail/${escape(cve)}" target="_blank">${escape(cve)}</a>`,
      )
      .join(', '),
    cve_details: [...advisory.cveIds]
      // CRITICAL -> HIGH -> MEDIUM -> LOW -> UNKNOWN; ties broken by CVE id so a
      // re-send of the same findings renders in a stable order.
      .sort((a: string, b: string) => severityRank(b, advisory, findings) - severityRank(a, advisory, findings) || a.localeCompare(b))
      .map((cve: string) => {
        // Multiple findings can share a CVE (one per matched asset); use the
        // highest-ranked severity among them so the badge never understates
        // risk for this specific CVE.
        const cveFindings = findings?.filter((f) => f.cveId === cve) || [];
        const ranks: Advisory['severity'][] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        const severity = cveFindings.reduce(
          (current, f) =>
            ranks.indexOf(f.cve.cvss.severity) > ranks.indexOf(current) ? f.cve.cvss.severity : current,
          (cveFindings.length ? 'UNKNOWN' : advisory.severity) as Advisory['severity'],
        );
        const primary = cveFindings.find((f) => f.cve.cvss.severity === severity) || cveFindings[0];
        const score = primary?.cve.cvss.score;
        const kev = cveFindings.some((f) => f.cve.cisaKev?.isKev);
        // Only a real, parseable http(s) vendor reference is published. The old
        // fallback chain ended at `advisory.vendorLink`, which is a synthesized
        // value rather than a vendor advisory URL, so "View Source" could point
        // at nothing useful.
        const vendorHref = safeHttpHref(
          cveFindings.find((f) => f.cve.remediation?.vendorAdvisoryRef)?.cve.remediation?.vendorAdvisoryRef || '',
        );
        // The description is rendered as prose (clamped) rather than a bullet:
        // it is the substance of the entry, not an attribute of it.
        const rawDescription =
          cveFindings.find((f) => f.cve.description)?.cve.description || 'No vendor description published.';
        const description =
          rawDescription.length > 600 ? `${rawDescription.slice(0, 597).trimEnd()}…` : rawDescription;
        const colour = SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN;
        const scoreLabel = typeof score === 'number' ? score.toFixed(1) : 'N/A';
        // NVD is the authoritative, always-available source for a CVE id; it is
        // the link the reader needs from the CVE ID itself.
        const nvdHref = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;
        const sources = [`<a href="${nvdHref}" target="_blank" rel="noopener noreferrer" style="color:#2563eb;text-decoration:none;">NVD</a>`];
        if (vendorHref)
          sources.push(
            `<a href="${escape(vendorHref)}" target="_blank" rel="noopener noreferrer" style="color:#2563eb;text-decoration:none;">Vendor advisory</a>`,
          );
        sources.push(
          `<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" style="color:#2563eb;text-decoration:none;">CISA KEV</a>`,
        );
        return `<div style="margin:0 0 14px;padding:14px 16px;border:1px solid #e2e8f0;border-left:4px solid ${colour};border-radius:6px;background:#ffffff;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
    <tr>
      <td style="padding:0;vertical-align:top;">
        <div style="font-size:14px;font-weight:bold;color:#0f172a;line-height:20px;">
          <a href="${nvdHref}" target="_blank" rel="noopener noreferrer" style="color:#0f172a;text-decoration:none;">${escape(cve)}</a>
        </div>
      </td>
      <td align="right" style="padding:0 0 0 12px;white-space:nowrap;vertical-align:top;">
        <span style="display:inline-block;background:${colour};color:#ffffff;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:bold;letter-spacing:0.3px;">${escape(severity)} \u00b7 CVSS ${scoreLabel}</span>
        ${kev ? '<span style="display:inline-block;margin-left:6px;background:#7f1d1d;color:#ffffff;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:bold;letter-spacing:0.3px;">KEV</span>' : ''}
      </td>
    </tr>
    <tr>
      <td colspan="2" style="padding:8px 0 0;font-size:12px;line-height:19px;color:#334155;text-align:left;">${escape(description)}</td>
    </tr>
    <tr>
      <td colspan="2" style="padding:8px 0 0;font-size:11px;line-height:16px;color:#64748b;text-align:left;">Sources: ${sources.join(' <span style="color:#cbd5e1;">&middot;</span> ')}</td>
    </tr>
  </table>
</div>`;
      })
      .join('\n'),
    // Prose blocks instead of bullets: a numbered step list reads as an ordered
    // procedure and survives plain-text clients without a bullet glyph.
    mitigation_steps: `<div style="font-size:12px;line-height:20px;color:#334155;">
  <div style="margin:0 0 6px;"><strong>1.</strong>&nbsp; Review and limit administrative access to trusted networks.</div>
  <div style="margin:0 0 6px;"><strong>2.</strong>&nbsp; Monitor affected services for anomalous activity following the advisory window.</div>
  <div style="margin:0;"><strong>3.</strong>&nbsp; Apply compensating controls if vendor patches are not yet deployable.</div>
</div>`,
    recommended_actions: `<div style="font-size:12px;line-height:20px;color:#334155;">
  <div style="margin:0 0 6px;"><strong>1.</strong>&nbsp; Inventory all affected systems identified in this advisory.</div>
  <div style="margin:0 0 6px;"><strong>2.</strong>&nbsp; Apply vendor patches immediately following your change management process.</div>
  <div style="margin:0;"><strong>3.</strong>&nbsp; Validate backup, restore, and operational functionality after remediation.</div>
</div>`,
    audience_notice: edits.audienceNotice
      ? escape(edits.audienceNotice).replace(/\n/g, '<br/>')
      : 'This advisory is being distributed to all recipients per the EVERYONE delivery policy.',
     reviewer_comment: edits.reviewerComment
       ? `<strong>Reviewer note${edits.reviewerName ? ` by ${escape(edits.reviewerName)}` : ''}</strong> ${escape(edits.reviewerComment).replace(/\n/g, '<br/>')}`
       : '',
     severity_badge: SEVERITY_BADGE(advisory.severity),
     severity_header_badge: SEVERITY_BADGE(advisory.severity, ' SEVERITY'),
   };
  const rawHtmlTokens = new Set([
    'cve_id_links',
    'cve_details',
    'affected_systems_html',
    'vendor_products_html',
    'mitigation_steps',
    'recommended_actions',
    'severity_badge',
    'severity_header_badge',
  ]);
  let processed = template.replace(/\{\{#if\s+([a-z_]+)\}\}([\s\S]*?)\{\{\/if\}\}/g, (_, key, content) => {
    return values[key] && values[key].trim() ? content : '';
  });
  return processed.replace(/{{([a-z_]+)}}/g, (_, key) => {
    if (rawHtmlTokens.has(key)) return values[key] || '';
    return escape(values[key] || '');
  });
}
