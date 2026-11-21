import type { Advisory, Finding, ReviewEdits } from '../src/types/index.ts';
import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
import { formatDate } from '../src/utils/dateTime.ts';
import { stripGeneratedExecutiveSummaryMarkup } from '../src/utils/templateCompiler.ts';
import { renderEmailTemplate } from '../src/utils/emailTemplate.ts';
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
  const escapedLabel = label.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch] ?? ch);
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

function versionRangeLabel(range?: Finding['cve']['versionRange']): string | undefined {
  if (!range) return undefined;
  const bounds = [
    range.versionStartIncluding ? `>= ${range.versionStartIncluding}` : '',
    range.versionStartExcluding ? `> ${range.versionStartExcluding}` : '',
    range.versionEndIncluding ? `<= ${range.versionEndIncluding}` : '',
    range.versionEndExcluding ? `< ${range.versionEndExcluding}` : '',
  ].filter(Boolean);
  return bounds.length ? bounds.join(' and ') : undefined;
}

function affectedVersionLabel(finding: Finding): string | undefined {
  const matchingCriteria = finding.cve.cpeMatchDetails?.filter(
    (detail) => detail.criteria === finding.matchedCpe,
  );
  const criteria = matchingCriteria?.length
    ? matchingCriteria
    : finding.cve.cpeMatchDetails?.length
      ? finding.cve.cpeMatchDetails
      : (finding.cve.cpeMatches || []).map((criteria) => ({ criteria, range: finding.cve.versionRange }));
  const versions = new Set<string>();
  for (const detail of criteria || []) {
    const parsed = parseCPE23(detail.criteria);
    if (parsed.isValid && parsed.version !== '*' && parsed.version !== '-') {
      versions.add(parsed.version);
      continue;
    }
    const range = versionRangeLabel(detail.range || finding.cve.versionRange);
    if (range) versions.add(range);
  }
  return versions.size ? [...versions].join('; ') : undefined;
}

function findingProductLabel(finding?: Finding): string {
  if (!finding) return 'Unavailable';
  const parsed = parseCPE23(finding.matchedCpe || '');
  const cpeVendor = parsed.isValid && !['*', '-'].includes(parsed.vendor) ? parsed.vendor : '';
  const cpeProduct = parsed.isValid && !['*', '-'].includes(parsed.product) ? parsed.product : '';
  const vendor = finding.matchedAssetVendor || cpeVendor;
  const product = finding.matchedAssetProduct || cpeProduct;
  if (vendor && product) return `${vendor} - ${product}`;
  return product || finding.matchedAssetName || 'Unavailable';
}

function formattedDate(value?: string | null): string {
  const date = formatDate(value);
  return date === '—' ? 'Unavailable' : date;
}

/**
 * True when the finding's measured match confidence is below certainty.
 *
 * Findings are never withheld for confidence: every correlation is dispatched.
 * The flag drives the in-finding notice that names the limitation and its
 * reason, so reduced confidence is communicated instead of being dropped.
 */
export function confidenceIsLimited(finding: Finding): boolean {
  const confidence = finding.confidence;
  return typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 100;
}

function confidencePercent(finding: Finding): string {
  const confidence = finding.confidence;
  return typeof confidence === 'number' && Number.isFinite(confidence)
    ? `${Math.round(confidence)}% match confidence`
    : '';
}

/**
 * Removes the machine-readable confidence suffix the pipeline appends to every
 * evidence string ("... (70% confidence)") so the notice does not repeat the
 * figure twice. Matching evidence is plain feed-derived text, never markup.
 */
function stripConfidenceEvidence(evidence?: string): string {
  return (evidence || '')
    .replace(/\s*\(\s*\d{1,3}% confidence\s*\)\s*$/i, '')
    .replace(/[\r\n\t]+/g, ' ')
    .trim();
}

export interface AdvisoryRenderOptions {
  /**
   * Pinned render instant.
   *
   * The template embeds a "Report Generated" timestamp. The same rendered HTML
   * drives both the email body and the PDF attachment, so the instant must be
   * supplied by the caller: rendering the body and the attachment separately
   * would stamp them a moment apart and make the attachment differ from the
   * email. Callers that render once may omit it.
   */
  generatedAt?: Date;
  /** Team name shown in the email footer. Operator-configurable. */
  contactTeam?: string;
  /** Address the recipient replies to, shown as the footer contact. */
  contactEmail?: string;
  /** Distribution marking shown in the footer (e.g. `TLP:AMBER // INTERNAL`). */
  tlpClassification?: string;
}

interface EnterpriseCve {
  id: string;
  source_url: string;
  severity: string;
  is_critical: boolean;
  is_high: boolean;
  is_medium: boolean;
  is_low: boolean;
  cvss_score: string;
  vendor: string;
  product: string;
  affected_versions: string;
  description: string;
  mitigations: string[];
}

/**
 * Placeholder values for the enterprise notification template.
 *
 * The shipped template addresses a flat top-level severity pair plus a nested
 * `cves` array whose items carry per-item boolean flags (`is_critical`,
 * `is_high`, ...) and a per-CVE `mitigations` list. None of that existed in the
 * engine's variable set, so rendering the template produced the static chrome
 * with every piece of content missing. Everything here is derived from the same
 * `findings` the rest of the view uses, so the two cannot disagree.
 *
 * Values are returned RAW, not pre-escaped. The renderer escapes `{{name}}`
 * itself; escaping here as well produced `&amp;amp;` in the output (a severity
 * label "CRITICAL & HIGH" reached recipients as "CRITICAL &amp;amp; HIGH").
 * Fields the template reads with `{{{triple}}}` (descriptions, mitigations) are
 * escaped in place at the point they are built, because those bypass the
 * renderer's escaping by design.
 */
function enterpriseTemplateValues(
  advisory: Advisory,
  findings: Finding[] | undefined,
  options: AdvisoryRenderOptions,
  vulnerabilityDetails: { cve_id: string; cvss_score: string; description: string; published_date: string; last_modified_date: string }[],
  escape: (value: string) => string,
): Record<string, unknown> {
  const rankOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const cveIds = [...advisory.cveIds].sort(
    (a, b) => severityRank(b, advisory, findings) - severityRank(a, advisory, findings) || a.localeCompare(b),
  );
  const severityOf = (cveId: string) => cveSeverity(cveId, advisory, findings).toUpperCase();

  // Top severity is the strongest severity present, so the strip and the hero
  // badge reflect the worst item rather than the advisory's stored label.
  const worst = cveIds.reduce<string>(
    (current, cveId) =>
      rankOrder.indexOf(severityOf(cveId)) !== -1 &&
      rankOrder.indexOf(severityOf(cveId)) < rankOrder.indexOf(current)
        ? severityOf(cveId)
        : current,
    advisory.severity.toUpperCase(),
  );
  const distinctSeverities = [...new Set(cveIds.map(severityOf))].filter((s) => s !== 'UNKNOWN');
  // "CRITICAL & HIGH" when several share top billing; a single word otherwise.
  const topSeverityLabel = distinctSeverities.length > 1
    ? distinctSeverities.sort((a, b) => rankOrder.indexOf(a) - rankOrder.indexOf(b)).join(' & ')
    : (distinctSeverities[0] ?? worst);

  const cves: EnterpriseCve[] = cveIds.map((cveId) => {
    const cveFindings = findings?.filter((finding) => finding.cveId === cveId) ?? [];
    const severity = severityOf(cveId);
    // Report the most severe finding first: it is the one an operator must act on.
    const primary =
      cveFindings.find((finding) => finding.cve.cvss.severity.toUpperCase() === severity) ?? cveFindings[0];
    const detail = vulnerabilityDetails.find((entry) => entry.cve_id === escape(cveId));
    const versionLines = [...new Set(cveFindings.map((finding) => affectedVersionLabel(finding)).filter(Boolean))];
    const mitigations = [...
      new Set(
        cveFindings.flatMap((finding) => [
          ...(finding.cve.remediation?.immediateActions ?? []),
          ...(finding.cve.remediation?.stepByStep ?? []),
        ]),
      ),
    ].filter((action) => action.trim());
    const sourceUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
    return {
      id: cveId,
      // The canonical enterprise template addresses `url` and `nvd_url`; keep
      // `source_url` for templates that use the older name. These objects are
      // the last `cves` assignment, so omitting the aliases made every CVE and
      // NVD link in the default advisory render with an empty href.
      source_url: sourceUrl,
      url: sourceUrl,
      nvd_url: sourceUrl,
      severity,
      is_critical: severity === 'CRITICAL',
      is_high: severity === 'HIGH',
      is_medium: severity === 'MEDIUM',
      is_low: severity === 'LOW' || severity === 'UNKNOWN',
      cvss_score: typeof primary?.cve.cvss.score === 'number' ? primary.cve.cvss.score.toFixed(1) : 'N/A',
      vendor: primary?.matchedAssetVendor || 'Unknown',
      product: primary?.matchedAssetProduct || findingProductLabel(primary),
      affected_versions: versionLines.length ? versionLines.join(', ') : 'All unpatched releases',
      // `{{{description}}}` in the template, so escape here: the value is CVE
      // prose from an external source, never markup we intend to honour.
      description: `${escape(detail?.description || primary?.cve.description || 'No vendor description published.')}${
        primary && confidenceIsLimited(primary)
          ? `<br><strong>Low confidence${confidencePercent(primary) ? ` (${escape(confidencePercent(primary))})` : ''}:</strong> ${escape(stripConfidenceEvidence(primary.matchingEvidence) || 'Applicability could not be fully verified; confirm the affected version with the vendor before remediation.')}`
          : ''
      }`,
      mitigations: mitigations.length
        ? mitigations.map((action) => escape(action))
        : ['Apply the vendor security update once tested in your environment.',
             'Restrict network access to affected systems until remediation is validated.'],
    };
  });

  const generatedAt = options.generatedAt ?? new Date();
  const commissioned = new Date(advisory.createdDate);
  return {
    top_severity_label: topSeverityLabel,
    is_top_critical: worst === 'CRITICAL',
    is_top_high: worst === 'HIGH',
    is_top_medium: worst === 'MEDIUM',
    is_top_low: worst === 'LOW' || worst === 'UNKNOWN',
    published_date: formattedDate(advisory.createdDate),
    updated_date:
      Number.isNaN(commissioned.getTime()) ? formattedDate(advisory.createdDate) : formattedDate(generatedAt.toISOString()),
    inventory_status: `${cves.length} Asset${cves.length === 1 ? '' : 's'} Flagged`,
    cve_count: cves.length,
    cves,
    honeywell_actions: [
      { title: 'Inventory & Scope:', detail: ' Identify all instances of the listed vendor products in your environment.' },
      { title: 'Validate Exposure:', detail: ' Confirm the deployed versions fall within the affected ranges before remediation.' },
      { title: 'Apply Remediation:', detail: ' Deploy vendor-supplied updates through your change control process.' },
    ],
    contact_team: options.contactTeam || 'Security Operations',
    contact_email: options.contactEmail || '',
    tlp_classification: options.tlpClassification || 'TLP:AMBER // INTERNAL',
  };
}

export function renderAdvisory(
  template: string,
  advisory: Advisory,
  findings?: Finding[],
  options: AdvisoryRenderOptions = {},
): string {
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
  // ML-guided summary uses the actual finding mix. Remediation stays tied to
  // supplied vendor guidance and playbooks rather than model-selected claims.
  let composedSummary = advisory.executiveSummary;
  const composedRemediation =
    'Confirm affected-system and version applicability against current vendor guidance. Follow only documented remediation or playbook steps; patch availability is not assumed.';
  const operatorRemediationNote = advisory.remediationInstructions.trim()
    ? `<div style="margin:10px 0 0;padding:9px 11px;border:1px solid #e2e8f0;background:#f8fafc;font-size:12px;line-height:19px;color:#334155;"><strong>Operator-provided note (unverified):</strong> ${escape(advisory.remediationInstructions)}<br/>This note is not evidence that a patch or fix is available. Confirm its instructions against current vendor guidance before acting.</div>`
    : '';
  if (findings?.length) {
    try {
      const composed = mlComposeAdvisoryEmail(findings, advisory);
      if (!edits.customBodyOverride && composed.executiveSummary)
        composedSummary = composed.executiveSummary;
    } catch {
      // Rendering must never fail because the ML layer is unavailable.
    }
  }
  const productEntries = findings
    ? [...new Map(findings.map((finding) => {
        const name = findingProductLabel(finding);
        const versions = affectedVersionLabel(finding);
        const line = `${name}${versions ? ` | Affected versions: ${versions}` : ' | Version applicability: confirm with vendor'}`;
        return [line, line];
      })).values()]
    : advisory.affectedSystems;
  const remediationBlocks = (advisory.cveIds.length ? advisory.cveIds : ['Advisory']).map((cveId) => {
    const cveFindings = findings?.filter((finding) => finding.cveId === cveId) || [];
    const heading = cveId === 'Advisory'
      ? 'General remediation guidance'
      : `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">${escape(cveId)}</a>`;
    const targets = cveFindings.length ? cveFindings : [undefined];
    const targetGuidance = targets.map((finding) => {
      const remediation = finding?.cve.remediation;
      const actions = [...new Set([
        ...(remediation?.immediateActions || []),
        ...(remediation?.stepByStep || []),
      ].filter((action) => action.trim()))];
      const patchHref = safeHttpHref(remediation?.patchUrl || '');
      const vendorHref = safeHttpHref(remediation?.vendorAdvisoryRef || '');
      const targetLabel = finding ? findingProductLabel(finding) : 'the affected products listed above';
      const actionList = actions.length
        ? actions
        : [
            `Confirm the affected versions of ${targetLabel} against current vendor guidance for ${cveId}. ${patchHref || vendorHref ? 'Follow only remediation steps documented by the vendor after confirming applicability.' : 'No vendor patch or fix guidance is supplied for this finding, so availability must not be assumed.'}`,
            'Use documented compensating controls only where appropriate, and monitor for further vendor guidance.',
          ];
      const actionHtml = actionList
        .map((action) => `<li style="margin:0 0 5px;padding:0;">${escape(action)}</li>`)
        .join('');
      const workarounds = [...new Set(remediation?.workarounds || [])];
      const workaroundHtml = workarounds.length
        ? `<div style="margin:10px 0 0;"><strong>Workarounds</strong><ul style="margin:5px 0 0;padding-left:20px;">${workarounds.map((item) => `<li style="margin:0 0 5px;">${escape(item)}</li>`).join('')}</ul></div>`
        : '';
      const rollbackHtml = remediation?.rollbackPlan?.trim()
        ? `<p style="margin:10px 0 0;"><strong>Rollback:</strong> ${escape(remediation.rollbackPlan)}</p>`
        : '';
      const guidanceLinks = [
        patchHref
          ? `<a href="${escape(patchHref)}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">Vendor patch</a>`
          : '',
        vendorHref
          ? `<a href="${escape(vendorHref)}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">Security advisory</a>`
          : '',
      ].filter(Boolean);
      const versionLabel = finding ? affectedVersionLabel(finding) : undefined;
      const targetHeading = finding
        ? `<div style="margin:8px 0 5px;font-size:12px;line-height:18px;font-weight:700;color:#334155;">${escape(targetLabel)}${versionLabel ? ` · ${escape(versionLabel)}` : ''}</div>`
        : '';
      return `${targetHeading}<ul style="margin:0;padding-left:20px;font-size:12px;line-height:19px;color:#334155;">${actionHtml}</ul>${workaroundHtml}${rollbackHtml}${guidanceLinks.length ? `<div style="margin:9px 0 0;font-size:12px;line-height:19px;">${guidanceLinks.join(' <span style="color:#94a3b8;padding:0 5px;">|</span> ')}</div>` : ''}`;
    }).join('');
    return `<div style="margin:0 0 12px;padding:12px 14px;border:1px solid #e2e8f0;border-radius:4px;background:#ffffff;">
  <div style="margin:0 0 7px;font-size:13px;line-height:19px;font-weight:700;color:#0f172a;">${heading}</div>
  ${targetGuidance}
</div>`;
  }).join('');
  const severity_color = SEVERITY_COLORS[advisory.severity] || SEVERITY_COLORS.UNKNOWN;
  const severity_text = advisory.severity || 'UNKNOWN';

  // Build per-CVE vulnerability detail objects for the {{#each vulnerabilities}} block.
  const vulnerabilityDetails = [...advisory.cveIds]
    .sort((a: string, b: string) => severityRank(b, advisory, findings) - severityRank(a, advisory, findings) || a.localeCompare(b))
    .map((cve: string) => {
      const cveFindings = findings?.filter((f) => f.cveId === cve) || [];
      const ranks: Advisory['severity'][] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const severity = cveFindings.reduce(
        (current, f) =>
          ranks.indexOf(f.cve.cvss.severity) > ranks.indexOf(current) ? f.cve.cvss.severity : current,
        (cveFindings.length ? 'UNKNOWN' : advisory.severity) as Advisory['severity'],
      );
      const primary = cveFindings.find((f) => f.cve.cvss.severity === severity) || cveFindings[0];
      const score = primary?.cve.cvss.score;
      const cveColour = SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN;
      const scoreLabel = typeof score === 'number' ? score.toFixed(1) : 'N/A';
      const rawDescription =
        cveFindings.find((f) => f.cve.description)?.cve.description || 'No vendor description published.';
      const description =
        rawDescription.length > 600 ? `${rawDescription.slice(0, 597).trimEnd()}…` : rawDescription;
      const published = primary?.cve.publishedDate
        ? formattedDate(primary.cve.publishedDate)
        : formattedDate(advisory.createdDate);
      const modified = primary?.cve.modifiedDate
        ? formattedDate(primary.cve.modifiedDate)
        : formattedDate(advisory.createdDate);
      const vendors = cveFindings
        .filter((f) => f.cve.remediation?.vendorAdvisoryRef)
        .map((f) => ({
          url: safeHttpHref(f.cve.remediation!.vendorAdvisoryRef!),
          name: escape(f.cve.cveId),
        }));
      const lowConfidenceNote = (finding?: Finding) => {
        if (!finding || !confidenceIsLimited(finding)) return '';
        const confidenceLabel = confidencePercent(finding);
        const evidence = stripConfidenceEvidence(finding.matchingEvidence);
        return `<div style="margin:5px 0 0;padding:7px 9px;border-left:3px solid #b7791f;background:#fffbeb;font-size:11px;line-height:17px;color:#7c2d12;"><strong>Low confidence${confidenceLabel ? ` (${escape(confidenceLabel)})` : ''}:</strong> ${escape(evidence || 'Applicability could not be fully verified; confirm the affected version with the vendor before remediation.')}</div>`;
      };
      const productMetadata = (cveFindings.length ? cveFindings : [undefined])
        .map((finding) => {
          const productName = findingProductLabel(finding);
          const version = finding ? affectedVersionLabel(finding) || 'Unavailable; confirm with vendor' : 'Unavailable';
          return `<div style="margin:5px 0 0;font-size:11px;line-height:17px;color:#475569;"><strong>Product:</strong> ${escape(productName)} &nbsp; <strong>Affected version(s):</strong> ${escape(version)}<br/><strong>Published:</strong> ${escape(formattedDate(finding?.cve.publishedDate))} &nbsp; <strong>Last modified:</strong> ${escape(formattedDate(finding?.cve.modifiedDate))}</div>${lowConfidenceNote(finding)}`;
        })
        .join('');
      return {
        cve_id: escape(cve),
        cve_url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`,
        severity: escape(severity),
        severity_color: cveColour,
        cvss_score: scoreLabel,
        published_date: escape(published),
        last_modified_date: escape(modified),
        description: escape(description),
        vendors,
        product_metadata: productMetadata,
      };
    });

  // Build reference objects for the {{#each references}} block.
  const referenceDetails = findings
    ?.filter((f) => f.cve.remediation?.vendorAdvisoryRef)
    .map((f) => ({
      url: safeHttpHref(f.cve.remediation!.vendorAdvisoryRef!),
      title: escape(`Vendor advisory for ${f.cve.cveId}`),
    })) || [];

  const cves = [...advisory.cveIds]
    .sort((a, b) => severityRank(b, advisory, findings) - severityRank(a, advisory, findings) || a.localeCompare(b))
    .flatMap((id) => {
      const cveFindings = findings?.filter((finding) => finding.cveId === id) || [];
      const severity = cveSeverity(id, advisory, findings);
      const records: Array<Finding | undefined> = cveFindings.length ? cveFindings : [undefined];
      return records.map((primary) => {
        const parsedCpe = parseCPE23(primary?.matchedCpe || '');
        const vendor = primary?.matchedAssetVendor || (parsedCpe.isValid ? parsedCpe.vendor : '') || 'Unavailable';
        const product = primary?.matchedAssetProduct || (parsedCpe.isValid ? parsedCpe.product : '') ||
          primary?.matchedAssetName || 'Unavailable';
        const version = primary ? affectedVersionLabel(primary) : undefined;
        const remediation = primary?.cve.remediation;
        const mitigations = [
          ...(remediation?.immediateActions || []),
          ...(remediation?.stepByStep || []),
          ...(remediation?.workarounds || []),
        ].filter((action) => action.trim()).map((action) => escape(action));
        const score = typeof primary?.cve.cvss.score === 'number' ? primary.cve.cvss.score.toFixed(1) : 'N/A';
        const descriptionText = primary?.cve.description || cveFindings.find((finding) => finding.cve.description)?.cve.description ||
          'No vendor description published.';
        return {
          id: escape(id),
          url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`,
          nvd_url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`,
          severity,
          is_critical: severity === 'CRITICAL',
          is_high: severity === 'HIGH',
          is_medium: severity === 'MEDIUM',
          cvss_score: score,
          vendor: escape(vendor),
          product: escape(product),
          description: escape(descriptionText),
          affected_versions: escape(version || 'Confirm with vendor'),
          mitigations: mitigations.length ? mitigations : [escape('Confirm affected versions and follow current vendor guidance before remediation.')],
        };
      });
    });
  const correlationCount = findings?.length ?? advisory.affectedSystems.length;
  const topSeverity = advisory.severity || 'UNKNOWN';
  const latestModified = findings
    ?.map((finding) => finding.cve.modifiedDate)
    .filter((value): value is string => Boolean(value))
    .sort()
    .slice(-1)[0];

  const values: Record<string, string | unknown> = {
    severity: advisory.severity,
    severity_text,
    severity_color,
    top_severity_label: topSeverity,
    is_top_critical: topSeverity === 'CRITICAL',
    is_top_high: topSeverity === 'HIGH',
    is_top_medium: topSeverity === 'MEDIUM',
    cve_count: advisory.cveIds.length,
    correlation_count: correlationCount,
    is_single_correlation: correlationCount === 1,
    subject: advisory.title,
    published_date: formattedDate(advisory.createdDate),
    updated_date: formattedDate(latestModified || advisory.createdDate),
    inventory_status: correlationCount ? `${correlationCount} current inventory correlation${correlationCount === 1 ? '' : 's'}` : 'No current inventory correlations',
    contact_team: 'BA Security Operations',
    contact_email: 'DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com',
    tlp_classification: 'TLP:AMBER // INTERNAL',
    honeywell_actions: [
      { title: 'Confirm scope', detail: escape('Validate affected assets and versions against current vendor guidance.') },
      { title: 'Plan remediation', detail: escape('Apply documented remediation through the established change management process.') },
      { title: 'Verify recovery', detail: escape('Rescan affected systems and confirm service health after remediation.') },
    ],
    cves,
    advisory_id: advisory.id,
    advisory_title: advisory.title,
    dispatch_date: (options.generatedAt ?? new Date()).toLocaleString('en-GB', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }),
    advisory_published_date: formattedDate(advisory.createdDate),
    executive_summary: escape(stripGeneratedExecutiveSummaryMarkup(composedSummary)),
    // Raw variant for templates that emit the summary with `{{{triple}}}` and
    // expect the emphasis the generator produces to survive. The escaped value
    // above remains the default so a `{{double}}` template can never inject
    // markup; the generator's own `<strong>` wrapper is the only markup this
    // carries, and it is re-escaped here so a hostile finding title inside the
    // sentence cannot break out of it.
    executive_summary_html: escape(composedSummary).replace(/&lt;strong&gt;/g, '<strong>').replace(/&lt;\/strong&gt;/g, '</strong>'),
    cve_ids: advisory.cveIds.join(', '),
    affected_systems: advisory.affectedSystems.join('\n'),
    affected_systems_html: advisory.affectedSystems
      .map((sys: string) => `<div style="margin:0 0 4px;padding-left:0;font-size:12px;line-height:18px;color:#334155;">${escape(sys)}</div>`)
      .join('\n'),
    vendor_products: productEntries.join('\n'),
    vendor_products_html: productEntries
      .map((entry) => `<div style="margin:0 0 8px;padding:0;font-size:12px;line-height:19px;color:#334155;">${escape(entry)}</div>`)
      .join('\n'),
    remediation_steps: `<p style="margin:0 0 10px;font-size:12px;line-height:19px;color:#334155;">${escape(composedRemediation)}</p>${remediationBlocks}${operatorRemediationNote}`,
    vendor_link: safeHttpHref(advisory.vendorLink || ''),
    remediation_link:
      safeHttpHref(
        findings?.find((f) => f.cve?.remediation?.patchUrl)?.cve?.remediation?.patchUrl || '',
      ),
    references_link:
      safeHttpHref(
        findings?.find((f) => f.cve?.remediation?.vendorAdvisoryRef)?.cve?.remediation?.vendorAdvisoryRef || '',
      ),
    references_html: referenceDetails.length
      ? referenceDetails
          .map(
            (ref) =>
              `<div><a href="${ref.url}" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">${ref.title}</a></div>`,
          )
          .join('\n')
      : '',
    cve_id_links: [...advisory.cveIds]
      .sort((a: string, b: string) => severityRank(b, advisory, findings) - severityRank(a, advisory, findings) || a.localeCompare(b))
      .map(
        (cve: string) =>
          `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}" target="_blank" rel="noopener noreferrer" style="display:inline-block;margin:0 8px 4px 0;color:#1d4ed8;text-decoration:underline;text-underline-offset:2px;">${escape(cve)}</a>`,
      )
      .join(', '),
    cve_details: vulnerabilityDetails.map((v) => `
      <table data-pdf-cve="${v.cve_id}" data-pdf-severity="${v.severity}" role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f8fafc;border:1px solid #e2e8f0;border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;margin-bottom:12px;">
      <tr><td style="padding:12px;">
        <div style="font-size:14px;font-weight:700;color:#0f172a;">
          <a href="${v.cve_url}" target="_blank" style="color:#0f172a;text-decoration:none;">${v.cve_id}</a>
        </div>
        <div style="padding-top:2px;"><span style="font-size:12px;font-weight:700;color:${v.severity_color};">${v.severity} \u00b7 CVSS ${v.cvss_score}</span></div>
        <div style="font-size:11px;color:#64748b;padding-top:2px;">Published: ${v.published_date} | Last Modified: ${v.last_modified_date}</div>
        <div style="font-size:13px;line-height:20px;color:#334155;padding-top:6px;">${v.description}</div>
        ${v.product_metadata}
      </td></tr></table>
    `).join('\n'),
    mitigation_steps: `<div style="font-size:12px;line-height:20px;color:#334155;">
  <div style="margin:0 0 6px;"><strong>1.</strong>&nbsp; Confirm affected products and versions with current vendor guidance.</div>
  <div style="margin:0 0 6px;"><strong>2.</strong>&nbsp; Use vendor-documented workarounds or compensating controls only when appropriate.</div>
  <div style="margin:0;"><strong>3.</strong>&nbsp; Monitor affected services for relevant vendor updates and validate any remediation through change management.</div>
</div>`,
    recommended_actions: `<div style="font-size:12px;line-height:20px;color:#334155;">
  <div style="margin:0 0 6px;"><strong>1.</strong>&nbsp; Inventory all affected systems identified in this advisory.</div>
  <div style="margin:0 0 6px;"><strong>2.</strong>&nbsp; Confirm applicability and available remediation with the current vendor guidance.</div>
  <div style="margin:0;"><strong>3.</strong>&nbsp; Validate backup, restore, and operational functionality after any documented remediation.</div>
</div>`,
    audience_notice: edits.audienceNotice
      ? escape(edits.audienceNotice).replace(/\n/g, '<br/>')
      : 'This advisory is being distributed to all recipients per the EVERYONE delivery policy.',
     reviewer_comment: edits.reviewerComment
       ? `<strong>Reviewer note${edits.reviewerName ? ` by ${escape(edits.reviewerName)}` : ''}</strong> ${escape(edits.reviewerComment).replace(/\n/g, '<br/>')}`
       : '',
    severity_badge: SEVERITY_BADGE(advisory.severity),
    severity_header_badge: SEVERITY_BADGE(advisory.severity, ' SEVERITY'),
    severity_summary: (() => {
      const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
      for (const cveId of advisory.cveIds) {
        const sev = cveSeverity(cveId, advisory, findings);
        counts[sev] = (counts[sev] || 0) + 1;
      }
      const order: string[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
      const labels: Record<string, string> = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', UNKNOWN: 'Unknown' };
      const parts: string[] = [];
      for (const sev of order) {
        const n = counts[sev];
        if (n > 0) {
          const color = SEVERITY_COLORS[sev] || SEVERITY_COLORS.UNKNOWN;
          parts.push(
            `<span style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:0.3px;background:${color};color:#ffffff;"><span style="display:inline-block;width:8px;height:8px;background:#ffffff;border-radius:50%;opacity:0.9;"></span>${n} ${escape(labels[sev])}</span>`
          );
        }
      }
      return parts.join(' <span style="color:#94a3b8;padding:0 5px;">·</span> ');
    })(),
    vulnerabilities: vulnerabilityDetails,
    references: referenceDetails,
    // ---- Schema required by the enterprise notification template ----------
    //
    // The attached template addresses a nested `cves` array with per-item
    // boolean severity flags, a top-level severity pair, and a fixed set of
    // operational fields. Without these, the template rendered as a shell: every
    // placeholder resolved to the empty string and only the static chrome
    // remained. These are derived from the same findings as the rest of the
    // view, so the two schemas can never disagree about the content.
    ...enterpriseTemplateValues(advisory, findings, options, vulnerabilityDetails, escape),
  };
  const rawHtmlTokens = new Set([
    'cve_id_links',
    'cve_details',
    'affected_systems_html',
    'vendor_products_html',
    'remediation_steps',
    'mitigation_steps',
    'recommended_actions',
    'severity_badge',
    'severity_header_badge',
    'severity_summary',
    // Carries the generator's own <strong> emphasis; see the note where it is
    // built. Registered as raw so `{{executive_summary_html}}` is not escaped a
    // second time.
    'executive_summary_html',
  ]);
  // The shared renderer handles nested conditions and loops identically in
  // the advisory email, PDF attachment source, and Template Studio preview.
  return renderEmailTemplate(template, values, { rawHtmlKeys: rawHtmlTokens });
}

interface TemplateRenderContext {
  escape: (value: string) => string;
  rawHtmlTokens: ReadonlySet<string>;
}

/** Thrown to abandon an unsafe template without emitting a partial document. */
class TemplateRenderError extends Error {}

/**
 * Resolves one placeholder against the scope stack (innermost scope first).
 *
 * Returns `undefined` when the name is not in scope, which is what lets a
 * template omit optional fields without leaking literal `{{name}}` text into a
 * recipient's inbox.
 */
function lookupTemplateValue(
  name: string,
  scopes: readonly Record<string, unknown>[],
): unknown {
  if (name === 'this' || name === '.') {
    const top = scopes[scopes.length - 1];
    // A primitive loop item is stored as `{ this: value }`, so `{{this}}` must
    // yield the value. Returning the wrapper object produced "[object Object]"
    // for every string item (e.g. each mitigation) and made the entry vanish.
    return Object.prototype.hasOwnProperty.call(top, 'this') ? top.this : top;
  }
  for (let i = scopes.length - 1; i >= 0; i--) {
    const scope = scopes[i];
    if (Object.prototype.hasOwnProperty.call(scope, name)) return scope[name];
  }
  return undefined;
}

/** Block truthiness: empty strings, empty arrays, false and undefined are false. */
function templateTruthy(value: unknown): boolean {
  if (value === undefined || value === null || value === false) return false;
  if (value === '') return false;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

function stringifyTemplateValue(value: unknown): string {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '';
}

/**
 * Renders `{{#if}}`, `{{#each}}` (including nested blocks and nested `{{#if}}`
 * inside them) and `{{{raw}}}` / `{{escaped}}` placeholders.
 *
 * Iterative with an explicit block stack rather than recursion per token, so a
 * deeply nested template cannot grow the JS stack. A template whose blocks are
 * unbalanced throws instead of emitting half a document, and the caller falls
 * back to the built-in template.
 */
function renderTemplateBlocks(
  template: string,
  scopes: Record<string, unknown>[],
  context: TemplateRenderContext,
): string {
  const token = /\{\{\{?\s*(#if\s+[^}\s]+|#each\s+[^}\s]+|\/[a-z]+|[^}]+?)\s*\}?\}\}/g;
  let out = '';
  let cursor = 0;

  for (let match = token.exec(template); match; match = token.exec(template)) {
    // Emit the literal text before this tag.
    out += template.slice(cursor, match.index);
    cursor = match.index + match[0].length;
    const inner = match[1].trim();
    const isTriple = match[0].startsWith('{{{');

    if (inner.startsWith('#if ')) {
      // Split the block on a TOP-LEVEL {{else}}: a nested if inside the true
      // branch owns its own else, so a plain indexOf would pick the wrong one.
      const end = findBlockEnd(template, cursor, 'if');
      if (!end) throw new TemplateRenderError('Unclosed {{#if}} block');
      const wholeBlock = template.slice(cursor, end.start);
      cursor = end.after;
      token.lastIndex = cursor;
      const split = splitOnElse(wholeBlock);
      const truthy = templateTruthy(lookupTemplateValue(inner.slice(4).trim(), scopes));
      if (truthy) out += renderTemplateBlocks(split.yes, scopes, context);
      else if (split.no) out += renderTemplateBlocks(split.no, scopes, context);
      continue;
    }

    if (inner.startsWith('#each ')) {
      const end = findBlockEnd(template, cursor, 'each');
      if (!end) throw new TemplateRenderError('Unclosed {{#each}} block');
      const body = template.slice(cursor, end.start);
      cursor = end.after;
      token.lastIndex = cursor;
      const value = lookupTemplateValue(inner.slice(6).trim(), scopes);
      if (Array.isArray(value))
        for (const item of value)
          out += renderTemplateBlocks(
            body,
            // A primitive item (e.g. a list of strings) is exposed as `this`;
            // an object item becomes its own scope so `{{title}}` resolves.
            item !== null && typeof item === 'object'
              ? [...scopes, item as Record<string, unknown>]
              : [...scopes, { this: item }],
            context,
          );
      continue;
    }

    if (inner.startsWith('/')) throw new TemplateRenderError(`Unexpected {{${inner}}}`);

    const text = stringifyTemplateValue(lookupTemplateValue(inner, scopes));
    out += isTriple || context.rawHtmlTokens.has(inner) ? text : context.escape(text);
  }

  return out + template.slice(cursor);
}

/**
 * Splits an `#if` body at its top-level `{{else}}`.
 *
 * A nested block may contain its own `{{else}}`, so the split walks the block
 * tags and only accepts an `{{else}}` seen at depth 0. Without this the template's
 * `{{#if}}...{{else}}{{#if}}...{{/if}}{{/if}}` chains paired the wrong tags and
 * the whole conditional collapsed to one branch.
 */
function splitOnElse(body: string): { yes: string; no: string | null } {
  const pattern = /\{\{\s*(#[a-z]+|\/[a-z]+|else)\s*\}\}/g;
  let depth = 0;
  for (let match = pattern.exec(body); match; match = pattern.exec(body)) {
    const tag = match[1];
    if (tag.startsWith('#')) depth++;
    else if (tag.startsWith('/')) depth--;
    else if (tag === 'else' && depth === 0)
      return { yes: body.slice(0, match.index), no: body.slice(match.index + match[0].length) };
  }
  return { yes: body, no: null };
}

/** Finds the matching close tag for a block starting at `from`, honouring nesting. */
function findBlockEnd(
  template: string,
  from: number,
  kind: 'each' | 'if',
): { start: number; after: number } | null {
  // Open tags carry an argument (`{{#if x}}`), close tags do not, so the
  // opener alternative must consume the rest of the tag. Matching only
  // `#[a-z]+` silently skipped every opener and left the scanner seeing nothing
  // but closes. `{{else}}` is a body separator, not a block, and must not change
  // the nesting depth.
  const pattern = /\{\{\s*(#[a-z]+(?:\s+[^}]*)?|\/[a-z]+)\s*\}\}/g;
  pattern.lastIndex = from;
  // Track a stack of open block kinds, not a single counter: `{{#if}}` and
  // `{{#each}}` nest inside each other, so a counter that increments on any
  // opener and decrements on any closer would let an inner close match an outer
  // open and report the wrong body.
  const open: string[] = [kind];
  for (let match = pattern.exec(template); match; match = pattern.exec(template)) {
    const tag = match[1];
    if (tag.startsWith('#')) {
      // Keep only the block kind, not its argument: `#if x` and `#if y` are the
      // same kind of block for matching purposes.
      open.push(tag.slice(1).split(/\s+/)[0]);
      continue;
    }
    const closing = tag.slice(1);
    if (open[open.length - 1] !== closing) continue;
    open.pop();
    if (!open.length) return { start: match.index, after: match.index + match[0].length };
  }
  return null;
}
