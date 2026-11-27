import type { Advisory, Finding, ReviewEdits } from '../src/types/index.ts';
import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
import { displayName } from '../src/utils/displayName.ts';
import { formatDate } from '../src/utils/dateTime.ts';
import { stripGeneratedExecutiveSummaryMarkup } from '../src/utils/templateCompiler.ts';
import { renderEmailTemplate } from '../src/utils/emailTemplate.ts';
import { mlComposeAdvisoryEmail, mlSummarizeAdvisoryEmail } from './ml/integration';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f59e0b',
  MEDIUM: '#eab308',
  LOW: '#10b981',
  UNKNOWN: '#6b7280',
};
/**
 * Per-severity colour sets the shipped template paints directly (no `{{#if}}`
 * inside table cells, per the Outlook Word-engine constraint):
 *  - `top`   the accent strip and the hero severity pill
 *  - `bg` / `border` / `text`  the summary-matrix pill
 *  - `badge` the CVE card header badge (white text on a solid colour)
 */
const SEVERITY_PILL: Record<string, { bg: string; border: string; text: string; badge: string; top: string }> = {
  CRITICAL: { bg: '#fef2f2', border: '#fecaca', text: '#991b1b', badge: '#991b1b', top: '#991b1b' },
  HIGH: { bg: '#fff7ed', border: '#fed7aa', text: '#c2410c', badge: '#dc2626', top: '#dc2626' },
  MEDIUM: { bg: '#fefce8', border: '#fde047', text: '#a16207', badge: '#d97706', top: '#d97706' },
  LOW: { bg: '#f0f9ff', border: '#bae6fd', text: '#0369a1', badge: '#0284c7', top: '#0284c7' },
  UNKNOWN: { bg: '#f0f9ff', border: '#bae6fd', text: '#0369a1', badge: '#0284c7', top: '#0284c7' },
};
const SEVERITY_BADGE = (severity: string, suffix = '') => {
  const label = severity || 'UNKNOWN';
  const color = SEVERITY_COLORS[label] || SEVERITY_COLORS.UNKNOWN;
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
  const { vendor, product } = findingDisplayNames(finding);
  if (vendor && product) return `${vendor} - ${product}`;
  return product || finding.matchedAssetName || 'Unavailable';
}

/**
 * Display vendor/product for a finding, preferring the matched asset data.
 *
 * `matchedAssetProduct` is the inventory *product* (e.g. "Widget"), which is the
 * same for every asset running it. When it is absent the CPE product is used, and
 * only then the asset name. A consolidated advisory lists affected systems as
 * vendor/product rows, so two assets matched against one CVE without a recorded
 * product must still be distinguishable: falling back to the asset name keeps
 * them separate, whereas an empty product made both rows read "Acme - " and the
 * second asset's row looked like a duplicate of the first.
 */
function findingDisplayNames(finding?: Finding): { vendor: string; product: string } {
  if (!finding) return { vendor: '', product: '' };
  const parsed = parseCPE23(finding.matchedCpe || '');
  const cpeVendor = parsed.isValid && !['*', '-'].includes(parsed.vendor) ? parsed.vendor : '';
  const cpeProduct = parsed.isValid && !['*', '-'].includes(parsed.product) ? parsed.product : '';
  return {
    vendor: displayName(finding.matchedAssetVendor || cpeVendor),
    product: displayName(finding.matchedAssetProduct || cpeProduct || finding.matchedAssetName || ''),
  };
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
 *
 * A wildcard vendor/product or all-versions registration is a declared
 * monitoring scope, not a limitation: the matcher scores it at 90% or above and
 * the email must present it as a normal finding. Lower scores (70% unverified
 * version, 85% alias) still carry their notice because those limitations are
 * independent of the wildcard.
 */
export function confidenceIsLimited(finding: Finding, threshold = 100): boolean {
  const confidence = finding.confidence;
  const measured = typeof confidence === 'number' && Number.isFinite(confidence);
  // A wildcard scope is a declared monitoring scope, not a limitation: the
  // matcher scores it at 90% or above and it must render as a normal finding.
  // This exemption is structural and independent of the operator threshold;
  // lowering the threshold must not start flagging wildcard findings.
  if (finding.wildcardScopeMatch && measured && confidence >= 90) return false;
  // An unmeasured confidence is always limited (nothing to compare); a measured
  // one is limited only when it falls below the configured threshold.
  return !measured || confidence < threshold;
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
  /**
   * When false, the HTML body omits every match-confidence notice. Operators
   * set this through Settings > match confidence; the default (undefined) keeps
   * the notice so any caller that does not opt in renders unchanged.
   */
  matchConfidenceEnabled?: boolean;
  /**
   * A finding whose match confidence is below this percentage is treated as
   * limited confidence. Undefined keeps the legacy 100% bar (any shortfall is
   * flagged). Only consulted when `matchConfidenceEnabled` is not false.
   */
  matchConfidenceThreshold?: number;
}

interface EnterpriseCve {
  id: string;
  /** Alias the shipped template addresses inside `cves`; `id` is the older name. */
  cve_id: string;
  source_url: string;
  /** Aliases of `source_url` kept for templates that use the older names. */
  url: string;
  nvd_url: string;
  /** Palette values the template writes straight into CSS/bgcolor attributes. */
  pill_bg: string;
  pill_border: string;
  pill_text: string;
  badge_bg: string;
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
  const showConfidence = options.matchConfidenceEnabled !== false;
  const confidenceThreshold = options.matchConfidenceThreshold ?? 100;
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

  /**
   * One entry per affected (CVE, asset) pair.
   *
   * This list feeds `{{#each cves}}` in the shipped template, which is how the
   * email lists affected systems. Keying it by CVE alone collapsed a CVE that \n   * matches several assets into a single row, so the delivered advisory silently
   * omitted every asset after the first while its own text body and the
   * advisory's `affectedSystems` listed them all. A CVE with no finding still
   * renders once (as a CVE-level row) so a pruned cache entry does not drop the
   * item entirely.
   */
  const cves: EnterpriseCve[] = cveIds.flatMap((cveId) => {
    const cveFindings = findings?.filter((finding) => finding.cveId === cveId) ?? [];
    const severity = severityOf(cveId);
    if (!cveFindings.length) return [cveEntry(cveId, severity, undefined)];
    // Report the most severe findings first: they are the ones an operator must act on.
    const ordered = [
      ...cveFindings.filter((finding) => finding.cve.cvss.severity.toUpperCase() === severity),
      ...cveFindings.filter((finding) => finding.cve.cvss.severity.toUpperCase() !== severity),
    ];
    return ordered.map((finding) => cveEntry(cveId, severity, finding));
  });

  function cveEntry(cveId: string, severity: string, primary: Finding | undefined): EnterpriseCve {
    const detail = vulnerabilityDetails.find((entry) => entry.cve_id === escape(cveId));
    // Version and mitigation columns describe THIS row's asset, not every asset
    // that shares the CVE. Aggregating across the CVE repeated the first asset's
    // versions on each row and attributed one asset's guidance to another.
    const versionLine = primary ? affectedVersionLabel(primary) : '';
    const versionLines = versionLine ? [versionLine] : [];
    const mitigations = [
      ...new Set(
        primary
          ? [
              ...(primary.cve.remediation?.immediateActions ?? []),
              ...(primary.cve.remediation?.stepByStep ?? []),
            ]
          : [],
      ),
    ].filter((action) => action.trim());
    const sourceUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
    // Pill and badge palettes are used directly as CSS/bgcolor values, so the
    // template needs plain strings rather than {{#if}} branches (an `if` inside
    // a table cell is exactly what the Outlook Word engine hoists). Colours
    // follow the same ladder as SEVERITY_COLORS but at the lighter badge tints
    // the matrix and card headers use.
    const pill = SEVERITY_PILL[severity] ?? SEVERITY_PILL.UNKNOWN;
    return {
      id: cveId,
      // `cve_id` is the name the shipped template addresses inside `cves`; `id`
      // is kept for templates written against the older key.
      cve_id: cveId,
      pill_bg: pill.bg,
      pill_border: pill.border,
      pill_text: pill.text,
      badge_bg: pill.badge,
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
      vendor: findingDisplayNames(primary).vendor || 'Unknown',
      // The template renders one row per entry as `vendor / product`, so the
      // asset must be distinguishable through these two fields. `matchedAssetProduct`
      // is the inventory product shared by every asset running it, which made two
      // assets render as identical rows; the asset name is appended when it differs
      // so each affected system stays identifiable.
      product: [findingDisplayNames(primary).product || findingProductLabel(primary), displayName(primary?.matchedAssetName || '')]
        .filter((part, index, all) => part && all.indexOf(part) === index)
        .join(' on '),
      affected_versions: versionLines.length ? versionLines.join(', ') : 'All unpatched releases',
      // `{{{description}}}` in the template, so escape here: the value is CVE
      // prose from an external source, never markup we intend to honour.
      description: `${escape(detail?.description || primary?.cve.description || 'No vendor description published.')}${
        showConfidence && primary && confidenceIsLimited(primary, confidenceThreshold)
          ? `<br><strong>Low confidence${confidencePercent(primary) ? ` (${escape(confidencePercent(primary))})` : ''}:</strong> ${escape(stripConfidenceEvidence(primary.matchingEvidence) || 'Applicability could not be fully verified; confirm the affected version with the vendor before remediation.')}`
          : ''
      }`,
      mitigations: mitigations.length
        ? mitigations.map((action) => escape(action))
        : ['Apply the vendor security update once tested in your environment.',
             'Restrict network access to affected systems until remediation is validated.'],
    };
  }

  const generatedAt = options.generatedAt ?? new Date();
  const commissioned = new Date(advisory.createdDate);
  return {
    top_severity_label: topSeverityLabel,
    // Solid accent colour for the top strip and hero pill; the template paints it
    // directly so no conditional sits inside a table cell.
    top_severity_color: (SEVERITY_PILL[worst] ?? SEVERITY_PILL.UNKNOWN).top,
    is_top_critical: worst === 'CRITICAL',
    is_top_high: worst === 'HIGH',
    is_top_medium: worst === 'MEDIUM',
    is_top_low: worst === 'LOW' || worst === 'UNKNOWN',
    published_date: formattedDate(advisory.createdDate),
    updated_date:
      Number.isNaN(commissioned.getTime()) ? formattedDate(advisory.createdDate) : formattedDate(generatedAt.toISOString()),
    // `cves` now has one entry per affected asset, so this count is the number of
    // flagged assets, which is what the label claims.
    inventory_status: `${cves.length} Asset${cves.length === 1 ? '' : 's'} Flagged`,
    // Distinct CVEs, not rows: one CVE on three assets is still one CVE.
    cve_count: new Set(cves.map((entry) => entry.id)).size,
    cves,
    honeywell_actions: [
      { title: 'Inventory & Scope', detail: ' Identify all instances of the listed vendor products in your environment.' },
      { title: 'Validate Exposure', detail: ' Confirm the deployed versions fall within the affected ranges before remediation.' },
      { title: 'Apply Remediation', detail: ' Deploy vendor-supplied updates through your change control process.' },
    ],
    contact_team: options.contactTeam || 'Security Operations',
    // Never the empty string: the shipped template writes this straight into
    // `<a href="mailto:{{contact_email}}">`, so a blank value produced an empty
    // `mailto:` link with no address. Fall back to the operations mailbox and
    // let the enterprise block below apply the deployment default first.
    contact_email: options.contactEmail || 'DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com',
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
  // `template` is untrusted operator source. Enforce the renderer's nesting cap
  // up front so a pathological template is rejected with a clear message before
  // any expensive value assembly runs (the renderer re-checks the same limit).
  assertTemplateBlockDepth(template);
  const escape = (v: string) =>
    v.replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
    );
  const edits: ReviewEdits = advisory.edits || {};
  // Match-confidence presentation is operator-controlled (Settings). When
  // disabled, no confidence notice is written anywhere in the body; when enabled
  // the configured threshold decides which findings are labelled limited.
  const showConfidence = options.matchConfidenceEnabled !== false;
  const confidenceThreshold = options.matchConfidenceThreshold ?? 100;
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
      if (!edits.customBodyOverride && composed.executiveSummary) {
        const summarized = mlSummarizeAdvisoryEmail(findings, composed.executiveSummary);
        composedSummary = summarized.summary || composed.executiveSummary;
      }
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
            // Compare with `Boolean(...)`: a precedence slip here would make the
            // sentence a ternary of its own or print an empty href reference.
            `Confirm the affected versions of ${targetLabel} against current vendor guidance for ${cveId}. ${Boolean(patchHref || vendorHref) ? 'Follow only remediation steps documented by the vendor after confirming applicability.' : 'No vendor patch or fix guidance is supplied for this finding, so availability must not be assumed.'}`,
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
        if (!showConfidence || !finding || !confidenceIsLimited(finding, confidenceThreshold)) return '';
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
    // Honour an explicit render option; otherwise the studio/deployment default.
    // These used to be hard-coded here, and because this object is spread last
    // in renderAdvisory it silently overrode the same keys set above, so a test
    // email or an override could never change the contact line.
    contact_team: options.contactTeam || 'BA Security Operations',
    contact_email: options.contactEmail || 'DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com',
    tlp_classification: options.tlpClassification || 'TLP:AMBER // INTERNAL',
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
  return renderAdvisoryTemplate(template, values, rawHtmlTokens);
}

/**
 * Upper bound on how deeply `{{#if}}` / `{{#each}}` blocks may nest.
 *
 * The shared renderer walks a parsed tree recursively, so nesting is JS stack
 * depth. A template is operator-supplied and up to 200,000 characters
 * (`/api/advisory-template-render`, the saved template record), so without a
 * cap a few thousand nested `{{#if}}` tags exhaust the stack mid-render. Render
 * happens on the dispatch path, so the failure would take down a delivery, not
 * just a preview.
 */
const MAX_TEMPLATE_BLOCK_DEPTH = 100;

/** Throws when block nesting exceeds the renderer's stack budget. */
function assertTemplateBlockDepth(template: string): void {
  // Count real block tags only. A stray `{{` (an operator mid-edit, or CVE
  // prose containing braces) is not a tag and must not consume the budget.
  const block = /\{\{\s*(#[a-z]+|\/[a-z]+|else)\b/g;
  let depth = 0;
  for (let match = block.exec(template); match; match = block.exec(template)) {
    const tag = match[1];
    if (tag.startsWith('/')) depth = Math.max(0, depth - 1);
    else if (tag.startsWith('#')) {
      depth += 1;
      if (depth > MAX_TEMPLATE_BLOCK_DEPTH)
        throw new Error(
          `Template blocks nest deeper than ${MAX_TEMPLATE_BLOCK_DEPTH} levels; flatten the template`,
        );
    }
  }
}

/**
 * Renders the advisory document with the shared Handlebars-subset engine.
 *
 * Every template construct the advisory/PDF/preview pipeline supports goes
 * through `renderEmailTemplate`; this function only supplies the values and the
 * set of keys whose content is already HTML. An earlier revision kept a second,
 * hand-rolled block engine here that matched blocks by regex, only accepted a
 * bare `{{else}}`, and treated close tags as extra array items. It drifted from
 * the shared engine (the same template previewed differently in Studio and
 * shipped differently to the recipient), so it is gone: a divergence here is a
 * delivery bug, not a preview bug.
 *
 * A template whose blocks are unbalanced, or nested deeper than
 * `MAX_TEMPLATE_BLOCK_DEPTH`, throws before any output is produced.
 */
function renderAdvisoryTemplate(
  template: string,
  values: Record<string, unknown>,
  rawHtmlKeys: ReadonlySet<string>,
): string {
  assertTemplateBlockDepth(template);
  return renderEmailTemplate(template, values, { rawHtmlKeys });
}
