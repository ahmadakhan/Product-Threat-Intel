import type { Advisory, Finding, TemplateCustomization } from '../src/types/index.ts';
import {
  DEFAULT_TEMPLATE_CUSTOMIZATION,
  compileCustomizedTemplate,
} from '../src/utils/templateCompiler.ts';
import { confidenceIsLimited, renderAdvisory } from './advisoryRender.ts';
import { advisoryEmail } from './advisoryEmail.ts';
import { mlComposeAdvisoryEmail } from './ml/integration.ts';
import { PDF_MAX_HTML_BYTES } from './pdf.ts';

/**
 * Canonical delivery document builder.
 *
 * Every finding email is rendered by *this* function and by nothing else, and
 * the PDF attachment is generated from its `html` output. That single-build
 * contract is what makes "the attachment is the email" a structural guarantee
 * rather than a convention: header colours, severity badges, CVE cards,
 * remediation blocks and the operator-provided note are produced once and used
 * by both transports.
 *
 * Two invariants make the attachment byte-identical to the body:
 *  - `generatedAt` is supplied by the caller. The template embeds a
 *    "Report Generated" timestamp; rendering the body and the attachment at two
 *    different instants would make them differ by a second, so the timestamp is
 *    pinned once per delivery and reused for the attachment render.
 *  - `renderFindingsDocument` returns the exact `html` that was attached to the
 *    payload, so a caller can never attach a document rendered from different
 *    findings than the ones described in the body.
 */

/**
 * Max rendered HTML size accepted by the PDF renderer.
 *
 * Imported from the renderer rather than duplicated so the delivery gate and the
 * renderer can never disagree about what is attachable.
 */
export const DELIVERY_HTML_MAX_BYTES = PDF_MAX_HTML_BYTES;

export interface DeliveryDocument {
  subject: string;
  text: string;
  html: string;
  /** The instant embedded in the document, pinned for attachment rendering. */
  generatedAt: Date;
}

const uniqueSorted = (values: string[]) => [...new Set(values.filter(Boolean))].sort();

const SEVERITY_RANK: Record<string, number> = {
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const highestSeverity = (findings: Finding[]): Advisory['severity'] =>
  findings.reduce(
    (severity, finding) =>
      (SEVERITY_RANK[finding.cve?.cvss?.severity] ?? 0) > (SEVERITY_RANK[severity] ?? 0)
        ? finding.cve.cvss.severity
        : severity,
    'UNKNOWN' as Advisory['severity'],
  );

const isLowConfidence = (finding: Finding): boolean => confidenceIsLimited(finding);

/**
 * Single-finding detail line used by the plain-text body. Held findings carry
 * their reason so the text alternative also states why confidence is limited.
 */
export const deliveryFindingDetail = (finding: Finding) =>
  `${finding.cveId} | ${finding.cve?.cvss?.severity ?? 'UNKNOWN'}${finding.cve?.cisaKev?.isKev ? ' | CISA KEV' : ''} | ${finding.matchedAssetName}`;

/**
 * Builds the recipient-specific advisory view for one delivery.
 *
 * The view is derived from the findings the recipient is actually receiving and
 * never from the union advisory, so a digest can never disclose a finding the
 * recipient is not subscribed to.
 */
export function deliveryAdvisoryView(original: Advisory, findings: Finding[]): Advisory {
  const links = uniqueSorted(
    findings.flatMap((finding) => [
      finding.cve?.remediation?.vendorAdvisoryRef || '',
      finding.cve?.remediation?.patchUrl || '',
    ]),
  );
  let composed: {
    subject?: string;
    executiveSummary: string;
    remediationInstructions: string;
  } = {
    executiveSummary: original.executiveSummary,
    remediationInstructions: original.remediationInstructions,
  };
  try {
    composed = mlComposeAdvisoryEmail(findings, original);
  } catch {
    // Rendering must never fail because the composition layer is unavailable.
  }
  return {
    ...original,
    severity: highestSeverity(findings),
    title: composed.subject || original.title,
    cveIds: uniqueSorted(findings.map((finding) => finding.cveId)),
    findingIds: findings.map((finding) => finding.id),
    affectedSystems: uniqueSorted(findings.map((finding) => finding.matchedAssetName)),
    executiveSummary: composed.executiveSummary || original.executiveSummary,
    remediationInstructions: composed.remediationInstructions || original.remediationInstructions,
    vendorLink: links[0] || '',
    isDigestBatch: findings.length > 1 ? true : original.isDigestBatch,
  };
}

/** The operator's saved template record (`records` kind `template`, id `main`). */
export interface SavedTemplateRecord {
  templateCustomization?: TemplateCustomization;
  /** A hand-authored advisory template that replaces the generated layout. */
  customAdvisoryTemplate?: string | null;
}

/**
 * Resolves the compiled advisory template the operator designed.
 *
 * This is the same precedence the application state uses (`customAdvisoryTemplate`
 * first, otherwise the compiled customization, otherwise the product default),
 * so a delivered email is rendered from the template the editor previews. The
 * consolidated finding path previously rendered from the built-in default, which
 * made real emails differ from the preview in layout, colours and branding.
 */
export function resolveAdvisoryTemplate(record?: SavedTemplateRecord | null): string {
  const custom = record?.customAdvisoryTemplate;
  if (typeof custom === 'string' && custom.trim()) return custom;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<title>BA Security Advisory</title>

<!--[if mso]>
<xml>
<o:OfficeDocumentSettings>
<o:AllowPNG/>
<o:PixelsPerInch>96</o:PixelsPerInch>
</o:OfficeDocumentSettings>
</xml>
<![endif]-->

<!--[if mso]>
<style>
body,table,td,div,p,a{
font-family:Arial,sans-serif !important;
}
table{
border-collapse:collapse !important;
border-spacing:0 !important;
}
td{
mso-line-height-rule:exactly;
}
</style>
<![endif]-->

<style>
@media only screen and (max-width:600px){
.container{
width:100%!important;
}
}
</style>
</head>

<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Segoe UI',Arial,sans-serif;">

<!-- Preview Text -->
<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all;">

{{#if advisory_title}}
{{advisory_title}}
{{else}}
Security Advisory
{{/if}}

-

{{severity_text}}

</div>

<table role="presentation"
       width="100%"
       cellpadding="0"
       cellspacing="0"
       border="0"
       bgcolor="#f1f5f9"
       style="border-collapse:collapse;background:#f1f5f9;mso-table-lspace:0pt;mso-table-rspace:0pt;">

<tr>
<td align="center" style="padding:12px;">

<table role="presentation"
       width="700"
       cellpadding="0"
       cellspacing="0"
       border="0"
       class="container"
       style="width:700px;max-width:700px;background:#ffffff;border:1px solid #e2e8f0;border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;">

<!-- HEADER -->

<tr>
<td bgcolor="#054971" style="padding:12px 20px;">

{{#if severity_header_badge}}
{{{severity_header_badge}}}
{{else}}
<span style="font-size:12px;font-weight:700;color:#dbeafe;">
INFORMATIONAL
</span>
{{/if}}

<div style="padding-top:6px;font-size:18px;line-height:22px;font-weight:700;color:#ffffff;">
BA Security Advisory
</div>

<div style="padding-top:3px;font-size:13px;line-height:18px;font-weight:600;color:#ffffff;">

{{#if advisory_title}}
{{advisory_title}}
{{else}}
Security Advisory
{{/if}}

</div>

<div style="padding-top:4px;font-size:11px;line-height:15px;color:#dbeafe;">

Advisory ID:

{{#if advisory_id}}
{{advisory_id}}
{{else}}
N/A
{{/if}}

|

Generated:

{{#if dispatch_date}}
{{dispatch_date}}
{{else}}
N/A
{{/if}}

</div>

</td>
</tr>

<!-- SUMMARY -->

<tr>
<td style="padding:16px 20px;border-bottom:1px solid #e2e8f0;">

<div style="font-size:11px;font-weight:700;letter-spacing:1px;color:#2563eb;padding-bottom:4px;">
SUMMARY
</div>

<div style="font-size:13px;line-height:20px;color:#334155;">
{{executive_summary}}
</div>

</td>
</tr>

<!-- DETAILS -->

<tr>
<td style="padding:20px;">

<div style="font-size:11px;font-weight:700;letter-spacing:1px;color:#2563eb;padding-bottom:8px;">
DETAILS
</div>

<table role="presentation"
       width="100%"
       cellpadding="0"
       cellspacing="0"
       border="0"
       style="border-collapse:collapse;border:1px solid #e2e8f0;mso-table-lspace:0pt;mso-table-rspace:0pt;">

<!-- CVES -->

<tr>
<td width="180"
    bgcolor="#f8fafc"
    style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
CVE(s)
</td>

<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;line-height:18px;">

{{#if vulnerabilities.length}}

{{#each vulnerabilities}}
<div>
<a href="{{cve_url}}"
   target="_blank"
   style="color:#2563eb;text-decoration:underline;word-break:break-word;">
{{cve_id}}
</a>
</div>
{{/each}}

{{else}}

<span style="color:#64748b;">
No CVEs were identified for this advisory.
</span>

{{/if}}

</td>
</tr>

<!-- SEVERITY -->

<tr>
<td bgcolor="#f8fafc"
    style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
Severity
</td>

<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;">

{{#if severity_badge}}
{{{severity_badge}}}
{{else}}
<span style="font-size:12px;font-weight:700;color:#64748b;">
INFORMATIONAL
</span>
{{/if}}

</td>
</tr>

<!-- DATES -->

<tr>
<td bgcolor="#f8fafc"
    style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
Advisory Dates
</td>

<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;">

<strong>Published:</strong>

{{#if advisory_published_date}}
{{advisory_published_date}}
{{else}}
N/A
{{/if}}

&nbsp;&nbsp;|&nbsp;&nbsp;

<strong>Updated:</strong>

{{#if dispatch_date}}
{{dispatch_date}}
{{else}}
N/A
{{/if}}

</td>
</tr>

<!-- AFFECTED PRODUCTS -->

<tr>
<td bgcolor="#f8fafc"
    style="padding:8px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
Affected Products
</td>

<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;line-height:18px;">

{{#if vendor_products_html}}
{{{vendor_products_html}}}
{{else}}
<span style="color:#64748b;">
No affected products have been identified.
</span>
{{/if}}

</td>
</tr>

<!-- VULNERABILITY DETAILS -->

<tr>
<td bgcolor="#f8fafc"
    style="padding:8px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
Vulnerability Details
</td>

<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;">

{{#if vulnerabilities.length}}

{{#each vulnerabilities}}

<table role="presentation"
       width="100%"
       cellpadding="0"
       cellspacing="0"
       border="0"
       style="background:#f8fafc;border:1px solid #e2e8f0;border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;margin-bottom:8px;">

<tr>
<td style="padding:10px;">

<div style="font-size:13px;font-weight:700;color:#0f172a;">
<a href="{{cve_url}}"
   target="_blank"
   style="color:#0f172a;text-decoration:none;">
{{cve_id}}
</a>
</div>

<div style="padding-top:2px;">
<span style="font-size:12px;font-weight:700;color:{{severity_color}};">
{{severity}} • CVSS {{cvss_score}}
</span>
</div>

<div style="font-size:11px;color:#64748b;padding-top:2px;">
Published: {{published_date}} |
Last Modified: {{last_modified_date}}
</div>

<div style="font-size:13px;line-height:18px;color:#334155;padding-top:6px;">
{{description}}
</div>

{{#if vendors}}
<div style="font-size:12px;color:#64748b;padding-top:6px;">
<strong>Vendor References:</strong>
{{#each vendors}}
<a href="{{url}}"
   target="_blank"
   style="color:#2563eb;text-decoration:underline;">
{{name}}
</a>{{#unless @last}} | {{/unless}}
{{/each}}
</div>
{{/if}}

</td>
</tr>

</table>

{{/each}}

{{else}}

<span style="color:#64748b;">
No detailed vulnerability information available.
</span>

{{/if}}

</td>
</tr>

<!-- REMEDIATION -->

<tr>
<td bgcolor="#f8fafc"
    style="padding:8px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
Remediation
</td>

<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;">

{{#if remediation_steps}}
{{{remediation_steps}}}
{{else}}
<span style="color:#64748b;">
No remediation guidance is currently available.
</span>
{{/if}}

{{#if remediation_link}}
<div style="padding-top:6px;">
<a href="{{remediation_link}}"
   target="_blank"
   style="color:#2563eb;text-decoration:underline;">
View Vendor Remediation Guidance
</a>
</div>
{{/if}}

</td>
</tr>

<!-- MITIGATION -->

<tr>
<td bgcolor="#f8fafc"
    style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
Mitigation
</td>

<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;">

{{#if mitigation_steps}}
{{{mitigation_steps}}}
{{else}}
<span style="color:#64748b;">
No mitigation guidance is currently available.
</span>
{{/if}}

</td>
</tr>

<!-- REFERENCES -->

<tr>
<td bgcolor="#f8fafc"
    style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
References
</td>

<td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;">

{{#if references}}

{{#each references}}
<div>
<a href="{{url}}"
   target="_blank"
   style="color:#2563eb;text-decoration:underline;">
{{title}}
</a>
</div>
{{/each}}

{{else}}

<span style="color:#64748b;">
No references available.
</span>

{{/if}}

</td>
</tr>

<!-- HONEYWELL ACTIONS -->

<tr>
<td bgcolor="#f8fafc"
    style="padding:8px 10px;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;vertical-align:top;">
Honeywell Recommended Actions
</td>

<td style="padding:8px 10px;font-size:13px;line-height:18px;">

{{#if recommended_actions}}
{{{recommended_actions}}}
{{else}}
<span style="color:#64748b;">
No additional Honeywell recommended actions at this time.
</span>
{{/if}}

</td>
</tr>

</table>

</td>
</tr>

<!-- FOOTER -->

<tr>
<td style="padding:14px 20px;border-top:1px solid #d1d5db;background:#fafafa;">

<div style="font-size:12px;font-weight:700;color:#0f172a;">
BA Security Operations
</div>

<div style="font-size:12px;line-height:18px;color:#64748b;padding-top:4px;">
This advisory is based on vendor disclosures, vulnerability intelligence, and threat intelligence sources. Assess applicability before implementing remediation or mitigation actions.
</div>

<div style="padding-top:8px;font-size:12px;color:#64748b;">
Questions or assistance:
<a href="mailto:DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com"
   style="color:#2563eb;text-decoration:underline;">
DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com
</a>
</div>

</td>
</tr>

</table>

</td>
</tr>
</table>

</body>
</html>`
}

export interface DeliveryDocumentInput {
  /** Advisory metadata for this recipient's view. */
  advisory: Advisory;
  /** Findings carried by this delivery, in the order they should render. */
  findings: Finding[];
  /**
   * Already-compiled advisory template (see `resolveAdvisoryTemplate`). Takes
   * precedence over `templateCustomization` so callers that have the operator's
   * saved template render from it.
   */
  template?: string;
  /** Operator-managed template customization used for the HTML body. */
  templateCustomization?: TemplateCustomization;
  /** Pinned render instant; one value per delivery. */
  generatedAt?: Date;
}

/**
 * Builds the one document used for an email body and its attachments.
 *
 * The text alternative carries the same limited-confidence notices as the HTML,
 * each with its reason, so a plain-text client is told exactly what the HTML
 * reader is told.
 */
export function renderFindingsDocument(input: DeliveryDocumentInput): DeliveryDocument {
  const { advisory, findings } = input;
  const generatedAt = input.generatedAt ?? new Date();
  const template =
    input.template ?? compileCustomizedTemplate(input.templateCustomization ?? DEFAULT_TEMPLATE_CUSTOMIZATION);
  const html = renderAdvisory(template, advisory, findings, { generatedAt });
  const email = advisoryEmail(advisory, html, findings.map(deliveryFindingDetail), { findings });
  const limited = limitedConfidenceLines(findings);
  const text = limited.length ? `${email.text}\n\n${limited.join('\n')}` : email.text;
  return { ...email, text, html: email.html ?? html, generatedAt };
}

export interface PlainTextSection {
  heading: string;
  lines: string[];
}

/**
 * Plain-text companion for the consolidated digest.
 *
 * The HTML body is the authoritative document; this is its text alternative for
 * clients that do not render HTML. It is generated from the same findings and the
 * same view so the two can never describe different sets.
 */
export function renderFindingsText(
  advisory: Advisory,
  findings: Finding[],
  sections: PlainTextSection[] = [],
): string {
  const lines: string[] = [
    `Advisory ID: ${advisory.id}`,
    `Advisory Title: ${advisory.title}`,
    `Severity: ${advisory.severity}`,
    `Created: ${advisory.createdDate}`,
  ];
  for (const section of sections) if (section.lines.length) lines.push('', `${section.heading}:`, ...section.lines);
  const limited = limitedConfidenceLines(findings);
  if (limited.length) lines.push('', ...limited);
  lines.push(
    '',
    'CVE IDs:',
    ...advisory.cveIds,
    '',
    'Executive Summary:',
    advisory.executiveSummary,
    '',
    'Affected Systems:',
    ...advisory.affectedSystems,
    '',
    'Remediation Instructions:',
    advisory.remediationInstructions,
  );
  if (advisory.vendorLink) lines.push('', `Vendor Advisory: ${advisory.vendorLink}`);
  return lines.join('\n');
}

const stripLine = (value: string | undefined) =>
  (value || '').replace(/[\r\n\t]+/g, ' ').replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '').trim();

/**
 * Plain-text notice for findings whose match confidence is limited: the heading
 * followed by one line per finding with its confidence and the reason. Empty when
 * every finding is fully confident. Shared by every text alternative so the
 * single-document and digest paths cannot word it differently.
 */
function limitedConfidenceLines(findings: readonly Finding[]): string[] {
  const limited = findings.filter(isLowConfidence);
  if (!limited.length) return [];
  return [
    'Limited confidence (confirm applicability before remediation):',
    ...limited.map(
      (finding) =>
        `- ${finding.cveId} | ${finding.matchedAssetName} | ${confidenceLabel(finding)} | ${
          stripLine(finding.matchingEvidence) || 'Applicability could not be fully verified'
        }`,
    ),
  ];
}

const confidenceLabel = (finding: Finding) =>
  typeof finding.confidence === 'number' && Number.isFinite(finding.confidence)
    ? `match confidence ${Math.round(finding.confidence)}%`
    : 'match confidence not available';

export { isLowConfidence as findingHasLimitedConfidence };

/**
 * True when a rendered document is small enough to attach.
 *
 * The PDF renderer rejects oversized HTML, and an oversized body would fail the
 * whole delivery. Callers use this to skip the attachment (degrading to
 * HTML-only) instead of failing the email.
 */
export const deliveryHtmlIsAttachable = (html: string | undefined): html is string =>
  typeof html === 'string' &&
  html.length > 0 &&
  Buffer.byteLength(html, 'utf8') <= DELIVERY_HTML_MAX_BYTES;

/**
 * Size ceiling for attaching the HTML document itself.
 *
 * The PDF renderer's 2 MB limit exists because Chromium has to lay the page out;
 * an HTML attachment is just the bytes of the body, so tying it to that limit
 * silently dropped the attachment for large digests (roughly 700+ findings). The
 * ceiling is still bounded because the message carries the body, the attachment
 * (base64, +33%) and optionally a PDF, and common providers reject a message
 * above about 15 MB in total.
 */
export const HTML_ATTACHMENT_MAX_BYTES = 4_000_000;

/** True when the exact email HTML can be attached as a file. */
export const htmlAttachmentIsAttachable = (html: string | undefined): html is string =>
  typeof html === 'string' &&
  html.length > 0 &&
  Buffer.byteLength(html, 'utf8') <= HTML_ATTACHMENT_MAX_BYTES;
