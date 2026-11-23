import { TemplateCustomization } from '../types/index.ts';
import { resolveTimezone, utcOffsetLabel } from './dateTime.ts';
import { renderEmailTemplate } from './emailTemplate.ts';

export const DEFAULT_TEMPLATE_CUSTOMIZATION: TemplateCustomization = {
  fontFamily: 'sans',
  fontColor: '#334155',
  headingColor: '#0f172a',
  accentColor: '#dc2626',
  canvasBg: '#f1f5f9',
  cardBg: '#ffffff',
  headerBg: '#0f172a',
  badgeStampText: 'BA CYBER SECURITY OPERATIONS',
  badgeStampColor: '#2563eb',
  showStamp: true,
  showClassificationBanner: false,
  classificationText: '',
  borderStyle: 'solid',
  borderRadius: '12px',
};

export function getFontFamilyCss(family: TemplateCustomization['fontFamily']): string {
  switch (family) {
    case 'mono':
      return '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace';
    case 'serif':
      return 'Georgia, Cambria, "Times New Roman", Times, serif';
    case 'system':
      return '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
    case 'sans':
    default:
      return '"Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
  }
}

export function compileCustomizedTemplate(config: TemplateCustomization): string {
  // Customization fields are text/CSS values, never arbitrary HTML or CSS.
  config = { ...DEFAULT_TEMPLATE_CUSTOMIZATION, ...config };
  for (const key of [
    'fontColor',
    'headingColor',
    'accentColor',
    'canvasBg',
    'cardBg',
    'headerBg',
    'badgeStampColor',
  ] as const) {
    if (!/^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i.test(config[key]))
      config[key] = DEFAULT_TEMPLATE_CUSTOMIZATION[key];
  }
  if (!['solid', 'dashed', 'none'].includes(config.borderStyle)) config.borderStyle = 'solid';
  if (!/^\d{1,3}(?:px|rem|%)$/.test(config.borderRadius)) config.borderRadius = '12px';
  const escapeHtml = (value: string) =>
    String(value).replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
    );
  config.badgeStampText = escapeHtml(config.badgeStampText);
  config.classificationText = escapeHtml(config.classificationText);
  const fontCss = getFontFamilyCss(config.fontFamily);

  const headerHex = config.headerBg.slice(1);
  const expanded = headerHex.length === 3 ? [...headerHex].map((ch) => ch + ch).join('') : headerHex;
  const luminance = [0, 2, 4]
    .map((offset) => parseInt(expanded.slice(offset, offset + 2), 16) / 255)
    .map((channel) => (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4))
    .reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
  const headerText = luminance > 0.179 ? '#0f172a' : '#ffffff';
  const headerMuted = luminance > 0.179 ? '#334155' : '#cbd5e1';
  const stampHtml = config.showStamp
    ? `<p style="margin:0 0 12px;font-size:11px;line-height:18px;letter-spacing:1.5px;font-weight:700;color:${config.badgeStampColor};">${config.badgeStampText}</p>`
    : '';
  const classificationBanner = config.showClassificationBanner
    ? `<tr><td style="padding:12px 28px;background:${config.canvasBg};color:${config.fontColor};font-size:10px;line-height:16px;letter-spacing:1px;text-align:center;">${config.classificationText}</td></tr>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<title>BA Security Advisory</title>

<style>
  body,table,td,a { -webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; }
  table,td { mso-table-lspace:0pt; mso-table-rspace:0pt; }
  table { border-collapse:collapse; }
  a { overflow-wrap:anywhere; word-break:break-word; }
  ul { margin:0; padding-left:20px; }
  body{
    margin:0;
    padding:0;
    background:${config.canvasBg};
    font-family:${escapeHtml(fontCss)};
  }
  table{
    border-collapse:collapse;
  }
  a{
    color:${config.accentColor};
    text-decoration:underline;
    word-break:break-word;
  }
  @media only screen and (max-width:600px){
    .container{
      width:100% !important;
    }
    .mobile-padding{
      padding:20px !important;
    }
    .title{
      font-size:22px !important;
      line-height:28px !important;
    }
  }
</style>

<!--[if mso]>
<style>
body,table,td,div,p,a{font-family:Arial,sans-serif !important;}
table{border-collapse:collapse !important;border-spacing:0 !important;}
td{mso-line-height-rule:exactly;}
</style>
<![endif]-->
</head>

<body>

<!-- Preview Text -->
<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all;">
{{#if advisory_title}}{{advisory_title}}{{else}}Security Advisory{{/if}} - {{severity_text}}
</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${config.canvasBg}">
<tr>
<td align="center" style="padding:12px;">

<table role="presentation" width="700" cellpadding="0" cellspacing="0" border="0" class="container" style="width:700px;max-width:700px;background:${config.cardBg};border:1px ${config.borderStyle} #e2e8f0;">

    ${classificationBanner}

    <!-- HEADER -->
    <tr>
        <td bgcolor="${config.headerBg}" style="padding:12px 20px;">

            ${stampHtml}

            {{severity_header_badge}}

            <div class="title" style="padding-top:6px;font-size:18px;line-height:22px;font-weight:700;color:${headerText};">
                BA Security Advisory
            </div>

            <div style="padding-top:3px;font-size:13px;line-height:18px;font-weight:600;color:${headerText};">
                {{advisory_title}}
            </div>

            <div style="padding-top:4px;font-size:11px;line-height:15px;color:${headerMuted};">
                Advisory ID: {{advisory_id}} | Generated: {{dispatch_date}}
            </div>

        </td>
    </tr>

    <!-- SUMMARY -->
    <tr>
        <td style="padding:16px 20px;border-bottom:1px solid #e2e8f0;">

            <div style="font-size:11px;font-weight:bold;letter-spacing:1px;color:${config.accentColor};padding-bottom:4px;">
                SUMMARY
            </div>

            <div style="font-size:13px;line-height:20px;color:${config.fontColor};">
                {{executive_summary}}
            </div>

        </td>
    </tr>

    <!-- DETAILS -->
    <tr>
        <td class="mobile-padding" style="padding:20px;">

            <div style="font-size:11px;font-weight:bold;letter-spacing:1px;color:${config.accentColor};padding-bottom:8px;">
                DETAILS
            </div>

             <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;border:1px solid #e2e8f0;font-size:13px;line-height:18px;">

                 <tr>
                     <td width="180" bgcolor="#f8fafc" style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
                         CVE(s)
                     </td>
                    <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;">
                        {{cve_id_links}}
                    </td>
                </tr>

                <tr>
                    <td width="180" bgcolor="#f8fafc" style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
                        Severity
                    </td>
                    <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;">
                        {{severity_badge}}
                    </td>
                </tr>

                <tr>
                    <td width="180" bgcolor="#f8fafc" style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
                        Advisory Dates
                    </td>
                    <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;">
                        <strong>Published:</strong> {{advisory_published_date}}
                        &nbsp;&nbsp;|&nbsp;&nbsp;
                        <strong>Updated:</strong> {{dispatch_date}}
                    </td>
                </tr>

                <tr>
                    <td width="180" bgcolor="#f8fafc" style="padding:8px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
                        Affected Products
                    </td>
                    <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;">
                        {{vendor_products_html}}
                    </td>
                </tr>

                <tr>
                    <td width="180" bgcolor="#f8fafc" style="padding:8px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
                        Vulnerability Details
                    </td>
                    <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;">
                        {{cve_details}}
                    </td>
                </tr>

                <tr>
                    <td width="180" bgcolor="#f8fafc" style="padding:8px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
                        Remediation
                    </td>
                    <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;">
                        {{remediation_steps}}

                        {{#if remediation_link}}<div style="padding-top:6px;">
                            <a href="{{remediation_link}}" target="_blank">
                                View Vendor Remediation Guidance
                            </a>
                        </div>{{/if}}
                    </td>
                </tr>

                <tr>
                    <td width="180" bgcolor="#f8fafc" style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
                        Mitigation
                    </td>
                    <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;">
                        {{mitigation_steps}}
                    </td>
                </tr>

                <tr>
                    <td width="180" bgcolor="#f8fafc" style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;">
                        References
                    </td>
                    <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:13px;">
                        {{references_html}}
                    </td>
                </tr>

                <tr>
                    <td width="180" bgcolor="#f8fafc" style="padding:8px 10px;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;vertical-align:top;">
                        Honeywell Recommended Actions
                    </td>
                    <td style="padding:8px 10px;">
                        {{recommended_actions}}
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
                This advisory is based on vendor disclosures, vulnerability intelligence, and threat
                intelligence sources. Assess applicability before implementing remediation or
                mitigation actions.
            </div>

            <div style="padding-top:8px;font-size:12px;color:#64748b;">
                Questions or assistance:
                <a href="mailto:DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com" style="color:${config.accentColor};text-decoration:underline;">DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com</a>
            </div>

        </td>
    </tr>

</table>

</td>
</tr>
</table>

</body>
</html>`;
}

/**
 * Digest defaults.
 *
 * These deliberately mirror the stock `DEFAULT_DAILY_DIGEST_TEMPLATE` markup
 * (system font stack, slate body text, blue accent, square 1px card, no stamp),
 * so `compileDailyDigestTemplate(DEFAULT_DAILY_DIGEST_CUSTOMIZATION)` produces
 * that document byte for byte. An operator who never opened the typography or
 * colour tools keeps the exact layout they already ship.
 */
export const DEFAULT_DAILY_DIGEST_CUSTOMIZATION: TemplateCustomization = {
  ...DEFAULT_TEMPLATE_CUSTOMIZATION,
  badgeStampText: 'DAILY DIGEST',
  fontFamily: 'system',
  fontColor: '#1e293b',
  headingColor: '#0f172a',
  accentColor: '#1d4ed8',
  canvasBg: '#f1f5f9',
  cardBg: '#ffffff',
  headerBg: '#f8fafc',
  borderRadius: '1px',
  showStamp: false,
};

export interface DigestFinding {
  cveId: string;
  severity: string;
  assetName: string;
  vendor?: string;
  sourceUrl?: string;
  cvssScore?: number;
  exploitStatus?: 'Active Weaponized' | 'POC Available' | 'Reported In Wild' | 'None';
  epssScore?: number;
  cisaKev?: boolean;
}

export interface DigestHealth {
  database: 'connected' | 'degraded';
  databaseLatencyMs: number;
  workerStatus: string;
  workerHeartbeatAgeSeconds: number | null;
  nextScheduledAttempt: string | null;
  nextDailyDigestAt?: string | null;
  backlog: { status: string; count: number }[];
  checkedAt: string;
  systemUptime: string;
  /** Legacy availability field; not displayed because process uptime is not availability. */
  systemUptimePercentage: number | null;
  pipelineJobs: { total: number; succeeded: number; failed: number };
}

export interface DailyDigestParts {
   advisory_id: string;
  advisory_title: string;
  dispatch_date: string;
  severity: string;
  finding_count: number;
  severity_counts: string;
  findings_summary: string;
  health_report: string;
  recipient_name: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  asset_count: number;
  executive_summary: string;
  report_generated: string;
  critical_summary: string;
  high_summary: string;
  medium_summary: string;
  low_summary: string;
  critical_kpi: string;
  high_kpi: string;
  medium_kpi: string;
  low_kpi: string;
  held_for_review?: string;
}

const digestEscapeHtml = (value: string) =>
  String(value).replace(
    /[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
  );

function normalizeDigestConfig(config: TemplateCustomization): TemplateCustomization {
  config = { ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION, ...config };
  for (const key of [
    'fontColor',
    'headingColor',
    'accentColor',
    'canvasBg',
    'cardBg',
    'headerBg',
    'badgeStampColor',
  ] as const) {
    if (!/^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i.test(config[key]))
      config[key] = DEFAULT_DAILY_DIGEST_CUSTOMIZATION[key];
  }
  if (!['solid', 'dashed', 'none'].includes(config.borderStyle)) config.borderStyle = 'solid';
  if (!/^\d{1,3}(?:px|rem|%)$/.test(config.borderRadius)) config.borderRadius = '12px';
  config.badgeStampText = digestEscapeHtml(config.badgeStampText);
  config.classificationText = digestEscapeHtml(config.classificationText);
  return config;
}

/**
 * Daily Vulnerability Digest Template Studio HTML — delivered digest email uses
 * exactly this markup. Renders through the Handlebars-subset engine
 * (`renderEmailTemplate`) which supports `{{{triple}}}` raw HTML fields.
 */
export const DEFAULT_DAILY_DIGEST_TEMPLATE = `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml"
  xmlns:o="urn:schemas-microsoft-com:office:office">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="x-apple-disable-message-reformatting">
  <meta name="dispatch-date" content="{{dispatch_date}}">
  <meta name="digest-severity" content="{{severity}}">
  <title>{{advisory_id}} | Daily Vulnerability Notification</title>
  <!--[if gte mso 9]>
<xml>
  <o:OfficeDocumentSettings>
    <o:AllowPNG/>
    <o:PixelsPerInch>96</o:PixelsPerInch>
  </o:OfficeDocumentSettings>
</xml>
<![endif]-->
  <style type="text/css">
    body,
    table,
    td,
    a {
      -webkit-text-size-adjust: 100%;
      -ms-text-size-adjust: 100%;
    }

    table,
    td {
      mso-table-lspace: 0pt;
      mso-table-rspace: 0pt;
      border-collapse: collapse;
    }

    img {
      border: 0;
      height: auto;
      line-height: 100%;
      outline: none;
      text-decoration: none;
      display: block;
    }

    body {
      margin: 0 !important;
      padding: 0 !important;
      width: 100% !important;
      background-color: #f1f5f9;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      color: #1e293b;
    }

    a[x-apple-data-detectors] {
      color: inherit !important;
      text-decoration: none !important;
      font-size: inherit !important;
      font-family: inherit !important;
      font-weight: inherit !important;
      line-height: inherit !important;
    }

    @media only screen and (max-width: 680px) {
      .container {
        width: 100% !important;
        max-width: 100% !important;
      }

      .mobile-pad {
        padding-left: 16px !important;
        padding-right: 16px !important;
      }

      .stack-col {
        display: block !important;
        width: 100% !important;
        max-width: 100% !important;
      }
    }
  </style>
</head>

<body bgcolor="#f1f5f9"
  style="margin: 0; padding: 0; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color: #1e293b;">

  <!-- Hidden Inbox Preheader -->
  <div
    style="display: none; font-size: 1px; line-height: 1px; max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden; mso-hide: all;">
    {{advisory_title}} - {{severity_counts}}
  </div>

  <!-- Outer Viewport Wrapper -->
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f1f5f9"
    style="background-color: #f1f5f9; width: 100%;">
    <tr>
      <td align="center" style="padding: 20px 10px;">

        <!--[if mso]>
        <table role="presentation" align="center" border="0" cellspacing="0" cellpadding="0" width="680" style="width: 680px;">
        <tr>
        <td align="center" valign="top" width="680">
        <![endif]-->

        <!-- Main Email Card -->
        <table role="presentation" class="container" width="680" cellpadding="0" cellspacing="0" border="0"
          bgcolor="#ffffff"
          style="width: 680px; max-width: 680px; background-color: #ffffff; border: 1px solid #cbd5e1;">

          <!-- Top Brand Accent Strip -->
          <tr>
            <td bgcolor="#1d4ed8" height="4"
              style="background-color: #1d4ed8; height: 4px; font-size: 1px; line-height: 1px;">&nbsp;</td>
          </tr>

          <!-- HEADER -->
          <tr>
            <td class="mobile-pad" bgcolor="#f8fafc"
              style="background-color: #f8fafc; padding: 16px 22px; border-bottom: 1px solid #cbd5e1;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width: 100%;">
                <tr>
                  <td valign="top" align="left" style="padding-right: 12px;">
                    <div
                      style="font-size: 10px; line-height: 14px; font-weight: 700; letter-spacing: 0.8px; text-transform: uppercase; color: #1d4ed8; mso-line-height-rule: exactly;">
                      DAILY VULNERABILITY DIGEST
                    </div>
                    <div
                      style="padding-top: 3px; font-size: 19px; line-height: 24px; font-weight: 700; color: #0f172a; mso-line-height-rule: exactly;">
                      BA Security Advisory
                    </div>
                    <div
                      style="padding-top: 3px; font-size: 13px; line-height: 18px; font-weight: 600; color: #334155; mso-line-height-rule: exactly;">
                      {{advisory_title}}
                    </div>
                  </td>
                  <td valign="top" align="right" style="white-space: nowrap;">
                    {{{severity_header_badge}}}
                  </td>
                </tr>
              </table>

              <!-- Metadata Bar -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                style="width: 100%; margin-top: 12px; border-top: 1px solid #e2e8f0;">
                <tr>
                  <td
                    style="padding-top: 10px; font-size: 11px; line-height: 15px; color: #475569; mso-line-height-rule: exactly;">
                    <strong style="color: #0f172a;">Advisory ID:</strong> {{advisory_id}} &nbsp;&bull;&nbsp; <strong
                      style="color: #0f172a;">Generated:</strong> {{report_generated}}
                  </td>
                  <td align="right"
                    style="padding-top: 10px; font-size: 11px; line-height: 15px; color: #475569; mso-line-height-rule: exactly;">
                    <strong style="color: #0f172a;">Summary:</strong> {{severity_counts}}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- 01 EXECUTIVE SUMMARY (Unshaded White) -->
          <tr>
            <td class="mobile-pad" bgcolor="#ffffff"
              style="background-color: #ffffff; padding: 18px 22px 16px 22px; border-bottom: 1px solid #e2e8f0;">
              <div
                style="font-size: 11px; line-height: 15px; font-weight: 700; letter-spacing: 0.8px; text-transform: uppercase; color: #0f172a; padding-bottom: 6px; mso-line-height-rule: exactly;">
                <span style="color: #1d4ed8;">01</span> &nbsp;EXECUTIVE SUMMARY
              </div>
              <div style="font-size: 12.5px; line-height: 19px; color: #334155; mso-line-height-rule: exactly;">
                {{{executive_summary}}}
              </div>
            </td>
          </tr>

          <!-- 02 EXPOSURE & ASSET SNAPSHOT -->
          <tr>
            <td class="mobile-pad" bgcolor="#ffffff" style="background-color: #ffffff; padding: 16px 22px 6px 22px;">
              <!-- Shaded Section Heading Bar -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f1f5f9"
                style="width: 100%; background-color: #f1f5f9; border: 1px solid #e2e8f0;">
                <tr>
                  <td
                    style="padding: 7px 12px; font-size: 11px; line-height: 15px; font-weight: 700; letter-spacing: 0.7px; text-transform: uppercase; color: #0f172a; mso-line-height-rule: exactly;">
                    <span style="color: #1d4ed8;">02</span> &nbsp;24-HOUR EXPOSURE &amp; ASSET SNAPSHOT
                  </td>
                </tr>
              </table>

              <!-- KPI Dashboard Grid -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                style="width: 100%; margin-top: 10px;">
                <tr>
                  <td align="center" valign="middle" bgcolor="#f8fafc"
                    style="background-color: #f8fafc; padding: 12px 6px; border: 1px solid #cbd5e1;">
                    <div
                      style="font-size: 20px; line-height: 24px; font-weight: 700; color: #0f172a; mso-line-height-rule: exactly;">
                      {{finding_count}}</div>
                    <div
                      style="padding-top: 3px; font-size: 9.5px; line-height: 13px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #64748b; mso-line-height-rule: exactly;">
                      TOTAL FINDINGS</div>
                  </td>

                  {{{critical_kpi}}}
                  {{{high_kpi}}}
                  {{{medium_kpi}}}
                  {{{low_kpi}}}

                  <td align="center" valign="middle" bgcolor="#eff6ff"
                    style="background-color: #eff6ff; padding: 12px 6px; border: 1px solid #bfdbfe;">
                    <div
                      style="font-size: 20px; line-height: 24px; font-weight: 700; color: #1d4ed8; mso-line-height-rule: exactly;">
                      {{asset_count}}</div>
                    <div
                      style="padding-top: 3px; font-size: 9.5px; line-height: 13px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #1e40af; mso-line-height-rule: exactly;">
                      ASSETS</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- 03 DIGEST DETAILS & PLATFORM TELEMETRY -->
          <tr>
            <td class="mobile-pad" bgcolor="#ffffff" style="background-color: #ffffff; padding: 14px 22px 20px 22px;">
              <!-- Shaded Section Heading Bar -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f1f5f9"
                style="width: 100%; background-color: #f1f5f9; border: 1px solid #e2e8f0;">
                <tr>
                  <td
                    style="padding: 7px 12px; font-size: 11px; line-height: 15px; font-weight: 700; letter-spacing: 0.7px; text-transform: uppercase; color: #0f172a; mso-line-height-rule: exactly;">
                    <span style="color: #1d4ed8;">03</span> &nbsp;DIGEST DETAILS &amp; PLATFORM TELEMETRY
                  </td>
                </tr>
              </table>

              <!-- Structured Telemetry Table -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                style="width: 100%; margin-top: 10px; border: 1px solid #cbd5e1; font-size: 12px; line-height: 17px;">
                <!-- SEVERITY BREAKDOWN -->
                <tr>
                  <td width="175" valign="top" bgcolor="#f8fafc"
                    style="width: 175px; background-color: #f8fafc; padding: 9px 12px; border-right: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; font-size: 10.5px; line-height: 15px; font-weight: 700; letter-spacing: 0.4px; color: #475569; text-transform: uppercase; mso-line-height-rule: exactly;">
                    Severity Breakdown
                  </td>
                  <td valign="middle" bgcolor="#ffffff"
                    style="background-color: #ffffff; padding: 9px 12px; border-bottom: 1px solid #e2e8f0; color: #1e293b; mso-line-height-rule: exactly;">
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                      style="width: 100%;">
                      <tr>
                        {{{critical_summary}}}{{{high_summary}}}{{{medium_summary}}}{{{low_summary}}}
                      </tr>
                    </table>
                  </td>
                </tr>

                <!-- FINDINGS (24H) -->
                <tr>
                  <td width="175" valign="top" bgcolor="#f8fafc"
                    style="width: 175px; background-color: #f8fafc; padding: 9px 12px; border-right: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; font-size: 10.5px; line-height: 15px; font-weight: 700; letter-spacing: 0.4px; color: #475569; text-transform: uppercase; mso-line-height-rule: exactly;">
                    Findings (24h)
                  </td>
                  <td valign="top" bgcolor="#ffffff"
                    style="background-color: #ffffff; padding: 9px 12px; border-bottom: 1px solid #e2e8f0; font-size: 12px; line-height: 17px; color: #1e293b; mso-line-height-rule: exactly;">
                    {{{findings_summary}}}
                  </td>
                </tr>

                <!-- CONFIDENCE FOLLOW-UP -->
                <tr>
                  <td width="175" valign="top" bgcolor="#f8fafc"
                    style="width: 175px; background-color: #f8fafc; padding: 9px 12px; border-right: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; font-size: 10.5px; line-height: 15px; font-weight: 700; letter-spacing: 0.4px; color: #475569; text-transform: uppercase; mso-line-height-rule: exactly;">
                    Confidence Follow-Up
                  </td>
                  <td valign="top" bgcolor="#ffffff"
                    style="background-color: #ffffff; padding: 9px 12px; border-bottom: 1px solid #e2e8f0; font-size: 12px; line-height: 17px; color: #1e293b; mso-line-height-rule: exactly;">
                    {{{held_for_review}}}
                  </td>
                </tr>

                <!-- PLATFORM HEALTH -->
                <tr>
                  <td width="175" valign="top" bgcolor="#f8fafc"
                    style="width: 175px; background-color: #f8fafc; padding: 9px 12px; border-right: 1px solid #e2e8f0; font-size: 10.5px; line-height: 15px; font-weight: 700; letter-spacing: 0.4px; color: #475569; text-transform: uppercase; mso-line-height-rule: exactly;">
                    Platform Health
                  </td>
                  <td valign="top" bgcolor="#ffffff"
                    style="background-color: #ffffff; padding: 9px 12px; font-size: 12px; line-height: 17px; color: #1e293b; mso-line-height-rule: exactly;">
                    {{{health_report}}}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- FOOTER -->
          <tr>
            <td class="mobile-pad" bgcolor="#f8fafc"
              style="background-color: #f8fafc; padding: 14px 22px; border-top: 1px solid #cbd5e1;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width: 100%;">
                <tr>
                  <td valign="middle" align="left"
                    style="font-size: 11.5px; line-height: 16px; font-weight: 700; color: #0f172a; mso-line-height-rule: exactly;">
                    BA Security Operations
                  </td>
                  <td valign="middle" align="right"
                    style="font-size: 11px; line-height: 16px; color: #475569; mso-line-height-rule: exactly;">
                    Contact: <a href="mailto:DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com"
                      style="color: #1d4ed8; font-weight: 600; text-decoration: none;">DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com</a>
                  </td>
                </tr>
                <tr>
                  <td colspan="2"
                    style="padding-top: 6px; font-size: 11px; line-height: 16px; color: #64748b; mso-line-height-rule: exactly;">
                    This digest provides a consolidated view of newly identified vulnerabilities and platform health
                    status. Assess applicability and prioritize remediation according to asset criticality and
                    established vulnerability management SLAs.
                  </td>
                </tr>
              </table>
            </td>
          </tr>

        </table>

        <!--[if mso]>
        </td>
        </tr>
        </table>
        <![endif]-->

      </td>
    </tr>
  </table>

</body>

</html>`;

/**
 * Compiles the Daily Digest studio HTML for the operator's customization.
 *
 * The Template Studio preview is meant to show what the recipient gets. This
 * function previously ignored `config` and returned the untouched default, so
 * every colour, typography, stamp and classification change the operator made
 * was discarded and the pane kept rendering the old stock layout.
 *
 * The stock markup is patched with targeted, anchored substitutions rather than
 * rebuilt, so the document structure (tables, MSO conditionals, placeholders)
 * is exactly the one that ships. Every anchor must still match: if the constant
 * is edited and an anchor goes stale this throws, instead of quietly returning
 * a half-styled document.
 */
export function compileDailyDigestTemplate(config: TemplateCustomization): string {
  const safe = normalizeDigestConfig({ ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION, ...config });
  const fontFamily = getFontFamilyCss(safe.fontFamily);
  // At the stock accent, the darker tints the template pairs with it are kept.
  const kpiLabelColor = safe.accentColor === '#1d4ed8' ? '#1e40af' : safe.accentColor;
  const strapColor = safe.fontColor === '#1e293b' ? '#334155' : safe.fontColor;

  let html = DEFAULT_DAILY_DIGEST_TEMPLATE;
  const apply = (pattern: RegExp, value: string, label: string) => {
    // test() on a /g/ regex advances lastIndex; use a fresh copy for the probe.
    if (!new RegExp(pattern.source, pattern.flags.replace('g', '')).test(html))
      throw new Error(`Daily digest template no longer contains the ${label} anchor`);
    html = html.replace(pattern, value);
  };

  // Stylesheet body rule: canvas colour, base font, body text colour.
  // Indentation is matched with `\s*` rather than a fixed number of spaces: the
  // canonical document indents the head by two spaces, and an anchor hard-coded
  // to four made every customization throw instead of rendering.
  apply(
    /(body \{\s*margin: 0 !important;\s*padding: 0 !important;\s*width: 100% !important;\s*background-color: )#f1f5f9;(\s*font-family: )[^\n]+;(\s*color: )#1e293b;/,
    `$1${safe.canvasBg};$2${fontFamily};$3${safe.fontColor};`,
    'stylesheet body rule',
  );
  // <body> element: colour only. Its font list is left exactly as written (the
  // stock markup quotes it with single quotes while the stylesheet uses double
  // quotes); rewriting it would change the default document for no benefit.
  // The canonical document wraps this tag across two lines, so the whitespace
  // between its attributes is matched with `\s+` rather than a single space.
  apply(
    /(<body bgcolor=")#f1f5f9("\s+style="margin: 0; padding: 0; background-color: )#f1f5f9(; font-family: [^;]+; color: )#1e293b;/,
    `$1${safe.canvasBg}$2${safe.canvasBg}$3${safe.fontColor};`,
    'body element',
  );
  // Canvas-coloured viewport wrappers. The canonical document may wrap this tag
  // across lines, so attribute whitespace is `\s*`.
  const wrapper = /(<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor=")#f1f5f9("\s*style=")([^"]*?background-color: )#f1f5f9;/g;
  apply(wrapper, `$1${safe.canvasBg}$2$3${safe.canvasBg};`, 'viewport wrapper');
  // Main card: background plus the configured border. Attributes may be wrapped
  // across lines in the canonical document, so inter-attribute whitespace is
  // `\s+`/`\s*` throughout.
  apply(
    /(<table role="presentation" class="container" width="680" cellpadding="0" cellspacing="0" border="0"\s+bgcolor=")#ffffff("\s*style="width: 680px; max-width: 680px; background-color: )#ffffff(; border: 1px solid #cbd5e1;)/,
    `$1${safe.cardBg}$2${safe.cardBg}$3`.replace(
      '; border: 1px solid #cbd5e1;',
      `; border: ${safe.borderRadius} ${safe.borderStyle} #cbd5e1;`,
    ),
    'main card',
  );
  // Brand accent strip at the top of the card.
  apply(
    /(<td bgcolor=")#1d4ed8("\s+height="4"\s+style="background-color: )#1d4ed8;/,
    `$1${safe.accentColor}$2${safe.accentColor};`,
    'brand accent strip',
  );
  // Header kicker ("DAILY VULNERABILITY DIGEST").
  apply(
    /(letter-spacing: 0\.8px; text-transform: uppercase; color: )#1d4ed8;( mso-line-height-rule: exactly;">\n\s+DAILY VULNERABILITY DIGEST)/,
    `$1${safe.accentColor};$2`,
    'header kicker',
  );
  // Numbered section accents (01 / 02 / 03).
  apply(
    /(<span style="color: )#1d4ed8(;">0[123]<\/span>)/g,
    `$1${safe.accentColor}$2`,
    'section numbers',
  );
  // Header band, headline and strap line.
  apply(
    /(<td class="mobile-pad" bgcolor=")#f8fafc("\s+style="background-color: )#f8fafc;/,
    `$1${safe.headerBg}$2${safe.headerBg};`,
    'header band',
  );
  apply(
    /(font-size: 19px; line-height: 24px; font-weight: 700; color: )#0f172a;/,
    `$1${safe.headingColor};`,
    'header headline',
  );
  apply(
    /(font-size: 13px; line-height: 18px; font-weight: 600; color: )#334155;/,
    `$1${strapColor};`,
    'header strap line',
  );
  // "ASSETS" KPI figure and label.
  apply(
    /(font-size: 20px; line-height: 24px; font-weight: 700; color: )#1d4ed8;/,
    `$1${safe.accentColor};`,
    'assets KPI figure',
  );
  apply(
    /(font-size: 9\.5px; line-height: 13px; font-weight: 700; letter-spacing: 0\.5px; text-transform: uppercase; color: )#1e40af;/,
    `$1${kpiLabelColor};`,
    'assets KPI label',
  );
  // Footer contact link.
  apply(
    /(HoneywellProd\.onmicrosoft\.com"\s+style="color: )#1d4ed8;/,
    `$1${safe.accentColor};`,
    'footer contact link',
  );

  // Optional blocks. Both are off at the stock defaults, so enabling them is
  // the only case that changes the document structure.
  if (safe.showStamp) {
    apply(
      /(<td class="mobile-pad"\s+bgcolor="[^"]+"\s+style="background-color: [^"]+; padding: 16px 22px; border-bottom: 1px solid #cbd5e1;">)/,
      `$1<div style="font-size:10px;line-height:14px;font-weight:700;letter-spacing:1.5px;color:${safe.badgeStampColor};padding-bottom:4px;">${safe.badgeStampText}</div>`,
      'header stamp slot',
    );
  }
  if (safe.showClassificationBanner) {
    apply(
      /(<table role="presentation" class="container"[^>]*>)/,
      `<tr><td style="padding:8px 22px;background-color:${safe.canvasBg};color:${safe.fontColor};font-size:10px;line-height:16px;letter-spacing:1px;text-align:center;">${safe.classificationText}</td></tr>$1`,
      'classification banner slot',
    );
  }
  return html;
}
export function renderDailyFindingSummary(findings: DigestFinding[], config: TemplateCustomization): string {
  const safe = normalizeDigestConfig(config);
  if (!findings.length) {
    return `<p style="margin:0;font-size:12px;line-height:20px;color:${safe.fontColor};">No findings in the last 24 hours.</p>`;
  }
  const bySeverity: Record<string, DigestFinding[]> = {};
  for (const finding of findings) (bySeverity[finding.severity] ||= []).push(finding);
  const ordered = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const).filter(
    (s) => bySeverity[s]?.length,
  );
  const severityStyle: Record<string, { bg: string; border: string; text: string }> = {
    CRITICAL: { bg: '#fef2f2', border: '#dc2626', text: '#b91c1c' },
    HIGH: { bg: '#fff7ed', border: '#ea580c', text: '#c2410c' },
    MEDIUM: { bg: '#fefce8', border: '#ca8a04', text: '#a16207' },
    LOW: { bg: '#ecfdf5', border: '#16a34a', text: '#15803d' },
    UNKNOWN: { bg: '#f8fafc', border: '#94a3b8', text: '#475569' },
  };
  return ordered
    .map((severity, index) => {
      const items = bySeverity[severity].slice().sort((left, right) => left.cveId.localeCompare(right.cveId));
      const style = severityStyle[severity] || severityStyle.UNKNOWN;
      const marginBottom = index < ordered.length - 1 ? ' style="margin-bottom:18px;"' : '';
      const cards = items
        .slice(0, 25)
        .map((f) => {
          // Links follow the operator's accent. This was hard-coded to the stock
          // blue, so a customized digest still showed blue CVE links.
          const cveIdHtml = f.sourceUrl
            ? `<a href="${digestEscapeHtml(f.sourceUrl)}" target="_blank" rel="noopener noreferrer" style="color:${safe.accentColor};text-decoration:underline;text-underline-offset:2px;">${digestEscapeHtml(f.cveId)}</a>`
            : `<strong style="color:${safe.accentColor};">${digestEscapeHtml(f.cveId)}</strong>`;
          const tags: string[] = [];
          if (typeof f.cvssScore === 'number') {
            tags.push(`CVSS ${f.cvssScore.toFixed(1)}`);
          }
          if (f.cisaKev) {
            tags.push('CISA KEV');
          }
          if (f.exploitStatus && f.exploitStatus !== 'None') {
            tags.push(f.exploitStatus);
          }
          if (typeof f.epssScore === 'number' && f.epssScore > 0.2) {
            tags.push(`EPSS ${(f.epssScore * 100).toFixed(0)}%`);
          }
          const tagHtml = tags.map((tag) =>
            `<span style="display:inline-block;margin:3px 5px 0 0;padding:2px 6px;border:1px solid #dbe2ea;border-radius:3px;background:#f8fafc;color:#475569;font-size:10px;line-height:15px;">${digestEscapeHtml(tag)}</span>`,
          ).join('');
          return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0 0 10px;border-collapse:collapse;table-layout:fixed;">
    <tr class="vulnstream-pdf-card" data-pdf-accent="${style.border}" data-pdf-cve="${digestEscapeHtml(f.cveId)}" data-pdf-severity="${digestEscapeHtml(f.severity)}">
        <td style="padding:12px 14px;border:1px solid #e2e8f0;border-left:4px solid ${style.border};background:#ffffff;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;table-layout:fixed;">
                <tr>
                    <td style="padding:0 8px 0 0;font-size:14px;line-height:20px;font-weight:700;word-break:break-word;">${cveIdHtml}</td>
                    <td align="right" style="width:1%;padding:0;white-space:nowrap;vertical-align:top;">
                        <span style="display:inline-block;padding:3px 7px;border-radius:3px;background:${style.bg};color:${style.text};font-size:10px;line-height:15px;font-weight:700;">${severity}${typeof f.cvssScore === 'number' ? ` · CVSS ${f.cvssScore.toFixed(1)}` : ''}</span>
                    </td>
                </tr>
            </table>
            <p style="margin:8px 0 0;font-size:12px;line-height:18px;color:#334155;"><strong>Asset:</strong> ${digestEscapeHtml(f.assetName)}${f.vendor ? ` (${digestEscapeHtml(f.vendor)})` : ''}</p>
            ${tagHtml ? `<div style="margin-top:5px;line-height:20px;">${tagHtml}</div>` : ''}
        </td>
    </tr>
</table>`;
        })
        .join('');
      const extra = items.length > 25
        ? `<p style="margin:0;font-size:11px;line-height:17px;color:#71717a;">${items.length - 25} more ${severity.toLowerCase()} finding${items.length - 25 === 1 ? '' : 's'} omitted</p>`
        : '';
      return `<div${marginBottom}>
    <p style="margin:0 0 9px;font-size:12px;line-height:18px;font-weight:700;color:${style.text};">${severity} (${items.length})</p>
    ${cards}${extra}
</div>`;
    })
    .join('\n');
}

export function renderDailyHealthReport(health: DigestHealth | null, config: TemplateCustomization & { timezone?: string }): string {
  if (!health) return '';
  const safe = normalizeDigestConfig(config);
  // Workspace timezone for every timestamp in this table. The digest body is
  // rendered on the server, so it cannot rely on the viewer's browser zone.
  const outputTimezone = resolveTimezone(config.timezone);
  const workerStatusLabel: Record<string, string> = {
    HEALTHY: 'Healthy',
    DISABLED: 'Disabled',
    STALE: 'Stale',
    NOT_OBSERVED: 'Not observed',
  };
  const workerStatusColor: Record<string, string> = {
    HEALTHY: '#16a34a',
    DISABLED: '#64748b',
    STALE: '#ea580c',
    NOT_OBSERVED: '#64748b',
  };
  const workerLabel = workerStatusLabel[health.workerStatus] || health.workerStatus;
  const workerColor = workerStatusColor[health.workerStatus] || '#64748b';
  const dbLabel = health.database === 'connected' ? `Operational (${health.databaseLatencyMs} ms)` : 'Degraded';
  const dbColor = health.database === 'connected' ? '#16a34a' : '#dc2626';
  const heartbeatLabel =
    health.workerHeartbeatAgeSeconds !== null
      ? `${health.workerHeartbeatAgeSeconds} seconds ago`
      : 'N/A';
  const formatHealthDate = (iso: string): string => {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return '—';
    // Rendered in the workspace timezone, not UTC: an operator reading the
    // digest at 09:00 local must not have to convert a UTC timestamp by hand.
    // The UTC offset is appended so the instant is never ambiguous.
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: outputTimezone,
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).formatToParts(date);
    const day = parts.find((p) => p.type === 'day')?.value || '';
    const month = parts.find((p) => p.type === 'month')?.value || '';
    const year = parts.find((p) => p.type === 'year')?.value || '';
    const hour = parts.find((p) => p.type === 'hour')?.value || '';
    const minute = parts.find((p) => p.type === 'minute')?.value || '';
    return `${day} ${month} ${year} ${hour}:${minute} ${utcOffsetLabel(date, outputTimezone)}`;
  };
  const nextDigest = health.nextDailyDigestAt
    ? formatHealthDate(health.nextDailyDigestAt)
    : 'Not scheduled';
  const lastCheck = formatHealthDate(health.checkedAt);
  // Built after `formatHealthDate` exists so the retry timestamp renders in the
  // workspace timezone like every other date in the report. A non-zero retained
  // count with no scheduled attempt is the interesting case: the queue is idle
  // but work is still held, so it is stated explicitly rather than inferred from
  // a bare count.
  const deliveryQueueLabel = [
    health.nextScheduledAttempt
      ? `Next delayed retry ${formatHealthDate(health.nextScheduledAttempt)}`
      : 'No future delivery attempt scheduled',
    ...[
      ['QUEUED', 'Queued'],
      ['SENDING', 'Sending'],
      ['REVIEW', 'Awaiting review'],
      ['ACCEPTED', 'Provider accepted'],
      ['FAILED', 'Failed'],
    ].map(([status, label]) => {
      const count = health.backlog.filter((b) => b.status === status).reduce((sum, b) => sum + b.count, 0);
      return `${count} ${label}`;
    }),
  ].join(' | ');
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0">

                <tr bgcolor="#f8fafc">
                    <td style="padding:10px;border:1px solid #e2e8f0;font-weight:bold;font-size:12px;">
                        Component
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-weight:bold;font-size:12px;">
                        Status
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Database Connectivity
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;color:${dbColor};font-size:12px;">
                        ${dbLabel}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Worker Process Uptime
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;color:#16a34a;font-size:12px;">
                        ${digestEscapeHtml(health.systemUptime)} (since restart)
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Notification Service
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;color:${workerColor};font-size:12px;">
                        ${workerLabel}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Last Heartbeat
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        ${digestEscapeHtml(heartbeatLabel)}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Delivery Queue (retained jobs)
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        ${digestEscapeHtml(deliveryQueueLabel)}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Pipeline Jobs (last 24h)
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        ${health.pipelineJobs.total} jobs &nbsp;|&nbsp; ${health.pipelineJobs.succeeded} succeeded &nbsp;|&nbsp; ${health.pipelineJobs.failed} failed
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Next Scheduled Digest
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        ${digestEscapeHtml(nextDigest)}
                    </td>
                </tr>

                <tr>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        Last Health Check
                    </td>
                    <td style="padding:10px;border:1px solid #e2e8f0;font-size:12px;">
                        ${digestEscapeHtml(lastCheck)}
                    </td>
                </tr>

            </table>`;
}

export function renderHeldForReview(count: number, config: TemplateCustomization): string {
  const safe = normalizeDigestConfig(config);
  if (count === 0) {
    return `<p style="margin:0;font-size:12px;line-height:20px;color:#64748b;">No outstanding confidence follow-ups.</p>`;
  }
  // Every finding is dispatched; a finding counted here was delivered with a
  // stated confidence limitation, not withheld for review.
  return `<p style="margin:0;font-size:14px;line-height:24px;color:#475569;">${count} finding(s) were dispatched with a stated confidence limitation. Each one requires manual verification of asset applicability against current vendor guidance; the delivered email names the reason on the finding itself.</p>`;
}

const SEVERITY_KPI: Record<string, { label: string; color: string; bg: string }> = {
  CRITICAL: { label: 'CRITICAL', color: '#dc2626', bg: '#fef2f2' },
  HIGH: { label: 'HIGH', color: '#ea580c', bg: '#fff7ed' },
  MEDIUM: { label: 'MEDIUM', color: '#ca8a04', bg: '#fefce8' },
  LOW: { label: 'LOW', color: '#16a34a', bg: '#ecfdf5' },
};

const SEVERITY_TITLE: Record<string, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
};

export const digestSeveritySummary = (
  severity: string,
  count: number,
  config: TemplateCustomization,
): string => {
  if (count === 0) return '';
  const safe = normalizeDigestConfig(config);
  const sev = SEVERITY_KPI[severity] ?? { label: severity, color: safe.fontColor, bg: '#f8fafc' };
  const color = severity === 'CRITICAL' ? '#dc2626' : severity === 'HIGH' ? '#ea580c' : severity === 'MEDIUM' ? '#ca8a04' : '#16a34a';
  return `<td style="font-size:12px;color:${color};" align="center">
    <strong>${SEVERITY_TITLE[severity] ?? severity}:</strong> ${count}
</td>`;
};

export const digestSeverityKpi = (
  severity: string,
  count: number,
  config: TemplateCustomization,
): string => {
  if (count === 0) return '';
  const safe = normalizeDigestConfig(config);
  const sev = SEVERITY_KPI[severity] ?? { label: severity, color: safe.fontColor, bg: '#f8fafc' };
  return `<td align="center" bgcolor="${sev.bg}" style="padding:14px 8px;border:1px solid #e2e8f0;border-radius:8px;">
    <div style="font-size:22px;line-height:26px;font-weight:bold;color:${sev.color};">${count}</div>
    <div style="padding-top:3px;font-size:10px;line-height:14px;font-weight:700;letter-spacing:0.5px;color:#64748b;">${sev.label}</div>
</td>`;
};

export const formatExecutiveSummary = (total: number, counts: Record<string, number>): string => {
  const overview = `A total of <strong>${total} ${total === 1 ? 'finding' : 'findings'}</strong> matched your subscriptions in the last 24 hours`;
  if (total === 0) {
    return `${overview}. This does not mean there are no open vulnerabilities. Findings held for review are excluded from this total.`;
  }
  const parts: string[] = [];
  for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const) {
    if (counts[severity] > 0) {
      parts.push(
        `<strong>${counts[severity]} ${severity.charAt(0) + severity.slice(1).toLowerCase()}</strong>`,
      );
    }
  }
  const summary =
    parts.length > 1
      ? `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`
      : parts.length === 1
        ? parts[0]
        : 'no';
  const guidance: string[] = [];
  if (counts.CRITICAL > 0) guidance.push('Prioritize immediate remediation of critical findings.');
  if (counts.HIGH > 0) guidance.push('Address high-severity findings promptly through your change management process.');
  const routineSeverities = ['MEDIUM', 'LOW'].filter((severity) => counts[severity] > 0);
  if (routineSeverities.length) guidance.push(`Address ${routineSeverities.map((severity) => severity.toLowerCase()).join(' and ')} severity findings according to established risk treatment procedures.`);
  if (counts.UNKNOWN > 0) guidance.push('Assess findings with unknown severity before assigning remediation priority.');
  return `${overview}, including ${summary} severity findings across monitored assets. ${guidance.join(' ')}`;
}

export const formatExecutiveSummaryText = (total: number, counts: Record<string, number>): string =>
  formatExecutiveSummary(total, counts).replace(/<\/?strong>/g, '');

export const stripGeneratedExecutiveSummaryMarkup = (value: string): string =>
  value.replace(/<\/?strong>/gi, '');

/**
 * The daily digest's executive summary is trusted HTML only when it is exactly
 * the sentence this module generates or a legacy generated sentence.
 * Anything else is data and is escaped.
 *
 * The comparison is made against the generated sentence itself rather than a
 * hand-written pattern: a pattern has to be kept in step with the wording by
 * hand, and one that drifts silently starts escaping legitimate markup (or, if
 * loosened, starts trusting injected markup).
 */
function digestSafeExecutiveSummary(value: string): string {
  const total = /^A total of <strong>(\d+) findings?<\/strong>/.exec(value);
  if (total) {
    const counts: Record<string, number> = {};
    for (const match of value.matchAll(/<strong>(\d+) (Critical|High|Medium|Low|Unknown)<\/strong>/g)) {
      counts[match[2].toUpperCase()] = Number(match[1]);
    }
    if (value === formatExecutiveSummary(Number(total[1]), counts)) return value;
  }
  // A generated sentence contains `<strong>` around a total and around each
  // severity count, and no other markup at all. Both halves are required: the
  // tag inventory alone would still allow arbitrary text inside the tags, and
  // the wording alone would still allow an extra tag to be appended.
  const noForeignMarkup = !value.replace(/<\/?strong>/g, '').includes('<');
   // The list separator accepts an Oxford comma as well as the generated form, so
  // a hand-authored summary that only differs in punctuation still renders.
  const element = '<strong>\\d+ [A-Z][a-z]+<\\/strong>';
  // Older generated summaries used "no" in place of an empty severity list.
  const generatedShape = new RegExp(
    `^A total of <strong>\\d+ vulnerabilit(?:y|ies)<\\/strong> were identified during the latest monitoring cycle, including (?:no|(?:${element})(?:,(?: and)? | and )?(?:${element}(?:,(?: and)? | and )?)*) severity findings across monitored assets\\. Immediate remediation of critical findings is recommended while medium and low severity items should be addressed according to established risk treatment and vulnerability management procedures\\.$`,
  );
  return noForeignMarkup && generatedShape.test(value) ? value : digestEscapeHtml(value);
}

const DIGEST_SEVERITY_BADGE: Record<string, { label: string; color: string }> = {
  CRITICAL: { label: 'CRITICAL SEVERITY', color: '#dc2626' },
  HIGH: { label: 'HIGH SEVERITY', color: '#ea580c' },
  MEDIUM: { label: 'MEDIUM SEVERITY', color: '#ca8a04' },
  LOW: { label: 'LOW SEVERITY', color: '#16a34a' },
};

const digestHeaderBadge = (severity: string): string => {
  const badge = DIGEST_SEVERITY_BADGE[severity];
  if (!badge) return '';
  return `<span style="display:inline-block;padding:4px 10px;border-radius:4px;background:${badge.color};color:#ffffff;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px;">${digestEscapeHtml(badge.label)}</span>`;
};

export function renderDailyDigest(config: TemplateCustomization, parts: DailyDigestParts, template?: string): string {
  // Without a hand-authored template, compile the studio markup with the
  // operator's customization. Using the bare constant here discarded every
  // colour, font, stamp and classification choice they had made.
  const compiled = template || compileDailyDigestTemplate(config);
  return renderEmailTemplate(compiled, {
    dispatch_date: parts.dispatch_date,
    severity: parts.severity,
    advisory_title: parts.advisory_title,
    advisory_id: parts.advisory_id,
    severity_header_badge: digestHeaderBadge(parts.severity),
    report_generated: parts.report_generated,
    severity_counts: parts.severity_counts,
    executive_summary: digestSafeExecutiveSummary(parts.executive_summary),
    finding_count: String(parts.finding_count),
    critical_kpi: parts.critical_kpi || '',
    high_kpi: parts.high_kpi || '',
    medium_kpi: parts.medium_kpi || '',
    low_kpi: parts.low_kpi || '',
    asset_count: String(parts.asset_count),
    critical_summary: parts.critical_summary || '',
    high_summary: parts.high_summary || '',
    medium_summary: parts.medium_summary || '',
    low_summary: parts.low_summary || '',
    findings_summary: parts.findings_summary,
    held_for_review: parts.held_for_review || '',
    health_report: parts.health_report,
  });
}

/**
 * News Template Studio HTML — delivered news email uses exactly this markup.
 * Renders through the Handlebars-subset engine (`renderEmailTemplate`) which
 * supports `{{#each news_sources}}` loops and `{{{triple}}}` raw HTML fields.
 */
export const DEFAULT_NEWS_EMAIL_TEMPLATE = `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>{{news_title}} | BA Threat Intelligence</title>

<!--[if gte mso 9]>
<xml>
  <o:OfficeDocumentSettings>
    <o:AllowPNG/>
    <o:PixelsPerInch>96</o:PixelsPerInch>
  </o:OfficeDocumentSettings>
</xml>
<![endif]-->

<!--
  =============================================================================
  HANDLEBARS / MUSTACHE JSON SCHEMA (OUTLOOK DESKTOP SAFE - NO MSO CONDITIONALS
  AROUND LOOP OR IF TAGS)
  =============================================================================
  {
    "news_title": "Weekly Cyber Threat & Vulnerability Briefing",
    "news_subject": "Enterprise & Industrial Security Digest",
    "news_subject_badge_text": "THREAT BRIEFING",
    "news_date": "22 Nov 2026",
    "news_count": 3,
    "news_summary": "Key threat intelligence developments covering critical infrastructure exploitation trends, zero-day patching priorities, and active ransomware TTPs.",
    "news_sources": [
      {
        "title": "CISA Adds Actively Exploited Network Appliance Flaws to KEV Catalog",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "source_name": "CISA Advisories",
        "published_at": "22 Nov 2026",
        "excerpt": "Federal cybersecurity officials confirmed active exploitation in the wild and urged immediate patching across perimeter appliances."
      }
    ],
    "news_articles": "",
    "news_footer": "For inquiries or threat intelligence support, contact BA Security Operations at DL-HBS-Cyber-Operations@HoneywellProd.onmicrosoft.com.",
    "sources_hub_url": "https://www.cisa.gov/news-events/cybersecurity-advisories"
  }
  =============================================================================
-->

<style type="text/css">
  body, table, td, p, a {
    -webkit-text-size-adjust: 100%;
    -ms-text-size-adjust: 100%;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  }
  table, td {
    mso-table-lspace: 0pt;
    mso-table-rspace: 0pt;
    border-collapse: collapse;
  }
  body {
    margin: 0 !important;
    padding: 0 !important;
    width: 100% !important;
    background-color: #f1f5f9;
    color: #1e293b;
  }
  a {
    color: #1d4ed8;
    text-decoration: underline;
  }
  @media only screen and (max-width: 680px) {
    .wrapper-table {
      width: 100% !important;
      max-width: 100% !important;
    }
    .mobile-pad {
      padding-left: 16px !important;
      padding-right: 16px !important;
    }
  }
</style>
</head>
<body bgcolor="#f1f5f9" style="margin: 0; padding: 0; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color: #1e293b;">

  <!-- Preheader -->
  <div style="display: none; font-size: 1px; line-height: 1px; max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden; mso-hide: all;">
    BA Threat Intelligence: {{news_title}} ({{news_count}} updates)
  </div>

  <!-- Outer Canvas -->
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f1f5f9" style="background-color: #f1f5f9; width: 100%;">
    <tr>
      <td align="center" style="padding: 20px 10px;">

        <!--[if (gte mso 9)|(IE)]>
        <table role="presentation" align="center" border="0" cellspacing="0" cellpadding="0" width="680">
        <tr>
        <td align="center" valign="top" width="680">
        <![endif]-->

        <!-- Main 680px Container -->
        <table role="presentation" class="wrapper-table" width="680" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="width: 680px; max-width: 680px; background-color: #ffffff; border: 1px solid #cbd5e1;">

          <!-- Top Accent Bar -->
          <tr>
            <td height="4" bgcolor="#1d4ed8" style="height: 4px; background-color: #1d4ed8; font-size: 1px; line-height: 1px;">&nbsp;</td>
          </tr>

          <!-- SIMPLE SOLID HEADER -->
          <tr>
            <td class="mobile-pad" bgcolor="#f8fafc" style="background-color: #f8fafc; padding: 16px 22px; border-bottom: 1px solid #cbd5e1;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width: 100%; table-layout: fixed;">
                <tr>
                  <td align="left" valign="middle" width="460" style="width: 460px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 10px; mso-line-height-rule: exactly; line-height: 14px; font-weight: 700; letter-spacing: 0.7px; text-transform: uppercase; color: #1d4ed8;">
                    BA THREAT INTELLIGENCE
                  </td>
                  <td align="right" valign="middle" width="174" style="width: 174px; text-align: right;">
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="right" style="margin-left: auto; margin-right: 0;">
                      <tr>
                        <td bgcolor="#dbeafe" style="background-color: #dbeafe; border: 1px solid #93c5fd; color: #1e40af; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 10px; mso-line-height-rule: exactly; line-height: 12px; font-weight: 700; letter-spacing: 0.4px; text-transform: uppercase; padding: 3px 8px; mso-padding-alt: 3px 8px;">
                          {{news_subject_badge_text}}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td colspan="2" style="padding-top: 6px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 18px; mso-line-height-rule: exactly; line-height: 23px; font-weight: 700; color: #0f172a;">
                    {{news_title}}
                  </td>
                </tr>
                <tr>
                  <td colspan="2" style="padding-top: 4px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 11px; mso-line-height-rule: exactly; line-height: 15px; color: #475569;">
                    <strong style="color: #1e293b;">{{news_subject}}</strong> &nbsp;&bull;&nbsp; Generated: {{news_date}} &nbsp;&bull;&nbsp; Articles: {{news_count}}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- 01 SUMMARY (Clean White Surface) -->
          <tr>
            <td class="mobile-pad" bgcolor="#ffffff" style="background-color: #ffffff; padding: 14px 22px 16px 22px; border-bottom: 1px solid #e2e8f0;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="padding-bottom: 6px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 11px; mso-line-height-rule: exactly; line-height: 15px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #0f172a;">
                    <span style="color: #1d4ed8;">01</span> &nbsp;Executive Summary
                  </td>
                </tr>
                <tr>
                  <td style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 12px; mso-line-height-rule: exactly; line-height: 18px; color: #334155;">
                    {{{news_summary}}}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- 02 SECURITY NEWS (Shaded Header Bar + Outlook-Safe Article Cards) -->
          <tr>
            <td class="mobile-pad" bgcolor="#ffffff" style="background-color: #ffffff; padding: 14px 22px 16px 22px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <!-- Shaded Section Heading Bar -->
                <tr>
                  <td bgcolor="#f1f5f9" style="background-color: #f1f5f9; border: 1px solid #cbd5e1; padding: 7px 12px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 11px; mso-line-height-rule: exactly; line-height: 15px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #0f172a;">
                    <span style="color: #1d4ed8;">02</span> &nbsp;Security News &amp; Source Links ({{news_count}})
                  </td>
                </tr>
                <tr>
                  <td height="10" style="height: 10px; font-size: 1px; line-height: 1px;">&nbsp;</td>
                </tr>

                <!-- Loop-Safe Structured News Articles -->
                {{#each news_sources}}
                <tr>
                  <td style="padding-bottom: 10px;">
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="width: 100%; border: 1px solid #cbd5e1; background-color: #ffffff;">
                      <!-- Card Top Metadata Bar -->
                      <tr>
                        <td bgcolor="#f8fafc" style="background-color: #f8fafc; padding: 6px 12px; border-bottom: 1px solid #e2e8f0;">
                          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width: 100%; table-layout: fixed;">
                            <tr>
                              <td align="left" valign="middle" width="430" style="width: 430px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 10px; mso-line-height-rule: exactly; line-height: 14px; color: #475569;">
                                <strong style="color: #1d4ed8; text-transform: uppercase; letter-spacing: 0.3px;">{{source_name}}</strong> &nbsp;&bull;&nbsp; {{published_at}}
                              </td>
                              <td align="right" valign="middle" width="180" style="width: 180px; text-align: right; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 10px; mso-line-height-rule: exactly; line-height: 14px; font-weight: 700;">
                                <a href="{{url}}" target="_blank" style="color: #1d4ed8; text-decoration: underline;">Source Link &#8599;</a>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                      <!-- Card Headline & Summary -->
                      <tr>
                        <td style="padding: 10px 12px;">
                          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                            <tr>
                              <td style="padding-bottom: 5px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 13px; mso-line-height-rule: exactly; line-height: 18px; font-weight: 700; color: #0f172a;">
                                <a href="{{url}}" target="_blank" style="color: #0f172a; text-decoration: none;">{{title}}</a>
                              </td>
                            </tr>
                            <tr>
                              <td style="padding-bottom: 7px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 11px; mso-line-height-rule: exactly; line-height: 16px; color: #334155;">
                                {{{excerpt}}}
                              </td>
                            </tr>
                            <tr>
                              <td style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 11px; mso-line-height-rule: exactly; line-height: 15px; font-weight: 600;">
                                <a href="{{url}}" target="_blank" style="color: #1d4ed8; text-decoration: underline;">Read full advisory at {{source_name}} &#8599;</a>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                {{/each}}

                <!-- Optional Pre-Rendered HTML Articles Slot -->
                <tr>
                  <td style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 12px; mso-line-height-rule: exactly; line-height: 18px; color: #334155;">
                    {{{news_articles}}}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- FOOTER (No TLP Tag, Includes Source Hub Link) -->
          <tr>
            <td class="mobile-pad" bgcolor="#f8fafc" style="background-color: #f8fafc; padding: 12px 22px; border-top: 1px solid #cbd5e1;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width: 100%; table-layout: fixed;">
                <tr>
                  <td align="left" valign="middle" width="430" style="width: 430px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 11px; mso-line-height-rule: exactly; line-height: 15px; font-weight: 700; color: #0f172a;">
                    BA Threat Intelligence
                  </td>
                  <td align="right" valign="middle" width="204" style="width: 204px; text-align: right; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 10px; mso-line-height-rule: exactly; line-height: 14px; font-weight: 700;">
                    <a href="{{sources_hub_url}}" target="_blank" style="color: #1d4ed8; text-decoration: underline;">Threat Intelligence Sources &#8599;</a>
                  </td>
                </tr>
                <tr>
                  <td colspan="2" style="padding-top: 5px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 11px; mso-line-height-rule: exactly; line-height: 15px; color: #64748b;">
                    {{{news_footer}}}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

        </table>

        <!--[if (gte mso 9)|(IE)]>
        </td>
        </tr>
        </table>
        <![endif]-->

      </td>
    </tr>
  </table>

</body>
</html>`;

/**
 * News Studio defaults.
 *
 * Mirrors `DEFAULT_NEWS_EMAIL_TEMPLATE` exactly (system font, slate text, blue
 * accent, square card, no stamp), so the default compile is byte-identical and
 * an operator who never opened the styling tools keeps the shipped layout.
 */
export const DEFAULT_NEWS_EMAIL_CUSTOMIZATION: TemplateCustomization = {
  ...DEFAULT_TEMPLATE_CUSTOMIZATION,
  fontFamily: 'system',
  fontColor: '#1e293b',
  headingColor: '#0f172a',
  accentColor: '#1d4ed8',
  canvasBg: '#f1f5f9',
  cardBg: '#ffffff',
  headerBg: '#f8fafc',
  borderRadius: '1px',
  showStamp: false,
  badgeStampText: 'THREAT BRIEFING',
};

/**
 * Compiles the News Template Studio HTML for the operator's customization.
 *
 * This used to ignore `config` and return the stock markup, so every colour and
 * typography choice made in the studio was dropped: the preview rendered one
 * document while the customization panel reported another. The stock markup is
 * patched with anchored substitutions (structure untouched). Every anchor is
 * asserted, so editing the constant cannot silently ship a half-styled mail.
 *
 * `DEFAULT_NEWS_EMAIL_CUSTOMIZATION` mirrors the stock document exactly, so the
 * default compile is byte-identical to it.
 */
export function compileNewsTemplate(config: TemplateCustomization): string {
  const safe = normalizeDigestConfig({ ...DEFAULT_NEWS_EMAIL_CUSTOMIZATION, ...config });
  const fontFamily = getFontFamilyCss(safe.fontFamily);
  // Tints the stock markup pairs with the accent.
  const isStockAccent = safe.accentColor.toLowerCase() === '#1d4ed8';
  const badgeBg = isStockAccent ? '#dbeafe' : safe.accentColor;
  const badgeBorder = isStockAccent ? '#93c5fd' : safe.accentColor;
  const badgeText = isStockAccent ? '#1e40af' : safe.accentColor;
  const isStockText = safe.fontColor === '#1e293b';
  const mutedText = isStockText ? '#475569' : safe.fontColor;
  const softText = isStockText ? '#334155' : safe.fontColor;
  // The meta line's emphasis keeps its own slate tone at the stock values.
  const metaStrong = isStockText && safe.headingColor === '#0f172a' ? '#1e293b' : safe.headingColor;

  let html = DEFAULT_NEWS_EMAIL_TEMPLATE;
  const apply = (pattern: RegExp, value: string, label: string) => {
    // test() on a /g/ regex advances lastIndex; probe with a fresh copy.
    if (!new RegExp(pattern.source, pattern.flags.replace('g', '')).test(html))
      throw new Error(`News template no longer contains the ${label} anchor`);
    html = html.replace(pattern, value);
  };

  // Stylesheet: font stack and body colours.
  apply(
    /(font-family: )-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;/,
    `$1${fontFamily};`,
    'stylesheet font stack',
  );
  apply(
    /(body \{\n    margin: 0 !important;\n    padding: 0 !important;\n    width: 100% !important;\n    background-color: )#f1f5f9;(\n    color: )#1e293b;/,
    `$1${safe.canvasBg};$2${safe.fontColor};`,
    'stylesheet body rule',
  );
  apply(/(\n  a \{\n    color: )#1d4ed8;/, `$1${safe.accentColor};`, 'stylesheet link colour');
  // <body> element: colours only; its font list keeps the document's own quoting.
  apply(
    /(<body bgcolor=")#f1f5f9(" style="margin: 0; padding: 0; background-color: )#f1f5f9(; font-family: [^;]+; color: )#1e293b;/,
    `$1${safe.canvasBg}$2${safe.canvasBg}$3${safe.fontColor};`,
    'body element',
  );
  // Outer canvas.
  apply(
    /(<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor=")#f1f5f9(" style="background-color: )#f1f5f9;/,
    `$1${safe.canvasBg}$2${safe.canvasBg};`,
    'outer canvas',
  );
  // Main 680px container.
  apply(
    /(<table role="presentation" class="wrapper-table" width="680" cellpadding="0" cellspacing="0" border="0" bgcolor=")#ffffff(" style="width: 680px; max-width: 680px; background-color: )#ffffff(; border: 1px solid #cbd5e1;)/,
    `$1${safe.cardBg}$2${safe.cardBg}$3`.replace(
      '; border: 1px solid #cbd5e1;',
      `; border: ${safe.borderRadius} ${safe.borderStyle} #cbd5e1;`,
    ),
    'main container',
  );
  // Top accent bar.
  apply(
    /(<td height="4" bgcolor=")#1d4ed8(" style="height: 4px; background-color: )#1d4ed8;/,
    `$1${safe.accentColor}$2${safe.accentColor};`,
    'top accent bar',
  );
  // Header band and its muted strap line.
  apply(
    /(<td class="mobile-pad" bgcolor=")#f8fafc(" style="background-color: )#f8fafc(; padding: 16px 22px; border-bottom: 1px solid #cbd5e1;">\n              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width: 100%; table-layout: fixed;">)/,
    `$1${safe.headerBg}$2${safe.headerBg}$3`,
    'header band',
  );
  // Kicker ("BA THREAT INTELLIGENCE") and the subject badge.
  apply(
    /(letter-spacing: 0\.7px; text-transform: uppercase; color: )#1d4ed8;/,
    `$1${safe.accentColor};`,
    'header kicker',
  );
  apply(
    /(<td bgcolor=")#dbeafe(" style="background-color: )#dbeafe(; border: 1px solid )#93c5fd(; color: )#1e40af;/,
    `$1${badgeBg}$2${badgeBg}$3${badgeBorder}$4${badgeText};`,
    'subject badge',
  );
  // Headline and meta line.
  apply(
    /(font-size: 18px; mso-line-height-rule: exactly; line-height: 23px; font-weight: 700; color: )#0f172a;/,
    `$1${safe.headingColor};`,
    'header headline',
  );
  apply(
    /(line-height: 15px; color: )#475569;(">\n\s+<strong style="color: )#1e293b;/,
    `$1${mutedText};$2${metaStrong};`,
    'header meta line',
  );
  // Section numbers and headings.
  apply(
    /(<span style="color: )#1d4ed8(;">0[123]<\/span>)/g,
    `$1${safe.accentColor}$2`,
    'section numbers',
  );
  apply(
    /(line-height: 15px; font-weight: 700; letter-spacing: 0\.5px; text-transform: uppercase; color: )#0f172a;/,
    `$1${safe.headingColor};`,
    'section heading',
  );
  // Article/meta and summary prose.
  apply(
    /(line-height: 18px; color: )#334155;/,
    `$1${softText};`,
    'summary prose',
  );
  // Footer band and its source-hub link.
  apply(
    /(<td class="mobile-pad" bgcolor=")#f8fafc(" style="background-color: )#f8fafc(; padding: 12px 22px; border-top: 1px solid #cbd5e1;">)/,
    `$1${safe.headerBg}$2${safe.headerBg}$3`,
    'footer band',
  );
  apply(
    /(<a href="\{\{sources_hub_url\}\}" target="_blank" style="color: )#1d4ed8;/,
    `$1${safe.accentColor};`,
    'footer source hub link',
  );
  // Per-source links inside the {{#each news_sources}} cards (three per card).
  const sourceLink = /(style="color: )#1d4ed8(; text-decoration: underline;">(?:Source Link|Read full advisory|Source Link &#8599;))/g;
  if (/style="color: #1d4ed8; text-decoration: underline;"/.test(html)) {
    html = html.replace(sourceLink, `$1${safe.accentColor}$2`);
  }
  // Source name emphasis, subject line and excerpt colour.
  apply(
    /(<strong style="color: )#1d4ed8(; text-transform: uppercase; letter-spacing: 0\.3px;">)/,
    `$1${safe.accentColor}$2`,
    'source name',
  );
  apply(
    /(color: )#0f172a(; text-decoration: none;">\{\{title\}\})/,
    `$1${safe.headingColor}$2`,
    'article title link',
  );
  apply(
    /(line-height: 16px; color: )#334155;/,
    `$1${softText};`,
    'article excerpt',
  );

  if (safe.showStamp) {
    apply(
      /(<td class="mobile-pad" bgcolor="[^"]+" style="background-color: [^"]+; padding: 16px 22px; border-bottom: 1px solid #cbd5e1;">)/,
      `$1<div style="font-family:${fontFamily};font-size:10px;line-height:14px;font-weight:700;letter-spacing:1.5px;color:${safe.badgeStampColor};padding-bottom:4px;">${safe.badgeStampText}</div>`,
      'header stamp slot',
    );
  }
  if (safe.showClassificationBanner) {
    apply(
      /(<table role="presentation" class="wrapper-table"[^>]*>)/,
      `<tr><td style="padding:8px 22px;background-color:${safe.canvasBg};color:${safe.fontColor};font-size:10px;line-height:16px;letter-spacing:1px;text-align:center;">${safe.classificationText}</td></tr>$1`,
      'classification banner slot',
    );
  }
  return html;
}

export function renderNewsTemplate(config: TemplateCustomization, parts: NewsTemplateParts, template?: string): string {
  // Without hand-authored HTML, compile the studio markup with the operator's
  // customization instead of shipping the stock document.
  const compiled = template || compileNewsTemplate(config);
  return renderEmailTemplate(compiled, {
    news_title: parts.news_title,
    news_subject_badge_text: parts.news_subject_badge_text,
    news_subject: parts.news_subject,
    news_date: parts.news_date,
    news_count: parts.news_count,
    news_summary: parts.news_summary,
    news_sources: parts.news_sources,
    news_articles: parts.news_articles,
    sources_hub_url: parts.sources_hub_url,
    news_footer: parts.news_footer,
  });
}

export interface NewsSource {
  title: string;
  url: string;
  source_name: string;
  published_at: string;
  excerpt: string;
}

export interface NewsTemplateParts {
  news_title: string;
  news_subject: string;
  news_date: string;
  news_count: number;
  news_summary: string;
  news_articles: string;
  news_footer: string;
  news_subject_badge_text: string;
  news_sources: NewsSource[];
  sources_hub_url: string;
}
