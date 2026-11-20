// src/design/pages.ts
import {
  LayoutDashboard,
  Server,
  ShieldAlert,
  Database,
  FileText,
  Zap,
  Activity,
  Bell,
  Radio,
  Users,
  FileCode,
  Mail,
  Inbox,
  Archive,
  FileCode2,
  Cpu,
  Tags,
  Settings,
  Search,
  PackageSearch,
  BarChart3,
  ScanLine,
  CalendarDays,
  BrainCircuit
} from "lucide-react";
var pages = {
  dashboard: { section: "Operations", title: "Intelligence overview", icon: LayoutDashboard },
  watchlist: { section: "Operations", title: "Monitored products", icon: Server },
  findings: { section: "Operations", title: "Vulnerabilities", icon: ShieldAlert },
  "threat-intelligence-search": { section: "Operations", title: "Threat intelligence search", icon: Search },
  "vulnerability-search": { section: "Operations", title: "Search vulnerability", icon: PackageSearch },
  "threat-data": { section: "Operations", title: "Threat intelligence", icon: Database },
  "threat-analytics": { section: "Operations", title: "Threat analytics & trends", icon: BarChart3 },
  "cpe-matcher": { section: "Operations", title: "CPE matcher & classifier", icon: ScanLine },
  advisories: { section: "Operations", title: "Security advisories", icon: FileText },
  correlation: { section: "Autonomous pipeline", title: "Live correlation", icon: Zap },
  pipeline: { section: "Autonomous pipeline", title: "Pipeline executions", icon: Activity },
  "alerted-cves": { section: "Autonomous pipeline", title: "Sent notification history", icon: Bell },
  feeds: { section: "Autonomous pipeline", title: "Threat feeds", icon: Radio },
  recipients: { section: "Autonomous pipeline", title: "Recipients & webhooks", icon: Users },
  template: { section: "Autonomous pipeline", title: "Email template studio", icon: FileCode },
  "daily-digest": { section: "Autonomous pipeline", title: "Daily digest studio", icon: CalendarDays },
  "news-template": { section: "Autonomous pipeline", title: "News template studio", icon: FileCode },
  emails: { section: "Autonomous pipeline", title: "Delivery log", icon: Mail },
  "email-queue": { section: "Autonomous pipeline", title: "Email queue", icon: Inbox },
  "action-center": { section: "Autonomous pipeline", title: "Email delivery action center", icon: Activity },
  archive: { section: "Archive & retention", title: "Archives & retention", icon: Archive },
  "ml-operations": { section: "System & audit", title: "ML operations", icon: BrainCircuit },
  logs: { section: "System & audit", title: "Audit logs", icon: FileCode2 },
  health: { section: "System & audit", title: "System health", icon: Cpu },
  aliases: { section: "System & audit", title: "Alias thesaurus", icon: Tags },
  settings: { section: "System & audit", title: "Settings", icon: Settings }
};

// src/components/PageHeading.tsx
import { jsx, jsxs } from "react/jsx-runtime";
function PageHeading({
  page,
  children,
  title: customTitle
}) {
  const { section, title, icon: Icon } = pages[page];
  return /* @__PURE__ */ jsxs("div", { className: "ui-page-heading", children: [
    /* @__PURE__ */ jsx("div", { className: "ui-page-eyebrow", children: section }),
    /* @__PURE__ */ jsxs("div", { className: "ui-page-title-row", children: [
      /* @__PURE__ */ jsx("span", { className: "ui-page-icon", children: /* @__PURE__ */ jsx(Icon, { size: 20, strokeWidth: 1.7, "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsx("h1", { id: "page-title", tabIndex: -1, children: customTitle ?? title })
    ] }),
    /* @__PURE__ */ jsx("p", { className: "ui-page-description", children })
  ] });
}

// src/components/AdvisoryTemplateView.tsx
import { useState, useRef, useEffect, useCallback, useMemo } from "react";

// test:context
var useApp = () => globalThis.__templateEditorContext;

// src/utils/clipboard.ts
async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
  }
  const field = document.createElement("textarea");
  field.value = text;
  field.setAttribute("readonly", "");
  field.style.position = "fixed";
  field.style.opacity = "0";
  document.body.appendChild(field);
  field.select();
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    field.remove();
  }
}

// src/components/AdvisoryTemplateView.tsx
import {
  FileCode as FileCode3,
  Send,
  RotateCcw,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  X,
  Type,
  Palette,
  Stamp,
  Sliders,
  Smartphone,
  Monitor,
  Maximize2,
  Minimize2,
  ZoomIn,
  ZoomOut,
  ArrowUp,
  ArrowDown,
  Eye,
  Code2,
  Download,
  Edit3,
  Hash
} from "lucide-react";

// shared/state.ts
var DEFAULT_TIMEZONE = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
})();
var HEAVY_COLLECTION_KINDS = [
  "cveData",
  "findings",
  "advisories",
  "alertedCves",
  "emailLogs",
  "webhookLogs",
  "executions",
  "auditLogs",
  "intelligenceArticles",
  "intelligenceMatches",
  // Audit F-3: digests accumulate one row per vendor/product that ever hit the
  // zero-day cap. Without this they are invisible to capped browsing and to
  // the archive screen's per-kind counts.
  "zeroDayDigests"
];
var COLLECTION_KINDS = [
  "feeds",
  "watchlist",
  "recipients",
  "webhooks",
  "aliases",
  ...HEAVY_COLLECTION_KINDS
];

// src/utils/templateCompiler.ts
var DEFAULT_TEMPLATE_CUSTOMIZATION = {
  fontFamily: "sans",
  fontColor: "#334155",
  headingColor: "#0f172a",
  accentColor: "#dc2626",
  canvasBg: "#f1f5f9",
  cardBg: "#ffffff",
  headerBg: "#0f172a",
  badgeStampText: "BA CYBER SECURITY OPERATIONS",
  badgeStampColor: "#2563eb",
  showStamp: true,
  showClassificationBanner: false,
  classificationText: "",
  borderStyle: "solid",
  borderRadius: "12px"
};
var DEFAULT_DAILY_DIGEST_CUSTOMIZATION = {
  ...DEFAULT_TEMPLATE_CUSTOMIZATION,
  badgeStampText: "DAILY DIGEST"
};

// src/components/AdvisoryTemplateView.tsx
import { jsx as jsx2, jsxs as jsxs2 } from "react/jsx-runtime";
var AdvisoryTemplateView = () => {
  const {
    advisoryTemplate,
    customAdvisoryTemplate,
    settings,
    templateCustomization,
    updateTemplateCustomization,
    sendTestEmail,
    saveTemplate,
    renderAdvisoryPreview,
    error,
    clearError
  } = useApp();
  const [testEmail, setTestEmail] = useState("");
  const [showTestModal, setShowTestModal] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saveToast, setSaveToast] = useState(false);
  const [previewDevice, setPreviewDevice] = useState("desktop");
  const [copiedToken, setCopiedToken] = useState(null);
  const [confirmSave, setConfirmSave] = useState(false);
  const [savingTemplate, setSavingTemplate] = useState(false);
  const [confirmSendTest, setConfirmSendTest] = useState(false);
  const [sendingTest, setSendingTest] = useState(false);
  const [serverPreview, setServerPreview] = useState(null);
  const [previewError, setPreviewError] = useState(null);
  const iframeRef = useRef(null);
  const previewDate = useRef(
    (/* @__PURE__ */ new Date()).toLocaleString("en-GB", {
      day: "numeric",
      month: "long",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    })
  ).current;
  const previewId = useRef(
    `${settings.advisoryPrefix}${(/* @__PURE__ */ new Date()).toLocaleDateString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric"
    }).replace(new RegExp(" ", "g"), "")}-PREVIEW`
  ).current;
  const [iframeHeight, setIframeHeight] = useState(880);
  const [scrollMode, setScrollMode] = useState("fit");
  const [zoomLevel, setZoomLevel] = useState(100);
  const [viewFormat, setViewFormat] = useState("preview");
  const [htmlSubView, setHtmlSubView] = useState("template");
  const [showTokensInCanvas, setShowTokensInCanvas] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [copiedHtml, setCopiedHtml] = useState(false);
  const [customTemplate, setCustomTemplate] = useState("");
  const [isCustomTemplate, setIsCustomTemplate] = useState(false);
  const [editorRef, setEditorRef] = useState(null);
  const isEditingRef = useRef(false);
  useEffect(() => {
    if (isEditingRef.current) return;
    if (customAdvisoryTemplate !== null && customAdvisoryTemplate !== customTemplate) {
      setCustomTemplate(customAdvisoryTemplate);
      setIsCustomTemplate(true);
    }
  }, [customAdvisoryTemplate, customTemplate]);
  const handleEnterEditor = () => {
    if (viewFormat !== "editor" && !isCustomTemplate) {
      setCustomTemplate(customAdvisoryTemplate ?? advisoryTemplate);
      setIsCustomTemplate(customAdvisoryTemplate !== null);
    }
    setViewFormat("editor");
  };
  const handleExitEditor = () => {
    isEditingRef.current = false;
    if (isCustomTemplate) {
      setCustomTemplate("");
      setIsCustomTemplate(false);
    }
    setViewFormat("preview");
  };
  const handleApplyCustomTemplate = async () => {
    const trimmed = customTemplate.trim();
    if (!trimmed) return;
    isEditingRef.current = true;
    try {
      await saveTemplate(trimmed);
      setIsCustomTemplate(true);
      setViewFormat("preview");
    } catch {
    } finally {
      isEditingRef.current = false;
    }
  };
  const tokenList = [
    "{{severity_header_badge}}",
    "{{severity_badge}}",
    "{{advisory_id}}",
    "{{advisory_title}}",
    "{{dispatch_date}}",
    "{{executive_summary}}",
    "{{cve_id_links}}",
    "{{cve_details}}",
    "{{affected_systems_html}}",
    "{{vendor_products_html}}",
    "{{remediation_steps}}",
    "{{remediation_link}}",
    "{{mitigation_steps}}",
    "{{references_link}}",
    "{{references_html}}",
    "{{vendor_link}}",
    "{{advisory_published_date}}",
    "{{recommended_actions}}"
  ];
  const handleInsertToken = (token) => {
    isEditingRef.current = true;
    const el = editorRef;
    if (el) {
      const start = el.selectionStart;
      const end = el.selectionEnd;
      const value = customTemplate;
      setCustomTemplate(value.slice(0, start) + token + value.slice(end));
      setIsCustomTemplate(true);
      const newPos = start + token.length;
      setTimeout(() => {
        el.focus();
        el.setSelectionRange(newPos, newPos);
      }, 0);
    }
  };
  const [toolTab, setToolTab] = useState("colors");
  const syncIframeHeight = useCallback(() => {
    try {
      const iframe = iframeRef.current;
      if (!iframe) return;
      const doc = iframe.contentDocument || iframe.contentWindow?.document;
      if (doc) {
        const h = Math.max(
          doc.documentElement.scrollHeight,
          doc.body.scrollHeight,
          doc.documentElement.offsetHeight,
          doc.body.offsetHeight
        );
        if (h > 200) {
          setIframeHeight(h + 24);
        }
      }
    } catch {
    }
  }, []);
  useEffect(() => {
    const timer = setTimeout(syncIframeHeight, 100);
    return () => clearTimeout(timer);
  }, [templateCustomization, previewDevice, advisoryTemplate, syncIframeHeight]);
  useEffect(() => {
    const source = customAdvisoryTemplate || advisoryTemplate;
    if (!source) return;
    let cancelled = false;
    const timer = setTimeout(() => {
      void renderAdvisoryPreview({ template: source }).then((result) => {
        if (cancelled) return;
        if (result.ok) {
          setServerPreview({ template: source, html: result.html });
          setPreviewError(null);
        } else {
          setPreviewError(result.error);
        }
      });
    }, 400);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [customAdvisoryTemplate, advisoryTemplate, renderAdvisoryPreview]);
  const scrollToIframeTop = () => {
    try {
      iframeRef.current?.contentWindow?.scrollTo({ top: 0, behavior: "smooth" });
    } catch {
    }
  };
  const scrollToIframeBottom = () => {
    try {
      iframeRef.current?.contentWindow?.scrollTo({ top: 99999, behavior: "smooth" });
    } catch {
    }
  };
  const handleDownloadHtml = () => {
    const blob = new Blob([getRenderedHtml()], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-advisory-template-${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1e3);
  };
  const handleCopyRawHtml = async () => {
    if (await copyText(getRenderedHtml())) {
      setCopiedHtml(true);
      setTimeout(() => setCopiedHtml(false), 2e3);
    }
  };
  const getTemplateSource = () => {
    return isCustomTemplate && customTemplate ? customTemplate : advisoryTemplate;
  };
  const getRenderedHtml = () => {
    const {
      accentColor = "#1d4ed8",
      fontColor = "#334155",
      cardBg = "#ffffff",
      headerBg = "#0f172a"
    } = templateCustomization;
    const headerHex = String(headerBg).slice(1);
    const expanded = headerHex.length === 3 ? [...headerHex].map((ch) => ch + ch).join("") : headerHex;
    const luminance = [0, 2, 4].map((offset) => parseInt(expanded.slice(offset, offset + 2), 16) / 255).map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4).reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
    const headerText = luminance > 0.179 ? "#0f172a" : "#ffffff";
    const headerMuted = luminance > 0.179 ? "#334155" : "#cbd5e1";
    const headerBanner = `
      <div style="background:${headerBg};padding:20px 32px;box-shadow:0 1px 3px rgba(0,0,0,0.2);font-family:'Plus Jakarta Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
        <div style="font-size:10px;font-weight:bold;letter-spacing:1.5px;color:${headerMuted};margin-bottom:8px;">
          THREAT INTELLIGENCE &amp; BA CYBER SECURITY OPERATIONS
        </div>
        <div style="font-size:24px;line-height:30px;font-weight:bold;color:${headerText};margin-bottom:6px;">
          Security Advisory
        </div>
        <div style="font-size:16px;line-height:22px;font-weight:600;color:${headerText};margin-bottom:8px;">
          {{advisory_title}}
        </div>
        <div style="font-size:12px;line-height:18px;color:${headerMuted};">
          Advisory ID: {{advisory_id}}<br>Report Generated: {{dispatch_date}}
        </div>
      </div>
    `;
    const source = isCustomTemplate && customTemplate ? customTemplate : advisoryTemplate;
    const hasExistingHeader = /<td\s+bgcolor=/i.test(source);
    let html = source.replace(
      /<td bgcolor="#[0-9a-f]{6}" style="padding:20px 32px;box-shadow:0 1px 3px rgba\(0,0,0,0\.2\);">/,
      `<td bgcolor="${headerBg}" style="padding:20px 32px;box-shadow:0 1px 3px rgba(0,0,0,0.2);">`
    );
    html = html.replace(
      /<div style="font-size:10px;font-weight:bold;letter-spacing:1\.5px;color:#[0-9a-f]{6};margin-bottom:8px;">/,
      `<div style="font-size:10px;font-weight:bold;letter-spacing:1.5px;color:${headerMuted};margin-bottom:8px;">`
    );
    html = html.replace(
      /<div class="title" style="font-size:24px;line-height:30px;font-weight:bold;color:#[0-9a-f]{6};margin-bottom:6px;">/,
      `<div class="title" style="font-size:24px;line-height:30px;font-weight:bold;color:${headerText};margin-bottom:6px;">`
    );
    html = html.replace(
      /<div style="font-size:16px;line-height:22px;font-weight:600;color:#[0-9a-f]{6};margin-bottom:8px;">/,
      `<div style="font-size:16px;line-height:22px;font-weight:600;color:${headerText};margin-bottom:8px;">`
    );
    const previewValues = {
      advisory_title: "Example advisory \u2014 template preview only",
      remediation_link: "https://example.com",
      severity: "HIGH"
    };
    const isPreviewTruthy = (key) => previewValues[key] !== void 0 && previewValues[key] !== null && previewValues[key] !== "";
    const SEVERITY_COLORS = {
      CRITICAL: "#ef4444",
      HIGH: "#f59e0b",
      MEDIUM: "#eab308",
      LOW: "#10b981",
      UNKNOWN: "#6b7280"
    };
    const previewSeverityColor = SEVERITY_COLORS[previewValues.severity] ?? SEVERITY_COLORS.UNKNOWN;
    const LINK_COLOR = "#1d4ed8";
    let processed = !hasExistingHeader ? headerBanner + html : html;
    processed = processed.replace(
      /\{\{#if\s+([a-z_]+)\}\}([\s\S]*?)\{\{else\}\}([\s\S]*?)\{\{\/if\}\}/g,
      (_, key, ifBranch, elseBranch) => isPreviewTruthy(key) ? ifBranch : elseBranch
    );
    processed = processed.replace(
      /\{\{#if\s+([a-z_]+)\}\}([\s\S]*?)\{\{\/if\}\}/g,
      (_, key, content) => isPreviewTruthy(key) ? content : ""
    );
    return processed.replace(/{{severity}}/g, "HIGH").replace(/{{severity_text}}/g, "High").replace(
      /{{severity_header_badge}}/g,
      `<span style="display:inline-block;padding:4px 10px;border-radius:4px;background:${previewSeverityColor};color:#ffffff;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px;">HIGH SEVERITY</span>`
    ).replace(
      /{{severity_badge}}/g,
      `<span style="display:inline-block;padding:4px 10px;border-radius:4px;background:${previewSeverityColor};color:#ffffff;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px;">HIGH</span>`
    ).replace(/{{advisory_id}}/g, previewId).replace(/{{advisory_title}}/g, "Example advisory \u2014 template preview only").replace(/{{dispatch_date}}/g, previewDate).replace(
      /{{executive_summary}}/g,
      "A high-severity security advisory has been identified affecting assets within the monitored environment. Security teams should assess applicability, determine potential exposure, and prioritize remediation in accordance with established vulnerability management and change control procedures."
    ).replace(
      /{{cve_id_links}}/g,
      `<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" style="display:inline-block;margin:0 8px 4px 0;color:${LINK_COLOR};text-decoration:underline;">CVE-2026-0001</a>, <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0002" style="display:inline-block;margin:0 8px 4px 0;color:${LINK_COLOR};text-decoration:underline;">CVE-2026-0002</a>`
    ).replace(
      /{{affected_systems_html}}/g,
      `<div style="margin:0 0 8px;font-size:12px;line-height:19px;color:${fontColor};">Example inventory asset 1</div>
<div style="margin:0 0 8px;font-size:12px;line-height:19px;color:${fontColor};">Example inventory asset 2</div>`
    ).replace(
      /{{vendor_products_html}}/g,
      `<div style="margin:0 0 8px;padding:0 0 8px;border-bottom:1px solid #e2e8f0;font-size:12px;line-height:19px;color:${fontColor};"><strong>VendorCorp - ProductSuite</strong><br>Affected versions: &gt;= 4.2 and &lt; 4.8</div>
<div style="margin:0 0 8px;padding:0 0 8px;border-bottom:1px solid #e2e8f0;font-size:12px;line-height:19px;color:${fontColor};"><strong>AnotherVendor - ProductLine</strong><br>Affected versions: 10.1 through 10.4</div>`
    ).replace(
      /{{cve_details}}/g,
      `<div style="margin:0 0 16px;padding:16px;border:1px solid #e2e8f0;border-radius:4px;background:${cardBg};"><div style="font-size:14px;font-weight:bold;line-height:20px;"><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" style="color:${LINK_COLOR};text-decoration:underline;">CVE-2026-0001</a></div><p style="margin:8px 0 0;font-size:12px;line-height:19px;color:${fontColor};">A remotely exploitable vulnerability affects the listed product versions.</p><div style="margin:8px 0 0;font-size:11px;line-height:17px;"><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" style="color:${LINK_COLOR};text-decoration:underline;">NVD</a> &nbsp;\xB7&nbsp; <a href="https://example.com" style="color:${LINK_COLOR};text-decoration:underline;">Vendor advisory</a></div></div>`
    ).replace(
      /{{remediation_steps}}/g,
      `<p style="margin:0 0 10px;font-size:12px;line-height:19px;color:${fontColor};">Review vendor guidance and validate remediation through your change process.</p><div style="margin:0 0 12px;padding:12px 14px;border:1px solid #e2e8f0;border-radius:4px;background:${cardBg};"><strong><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" style="color:${LINK_COLOR};text-decoration:underline;">CVE-2026-0001</a></strong><ul style="margin:6px 0 0;padding-left:20px;font-size:12px;line-height:19px;color:${fontColor};"><li>Confirm affected versions with the vendor.</li><li>Apply a tested vendor-supported fix.</li><li>Rescan affected systems and record the outcome.</li></ul><p style="margin:8px 0 0;font-size:12px;"><a href="https://example.com/patch-guidance" style="color:${LINK_COLOR};text-decoration:underline;">Vendor patch</a></p></div><div style="margin:0 0 12px;padding:12px 14px;border:1px solid #e2e8f0;border-radius:4px;background:${cardBg};"><strong><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0002" style="color:${LINK_COLOR};text-decoration:underline;">CVE-2026-0002</a></strong><ul style="margin:6px 0 0;padding-left:20px;font-size:12px;line-height:19px;color:${fontColor};"><li>Disable the vulnerable feature until the vendor update is deployed.</li><li>Verify service health after remediation.</li></ul></div>`
    ).replace(
      /{{mitigation_steps}}/g,
      "<ul>\n<li>Review and limit administrative access to trusted networks.</li>\n<li>Monitor affected services for anomalous activity following the advisory window.</li>\n<li>Apply compensating controls if vendor patches are not yet deployable.</li>\n</ul>"
    ).replace(
      /{{recommended_actions}}/g,
      "<ul>\n<li>Inventory all affected systems identified in this advisory.</li>\n<li>Apply vendor patches immediately following your change management process.</li>\n<li>Validate backup, restore, and operational functionality after remediation.</li>\n</ul>"
    ).replace(/{{vendor_link}}/g, "https://example.com").replace(/{{advisory_published_date}}/g, previewDate).replace(/{{remediation_link}}/g, "https://example.com/patch-guidance").replace(
      /{{references_html}}/g,
      `<div><a href="https://example.com/vendor-advisory" target="_blank" rel="noopener noreferrer" style="color:${LINK_COLOR};text-decoration:underline;">Vendor advisory for CVE-2026-0001</a></div>
<div><a href="https://example.com/vendor-advisory-2" target="_blank" rel="noopener noreferrer" style="color:${LINK_COLOR};text-decoration:underline;">Vendor advisory for CVE-2026-0002</a></div>`
    ).replace(/{{references_link}}/g, "https://example.com/vendor-advisory");
  };
  const currentTemplateSource = customAdvisoryTemplate || advisoryTemplate;
  const usingBuiltInTemplate = !customAdvisoryTemplate;
  const previewHtml = serverPreview && serverPreview.template === currentTemplateSource ? serverPreview.html : getRenderedHtml();
  const HEX_COLOR_RE = /^#[0-9a-f]{6}$/i;
  const COLOR_FIELD_LABELS = {
    canvasBg: "Canvas Background",
    cardBg: "Card Background",
    headerBg: "Header Banner Bg",
    accentColor: "Link Color",
    headingColor: "Heading Color",
    fontColor: "Font Color",
    badgeStampColor: "Badge/Stamp Color"
  };
  const getInvalidColorFields = () => Object.keys(COLOR_FIELD_LABELS).filter((key) => {
    const value = templateCustomization[key];
    return typeof value !== "string" || !HEX_COLOR_RE.test(value);
  });
  const saveValidationError = useMemo(() => {
    const invalid = getInvalidColorFields();
    return invalid.length ? `Fix the color value${invalid.length > 1 ? "s" : ""} for: ${invalid.map((key) => COLOR_FIELD_LABELS[key]).join(", ")}. Colors must be a 6-digit hex code like #09090b.` : null;
  }, [templateCustomization]);
  const handleSave = () => {
    clearError();
    setConfirmSave(true);
  };
  const confirmSaveAction = async () => {
    if (savingTemplate || saveValidationError) return;
    setSavingTemplate(true);
    try {
      const ok = await saveTemplate(isCustomTemplate ? customTemplate : void 0);
      if (!ok) {
        return;
      }
      if (!isCustomTemplate) {
        setCustomTemplate("");
        setIsCustomTemplate(false);
      }
      setViewFormat("preview");
      setConfirmSave(false);
      setSaveToast(true);
      setTimeout(() => setSaveToast(false), 2500);
    } finally {
      setSavingTemplate(false);
      isEditingRef.current = false;
    }
  };
  const handleReset = () => {
    setShowResetConfirm(true);
  };
  const confirmReset = () => {
    updateTemplateCustomization(DEFAULT_TEMPLATE_CUSTOMIZATION);
    setShowResetConfirm(false);
  };
  const handleSendTest = (event) => {
    event.preventDefault();
    setConfirmSendTest(true);
  };
  const confirmSendTestAction = async () => {
    if (sendingTest) return;
    setSendingTest(true);
    try {
      const rendered = getRenderedHtml();
      const unrenderedTokens = rendered.match(/\{\{[a-z_]+\}\}/g);
      if (unrenderedTokens && unrenderedTokens.length > 0) {
        setTestResult({
          success: false,
          message: `Template has unrendered tokens in preview: ${[...new Set(unrenderedTokens)].join(", ")}. Check the HTML source or token list.`
        });
        setConfirmSendTest(false);
        return;
      }
      const res = await sendTestEmail(testEmail, false, rendered);
      setTestResult(res);
      setConfirmSendTest(false);
      if (res.success) {
        setTimeout(() => {
          setShowTestModal(false);
          setTestResult(null);
        }, 1500);
      }
    } catch (error2) {
      setTestResult({
        success: false,
        message: error2 instanceof Error ? error2.message : "Test email could not be queued."
      });
      setConfirmSendTest(false);
    } finally {
      setSendingTest(false);
    }
  };
  const handleCopyToken = async (token) => {
    if (await copyText(token)) {
      setCopiedToken(token);
      setTimeout(() => setCopiedToken(null), 1800);
    }
  };
  return /* @__PURE__ */ jsxs2("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxs2("div", { className: "ui-page-header", children: [
      /* @__PURE__ */ jsx2(PageHeading, { page: "template", children: "Design clear, professional security advisories. Preview desktop and mobile layouts, customize your branding, then save to apply the template to future notifications." }),
      /* @__PURE__ */ jsxs2("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxs2(
          "button",
          {
            onClick: handleReset,
            className: "text-xs px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium transition flex items-center space-x-1",
            children: [
              /* @__PURE__ */ jsx2(RotateCcw, { className: "w-3.5 h-3.5" }),
              /* @__PURE__ */ jsx2("span", { children: "Professional Default" })
            ]
          }
        ),
        /* @__PURE__ */ jsxs2(
          "button",
          {
            onClick: () => {
              setTestResult(null);
              setShowTestModal(true);
            },
            disabled: confirmSave || confirmSendTest,
            className: "text-xs px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-semibold transition flex items-center space-x-1.5",
            children: [
              /* @__PURE__ */ jsx2(Send, { className: "w-3.5 h-3.5" }),
              /* @__PURE__ */ jsx2("span", { children: "Send Test Email" })
            ]
          }
        ),
        /* @__PURE__ */ jsx2(
          "button",
          {
            onClick: handleSave,
            disabled: confirmSave || confirmSendTest,
            className: "text-xs px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition shadow-sm",
            children: saveToast ? "Applied to All Notifications!" : "Save & Apply to Notifications"
          }
        )
      ] })
    ] }),
    /* @__PURE__ */ jsxs2("div", { className: "ui-panel bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 shadow-sm space-y-4 transition-colors", children: [
      /* @__PURE__ */ jsxs2("div", { className: "flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-200 pb-3", children: [
        /* @__PURE__ */ jsxs2("div", { className: "flex min-w-0 max-w-full overflow-x-auto items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-1 rounded-xl", children: [
          /* @__PURE__ */ jsxs2(
            "button",
            {
              onClick: () => setToolTab("colors"),
              className: `px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${toolTab === "colors" ? "bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold" : "text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"}`,
              children: [
                /* @__PURE__ */ jsx2(Palette, { className: "w-3.5 h-3.5" }),
                /* @__PURE__ */ jsx2("span", { children: "Background & Colors" })
              ]
            }
          ),
          /* @__PURE__ */ jsxs2(
            "button",
            {
              onClick: () => setToolTab("typography"),
              className: `px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${toolTab === "typography" ? "bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold" : "text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"}`,
              children: [
                /* @__PURE__ */ jsx2(Type, { className: "w-3.5 h-3.5" }),
                /* @__PURE__ */ jsx2("span", { children: "Font Style & Typography" })
              ]
            }
          ),
          /* @__PURE__ */ jsxs2(
            "button",
            {
              onClick: () => setToolTab("stamps"),
              className: `px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${toolTab === "stamps" ? "bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold" : "text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"}`,
              children: [
                /* @__PURE__ */ jsx2(Stamp, { className: "w-3.5 h-3.5" }),
                /* @__PURE__ */ jsx2("span", { children: "Drawing Objects & Stamps" })
              ]
            }
          ),
          /* @__PURE__ */ jsxs2(
            "button",
            {
              onClick: () => setToolTab("tokens"),
              className: `px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${toolTab === "tokens" ? "bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold" : "text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"}`,
              children: [
                /* @__PURE__ */ jsx2(Sliders, { className: "w-3.5 h-3.5" }),
                /* @__PURE__ */ jsx2("span", { children: "Dynamic Tokens" })
              ]
            }
          )
        ] }),
        /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-1 rounded-xl", children: [
          /* @__PURE__ */ jsx2(
            "button",
            {
              onClick: () => setPreviewDevice("desktop"),
              className: `p-1.5 rounded-lg transition ${previewDevice === "desktop" ? "bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm" : "text-zinc-500 hover:text-zinc-300"}`,
              title: "Desktop View (680px)",
              children: /* @__PURE__ */ jsx2(Monitor, { className: "w-4 h-4" })
            }
          ),
          /* @__PURE__ */ jsx2(
            "button",
            {
              onClick: () => setPreviewDevice("mobile"),
              className: `p-1.5 rounded-lg transition ${previewDevice === "mobile" ? "bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm" : "text-zinc-500 hover:text-zinc-300"}`,
              title: "Mobile Client View (390px)",
              children: /* @__PURE__ */ jsx2(Smartphone, { className: "w-4 h-4" })
            }
          )
        ] })
      ] }),
      toolTab === "colors" && /* @__PURE__ */ jsxs2("div", { className: "grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs", children: [
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsx2("label", { className: "block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5", children: "Canvas Background" }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "color",
                value: templateCustomization.canvasBg,
                onChange: (e) => updateTemplateCustomization({ canvasBg: e.target.value }),
                className: "w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
              }
            ),
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "text",
                value: templateCustomization.canvasBg,
                onChange: (e) => updateTemplateCustomization({ canvasBg: e.target.value }),
                className: "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
              }
            )
          ] }),
          /* @__PURE__ */ jsx2("div", { className: "flex gap-1.5 mt-2", children: ["#09090b", "#0b0f19", "#18181b", "#f8fafc"].map((c) => /* @__PURE__ */ jsx2(
            "button",
            {
              onClick: () => updateTemplateCustomization({ canvasBg: c }),
              className: "w-5 h-5 rounded-md border border-zinc-700",
              style: { backgroundColor: c }
            },
            c
          )) })
        ] }),
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsx2("label", { className: "block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5", children: "Card Background" }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "color",
                value: templateCustomization.cardBg,
                onChange: (e) => updateTemplateCustomization({ cardBg: e.target.value }),
                className: "w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
              }
            ),
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "text",
                value: templateCustomization.cardBg,
                onChange: (e) => updateTemplateCustomization({ cardBg: e.target.value }),
                className: "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
              }
            )
          ] }),
          /* @__PURE__ */ jsx2("div", { className: "flex gap-1.5 mt-2", children: ["#18181b", "#1e293b", "#27272a", "#ffffff"].map((c) => /* @__PURE__ */ jsx2(
            "button",
            {
              onClick: () => updateTemplateCustomization({ cardBg: c }),
              className: "w-5 h-5 rounded-md border border-zinc-700",
              style: { backgroundColor: c }
            },
            c
          )) })
        ] }),
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsx2("label", { className: "block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5", children: "Header Banner Bg" }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "color",
                value: templateCustomization.headerBg,
                onChange: (e) => updateTemplateCustomization({ headerBg: e.target.value }),
                className: "w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
              }
            ),
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "text",
                value: templateCustomization.headerBg,
                onChange: (e) => updateTemplateCustomization({ headerBg: e.target.value }),
                className: "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
              }
            )
          ] }),
          /* @__PURE__ */ jsx2("div", { className: "flex gap-1.5 mt-2", children: ["#1e293b", "#09090b", "#312e81", "#450a0a"].map((c) => /* @__PURE__ */ jsx2(
            "button",
            {
              onClick: () => updateTemplateCustomization({ headerBg: c }),
              className: "w-5 h-5 rounded-md border border-zinc-700",
              style: { backgroundColor: c }
            },
            c
          )) })
        ] }),
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsx2("label", { className: "block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5", children: "Link Color" }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "color",
                value: templateCustomization.accentColor,
                onChange: (e) => updateTemplateCustomization({ accentColor: e.target.value }),
                className: "w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
              }
            ),
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "text",
                value: templateCustomization.accentColor,
                onChange: (e) => updateTemplateCustomization({ accentColor: e.target.value }),
                className: "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
              }
            )
          ] }),
          /* @__PURE__ */ jsx2("div", { className: "flex gap-1.5 mt-2", children: ["#3b82f6", "#10b981", "#8b5cf6", "#ef4444"].map((c) => /* @__PURE__ */ jsx2(
            "button",
            {
              onClick: () => updateTemplateCustomization({ accentColor: c }),
              className: "w-5 h-5 rounded-md border border-zinc-700",
              style: { backgroundColor: c }
            },
            c
          )) })
        ] })
      ] }),
      toolTab === "typography" && /* @__PURE__ */ jsxs2("div", { className: "grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs", children: [
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsx2("label", { className: "block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5", children: "Font Style / Family" }),
          /* @__PURE__ */ jsxs2(
            "select",
            {
              value: templateCustomization.fontFamily,
              onChange: (e) => updateTemplateCustomization({
                fontFamily: e.target.value
              }),
              className: "w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-3 py-2 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-medium",
              children: [
                /* @__PURE__ */ jsx2("option", { value: "sans", children: "Plus Jakarta Sans / Modern" }),
                /* @__PURE__ */ jsx2("option", { value: "mono", children: "JetBrains Mono / Technical" }),
                /* @__PURE__ */ jsx2("option", { value: "serif", children: "Georgia / Editorial Serif" }),
                /* @__PURE__ */ jsx2("option", { value: "system", children: "System Clean / Native" })
              ]
            }
          )
        ] }),
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsx2("label", { className: "block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5", children: "Heading Font Color" }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "color",
                value: templateCustomization.headingColor,
                onChange: (e) => updateTemplateCustomization({ headingColor: e.target.value }),
                className: "w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
              }
            ),
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "text",
                value: templateCustomization.headingColor,
                onChange: (e) => updateTemplateCustomization({ headingColor: e.target.value }),
                className: "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
              }
            )
          ] })
        ] }),
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsx2("label", { className: "block text-zinc-400 font-mono mb-1.5", children: "Body Font Color" }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "color",
                value: templateCustomization.fontColor,
                onChange: (e) => updateTemplateCustomization({ fontColor: e.target.value }),
                className: "w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
              }
            ),
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "text",
                value: templateCustomization.fontColor,
                onChange: (e) => updateTemplateCustomization({ fontColor: e.target.value }),
                className: "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
              }
            )
          ] })
        ] }),
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsx2("label", { className: "block text-zinc-400 font-mono mb-1.5", children: "Border Style & Radius" }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsxs2(
              "select",
              {
                value: templateCustomization.borderStyle,
                onChange: (e) => updateTemplateCustomization({ borderStyle: e.target.value }),
                className: "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2 py-1.5 text-zinc-200 text-xs flex-1",
                children: [
                  /* @__PURE__ */ jsx2("option", { value: "solid", children: "Solid Border" }),
                  /* @__PURE__ */ jsx2("option", { value: "dashed", children: "Dashed Border" }),
                  /* @__PURE__ */ jsx2("option", { value: "none", children: "No Border" })
                ]
              }
            ),
            /* @__PURE__ */ jsxs2(
              "select",
              {
                value: templateCustomization.borderRadius,
                onChange: (e) => updateTemplateCustomization({ borderRadius: e.target.value }),
                className: "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2 py-1.5 text-zinc-200 text-xs",
                children: [
                  /* @__PURE__ */ jsx2("option", { value: "0px", children: "Sharp (0px)" }),
                  /* @__PURE__ */ jsx2("option", { value: "8px", children: "Round (8px)" }),
                  /* @__PURE__ */ jsx2("option", { value: "12px", children: "Pill (12px)" }),
                  /* @__PURE__ */ jsx2("option", { value: "20px", children: "Curved (20px)" })
                ]
              }
            )
          ] })
        ] })
      ] }),
      toolTab === "stamps" && /* @__PURE__ */ jsxs2("div", { className: "grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 text-xs", children: [
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center justify-between mb-1.5", children: [
            /* @__PURE__ */ jsx2("label", { className: "text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono", children: "Security Stamp Object" }),
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "checkbox",
                checked: templateCustomization.showStamp,
                onChange: (e) => updateTemplateCustomization({ showStamp: e.target.checked }),
                className: "rounded border-zinc-700 text-zinc-200"
              }
            )
          ] }),
          /* @__PURE__ */ jsx2(
            "input",
            {
              type: "text",
              value: templateCustomization.badgeStampText,
              onChange: (e) => updateTemplateCustomization({ badgeStampText: e.target.value }),
              placeholder: "e.g. OFFICIAL SECURITY BULLETIN",
              disabled: !templateCustomization.showStamp,
              className: "w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-3 py-2 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 disabled:opacity-40 font-mono text-xs"
            }
          ),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-1.5 mt-2", children: [
            /* @__PURE__ */ jsx2("span", { className: "text-[11px] text-zinc-500 font-mono", children: "Presets:" }),
            ["CONFIDENTIAL", "URGENT ACTION", "OFFICIAL BULLETIN", "CSAF VEX"].map((t) => /* @__PURE__ */ jsx2(
              "button",
              {
                onClick: () => updateTemplateCustomization({ badgeStampText: t }),
                className: "px-2 py-0.5 rounded bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 text-[10px] font-mono hover:bg-zinc-700",
                children: t
              },
              t
            ))
          ] })
        ] }),
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsx2("label", { className: "block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5", children: "Stamp Color" }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "color",
                value: templateCustomization.badgeStampColor,
                onChange: (e) => updateTemplateCustomization({ badgeStampColor: e.target.value }),
                disabled: !templateCustomization.showStamp,
                className: "w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0 disabled:opacity-40"
              }
            ),
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "text",
                value: templateCustomization.badgeStampColor,
                onChange: (e) => updateTemplateCustomization({ badgeStampColor: e.target.value }),
                disabled: !templateCustomization.showStamp,
                className: "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1 disabled:opacity-40"
              }
            )
          ] }),
          /* @__PURE__ */ jsx2("div", { className: "flex gap-1.5 mt-2", children: ["#ef4444", "#f59e0b", "#10b981", "#6366f1"].map((c) => /* @__PURE__ */ jsx2(
            "button",
            {
              onClick: () => updateTemplateCustomization({ badgeStampColor: c }),
              className: "w-5 h-5 rounded-md border border-zinc-700",
              style: { backgroundColor: c }
            },
            c
          )) })
        ] }),
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center justify-between mb-1.5", children: [
            /* @__PURE__ */ jsx2("label", { className: "text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono", children: "Classification Banner" }),
            /* @__PURE__ */ jsx2(
              "input",
              {
                type: "checkbox",
                checked: templateCustomization.showClassificationBanner,
                onChange: (e) => updateTemplateCustomization({ showClassificationBanner: e.target.checked }),
                className: "rounded border-zinc-700 text-zinc-200"
              }
            )
          ] }),
          /* @__PURE__ */ jsx2(
            "input",
            {
              type: "text",
              value: templateCustomization.classificationText,
              onChange: (e) => updateTemplateCustomization({ classificationText: e.target.value }),
              disabled: !templateCustomization.showClassificationBanner,
              className: "w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-3 py-2 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 disabled:opacity-40 font-mono text-xs"
            }
          ),
          /* @__PURE__ */ jsx2("span", { className: "text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono block mt-1", children: "Rendered across the top edge of email notices" })
        ] })
      ] }),
      toolTab === "tokens" && /* @__PURE__ */ jsxs2("div", { className: "flex flex-wrap items-center gap-2 text-xs", children: [
        /* @__PURE__ */ jsx2("span", { className: "text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono text-[11px] font-medium", children: "Click to Copy:" }),
        [
          "{{severity_header_badge}}",
          "{{severity_badge}}",
          "{{advisory_id}}",
          "{{advisory_title}}",
          "{{severity}}",
          "{{dispatch_date}}",
          "{{executive_summary}}",
          "{{cve_id_links}}",
          "{{affected_systems_html}}",
          "{{vendor_products_html}}",
          "{{cve_details}}",
          "{{remediation_steps}}",
          "{{remediation_link}}",
          "{{mitigation_steps}}",
          "{{references_link}}",
          "{{recommended_actions}}",
          "{{vendor_link}}"
        ].map((token) => /* @__PURE__ */ jsxs2(
          "button",
          {
            onClick: () => handleCopyToken(token),
            className: "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 px-2.5 py-1 rounded-lg text-[11px] font-mono hover:border-zinc-600 transition flex items-center space-x-1",
            title: "Click to copy token",
            children: [
              /* @__PURE__ */ jsx2("span", { children: token }),
              copiedToken === token && /* @__PURE__ */ jsx2(Check, { className: "w-3 h-3 text-emerald-400" })
            ]
          },
          token
        ))
      ] })
    ] }),
    /* @__PURE__ */ jsxs2("div", { className: "ui-panel bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm space-y-4 transition-colors", children: [
      /* @__PURE__ */ jsxs2("div", { className: "flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 pb-3.5", children: [
        /* @__PURE__ */ jsxs2("div", { className: "flex flex-wrap items-center gap-2.5", children: [
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsx2(FileCode3, { className: "w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" }),
            /* @__PURE__ */ jsx2("h2", { className: "text-xs font-bold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider font-mono", children: "HTML Template" })
          ] }),
          /* @__PURE__ */ jsxs2("span", { className: "text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/40 text-emerald-300 border border-emerald-800/60 flex items-center space-x-1.5", children: [
            /* @__PURE__ */ jsx2("span", { className: "w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" }),
            /* @__PURE__ */ jsx2("span", { children: "Live Rendering Active" })
          ] }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-0.5 rounded-xl ml-2", children: [
            /* @__PURE__ */ jsxs2(
              "button",
              {
                type: "button",
                onClick: () => setViewFormat("preview"),
                className: `px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${viewFormat === "preview" ? "bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm" : "text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"}`,
                children: [
                  /* @__PURE__ */ jsx2(Eye, { className: "w-3.5 h-3.5" }),
                  /* @__PURE__ */ jsx2("span", { children: "Visual Canvas" })
                ]
              }
            ),
            /* @__PURE__ */ jsxs2(
              "button",
              {
                type: "button",
                onClick: handleEnterEditor,
                className: `px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${viewFormat === "editor" ? "bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm" : "text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"}`,
                children: [
                  /* @__PURE__ */ jsx2(Edit3, { className: "w-3.5 h-3.5" }),
                  /* @__PURE__ */ jsx2("span", { children: "Template Editor" })
                ]
              }
            ),
            /* @__PURE__ */ jsxs2(
              "button",
              {
                type: "button",
                onClick: () => setViewFormat("html"),
                className: `px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${viewFormat === "html" ? "bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm" : "text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"}`,
                children: [
                  /* @__PURE__ */ jsx2(Code2, { className: "w-3.5 h-3.5" }),
                  /* @__PURE__ */ jsx2("span", { children: "HTML Code" })
                ]
              }
            )
          ] })
        ] }),
        /* @__PURE__ */ jsxs2("div", { className: "flex flex-wrap items-center gap-2 text-xs", children: [
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-0.5 rounded-xl", children: [
            /* @__PURE__ */ jsx2(
              "button",
              {
                type: "button",
                onClick: () => setScrollMode("fit"),
                className: `px-2.5 py-1 rounded-lg text-[11px] font-mono transition ${scrollMode === "fit" ? "bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm font-semibold" : "text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"}`,
                title: "Auto-Fit Full Height: Automatically expands iframe height to eliminate inner scrollbars and scroll trapping.",
                children: "Auto-Fit Flow"
              }
            ),
            /* @__PURE__ */ jsx2(
              "button",
              {
                type: "button",
                onClick: () => setScrollMode("contained"),
                className: `px-2.5 py-1 rounded-lg text-[11px] font-mono transition ${scrollMode === "contained" ? "bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm font-semibold" : "text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"}`,
                title: "Contained Viewport: Fixed 640px height with device frame and quick scroll controls.",
                children: "Fixed Viewport"
              }
            )
          ] }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-0.5 rounded-xl font-mono text-[11px]", children: [
            /* @__PURE__ */ jsx2(
              "button",
              {
                type: "button",
                onClick: () => setZoomLevel((prev) => Math.max(65, prev - 10)),
                className: "p-1 text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900",
                title: "Zoom Out",
                children: /* @__PURE__ */ jsx2(ZoomOut, { className: "w-3.5 h-3.5" })
              }
            ),
            /* @__PURE__ */ jsxs2("span", { className: "px-1 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 min-w-[34px] text-center", children: [
              zoomLevel,
              "%"
            ] }),
            /* @__PURE__ */ jsx2(
              "button",
              {
                type: "button",
                onClick: () => setZoomLevel((prev) => Math.min(130, prev + 10)),
                className: "p-1 text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900",
                title: "Zoom In",
                children: /* @__PURE__ */ jsx2(ZoomIn, { className: "w-3.5 h-3.5" })
              }
            ),
            zoomLevel !== 100 && /* @__PURE__ */ jsx2(
              "button",
              {
                type: "button",
                onClick: () => setZoomLevel(100),
                className: "text-[10px] text-zinc-500 hover:text-zinc-300 dark:text-zinc-500 dark:hover:text-zinc-300 light:text-zinc-600 light:hover:text-zinc-800 px-1 border-l border-zinc-800 dark:border-zinc-800 light:border-zinc-300",
                children: "Reset"
              }
            )
          ] }),
          /* @__PURE__ */ jsx2(
            "button",
            {
              type: "button",
              onClick: handleCopyRawHtml,
              className: "p-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 transition",
              title: "Copy Rendered HTML Code",
              children: copiedHtml ? /* @__PURE__ */ jsx2(Check, { className: "w-3.5 h-3.5 text-emerald-400" }) : /* @__PURE__ */ jsx2(Copy, { className: "w-3.5 h-3.5" })
            }
          ),
          /* @__PURE__ */ jsx2(
            "button",
            {
              type: "button",
              onClick: handleDownloadHtml,
              className: "p-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 transition",
              title: "Download Advisory HTML File",
              children: /* @__PURE__ */ jsx2(Download, { className: "w-3.5 h-3.5" })
            }
          ),
          /* @__PURE__ */ jsx2(
            "button",
            {
              type: "button",
              onClick: () => setIsFullscreen(true),
              className: "p-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 transition",
              title: "Fullscreen Template Studio",
              children: /* @__PURE__ */ jsx2(Maximize2, { className: "w-3.5 h-3.5" })
            }
          ),
          /* @__PURE__ */ jsxs2(
            "button",
            {
              type: "button",
              onClick: () => setShowTokensInCanvas(!showTokensInCanvas),
              className: `p-1.5 rounded-xl flex items-center space-x-1.5 text-xs font-mono transition ${showTokensInCanvas ? "bg-blue-600/20 border border-blue-600 text-blue-300" : "bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700"}`,
              title: showTokensInCanvas ? "Show rendered preview" : "Show token placeholders in canvas",
              children: [
                /* @__PURE__ */ jsx2(Hash, { className: "w-3.5 h-3.5" }),
                /* @__PURE__ */ jsx2("span", { children: "Show Tokens" })
              ]
            }
          )
        ] })
      ] }),
      viewFormat === "editor" ? /* @__PURE__ */ jsxs2("div", { className: "ui-panel w-full flex flex-col gap-4 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 rounded-2xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-300 overflow-hidden", children: [
        /* @__PURE__ */ jsxs2("div", { className: "flex items-center justify-between px-4 py-2.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400", children: [
          /* @__PURE__ */ jsxs2("span", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsx2(Edit3, { className: "w-3.5 h-3.5 text-zinc-400" }),
            /* @__PURE__ */ jsx2("span", { children: "Template Editor \u2014 Live Preview" })
          ] }),
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-1", children: [
            /* @__PURE__ */ jsxs2("span", { className: "text-zinc-500", children: [
              customTemplate.length,
              " characters"
            ] }),
            isCustomTemplate && /* @__PURE__ */ jsx2("span", { className: "w-2 h-2 rounded-full bg-emerald-400 inline-block", title: "Custom template active" })
          ] })
        ] }),
        /* @__PURE__ */ jsxs2("div", { className: "flex flex-wrap items-center gap-1.5 px-4 py-2 bg-zinc-950 border-b border-zinc-800", children: [
          /* @__PURE__ */ jsx2("span", { className: "text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono text-[10px]", children: "Insert Token:" }),
          tokenList.map((token) => /* @__PURE__ */ jsx2(
            "button",
            {
              type: "button",
              onClick: () => handleInsertToken(token),
              className: "bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 px-2 py-0.5 rounded font-mono text-[10px] hover:border-zinc-600 transition",
              title: `Insert ${token}`,
              children: token
            },
            token
          ))
        ] }),
        /* @__PURE__ */ jsxs2("div", { className: "flex-1 flex h-[560px]", children: [
          /* @__PURE__ */ jsxs2("div", { className: "w-1/2 border-r border-zinc-800 flex flex-col", children: [
            /* @__PURE__ */ jsx2("div", { className: "flex items-center justify-between px-3 py-1.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400", children: /* @__PURE__ */ jsx2("span", { children: "Template HTML Source" }) }),
            /* @__PURE__ */ jsx2(
              "textarea",
              {
                ref: setEditorRef,
                value: customTemplate,
                onChange: (e) => {
                  isEditingRef.current = true;
                  setCustomTemplate(e.target.value);
                  setIsCustomTemplate(true);
                },
                onBlur: () => {
                  isEditingRef.current = false;
                },
                onKeyDown: (e) => {
                  if (e.ctrlKey && e.key === "s") {
                    e.preventDefault();
                    handleApplyCustomTemplate();
                  }
                },
                className: "flex-1 w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-mono text-xs p-3 border-0 resize-none focus:outline-none focus:ring-1 focus:ring-blue-500 overflow-auto",
                spellCheck: false,
                placeholder: "Edit your advisory template HTML with {{token}} placeholders..."
              }
            ),
            /* @__PURE__ */ jsxs2("div", { className: "flex items-center justify-end gap-2 px-3 py-2 bg-zinc-900/80 border-t border-zinc-800 text-[10px] text-zinc-500 font-mono", children: [
              /* @__PURE__ */ jsx2("span", { children: "Ctrl+S to apply" }),
              /* @__PURE__ */ jsx2(
                "button",
                {
                  type: "button",
                  onClick: handleApplyCustomTemplate,
                  className: "px-2.5 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded font-medium transition",
                  children: "Apply to Preview"
                }
              ),
              isCustomTemplate && /* @__PURE__ */ jsx2(
                "button",
                {
                  type: "button",
                  onClick: handleExitEditor,
                  className: "px-2.5 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded font-medium transition",
                  children: "Discard Changes"
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ jsxs2("div", { className: "w-1/2 flex flex-col", children: [
            /* @__PURE__ */ jsxs2("div", { className: "flex items-center justify-between px-3 py-1.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400", children: [
              /* @__PURE__ */ jsx2("span", { children: "Live Rendered Preview" }),
              /* @__PURE__ */ jsx2("div", { className: "flex items-center space-x-1", children: /* @__PURE__ */ jsxs2("span", { className: "text-zinc-500", children: [
                previewHtml.length,
                " chars",
                previewError ? " \u2014 preview error" : usingBuiltInTemplate ? " \u2014 built-in template (no custom template saved)" : serverPreview?.html ? " \u2014 server-rendered" : ""
              ] }) })
            ] }),
            previewError && /* @__PURE__ */ jsxs2("div", { className: "px-3 py-2 bg-red-950/60 border-b border-red-900 text-[11px] font-mono text-red-300 whitespace-pre-wrap", children: [
              "Template could not be rendered: ",
              previewError
            ] }),
            /* @__PURE__ */ jsx2("div", { className: "flex-1 overflow-auto bg-zinc-950/80", children: /* @__PURE__ */ jsx2("div", { className: "w-[720px] max-w-full mx-auto py-4", children: /* @__PURE__ */ jsx2(
              "iframe",
              {
                srcDoc: previewHtml,
                onLoad: syncIframeHeight,
                scrolling: "no",
                style: {
                  height: "500px",
                  width: "100%",
                  display: "block",
                  border: "none"
                },
                className: "transition-all duration-150",
                sandbox: "allow-same-origin",
                title: "Template Editor Live Preview"
              }
            ) }) })
          ] })
        ] })
      ] }) : viewFormat === "html" ? /* @__PURE__ */ jsxs2("div", { className: "bg-zinc-950 border border-zinc-800 rounded-xl overflow-hidden shadow-inner", children: [
        /* @__PURE__ */ jsxs2("div", { className: "flex items-center justify-between px-4 py-2.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400", children: [
          /* @__PURE__ */ jsxs2("span", { className: "flex items-center space-x-2", children: [
            /* @__PURE__ */ jsx2(Code2, { className: "w-3.5 h-3.5 text-zinc-400" }),
            /* @__PURE__ */ jsx2("span", { children: "Template HTML Source" }),
            /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-1 bg-zinc-950 border border-zinc-800 rounded-lg ml-4", children: [
              /* @__PURE__ */ jsx2(
                "button",
                {
                  type: "button",
                  onClick: () => setHtmlSubView("template"),
                  className: `px-2.5 py-1 rounded-lg text-xs font-medium transition ${htmlSubView === "template" ? "bg-blue-600 text-white" : "text-zinc-400 hover:text-zinc-200"}`,
                  children: "Template (with tokens)"
                }
              ),
              /* @__PURE__ */ jsx2(
                "button",
                {
                  type: "button",
                  onClick: () => setHtmlSubView("rendered"),
                  className: `px-2.5 py-1 rounded-lg text-xs font-medium transition ${htmlSubView === "rendered" ? "bg-blue-600 text-white" : "text-zinc-400 hover:text-zinc-200"}`,
                  children: "Rendered (preview values)"
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ jsxs2("span", { children: [
            (htmlSubView === "template" ? getTemplateSource() : getRenderedHtml()).length,
            " characters"
          ] })
        ] }),
        /* @__PURE__ */ jsx2("pre", { className: "p-4 text-xs font-mono text-zinc-300 overflow-x-auto max-h-[640px] leading-relaxed selection:bg-zinc-800", children: /* @__PURE__ */ jsx2("code", { children: htmlSubView === "template" ? getTemplateSource() : getRenderedHtml() }) })
      ] }) : (
        /* View Mode 2: Visual Client Canvas with Enterprise Chrome & Non-Trapping Scrolling */
        /* @__PURE__ */ jsx2("div", { className: "ui-panel w-full flex justify-center py-6 px-2 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 rounded-2xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-300 overflow-x-auto relative", children: /* @__PURE__ */ jsxs2(
          "div",
          {
            className: `transition-all duration-300 shadow-2xl relative ${previewDevice === "desktop" ? "w-[720px] max-w-full rounded-2xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 overflow-hidden bg-zinc-900" : "w-[410px] max-w-full rounded-[38px] p-2.5 bg-zinc-900 border-4 border-zinc-700 shadow-2xl"}`,
            style: {
              transform: zoomLevel !== 100 ? `scale(${zoomLevel / 100})` : void 0,
              transformOrigin: "top center"
            },
            children: [
              previewDevice === "desktop" && /* @__PURE__ */ jsxs2("div", { className: "bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-300 px-4 py-2.5 flex items-center justify-between text-xs font-mono", children: [
                /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-1.5", children: [
                  /* @__PURE__ */ jsx2("span", { className: "w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" }),
                  /* @__PURE__ */ jsx2("span", { className: "w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" }),
                  /* @__PURE__ */ jsx2("span", { className: "w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" })
                ] }),
                /* @__PURE__ */ jsx2("div", { className: "bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-white text-zinc-400 dark:text-zinc-400 light:text-zinc-600 px-3 py-1 rounded-lg text-[11px] truncate max-w-md border border-zinc-800/60 dark:border-zinc-800/60 light:border-zinc-300", children: "Email preview" }),
                /* @__PURE__ */ jsx2("div", { className: "text-[10px] text-zinc-500", children: "680px Canvas" })
              ] }),
              previewDevice === "mobile" && /* @__PURE__ */ jsx2("div", { className: "relative rounded-[32px] overflow-hidden bg-zinc-950 border border-zinc-800", children: /* @__PURE__ */ jsxs2("div", { className: "bg-zinc-950 text-zinc-400 px-6 pt-2 pb-1.5 flex items-center justify-between text-[11px] font-mono border-b border-zinc-800/40", children: [
                /* @__PURE__ */ jsx2("span", { children: "9:41" }),
                /* @__PURE__ */ jsx2("div", { className: "w-18 h-3.5 bg-zinc-800 rounded-full" }),
                /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-1", children: [
                  /* @__PURE__ */ jsx2("span", { children: "5G" }),
                  /* @__PURE__ */ jsx2("span", { className: "w-2 h-2 rounded-full bg-emerald-400" })
                ] })
              ] }) }),
              /* @__PURE__ */ jsxs2(
                "div",
                {
                  className: `relative bg-zinc-950 ${scrollMode === "contained" ? "overflow-y-auto max-h-[640px]" : ""}`,
                  children: [
                    /* @__PURE__ */ jsx2(
                      "iframe",
                      {
                        ref: iframeRef,
                        title: "HTML Template Preview",
                        srcDoc: showTokensInCanvas ? getTemplateSource() : getRenderedHtml(),
                        onLoad: syncIframeHeight,
                        scrolling: scrollMode === "fit" ? "no" : "auto",
                        style: {
                          height: scrollMode === "fit" ? `${iframeHeight}px` : "640px",
                          width: "100%",
                          display: "block",
                          border: "none",
                          backgroundColor: templateCustomization.canvasBg || "#09090b"
                        },
                        className: "w-full transition-all duration-150",
                        sandbox: "allow-same-origin"
                      }
                    ),
                    scrollMode === "contained" && /* @__PURE__ */ jsxs2("div", { className: "absolute bottom-4 right-4 flex flex-col space-y-1.5 z-10", children: [
                      /* @__PURE__ */ jsx2(
                        "button",
                        {
                          type: "button",
                          onClick: scrollToIframeTop,
                          className: "p-2 rounded-xl bg-zinc-900/90 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/80 shadow-lg backdrop-blur-sm transition",
                          title: "Scroll to Top of Email",
                          children: /* @__PURE__ */ jsx2(ArrowUp, { className: "w-3.5 h-3.5" })
                        }
                      ),
                      /* @__PURE__ */ jsx2(
                        "button",
                        {
                          type: "button",
                          onClick: scrollToIframeBottom,
                          className: "p-2 rounded-xl bg-zinc-900/90 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/80 shadow-lg backdrop-blur-sm transition",
                          title: "Scroll to Bottom of Email",
                          children: /* @__PURE__ */ jsx2(ArrowDown, { className: "w-3.5 h-3.5" })
                        }
                      )
                    ] })
                  ]
                }
              )
            ]
          }
        ) })
      )
    ] }),
    isFullscreen && /* @__PURE__ */ jsxs2("div", { className: "fixed inset-0 z-50 flex flex-col bg-zinc-950/95 backdrop-blur-md p-4 sm:p-6 overflow-hidden", children: [
      /* @__PURE__ */ jsxs2("div", { className: "flex items-center justify-between pb-4 border-b border-zinc-800", children: [
        /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
          /* @__PURE__ */ jsx2(FileCode3, { className: "w-5 h-5 text-zinc-300" }),
          /* @__PURE__ */ jsx2("h2", { className: "text-sm font-bold text-zinc-100 font-mono", children: "Email Template Studio \u2014 Fullscreen Inspection" })
        ] }),
        /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-2", children: [
          /* @__PURE__ */ jsxs2("div", { className: "flex items-center space-x-1 bg-zinc-900 border border-zinc-800 p-0.5 rounded-xl", children: [
            /* @__PURE__ */ jsx2(
              "button",
              {
                type: "button",
                "aria-label": "Desktop preview",
                onClick: () => setPreviewDevice("desktop"),
                className: `p-1.5 rounded-lg text-xs ${previewDevice === "desktop" ? "bg-zinc-800 text-white" : "text-zinc-400"}`,
                children: /* @__PURE__ */ jsx2(Monitor, { className: "w-4 h-4" })
              }
            ),
            /* @__PURE__ */ jsx2(
              "button",
              {
                type: "button",
                "aria-label": "Mobile preview",
                onClick: () => setPreviewDevice("mobile"),
                className: `p-1.5 rounded-lg text-xs ${previewDevice === "mobile" ? "bg-zinc-800 text-white" : "text-zinc-400"}`,
                children: /* @__PURE__ */ jsx2(Smartphone, { className: "w-4 h-4" })
              }
            )
          ] }),
          /* @__PURE__ */ jsx2(
            "button",
            {
              type: "button",
              "aria-label": "Close fullscreen preview",
              onClick: () => setIsFullscreen(false),
              className: "p-2 rounded-xl bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 transition",
              children: /* @__PURE__ */ jsx2(Minimize2, { className: "w-4 h-4" })
            }
          )
        ] })
      ] }),
      /* @__PURE__ */ jsx2("div", { className: "flex-1 overflow-y-auto flex justify-center py-6", children: /* @__PURE__ */ jsx2(
        "div",
        {
          className: `self-start shrink-0 max-w-full transition-all duration-300 shadow-2xl rounded-2xl overflow-hidden border border-zinc-800 ${previewDevice === "desktop" ? "w-[720px]" : "w-[400px]"}`,
          children: /* @__PURE__ */ jsx2(
            "iframe",
            {
              title: "Fullscreen Preview",
              scrolling: "no",
              onLoad: (event) => {
                const frame = event.currentTarget;
                const height = frame.contentDocument?.documentElement.scrollHeight;
                if (height) frame.style.height = `${height + 24}px`;
              },
              srcDoc: getRenderedHtml(),
              className: "w-full min-h-[900px] border-none bg-zinc-950",
              sandbox: "allow-same-origin"
            },
            previewDevice
          )
        }
      ) })
    ] }),
    showTestModal && /* @__PURE__ */ jsx2("div", { className: "fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4", children: /* @__PURE__ */ jsxs2("div", { className: "ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative", children: [
      /* @__PURE__ */ jsx2(
        "button",
        {
          onClick: () => setShowTestModal(false),
          className: "absolute top-4 right-4 text-zinc-500 hover:text-zinc-200",
          children: /* @__PURE__ */ jsx2(X, { className: "w-5 h-5" })
        }
      ),
      /* @__PURE__ */ jsxs2("h2", { className: "text-base font-bold text-zinc-100 mb-1 flex items-center gap-2", children: [
        /* @__PURE__ */ jsx2(Send, { className: "w-4 h-4 text-zinc-300" }),
        "Send Test Notification"
      ] }),
      /* @__PURE__ */ jsx2("p", { className: "text-xs text-zinc-400 mb-4", children: "Sends an email with the customized HTML template to verify rendering across client mailboxes." }),
      testResult && /* @__PURE__ */ jsxs2(
        "div",
        {
          className: `p-3 rounded-xl text-xs mb-3 flex items-center gap-2 ${testResult.success ? "bg-zinc-950 border border-emerald-800 text-emerald-300" : "bg-zinc-950 border border-zinc-700 text-zinc-300"}`,
          children: [
            testResult.success ? /* @__PURE__ */ jsx2(CheckCircle2, { className: "w-4 h-4 text-emerald-400 shrink-0" }) : /* @__PURE__ */ jsx2(AlertCircle, { className: "w-4 h-4 text-zinc-400 shrink-0" }),
            /* @__PURE__ */ jsx2("span", { children: testResult.message })
          ]
        }
      ),
      /* @__PURE__ */ jsxs2("form", { onSubmit: handleSendTest, className: "space-y-4 text-xs", children: [
        /* @__PURE__ */ jsxs2("div", { children: [
          /* @__PURE__ */ jsx2("label", { className: "block text-zinc-400 mb-1 font-mono", children: "Destination Email Address *" }),
          /* @__PURE__ */ jsx2(
            "input",
            {
              type: "email",
              required: true,
              value: testEmail,
              onChange: (e) => setTestEmail(e.target.value),
              className: "w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono focus:border-zinc-600 focus:outline-none"
            }
          )
        ] }),
        /* @__PURE__ */ jsxs2("div", { className: "flex justify-end space-x-2 pt-3 border-t border-zinc-800", children: [
          /* @__PURE__ */ jsx2(
            "button",
            {
              type: "button",
              onClick: () => setShowTestModal(false),
              disabled: sendingTest,
              className: "px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300",
              children: "Cancel"
            }
          ),
          /* @__PURE__ */ jsx2(
            "button",
            {
              type: "submit",
              className: "px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 text-zinc-900 font-semibold",
              children: "Send Test"
            }
          )
        ] })
      ] })
    ] }) }),
    showResetConfirm && /* @__PURE__ */ jsx2("div", { className: "fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4", children: /* @__PURE__ */ jsxs2("div", { className: "ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative", children: [
      /* @__PURE__ */ jsx2("h3", { className: "text-sm font-bold text-zinc-100 mb-2", children: "Apply professional default?" }),
      /* @__PURE__ */ jsx2("p", { className: "text-xs text-zinc-400 leading-relaxed mb-6", children: "Replace the preview with the professional navy-and-white preset. Save the template to apply it to future notifications." }),
      /* @__PURE__ */ jsxs2("div", { className: "flex justify-end space-x-2", children: [
        /* @__PURE__ */ jsx2(
          "button",
          {
            type: "button",
            onClick: () => setShowResetConfirm(false),
            className: "px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium",
            children: "Cancel"
          }
        ),
        /* @__PURE__ */ jsx2(
          "button",
          {
            type: "button",
            onClick: confirmReset,
            className: "px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold",
            children: "Apply to preview"
          }
        )
      ] })
    ] }) }),
    confirmSave && /* @__PURE__ */ jsx2("div", { className: "fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4", children: /* @__PURE__ */ jsxs2("div", { className: "ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative", children: [
      /* @__PURE__ */ jsx2("h3", { className: "text-sm font-bold text-zinc-100 mb-2", children: "Save & Apply to Notifications?" }),
      /* @__PURE__ */ jsx2("p", { className: "text-xs text-zinc-400 leading-relaxed mb-4", children: "Persist the customized advisory template to the server so it applies to future notifications." }),
      (saveValidationError || error) && /* @__PURE__ */ jsx2(
        "div",
        {
          role: "alert",
          className: "mb-4 rounded-xl border border-rose-800/50 bg-rose-950/70 px-3 py-2.5 text-xs text-rose-100",
          children: saveValidationError || error
        }
      ),
      /* @__PURE__ */ jsxs2("div", { className: "flex justify-end space-x-2", children: [
        /* @__PURE__ */ jsx2(
          "button",
          {
            type: "button",
            onClick: () => {
              setConfirmSave(false);
              clearError();
            },
            disabled: savingTemplate,
            className: "px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium",
            children: "Cancel"
          }
        ),
        /* @__PURE__ */ jsx2(
          "button",
          {
            type: "button",
            onClick: confirmSaveAction,
            disabled: savingTemplate || !!saveValidationError,
            className: "px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-white text-xs font-semibold",
            children: savingTemplate ? "Saving\u2026" : "Save & Apply"
          }
        )
      ] })
    ] }) }),
    confirmSendTest && /* @__PURE__ */ jsx2("div", { className: "fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4", children: /* @__PURE__ */ jsxs2("div", { className: "ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative", children: [
      /* @__PURE__ */ jsx2("h3", { className: "text-sm font-bold text-zinc-100 mb-2", children: "Send Test Email?" }),
      /* @__PURE__ */ jsxs2("p", { className: "text-xs text-zinc-400 leading-relaxed mb-6", children: [
        "Sends a real email to ",
        testEmail || "(no address entered)",
        " using the customized template. Confirm to send."
      ] }),
      /* @__PURE__ */ jsxs2("div", { className: "flex justify-end space-x-2", children: [
        /* @__PURE__ */ jsx2(
          "button",
          {
            type: "button",
            onClick: () => setConfirmSendTest(false),
            disabled: sendingTest,
            className: "px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium",
            children: "Cancel"
          }
        ),
        /* @__PURE__ */ jsx2(
          "button",
          {
            type: "button",
            onClick: confirmSendTestAction,
            disabled: sendingTest,
            className: "px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-white text-xs font-semibold",
            children: sendingTest ? "Sending\u2026" : "Send Test Email"
          }
        )
      ] })
    ] }) })
  ] });
};
export {
  AdvisoryTemplateView
};
