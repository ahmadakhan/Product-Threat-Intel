import { PageHeading } from './PageHeading';
import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { useApp } from '../context/AppContext';
import type { SystemHealth } from '../types';
import { formatDateTime } from '../utils/dateTime';
import { copyText } from '../utils/clipboard';
import {
  FileCode,
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
  CalendarDays,
  Edit3,
  Hash,
} from 'lucide-react';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  renderDailyFindingSummary,
  renderDailyHealthReport,
  digestSeveritySummary,
  digestSeverityKpi,
  formatExecutiveSummary,
  countDigestSeverities,
  formatDigestSeverityCounts,
  renderDailyDigest,
  renderHeldForReview,
  compileDailyDigestTemplate,
  type DigestFinding,
  type DigestHealth,
} from '../utils/templateCompiler';

const DIGEST_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** Calendar day in the workspace timezone, matching the server's digest key. */
const digestDateKey = (timezone: string, at: Date): string =>
  new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(at);

/** `YYYY-MM-DD` to the `ddMMMyyyy` form used in the delivered digest title. */
const formatDigestDate = (dateKey: string): string => {
  const [year, month, day] = dateKey.split('-');
  if (!year || !month || !day) return dateKey;
  return `${day.padStart(2, '0')}${DIGEST_MONTHS[Number(month) - 1] ?? month}${year}`;
};

const DIGEST_SEVERITY_ORDER = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
type DigestSeverity = (typeof DIGEST_SEVERITY_ORDER)[number];

const highestDigestSeverity = (findings: DigestFinding[]): DigestSeverity => {
  let highest: DigestSeverity = 'UNKNOWN';
  for (const finding of findings) {
    // Normalise before matching, exactly as countDigestSeverities does. Without
    // it a lowercase `high` was counted in the HIGH tile but left the headline
    // badge at UNKNOWN ("NO NEW FINDINGS"), so the header contradicted the KPI.
    const candidate = String(finding.severity ?? '')
      .trim()
      .toUpperCase();
    const severity: DigestSeverity = (DIGEST_SEVERITY_ORDER as readonly string[]).includes(candidate)
      ? (candidate as DigestSeverity)
      : 'UNKNOWN';
    if (DIGEST_SEVERITY_ORDER.indexOf(severity) > DIGEST_SEVERITY_ORDER.indexOf(highest)) highest = severity;
  }
  return highest;
};

/** Process uptime in the same `N Days H Hours` form the delivered digest uses. */
const formatUptime = (seconds: number): string => {
  const days = Math.floor(Math.max(0, seconds) / 86400);
  const hours = Math.floor((Math.max(0, seconds) % 86400) / 3600);
  return `${days} ${days === 1 ? 'Day' : 'Days'} ${hours} ${hours === 1 ? 'Hour' : 'Hours'}`;
};

export const DailyDigestView: React.FC = () => {
  const {
    settings,
    findings,
    health,
    dailyDigestTemplate,
    dailyDigestCustomization,
    savedDailyDigestCustomization,
    savedDailyDigestCustomTemplate,
    updateDailyDigestCustomization,
    sendTestDailyDigestEmail,
    saveDailyDigestTemplate,
    setDailyDigestCustomTemplate,
  } = useApp();

  const [testEmail, setTestEmail] = useState('');
  const [showTestModal, setShowTestModal] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [confirmSave, setConfirmSave] = useState<{ action: string; label: string } | null>(null);
  const [confirmSendTest, setConfirmSendTest] = useState<{ action: string; label: string } | null>(null);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [saveToast, setSaveToast] = useState(false);
  const [previewKey, setPreviewKey] = useState(0);
  const [previewDevice, setPreviewDevice] = useState<'desktop' | 'mobile'>('desktop');
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);

  // Enterprise Live Rendering & Scroll Management
  const iframeRef = useRef<HTMLIFrameElement>(null);
  // Rendered with the workspace timezone (not the browser's) and labelled with
  // its UTC offset, matching every other timestamp in the product.
  const displayTimezone = settings.timezone;
  const previewDate = useRef(formatDateTime(new Date(), displayTimezone).replace(',', ' |')).current;
  const previewTimestamp = useRef(new Date().toISOString()).current;
  // The context value is rebuilt on every poll; keep the latest health loader in
  // a ref so the 30-second refresh below is not restarted by unrelated renders.
  const healthRef = useRef(health);
  healthRef.current = health;
  useEffect(() => {
    let active = true;
    const loadHealth = async () => {
      const snapshot = await healthRef.current();
      if (active && snapshot) setSystemHealth(snapshot);
    };
    void loadHealth();
    const timer = setInterval(loadHealth, 30_000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);
  const [iframeHeight, setIframeHeight] = useState<number>(880);
  const [scrollMode, setScrollMode] = useState<'fit' | 'contained'>('fit');
  const [zoomLevel, setZoomLevel] = useState<number>(100);
  const [viewFormat, setViewFormat] = useState<'preview' | 'editor' | 'html'>('preview');
  const [htmlSubView, setHtmlSubView] = useState<'template' | 'rendered'>('template');
  const [showTokensInCanvas, setShowTokensInCanvas] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [copiedHtml, setCopiedHtml] = useState(false);

  const [customTemplate, setCustomTemplate] = useState<string>('');
  const [isCustomTemplate, setIsCustomTemplate] = useState(false);

  const [editorRef, setEditorRef] = useState<HTMLTextAreaElement | null>(null);

  const handleEnterEditor = () => {
    setCustomTemplate(dailyDigestTemplate);
    setIsCustomTemplate(true);
    setViewFormat('editor');
  };

  const handleExitEditor = () => {
    if (isCustomTemplate) {
      setCustomTemplate('');
      setIsCustomTemplate(false);
    }
    setViewFormat('preview');
  };

  const handleApplyCustomTemplate = () => {
    const trimmed = customTemplate.trim();
    if (trimmed) {
      setDailyDigestCustomTemplate(trimmed);
      setIsCustomTemplate(true);
      setViewFormat('preview');
    }
  };

  const handleResetCustomTemplate = () => {
    setDailyDigestCustomTemplate(null);
    setIsCustomTemplate(false);
    setCustomTemplate('');
  };

  const tokenList = useMemo(
    () => [
      '{{report_generated}}',
      '{{advisory_id}}',
      '{{advisory_title}}',
      '{{finding_count}}',
      '{{critical_count}}',
      '{{high_count}}',
      '{{medium_count}}',
      '{{low_count}}',
      '{{asset_count}}',
      '{{severity_counts}}',
      '{{severity}}',
      '{{severity_header_badge}}',
      '{{dispatch_date}}',
      '{{recipient_name}}',
      '{{executive_summary}}',
      '{{findings_summary}}',
      '{{health_report}}',
      '{{critical_summary}}',
      '{{high_summary}}',
      '{{medium_summary}}',
      '{{low_summary}}',
      '{{critical_kpi}}',
      '{{high_kpi}}',
      '{{medium_kpi}}',
      '{{low_kpi}}',
    ],
    [],
  );

  const handleInsertToken = (token: string) => {
    const el = editorRef;
    if (el) {
      const start = el.selectionStart;
      const end = el.selectionEnd;
      const value = customTemplate;
      setCustomTemplate(value.slice(0, start) + token + value.slice(end));
      const newPos = start + token.length;
      setTimeout(() => {
        el.focus();
        el.setSelectionRange(newPos, newPos);
      }, 0);
    }
  };

  // Real findings from the workspace snapshot, mapped to the digest shape the
  // delivery renderer consumes (server/dailyDigest.ts). The studio used to show
  // a hard-coded five-finding sample while the delivered digest carried live
  // data, so the two never agreed.
  const previewFindings = useMemo<DigestFinding[]>(
    () =>
      (findings ?? []).map((finding) => ({
        cveId: finding.cveId,
        severity: finding.cve.cvss.severity,
        assetName: finding.matchedAssetName,
        vendor: finding.matchedAssetVendor,
        sourceUrl: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(finding.cveId)}`,
        cvssScore: finding.cve.cvss.score,
        exploitStatus: finding.cve.exploitStatus,
        epssScore: finding.cve.epss?.score,
        cisaKev: finding.cve.cisaKev?.isKev,
      })),
    [findings],
  );
  const previewSeverityCounts = useMemo(() => countDigestSeverities(previewFindings), [previewFindings]);
  const previewSeverity = useMemo(() => highestDigestSeverity(previewFindings), [previewFindings]);
  const heldForReview = useMemo(
    () => (findings ?? []).filter((finding) => finding.notificationStatus === 'REVIEW_REQUIRED').length,
    [findings],
  );

  // Save & Apply is only enabled when the live customization or the custom body
  // diverges from the committed snapshot. This keeps the operator from
  // re-saving identical state and makes "no change" visually obvious.
  const hasChanges = useMemo(() => {
    const customizationChanged =
      JSON.stringify(dailyDigestCustomization) !== JSON.stringify(savedDailyDigestCustomization);
    const bodyChanged = customTemplate !== savedDailyDigestCustomTemplate;
    return customizationChanged || bodyChanged;
  }, [
    dailyDigestCustomization,
    savedDailyDigestCustomization,
    customTemplate,
    savedDailyDigestCustomTemplate,
  ]);

  // Map the authenticated health endpoint onto the digest's health shape so the
  // Platform Health table reports the running system, not fixture values.
  const digestHealth = useMemo<DigestHealth | null>(() => {
    if (!systemHealth) return null;
    return {
      database: systemHealth.database === 'degraded' ? 'degraded' : 'connected',
      databaseLatencyMs: systemHealth.databaseLatencyMs,
      workerStatus: systemHealth.workerStatus,
      workerHeartbeatAgeSeconds: systemHealth.heartbeatAgeSeconds,
      nextScheduledAttempt: systemHealth.deliveryQueue?.nextScheduledAttempt ?? null,
      nextDailyDigestAt: systemHealth.nextDailyDigestAt ?? null,
      backlog: systemHealth.backlog ?? [],
      checkedAt: systemHealth.checkedAt,
      systemUptime: formatUptime(systemHealth.uptimeSeconds),
      systemUptimePercentage: null,
      pipelineJobs: systemHealth.pipelineJobs ?? { total: 0, succeeded: 0, failed: 0 },
    };
  }, [systemHealth]);

  const findingsSummary = useMemo(
    () => renderDailyFindingSummary(previewFindings, dailyDigestCustomization),
    [previewFindings, dailyDigestCustomization],
  );
  const healthReport = useMemo(
    () => renderDailyHealthReport(digestHealth, { ...dailyDigestCustomization, timezone: displayTimezone }),
    [digestHealth, dailyDigestCustomization, displayTimezone],
  );
  const digestDate = useMemo(() => digestDateKey(displayTimezone, new Date()), [displayTimezone]);
  const previewAdvisoryId = `${settings.advisoryPrefix ?? ''}DAILY-PREVIEW`;
  const previewAdvisoryTitle = useMemo(
    () => `Daily Vulnerability Notification — ${formatDigestDate(digestDate)}`,
    [digestDate],
  );
  const previewCveIds = useMemo(
    () => [...new Set(previewFindings.map((finding) => finding.cveId))],
    [previewFindings],
  );

  /**
   * The one rendered digest document the studio shows.
   *
   * This is `renderDailyDigest` — the exact renderer the delivered digest uses
   * (`server/dailyDigest.ts`) — fed the workspace's real findings and health and
   * the operator's live customization. It replaces a hand-rolled `.replace()`
   * chain that had drifted from the renderer: it blanked `held_for_review`,
   * hard-coded the severity badge, and skipped the `{{#if}}` branches, so the
   * pane and the delivered mail disagreed even when the template was identical.
   */
  const getRenderedHtml = (): string => {
    const criticalCount = previewSeverityCounts.CRITICAL ?? 0;
    const highCount = previewSeverityCounts.HIGH ?? 0;
    const mediumCount = previewSeverityCounts.MEDIUM ?? 0;
    const lowCount = previewSeverityCounts.LOW ?? 0;
    return renderDailyDigest(
      dailyDigestCustomization,
      {
        // Carry the workspace advisory prefix, exactly as a real digest does:
        // the preview ID must match the ID family in the delivered email (and in
        // server/app.ts test-daily-digest), or the email path legitimately treats
        // it as a different advisory and injects an identity line into the body.
        advisory_id: previewAdvisoryId,
        advisory_title: previewAdvisoryTitle,
        dispatch_date: previewTimestamp,
        severity: previewSeverity,
        finding_count: previewFindings.length,
        severity_counts: formatDigestSeverityCounts(previewSeverityCounts),
        findings_summary: findingsSummary,
        health_report: healthReport,
        recipient_name: 'preview@example.invalid',
        critical_count: criticalCount,
        high_count: highCount,
        medium_count: mediumCount,
        low_count: lowCount,
        asset_count: new Set(previewFindings.map((finding) => finding.assetName)).size,
        executive_summary: formatExecutiveSummary(previewFindings.length, previewSeverityCounts),
        report_generated: previewDate,
        held_for_review: renderHeldForReview(heldForReview, dailyDigestCustomization),
        critical_summary: digestSeveritySummary('CRITICAL', criticalCount, dailyDigestCustomization),
        high_summary: digestSeveritySummary('HIGH', highCount, dailyDigestCustomization),
        medium_summary: digestSeveritySummary('MEDIUM', mediumCount, dailyDigestCustomization),
        low_summary: digestSeveritySummary('LOW', lowCount, dailyDigestCustomization),
        critical_kpi: digestSeverityKpi('CRITICAL', criticalCount, dailyDigestCustomization),
        high_kpi: digestSeverityKpi('HIGH', highCount, dailyDigestCustomization),
        medium_kpi: digestSeverityKpi('MEDIUM', mediumCount, dailyDigestCustomization),
        low_kpi: digestSeverityKpi('LOW', lowCount, dailyDigestCustomization),
      },
      // An unsaved editor edit wins; otherwise the saved studio document (which
      // AppContext keeps compiled from the live customization).
      isCustomTemplate && customTemplate
        ? customTemplate
        : dailyDigestTemplate || compileDailyDigestTemplate(dailyDigestCustomization),
    );
  };

  const getTemplateSource = (): string => {
    if (isCustomTemplate && customTemplate) return customTemplate;
    return dailyDigestTemplate || compileDailyDigestTemplate(dailyDigestCustomization);
  };

  // Dynamically sync iframe height to eliminate internal scrollbars and scroll trapping
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
          doc.body.offsetHeight,
        );
        if (h > 200) {
          setIframeHeight(h + 24);
        }
      }
    } catch {
      // fallback
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(syncIframeHeight, 100);
    return () => clearTimeout(timer);
  }, [getRenderedHtml, previewDevice, syncIframeHeight]);

  // Bump the preview key whenever the live customization changes so the
  // iframe remounts and reloads with fresh HTML (srcDoc changes alone are
  // not always enough for the browser to re-render).
  useEffect(() => {
    setPreviewKey((k) => k + 1);
  }, [dailyDigestCustomization]);

  const scrollToIframeTop = () => {
    try {
      iframeRef.current?.contentWindow?.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (error) {
      console.debug('Daily Digest iframe scroll-to-top failed:', error);
    }
  };

  const scrollToIframeBottom = () => {
    try {
      iframeRef.current?.contentWindow?.scrollTo({ top: 99999, behavior: 'smooth' });
    } catch (error) {
      console.debug('Daily Digest iframe scroll-to-bottom failed:', error);
    }
  };

  const handleDownloadHtml = () => {
    const blob = new Blob([getRenderedHtml()], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `daily-digest-template-${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const handleCopyRawHtml = async () => {
    if (await copyText(getRenderedHtml())) {
      setCopiedHtml(true);
      setTimeout(() => setCopiedHtml(false), 2000);
    }
  };

  const handleSave = () => {
    setConfirmSave({ action: 'save', label: 'Save & Apply to Daily Digest' });
  };

  const executeSave = async () => {
    if (!confirmSave) return;
    try {
      if (!(await saveDailyDigestTemplate(isCustomTemplate ? customTemplate : null))) return;
      // The save committed to the server and refresh() reloaded the snapshot.
      // Re-seed the local editor draft so the preview renders the committed
      // template rather than a stale pre-save draft.
      //
      // Do NOT read dailyDigestTemplate here: React has not yet committed the
      // post-save snapshot refresh, so that context value is still stale.
      // For a settings-only save (no custom body), dropping isCustomTemplate
      // lets the next render read the refreshed dailyDigestTemplate, which is
      // compiled from the saved customization.
      // For a custom-body save, local customTemplate already equals the saved
      // body, so keep it.
      if (!isCustomTemplate) {
        setCustomTemplate('');
        setIsCustomTemplate(false);
      }
      setSaveToast(true);
      setTimeout(() => setSaveToast(false), 2500);
    } finally {
      setConfirmSave(null);
    }
  };

  const handleReset = () => {
    setShowResetConfirm(true);
  };

  const confirmReset = () => {
    updateDailyDigestCustomization(DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
    setShowResetConfirm(false);
  };

  const handleSendTest = async (e: React.FormEvent) => {
    e.preventDefault();
    const recipient = testEmail.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient)) {
      setTestResult({ success: false, message: 'Enter a valid email address to receive the test.' });
      return;
    }
    const rendered = getRenderedHtml();
    const unrenderedTokens = rendered.match(/\{\{\{?\s*[a-z_][a-z0-9_]*\s*\}?\}\}/gi);
    if (unrenderedTokens && unrenderedTokens.length > 0) {
      setTestResult({
        success: false,
        message: `Template has unrendered tokens in preview: ${[...new Set(unrenderedTokens)].join(', ')}. Check the HTML source or token list.`,
      });
      return;
    }
    setShowTestModal(false);
    setConfirmSendTest({ action: 'send-test', label: `test email to ${recipient}` });
  };

  const executeSendTest = async () => {
    if (!confirmSendTest) return;
    try {
      // Send the document the canvas and rendered pane are showing, not a
      // second server render of saved state: the preview clock and any unsaved
      // template edit must reach the mailbox byte for byte. The advisory
      // identity and severity travel with it so the subject matches the body.
      const res = await sendTestDailyDigestEmail(testEmail.trim(), getRenderedHtml(), {
        advisoryId: previewAdvisoryId,
        advisoryTitle: previewAdvisoryTitle,
        severity: previewSeverity,
        cveIds: previewCveIds,
      });
      if (res.success) {
        setTimeout(() => {
          setTestResult(null);
        }, 1500);
      }
    } finally {
      setConfirmSendTest(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="ui-page-header">
        <PageHeading page="daily-digest">
          Design a customized daily digest. The digest sends an overall summary of daily findings and
          operational health — never a PDF attachment. Preview desktop and mobile layouts, customize your
          branding, then save to apply it to future daily digests.
        </PageHeading>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleReset}
            disabled={!!(confirmSave || confirmSendTest)}
            className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium transition flex items-center space-x-1"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Professional Default</span>
          </button>
          <button
            onClick={() => {
              setTestResult(null);
              setShowTestModal(true);
            }}
            disabled={!!(confirmSave || confirmSendTest)}
            className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-semibold transition flex items-center space-x-1.5"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Send Test Email</span>
          </button>
          <button
            onClick={handleSave}
            disabled={!hasChanges || !!confirmSave || !!confirmSendTest}
            className="text-xs px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition shadow-sm"
          >
            {saveToast ? 'Applied to Daily Digest!' : 'Save & Apply to Daily Digest'}
          </button>
        </div>
      </div>

      {/* RENDERED CLIENT PREVIEW: RENAMED TO "HTML template" WITH ENTERPRISE SCROLL ENGINE */}
      <div className="ui-panel bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm space-y-4 transition-colors">
        {/* Studio Control Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 pb-3.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="flex items-center space-x-2">
              <FileCode className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              <h2 className="text-xs font-bold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider font-mono">
                HTML Template
              </h2>
            </div>

            {/* Live Indicator */}
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/40 text-emerald-300 border border-emerald-800/60 flex items-center space-x-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>Live Rendering Active</span>
            </span>

            {/* Format Switcher: Visual Preview vs HTML Source */}
            <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-0.5 rounded-xl ml-2">
              <button
                type="button"
                onClick={() => setViewFormat('preview')}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                  viewFormat === 'preview'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Visual Canvas</span>
              </button>
              <button
                type="button"
                onClick={handleEnterEditor}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                  viewFormat === 'editor'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
              >
                <Edit3 className="w-3.5 h-3.5" />
                <span>Template Editor</span>
              </button>
              <button
                type="button"
                onClick={() => setViewFormat('html')}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                  viewFormat === 'html'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
              >
                <Code2 className="w-3.5 h-3.5" />
                <span>HTML Code</span>
              </button>
            </div>
          </div>

          {/* Device Preview Switcher */}
          <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-1 rounded-xl">
            <button
              onClick={() => setPreviewDevice('desktop')}
              className={`p-1.5 rounded-lg transition ${
                previewDevice === 'desktop'
                  ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
              title="Desktop View (680px)"
            >
              <Monitor className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPreviewDevice('mobile')}
              className={`p-1.5 rounded-lg transition ${
                previewDevice === 'mobile'
                  ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
              title="Mobile Client View (390px)"
            >
              <Smartphone className="w-4 h-4" />
            </button>
          </div>

          {/* Right Toolbar: Scroll Mode, Zoom, Export & Fullscreen */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Scroll Engine Mode */}
            <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-0.5 rounded-xl">
              <button
                type="button"
                onClick={() => setScrollMode('fit')}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition ${
                  scrollMode === 'fit'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm font-semibold'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
                title="Auto-Fit Full Height: Automatically expands iframe height to eliminate inner scrollbars and scroll trapping."
              >
                Auto-Fit Flow
              </button>
              <button
                type="button"
                onClick={() => setScrollMode('contained')}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition ${
                  scrollMode === 'contained'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm font-semibold'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
                title="Contained Viewport: Fixed 640px height with device frame and quick scroll controls."
              >
                Fixed Viewport
              </button>
            </div>

            {/* Zoom Controls */}
            <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-0.5 rounded-xl font-mono text-[11px]">
              <button
                type="button"
                onClick={() => setZoomLevel((prev) => Math.max(65, prev - 10))}
                className="p-1 text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <span className="px-1 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 min-w-[34px] text-center">
                {zoomLevel}%
              </span>
              <button
                type="button"
                onClick={() => setZoomLevel((prev) => Math.min(130, prev + 10))}
                className="p-1 text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              {zoomLevel !== 100 && (
                <button
                  type="button"
                  onClick={() => setZoomLevel(100)}
                  className="text-[10px] text-zinc-500 hover:text-zinc-300 dark:text-zinc-500 dark:hover:text-zinc-300 light:text-zinc-600 light:hover:text-zinc-800 px-1 border-l border-zinc-800 dark:border-zinc-800 light:border-zinc-300"
                >
                  Reset
                </button>
              )}
            </div>

            {/* Actions: Copy HTML, Download, Fullscreen */}
            <button
              type="button"
              onClick={handleCopyRawHtml}
              className="p-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 transition"
              title="Copy Rendered HTML Code"
            >
              {copiedHtml ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
            </button>
            <button
              type="button"
              onClick={handleDownloadHtml}
              className="p-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 transition"
              title="Download Daily Digest HTML Template"
            >
              <Download className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => setIsFullscreen(true)}
              className="p-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 transition"
              title="Fullscreen Template Studio"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => setShowTokensInCanvas(!showTokensInCanvas)}
              className={`p-1.5 rounded-xl flex items-center space-x-1.5 text-xs font-mono transition ${
                showTokensInCanvas
                  ? 'bg-blue-600/20 border border-blue-600 text-blue-300'
                  : 'bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700'
              }`}
              title={showTokensInCanvas ? 'Show rendered preview' : 'Show token placeholders in canvas'}
            >
              <Hash className="w-3.5 h-3.5" />
              <span>Show Tokens</span>
            </button>
          </div>
        </div>

        {/* View Mode 1: HTML Code Inspector with Token/Rendered toggle */}
        {viewFormat === 'html' ? (
          <div className="bg-zinc-950 border border-zinc-800 rounded-xl overflow-hidden shadow-inner">
            <div className="flex items-center justify-between px-4 py-2.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400">
              <span className="flex items-center space-x-2">
                <Code2 className="w-3.5 h-3.5 text-zinc-400" />
                <span>Template HTML Source</span>
                <div className="flex items-center space-x-1 bg-zinc-950 border border-zinc-800 rounded-lg ml-4">
                  <button
                    type="button"
                    onClick={() => setHtmlSubView('template')}
                    className={`px-2.5 py-1 rounded-lg text-xs font-medium transition ${
                      htmlSubView === 'template'
                        ? 'bg-blue-600 text-white'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Template (with tokens)
                  </button>
                  <button
                    type="button"
                    onClick={() => setHtmlSubView('rendered')}
                    className={`px-2.5 py-1 rounded-lg text-xs font-medium transition ${
                      htmlSubView === 'rendered'
                        ? 'bg-blue-600 text-white'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Rendered (preview values)
                  </button>
                </div>
              </span>
              <span>
                {(htmlSubView === 'template' ? getTemplateSource() : getRenderedHtml()).length} characters
              </span>
            </div>
            <p className="px-4 py-2 bg-zinc-950 border-b border-zinc-800 text-[11px] leading-relaxed text-zinc-500">
              {htmlSubView === 'template'
                ? 'Template source: the document with {{tokens}}. This is what gets saved and re-rendered per recipient. It is expected to differ from the Rendered tab once tokens are replaced.'
                : 'Rendered: the template rendered by the same engine the delivered digest uses, with preview values and the live customization applied. This is byte-for-byte what "Live Rendered Preview" below shows.'}
            </p>
            <pre className="p-4 text-xs font-mono text-zinc-300 overflow-x-auto max-h-[640px] leading-relaxed selection:bg-zinc-800">
              <code>{htmlSubView === 'template' ? getTemplateSource() : getRenderedHtml()}</code>
            </pre>
          </div>
        ) : viewFormat === 'editor' ? (
          <div className="ui-panel w-full flex flex-col gap-4 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 rounded-2xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-300 overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400">
              <span className="flex items-center space-x-2">
                <Edit3 className="w-3.5 h-3.5 text-zinc-400" />
                <span>Template Editor — Live Preview</span>
              </span>
              <div className="flex items-center space-x-1">
                <span className="text-zinc-500">{customTemplate.length} characters</span>
                {isCustomTemplate && (
                  <span
                    className="w-2 h-2 rounded-full bg-emerald-400 inline-block"
                    title="Custom template active"
                  />
                )}
              </div>
            </div>

            {/* Token Toolbar */}
            <div className="flex flex-wrap items-center gap-1.5 px-4 py-2 bg-zinc-950 border-b border-zinc-800">
              <span className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono text-[10px]">
                Insert Token:
              </span>
              {tokenList.map((token) => (
                <button
                  key={token}
                  type="button"
                  onClick={() => handleInsertToken(token)}
                  className="bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 px-2 py-0.5 rounded font-mono text-[10px] hover:border-zinc-600 transition"
                  title={`Insert ${token}`}
                >
                  {token}
                </button>
              ))}
            </div>

            {/* Split View: Editor + Live Preview */}
            <div className="flex-1 flex h-[560px]">
              {/* Left: Code Editor */}
              <div className="w-1/2 border-r border-zinc-800 flex flex-col">
                <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400">
                  <span>Template HTML Source</span>
                  <div className="flex items-center space-x-1">
                    <button
                      type="button"
                      onClick={() => editorRef?.focus()}
                      className="p-1 text-zinc-400 hover:text-zinc-200"
                      title="Focus editor"
                    >
                      <Edit3 className="w-3 h-3" />
                    </button>
                  </div>
                </div>
                <textarea
                  ref={setEditorRef}
                  value={customTemplate}
                  onChange={(e) => {
                    setCustomTemplate(e.target.value);
                  }}
                  onKeyDown={(e) => {
                    if (e.ctrlKey && e.key === 's') {
                      e.preventDefault();
                      handleApplyCustomTemplate();
                    }
                  }}
                  className="flex-1 w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-mono text-xs p-3 border-0 resize-none focus:outline-none focus:ring-1 focus:ring-blue-500 overflow-auto"
                  spellCheck={false}
                  placeholder="Edit your digest template HTML with {{token}} placeholders..."
                />
                <div className="flex items-center justify-end gap-2 px-3 py-2 bg-zinc-900/80 border-t border-zinc-800 text-[10px] text-zinc-500 font-mono">
                  <span>Ctrl+S to apply</span>
                  <button
                    type="button"
                    onClick={handleApplyCustomTemplate}
                    className="px-2.5 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded font-medium transition"
                  >
                    Apply to Preview
                  </button>
                  {isCustomTemplate && (
                    <button
                      type="button"
                      onClick={handleResetCustomTemplate}
                      className="px-2.5 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded font-medium transition"
                      title="Discard custom template and revert to generated one"
                    >
                      Discard Changes
                    </button>
                  )}
                </div>
              </div>

              {/* Right: Live Preview */}
              <div className="w-1/2 flex flex-col">
                <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400">
                  {/* The label follows the toggle: showing the raw template must
                      never be presented as a rendered preview. */}
                  <span>
                    {showTokensInCanvas ? 'Template With Tokens (unrendered)' : 'Live Rendered Preview'}
                  </span>
                  <div className="flex items-center space-x-1">
                    <span className="text-zinc-500">
                      {(showTokensInCanvas ? getTemplateSource() : getRenderedHtml()).length} chars
                    </span>
                  </div>
                </div>
                <div className="flex-1 overflow-auto bg-zinc-950/80">
                  <div className="w-[720px] max-w-full mx-auto py-4">
                    <iframe
                      key={previewKey}
                      srcDoc={showTokensInCanvas ? getTemplateSource() : getRenderedHtml()}
                      onLoad={syncIframeHeight}
                      scrolling="auto"
                      style={{
                        height: '500px',
                        width: '100%',
                        display: 'block',
                        border: 'none',
                        backgroundColor: dailyDigestCustomization.canvasBg || '#09090b',
                      }}
                      className="transition-all duration-150"
                      title="Template Editor Live Preview"
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          /* View Mode 2: Visual Client Canvas with Enterprise Chrome & Non-Trapping Scrolling */
          <div className="ui-panel w-full flex justify-center py-6 px-2 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 rounded-2xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-300 overflow-x-auto relative">
            {/* Device Container Frame */}
            <div
              className={`transition-all duration-300 shadow-2xl relative ${
                previewDevice === 'desktop'
                  ? 'w-[720px] max-w-full rounded-2xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 overflow-hidden bg-zinc-900'
                  : 'w-[410px] max-w-full rounded-[38px] p-2.5 bg-zinc-900 border-4 border-zinc-700 shadow-2xl'
              }`}
              style={{
                transform: zoomLevel !== 100 ? `scale(${zoomLevel / 100})` : undefined,
                transformOrigin: 'top center',
              }}
            >
              {/* Desktop Browser Chrome */}
              {previewDevice === 'desktop' && (
                <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-300 px-4 py-2.5 flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center space-x-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" />
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
                  </div>
                  <div className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-white text-zinc-400 dark:text-zinc-400 light:text-zinc-600 px-3 py-1 rounded-lg text-[11px] truncate max-w-md border border-zinc-800/60 dark:border-zinc-800/60 light:border-zinc-300">
                    Email preview
                  </div>
                  <div className="text-[10px] text-zinc-500">680px Canvas</div>
                </div>
              )}

              {/* Mobile Phone Chrome */}
              {previewDevice === 'mobile' && (
                <div className="relative rounded-[32px] overflow-hidden bg-zinc-950 border border-zinc-800">
                  {/* Speaker Notch & Status Bar */}
                  <div className="bg-zinc-950 text-zinc-400 px-6 pt-2 pb-1.5 flex items-center justify-between text-[11px] font-mono border-b border-zinc-800/40">
                    <span>9:41</span>
                    <div className="w-18 h-3.5 bg-zinc-800 rounded-full" />
                    <div className="flex items-center space-x-1">
                      <span>5G</span>
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    </div>
                  </div>
                </div>
              )}

              {/* The Iframe Itself with Scroll-Trap Elimination */}
              <div
                className={`relative bg-zinc-950 ${
                  scrollMode === 'contained' ? 'overflow-y-auto max-h-[640px]' : ''
                }`}
              >
                <iframe
                  ref={iframeRef}
                  key={previewKey}
                  title="Daily Digest Preview"
                  srcDoc={showTokensInCanvas ? getTemplateSource() : getRenderedHtml()}
                  onLoad={syncIframeHeight}
                  scrolling="auto"
                  style={{
                    height: scrollMode === 'fit' ? `${iframeHeight}px` : '640px',
                    width: '100%',
                    display: 'block',
                    border: 'none',
                    backgroundColor: dailyDigestCustomization.canvasBg || '#09090b',
                  }}
                  className="w-full transition-all duration-150"
                />

                {/* Floating Navigation Controls in Contained Viewport Mode */}
                {scrollMode === 'contained' && (
                  <div className="absolute bottom-4 right-4 flex flex-col space-y-1.5 z-10">
                    <button
                      type="button"
                      onClick={scrollToIframeTop}
                      className="p-2 rounded-xl bg-zinc-900/90 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/80 shadow-lg backdrop-blur-sm transition"
                      title="Scroll to Top of Email"
                    >
                      <ArrowUp className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={scrollToIframeBottom}
                      className="p-2 rounded-xl bg-zinc-900/90 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/80 shadow-lg backdrop-blur-sm transition"
                      title="Scroll to Bottom of Email"
                    >
                      <ArrowDown className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Fullscreen Template Studio Modal */}
      {isFullscreen && (
        <div className="fixed inset-0 z-50 flex flex-col bg-zinc-950/95 backdrop-blur-md p-4 sm:p-6 overflow-hidden">
          <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
            <div className="flex items-center space-x-2">
              <CalendarDays className="w-5 h-5 text-zinc-300" />
              <h2 className="text-sm font-bold text-zinc-100 font-mono">
                Daily Digest Studio — Fullscreen Inspection
              </h2>
            </div>
            <div className="flex items-center space-x-2">
              <div className="flex items-center space-x-1 bg-zinc-900 border border-zinc-800 p-0.5 rounded-xl">
                <button
                  type="button"
                  aria-label="Desktop preview"
                  onClick={() => setPreviewDevice('desktop')}
                  className={`p-1.5 rounded-lg text-xs ${previewDevice === 'desktop' ? 'bg-zinc-800 text-white' : 'text-zinc-400'}`}
                >
                  <Monitor className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  aria-label="Mobile preview"
                  onClick={() => setPreviewDevice('mobile')}
                  className={`p-1.5 rounded-lg text-xs ${previewDevice === 'mobile' ? 'bg-zinc-800 text-white' : 'text-zinc-400'}`}
                >
                  <Smartphone className="w-4 h-4" />
                </button>
              </div>
              <button
                type="button"
                aria-label="Close fullscreen preview"
                onClick={() => setIsFullscreen(false)}
                className="p-2 rounded-xl bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 transition"
              >
                <Minimize2 className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto flex justify-center py-6">
            <div
              className={`self-start shrink-0 max-w-full transition-all duration-300 shadow-2xl rounded-2xl overflow-hidden border border-zinc-800 ${
                previewDevice === 'desktop' ? 'w-[720px]' : 'w-[400px]'
              }`}
            >
              <iframe
                title="Fullscreen Daily Digest Preview"
                key={`${previewDevice}-${previewKey}`}
                scrolling="auto"
                onLoad={(event) => {
                  const frame = event.currentTarget;
                  const height = frame.contentDocument?.documentElement.scrollHeight;
                  if (height) frame.style.height = `${height + 24}px`;
                }}
                srcDoc={getRenderedHtml()}
                className="w-full min-h-[900px] border-none bg-zinc-950"
              />
            </div>
          </div>
        </div>
      )}

      {/* Send Test Email Modal */}
      {showTestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setShowTestModal(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-bold text-zinc-100 mb-1 flex items-center gap-2">
              <Send className="w-4 h-4 text-zinc-300" />
              Send Test Daily Digest
            </h2>
            <p className="text-xs text-zinc-400 mb-4">
              Sends a sample daily digest email (overall summary, no PDF attachment) to verify rendering
              across client mailboxes.
            </p>

            {testResult && (
              <div
                className={`p-3 rounded-xl text-xs mb-3 flex items-center gap-2 ${
                  testResult.success
                    ? 'bg-zinc-950 border border-emerald-800 text-emerald-300'
                    : 'bg-zinc-950 border border-zinc-700 text-zinc-300'
                }`}
              >
                {testResult.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-zinc-400 shrink-0" />
                )}
                <span>{testResult.message}</span>
              </div>
            )}

            <form onSubmit={handleSendTest} className="space-y-4 text-xs">
              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Destination Email Address *</label>
                <input
                  type="email"
                  required
                  value={testEmail}
                  onChange={(e) => setTestEmail(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setShowTestModal(false)}
                  className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 text-zinc-900 font-semibold"
                >
                  Send Test
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Reset Confirmation Modal */}
      {showResetConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 mb-2">Apply professional default?</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-6">
              Replace the preview with the professional navy-and-white preset. Save the template to apply it
              to future daily digests.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                type="button"
                onClick={() => setShowResetConfirm(false)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmReset}
                className="px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold"
              >
                Apply to preview
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Dirty State Toast */}
      {saveToast && (
        <div className="fixed bottom-6 right-6 z-50 bg-emerald-900/90 text-emerald-100 border border-emerald-700 rounded-xl px-4 py-2.5 text-xs font-mono shadow-xl flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-300" />
          <span>Daily digest customization saved and applied</span>
        </div>
      )}

      {/* Save Confirmation Modal */}
      {confirmSave && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirmSave(null);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-save-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-save-title" className="text-sm font-semibold text-zinc-100">
              Save daily digest changes?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              This will{' '}
              <span className="font-medium text-zinc-200 light:text-zinc-800">{confirmSave.label}</span>. The
              updated template will be applied to future daily digests.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className="ui-secondary" onClick={() => setConfirmSave(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-sky-500"
                onClick={() => void executeSave()}
              >
                Confirm save
              </button>
            </div>
          </section>
        </div>
      )}

      {/* Send Test Email Confirmation Modal */}
      {confirmSendTest && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setConfirmSendTest(null);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-send-test-title"
            className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
          >
            <h2 id="confirm-send-test-title" className="text-sm font-semibold text-zinc-100">
              Send test email?
            </h2>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              This will{' '}
              <span className="font-medium text-zinc-200 light:text-zinc-800">{confirmSendTest.label}</span>{' '}
              using the current rendered template. A delivery audit record will be created.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className="ui-secondary" onClick={() => setConfirmSendTest(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-sky-500"
                onClick={() => void executeSendTest()}
              >
                Confirm send
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
};
