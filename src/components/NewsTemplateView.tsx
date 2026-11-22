import { PageHeading } from './PageHeading';
import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { useApp } from '../context/AppContext';
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
  Edit3,
  Hash,
} from 'lucide-react';
import {
  DEFAULT_NEWS_EMAIL_CUSTOMIZATION,
  DEFAULT_NEWS_EMAIL_TEMPLATE,
  renderNewsTemplate,
  type NewsSource,
} from '../utils/templateCompiler';

const SAMPLE_NEWS_ARTICLES = [
  {
    title: 'Critical Authentication Bypass in Enterprise Firewall',
    source: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001',
    published: '15 Nov 2026',
    feed: 'BleepingComputer',
    assets: ['edge-router-01'],
    cves: ['CVE-2026-0001'],
    evidence: 'Active exploitation observed in the wild; CISA KEV catalog updated.',
    credibilityScore: 88,
    zeroDay: true,
  },
  {
    title: 'Remote Code Execution in Collaboration Suite',
    source: 'https://example.com/advisory/cve-2026-0002',
    published: '14 Nov 2026',
    feed: 'The Hacker News',
    assets: ['auth-service'],
    cves: ['CVE-2026-0002'],
    evidence: 'Patch available from vendor; no known active exploitation.',
    credibilityScore: 62,
    zeroDay: false,
  },
  {
    title: 'Privilege Escalation in Cloud Identity Platform',
    source: 'https://example.com/advisory/cve-2026-0003',
    published: '13 Nov 2026',
    feed: 'SecurityWeek',
    assets: ['portal-web'],
    cves: ['CVE-2026-0003'],
    evidence: 'Local privilege escalation; requires authenticated access.',
    credibilityScore: 74,
    zeroDay: false,
  },
];

export const NewsTemplateView: React.FC = () => {
  const {
    settings,
    error,
    clearError,
    newsDigestTemplate,
    newsDigestCustomization,
    updateNewsDigestCustomization,
    saveNewsDigestTemplate,
    setNewsDigestCustomTemplate,
    sendTestEmail,
  } = useApp();

  const [testEmail, setTestEmail] = useState('');
  const [showTestModal, setShowTestModal] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [confirmSave, setConfirmSave] = useState<{ action: string; label: string } | null>(null);
  const [savingTemplate, setSavingTemplate] = useState(false);
  const [confirmSendTest, setConfirmSendTest] = useState<{ action: string; label: string } | null>(null);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [saveToast, setSaveToast] = useState(false);
  const [previewKey, setPreviewKey] = useState(0);
  const [previewDevice, setPreviewDevice] = useState<'desktop' | 'mobile'>('desktop');
  const [copiedToken, setCopiedToken] = useState<string | null>(null);
  const [copiedHtml, setCopiedHtml] = useState(false);

  // Enterprise Live Rendering & Scroll Management
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const displayTimezone = settings.timezone;
  const previewDate = useRef(
    formatDateTime(new Date(), displayTimezone).replace(',', ' |'),
  ).current;
  const previewTimestamp = useRef(new Date().toISOString()).current;
  const [iframeHeight, setIframeHeight] = useState<number>(880);
  const [scrollMode, setScrollMode] = useState<'fit' | 'contained'>('fit');
  const [zoomLevel, setZoomLevel] = useState<number>(100);
  const [viewFormat, setViewFormat] = useState<'preview' | 'editor' | 'html'>('preview');
  const [htmlSubView, setHtmlSubView] = useState<'template' | 'rendered'>('template');
  const [showTokensInCanvas, setShowTokensInCanvas] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const [customTemplate, setCustomTemplate] = useState<string>('');
  const [isCustomTemplate, setIsCustomTemplate] = useState(false);
  const [editorRef, setEditorRef] = useState<HTMLTextAreaElement | null>(null);

  const handleEnterEditor = () => {
    setCustomTemplate(newsDigestTemplate);
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
      setNewsDigestCustomTemplate(trimmed);
      setIsCustomTemplate(true);
      setViewFormat('preview');
    }
  };

  const handleResetCustomTemplate = () => {
    setNewsDigestCustomTemplate(null);
    setIsCustomTemplate(false);
    setCustomTemplate('');
  };

  const tokenList = useMemo(
    () => [
      '{{news_title}}',
      '{{news_subject_badge_text}}',
      '{{news_subject}}',
      '{{news_date}}',
      '{{news_count}}',
      '{{news_summary}}',
      '{{#each news_sources}}',
      '{{source_name}}',
      '{{published_at}}',
      '{{title}}',
      '{{url}}',
      '{{excerpt}}',
      '{{/each}}',
      '{{news_articles}}',
      '{{sources_hub_url}}',
      '{{news_footer}}',
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

  const [toolTab, setToolTab] = useState<'typography' | 'colors' | 'stamps' | 'tokens'>('colors');

  const newsSources: NewsSource[] = useMemo(() => {
    return SAMPLE_NEWS_ARTICLES.map((article) => ({
      title: article.title,
      url: article.source,
      source_name: article.feed,
      published_at: article.published,
      excerpt: article.evidence,
    }));
  }, []);

  /**
   * The template body in use right now.
   *
   * An unsaved edit in the HTML editor wins, so "Live Rendered Preview" shows
   * the code the operator is actually editing. Otherwise the saved studio
   * template is used, which the app keeps compiled from the live customization.
   */
  const activeTemplateSource = (): string => {
    if (isCustomTemplate && customTemplate.trim()) return customTemplate;
    return newsDigestTemplate || DEFAULT_NEWS_EMAIL_TEMPLATE;
  };

  /**
   * The one rendered document the studio shows.
   *
   * Both the "Rendered" inspector tab and the "Live Rendered Preview" pane read
   * this, so they can never disagree. It is the same renderer the delivery path
   * uses (`server/newsEmail.ts`), fed with the operator's LIVE customization
   * rather than a hard-coded default: the preview previously ignored every
   * colour and typography change, which is what made the source and the pane
   * show different documents.
   */
  const getRenderedHtml = (): string =>
    renderNewsTemplate(
      newsDigestCustomization,
      {
        news_title: 'Security News — Threat Intelligence',
        news_subject_badge_text: 'THREAT BRIEFING',
        news_subject:
          '[Threat intelligence] [NEWS] 3 articles: Critical Authentication Bypass in Enterprise Firewall',
        news_date: previewDate,
        news_count: SAMPLE_NEWS_ARTICLES.length,
        news_summary:
          'A total of 3 security news articles matched your monitored inventory in this intelligence run, including 1 potential zero-day, 1 high-severity RCE, and 1 medium-severity privilege escalation across monitored assets.',
        news_sources: newsSources,
        news_articles: '',
        sources_hub_url: 'https://www.cisa.gov/news-events/cybersecurity-advisories',
        news_footer:
          'This is applicability evidence, not a confirmed advisory. Confirm source authenticity and consult the vendor before remediation.',
      },
      activeTemplateSource(),
    );

  const getTemplateSource = (): string => activeTemplateSource();

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

  useEffect(() => {
    setPreviewKey((k) => k + 1);
  }, [newsDigestCustomization]);

  const scrollToIframeTop = () => {
    try {
      iframeRef.current?.contentWindow?.scrollTo({ top: 0, behavior: 'smooth' });
    } catch {}
  };

  const scrollToIframeBottom = () => {
    try {
      iframeRef.current?.contentWindow?.scrollTo({ top: 99999, behavior: 'smooth' });
    } catch {}
  };

  const handleDownloadHtml = () => {
    const blob = new Blob([getRenderedHtml()], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `news-template-${new Date().toISOString().split('T')[0]}.html`;
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

  // Colors are free-text inputs, so a malformed hex fails server validation. Surface
  // that before the save so the confirmation dialog can explain it instead of the
  // save appearing to do nothing.
  const saveValidationError = useMemo(() => {
    const labels: Array<[string, string]> = [
      ['canvasBg', 'Canvas Background'],
      ['cardBg', 'Card Background'],
      ['headerBg', 'Header Banner Bg'],
      ['accentColor', 'Accent & Link Color'],
      ['headingColor', 'Heading Font Color'],
      ['fontColor', 'Body Font Color'],
      ['badgeStampColor', 'Stamp Color'],
    ];
    const invalid = labels
      .filter(([key]) => !/^#[0-9a-f]{6}$/i.test(newsDigestCustomization[key as keyof typeof newsDigestCustomization] as string))
      .map(([, label]) => label);
    return invalid.length
      ? `Fix the color value${invalid.length > 1 ? 's' : ''} for: ${invalid.join(
          ', ',
        )}. Colors must be a 6-digit hex code like #1e40af.`
      : null;
  }, [newsDigestCustomization]);

  const handleSave = () => {
    clearError();
    setConfirmSave({ action: 'save', label: 'Save & Apply to News Digest' });
  };

  const executeSave = async () => {
    if (!confirmSave || savingTemplate || saveValidationError) return;
    setSavingTemplate(true);
    try {
      const ok = await saveNewsDigestTemplate(isCustomTemplate ? customTemplate : null);
      if (!ok) {
        // The save failed (server-side validation or a transient error); the
        // context `error` now holds the reason. Keep the dialog open so the
        // failure is visible where the operator clicked.
        return;
      }
      if (!isCustomTemplate) {
        setCustomTemplate('');
        setIsCustomTemplate(false);
      }
      setConfirmSave(null);
      setSaveToast(true);
      setTimeout(() => setSaveToast(false), 2500);
    } catch (saveError) {
      setConfirmSave(null);
      setTestResult({
        success: false,
        message: saveError instanceof Error ? saveError.message : 'Save failed',
      });
    } finally {
      setSavingTemplate(false);
    }
  };

  const handleReset = () => {
    setShowResetConfirm(true);
  };

  const confirmReset = () => {
    // Reset restores the NEWS studio defaults, not the daily-digest ones: the
    // two templates have different stock colours and fonts. Seeding from the
    // digest's palette recoloured the news document (slate/blue shipping
    // layout became the digest's theme) and kept the unsaved draft dirty, so a
    // "reset" immediately asked to be saved again.
    updateNewsDigestCustomization(DEFAULT_NEWS_EMAIL_CUSTOMIZATION);
    setShowResetConfirm(false);
  };

  const handleSendTest = async (e: React.FormEvent) => {
    e.preventDefault();
    // The server validates the address (`z.email()`), and the confirmation text
    // used to read "test email to recipient" when the field was empty. Reject it
    // here so the operator gets the reason instead of a 400 from the API.
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(testEmail.trim())) {
      setTestResult({ success: false, message: 'Enter a valid email address to receive the test.' });
      return;
    }
    const rendered = getRenderedHtml();
    const unrenderedTokens = rendered.match(/\{\{[a-z_]+\}\}/g);
    if (unrenderedTokens && unrenderedTokens.length > 0) {
      setTestResult({
        success: false,
        message: `Template has unrendered tokens in preview: ${[...new Set(unrenderedTokens)].join(', ')}. Check the HTML source or token list.`,
      });
      return;
    }
    setShowTestModal(false);
    setConfirmSendTest({ action: 'send-test', label: `test email to ${testEmail.trim()}` });
  };

  const executeSendTest = async () => {
    if (!confirmSendTest) return;
    try {
      // Route through the app context, exactly like the advisory and digest
      // studios. The previous implementation posted to `/api/test-news-email`,
      // an endpoint that does not exist on the server, with an empty CSRF
      // token: the request always failed (404 / CSRF rejection), the CSS-only
      // result banner stayed blank, and no test email was ever queued. The
      // context action attaches the session CSRF token, surfaces request errors
      // through the shared error banner, and hits the real `/api/test-email`
      // endpoint that accepts a pre-rendered News Studio document.
      const res = await sendTestEmail(testEmail.trim(), false, getRenderedHtml());
      setTestResult(res);
      if (res.success) {
        setTimeout(() => {
          setTestResult(null);
        }, 2500);
      }
    } finally {
      setConfirmSendTest(null);
    }
  };

  const handleCopyToken = async (token: string) => {
    if (await copyText(token)) {
      setCopiedToken(token);
      setTimeout(() => setCopiedToken(null), 1800);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="ui-page-header">
        <PageHeading page="news-template">
          Design a customized news digest. The digest sends a summary of matched security news articles and threat intelligence — never a PDF attachment. Preview desktop and mobile layouts, customize your branding, then save to apply it to future news digests.
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
            disabled={!!(confirmSave || confirmSendTest)}
            className="text-xs px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition shadow-sm"
          >
            {saveToast ? 'Applied to News Digest!' : 'Save & Apply to News Digest'}
          </button>
        </div>
      </div>

      {/* Live Controls Toolbar (Direct Customization) */}
      <div className="ui-panel bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 shadow-sm space-y-4 transition-colors">
        {/* Tool Sub-Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-200 pb-3">
          <div className="flex min-w-0 max-w-full overflow-x-auto items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-1 rounded-xl">
            <button
              onClick={() => setToolTab('colors')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                toolTab === 'colors'
                  ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                  : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
              }`}
            >
              <Palette className="w-3.5 h-3.5" />
              <span>Background &amp; Colors</span>
            </button>

            <button
              onClick={() => setToolTab('typography')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                toolTab === 'typography'
                  ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                  : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
              }`}
            >
              <Type className="w-3.5 h-3.5" />
              <span>Font Style &amp; Typography</span>
            </button>

            <button
              onClick={() => setToolTab('stamps')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                toolTab === 'stamps'
                  ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                  : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
              }`}
            >
              <Stamp className="w-3.5 h-3.5" />
              <span>Drawing Objects &amp; Stamps</span>
            </button>

            <button
              onClick={() => setToolTab('tokens')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
                toolTab === 'tokens'
                  ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                  : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Dynamic Tokens</span>
            </button>
          </div>

          {/* Device Preview Switcher */}
          <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-1 rounded-xl">
            <button
              onClick={() => setPreviewDevice('desktop')}
              className={`p-1.5 rounded-lg transition ${
                previewDevice === 'desktop'
                  ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-300'
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
                  : 'text-zinc-400 hover:text-zinc-300'
              }`}
              title="Mobile Client View (390px)"
            >
              <Smartphone className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab 1: Colors & Backgrounds */}
        {toolTab === 'colors' && (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Canvas Background
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={newsDigestCustomization.canvasBg}
                  onChange={(e) => updateNewsDigestCustomization({ canvasBg: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={newsDigestCustomization.canvasBg}
                  onChange={(e) => updateNewsDigestCustomization({ canvasBg: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
              <div className="flex gap-1.5 mt-2">
                {['#09090b', '#0b0f19', '#18181b', '#f8fafc'].map((c) => (
                  <button
                    key={c}
                    onClick={() => updateNewsDigestCustomization({ canvasBg: c })}
                    className="w-5 h-5 rounded-md border border-zinc-700"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Card Background
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={newsDigestCustomization.cardBg}
                  onChange={(e) => updateNewsDigestCustomization({ cardBg: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={newsDigestCustomization.cardBg}
                  onChange={(e) => updateNewsDigestCustomization({ cardBg: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
              <div className="flex gap-1.5 mt-2">
                {['#18181b', '#1e293b', '#27272a', '#ffffff'].map((c) => (
                  <button
                    key={c}
                    onClick={() => updateNewsDigestCustomization({ cardBg: c })}
                    className="w-5 h-5 rounded-md border border-zinc-700"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Header Banner Bg
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={newsDigestCustomization.headerBg}
                  onChange={(e) => updateNewsDigestCustomization({ headerBg: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={newsDigestCustomization.headerBg}
                  onChange={(e) => updateNewsDigestCustomization({ headerBg: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
              <div className="flex gap-1.5 mt-2">
                {['#1e293b', '#09090b', '#312e81', '#450a0a'].map((c) => (
                  <button
                    key={c}
                    onClick={() => updateNewsDigestCustomization({ headerBg: c })}
                    className="w-5 h-5 rounded-md border border-zinc-700"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Accent &amp; Link Color
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={newsDigestCustomization.accentColor}
                  onChange={(e) => updateNewsDigestCustomization({ accentColor: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={newsDigestCustomization.accentColor}
                  onChange={(e) => updateNewsDigestCustomization({ accentColor: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
              <div className="flex gap-1.5 mt-2">
                {['#3b82f6', '#10b981', '#8b5cf6', '#ef4444'].map((c) => (
                  <button
                    key={c}
                    onClick={() => updateNewsDigestCustomization({ accentColor: c })}
                    className="w-5 h-5 rounded-md border border-zinc-700"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Typography */}
        {toolTab === 'typography' && (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Font Style / Family
              </label>
              <select
                value={newsDigestCustomization.fontFamily}
                onChange={(e) =>
                  updateNewsDigestCustomization({
                    fontFamily: e.target.value as any,
                  })
                }
                className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-3 py-2 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-medium"
              >
                <option value="sans">Plus Jakarta Sans / Modern</option>
                <option value="mono">JetBrains Mono / Technical</option>
                <option value="serif">Georgia / Editorial Serif</option>
                <option value="system">System Clean / Native</option>
              </select>
            </div>

            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Heading Font Color
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={newsDigestCustomization.headingColor}
                  onChange={(e) => updateNewsDigestCustomization({ headingColor: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={newsDigestCustomization.headingColor}
                  onChange={(e) => updateNewsDigestCustomization({ headingColor: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 font-mono mb-1.5">Body Font Color</label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={newsDigestCustomization.fontColor}
                  onChange={(e) => updateNewsDigestCustomization({ fontColor: e.target.value })}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0"
                />
                <input
                  type="text"
                  value={newsDigestCustomization.fontColor}
                  onChange={(e) => updateNewsDigestCustomization({ fontColor: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1"
                />
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 font-mono mb-1.5">Border Style &amp; Radius</label>
              <div className="flex items-center space-x-2">
                <select
                  value={newsDigestCustomization.borderStyle}
                  onChange={(e) => updateNewsDigestCustomization({ borderStyle: e.target.value as any })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2 py-1.5 text-zinc-200 text-xs flex-1"
                >
                  <option value="solid">Solid Border</option>
                  <option value="dashed">Dashed Border</option>
                  <option value="none">No Border</option>
                </select>
                <select
                  value={newsDigestCustomization.borderRadius}
                  onChange={(e) => updateNewsDigestCustomization({ borderRadius: e.target.value })}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2 py-1.5 text-zinc-200 text-xs"
                >
                  <option value="0px">Sharp (0px)</option>
                  <option value="8px">Round (8px)</option>
                  <option value="12px">Pill (12px)</option>
                  <option value="20px">Curved (20px)</option>
                </select>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Drawing Objects & Stamps */}
        {toolTab === 'stamps' && (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 text-xs">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono">
                  Security Stamp Object
                </label>
                <input
                  type="checkbox"
                  checked={newsDigestCustomization.showStamp}
                  onChange={(e) => updateNewsDigestCustomization({ showStamp: e.target.checked })}
                  className="rounded border-zinc-700 text-zinc-200"
                />
              </div>
              <input
                type="text"
                value={newsDigestCustomization.badgeStampText}
                onChange={(e) => updateNewsDigestCustomization({ badgeStampText: e.target.value })}
                placeholder="e.g. SECURITY NEWS"
                disabled={!newsDigestCustomization.showStamp}
                className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-3 py-2 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 disabled:opacity-40 font-mono text-xs"
              />
              <div className="flex items-center space-x-1.5 mt-2">
                <span className="text-[11px] text-zinc-500 font-mono">Presets:</span>
                {['CONFIDENTIAL', 'URGENT ACTION', 'OFFICIAL BULLETIN', 'CSAF VEX'].map((t) => (
                  <button
                    key={t}
                    onClick={() => updateNewsDigestCustomization({ badgeStampText: t })}
                    className="px-2 py-0.5 rounded bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 text-[10px] font-mono hover:bg-zinc-700"
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mb-1.5">
                Stamp Color
              </label>
              <div className="flex items-center space-x-2">
                <input
                  type="color"
                  value={newsDigestCustomization.badgeStampColor}
                  onChange={(e) => updateNewsDigestCustomization({ badgeStampColor: e.target.value })}
                  disabled={!newsDigestCustomization.showStamp}
                  className="w-8 h-8 rounded-lg cursor-pointer bg-transparent border-0 disabled:opacity-40"
                />
                <input
                  type="text"
                  value={newsDigestCustomization.badgeStampColor}
                  onChange={(e) => updateNewsDigestCustomization({ badgeStampColor: e.target.value })}
                  disabled={!newsDigestCustomization.showStamp}
                  className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs flex-1 disabled:opacity-40"
                />
              </div>
              <div className="flex gap-1.5 mt-2">
                {['#ef4444', '#f59e0b', '#10b981', '#6366f1'].map((c) => (
                  <button
                    key={c}
                    onClick={() => updateNewsDigestCustomization({ badgeStampColor: c })}
                    className="w-5 h-5 rounded-md border border-zinc-700"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono">
                  Classification Banner
                </label>
                <input
                  type="checkbox"
                  checked={newsDigestCustomization.showClassificationBanner}
                  onChange={(e) =>
                    updateNewsDigestCustomization({ showClassificationBanner: e.target.checked })
                  }
                  className="rounded border-zinc-700 text-zinc-200"
                />
              </div>
              <input
                type="text"
                value={newsDigestCustomization.classificationText}
                onChange={(e) => updateNewsDigestCustomization({ classificationText: e.target.value })}
                disabled={!newsDigestCustomization.showClassificationBanner}
                className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg px-3 py-2 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 disabled:opacity-40 font-mono text-xs"
              />
              <span className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono block mt-1">
                Rendered across the top edge of news digest emails
              </span>
            </div>
          </div>
        )}

        {/* Tab 4: Dynamic Tokens */}
        {toolTab === 'tokens' && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono text-[11px] font-medium">
              Click to Copy:
            </span>
            {tokenList.map((token) => (
              <button
                key={token}
                type="button"
                onClick={() => handleCopyToken(token)}
                className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 px-2.5 py-1 rounded-lg text-[11px] font-mono hover:border-zinc-600 transition flex items-center space-x-1"
                title="Click to copy token"
              >
                <span>{token}</span>
                {copiedToken === token && <Check className="w-3 h-3 text-emerald-400" />}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* RENDERED CLIENT PREVIEW */}
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

            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/40 text-emerald-300 border border-emerald-800/60 flex items-center space-x-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>Live Rendering Active</span>
            </span>

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

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-0.5 rounded-xl">
              <button
                type="button"
                onClick={() => setScrollMode('fit')}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition ${
                  scrollMode === 'fit'
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm font-semibold'
                    : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
                }`}
                title="Auto-Fit Full Height"
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
                title="Fixed Viewport"
              >
                Fixed Viewport
              </button>
            </div>

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
              title="Download News HTML Template"
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

        {/* View Mode 1: HTML Code Inspector */}
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
              <span>{(htmlSubView === 'template' ? getTemplateSource() : getRenderedHtml()).length} characters</span>
            </div>
            <p className="px-4 py-2 bg-zinc-950 border-b border-zinc-800 text-[11px] leading-relaxed text-zinc-500">
              {htmlSubView === 'template'
                ? 'Template source: the document with {{tokens}}. This is what gets saved and re-rendered per recipient. It is expected to differ from the Rendered tab once tokens are replaced.'
                : 'Rendered: the template with preview values substituted and the live customization applied. This is byte-for-byte what "Live Rendered Preview" below shows.'}
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
                  <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" title="Custom template active" />
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-1.5 px-4 py-2 bg-zinc-950 border-b border-zinc-800">
              <span className="text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono text-[10px]">
                Insert Token:
              </span>
              {tokenList.map((token) => (
                <button
                  key={token}
                  type="button"
                  onClick={() => handleInsertToken(token)}
                  className="bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 px-2 py-0.5 rounded font-mono text-[10px] hover:border-zinc-600 transition flex items-center space-x-1"
                  title={`Insert ${token}`}
                >
                  {token}
                </button>
              ))}
            </div>

            <div className="flex-1 flex h-[560px]">
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

              <div className="w-1/2 flex flex-col">
                <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900/80 border-b border-zinc-800 text-xs font-mono text-zinc-400">
                  {/* The label follows the toggle: showing the raw template must
                      never be presented as a rendered preview. */}
                  <span>{showTokensInCanvas ? 'Template With Tokens (unrendered)' : 'Live Rendered Preview'}</span>
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
                        backgroundColor: newsDigestCustomization.canvasBg || '#09090b',
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
          <div className="ui-panel w-full flex justify-center py-6 px-2 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 rounded-2xl border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-300 overflow-x-auto relative">
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
              {previewDevice === 'desktop' && (
                <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-200 border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-300 px-4 py-2.5 flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center space-x-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" />
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
                  </div>
                  <div className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-white text-zinc-400 dark:text-zinc-400 light:text-zinc-600 px-3 py-1 rounded-lg text-[11px] truncate max-w-md border border-zinc-800/60 dark:border-zinc-800/60 light:border-zinc-300">
                    News preview
                  </div>
                  <div className="text-[10px] text-zinc-500">680px Canvas</div>
                </div>
              )}

              {previewDevice === 'mobile' && (
                <div className="relative rounded-[32px] overflow-hidden bg-zinc-950 border border-zinc-800">
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

              <div
                className={`relative bg-zinc-950 ${
                  scrollMode === 'contained' ? 'overflow-y-auto max-h-[640px]' : ''
                }`}
              >
                <iframe
                  ref={iframeRef}
                  key={previewKey}
                  title="News Digest Preview"
                srcDoc={showTokensInCanvas ? getTemplateSource() : getRenderedHtml()}
                  onLoad={syncIframeHeight}
                  scrolling="auto"
                  style={{
                    height: scrollMode === 'fit' ? `${iframeHeight}px` : '640px',
                    width: '100%',
                    display: 'block',
                    border: 'none',
                    backgroundColor: newsDigestCustomization.canvasBg || '#09090b',
                  }}
                  className="w-full transition-all duration-150"
                />

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
              <FileCode className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              <h2 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                Fullscreen News Template Studio
              </h2>
            </div>
            <button
              type="button"
              onClick={() => setIsFullscreen(false)}
              className="p-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-600 light:hover:text-zinc-900 transition"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="flex-1 overflow-auto p-4">
            <iframe
              key={previewKey}
              title="Fullscreen News Digest Preview"
            srcDoc={getRenderedHtml()}
              style={{
                width: '100%',
                height: '800px',
                display: 'block',
                border: 'none',
                backgroundColor: newsDigestCustomization.canvasBg || '#09090b',
              }}
              className="border-none"
            />
          </div>
        </div>
      )}

      {/* Confirmation Modals. z-[60] keeps them above the fullscreen studio
          overlay and the sticky shell headers (both z-50). */}
      {confirmSave && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="news-template-save-title"
        >
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-sm"
            onClick={() => {
              if (savingTemplate) return;
              setConfirmSave(null);
              clearError();
            }}
          />
          <div className="relative bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <h3
              id="news-template-save-title"
              className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2"
            >
              Save News Template?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              This will apply your customized news digest template to all future news digests.
            </p>
            {(saveValidationError || error) && (
              <div
                role="alert"
                className="mb-4 rounded-xl border border-rose-800/50 bg-rose-950/70 light:bg-rose-50 px-3 py-2.5 text-xs text-rose-100 light:text-rose-800"
              >
                {saveValidationError || error}
              </div>
            )}
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setConfirmSave(null);
                  clearError();
                }}
                disabled={savingTemplate}
                className="px-4 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 light:hover:text-zinc-900 font-medium transition disabled:opacity-60"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={executeSave}
                disabled={savingTemplate || !!saveValidationError}
                className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-medium transition disabled:opacity-60"
              >
                {savingTemplate ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
      {confirmSendTest && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" role="dialog" aria-modal="true">
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setConfirmSendTest(null)} />
          <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              Send Test News Email?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-6">
              Send a test email with the current preview to{confirmSendTest.label.replace('send-test ', '')}.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmSendTest(null)}
                className="px-4 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 light:hover:text-zinc-900 font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={executeSendTest}
                disabled={confirmSendTest?.action === 'sending'}
                className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium transition"
              >
                {confirmSendTest.action === 'sending' ? 'Sending...' : 'Send'}
              </button>
            </div>
          </div>
        </div>
      )}
      {showTestModal && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" role="dialog" aria-modal="true">
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setShowTestModal(false)} />
          <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-4">
              Send Test News Email
            </h3>
            <div className="space-y-3">
              <label className="block text-xs text-zinc-500 font-mono uppercase mb-1">Recipient Email</label>
              <input
                type="email"
                value={testEmail}
                onChange={(e) => setTestEmail(e.target.value)}
                placeholder="you@example.com"
                className="w-full px-3 py-2 rounded bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-mono text-xs focus:outline-none focus:border-accent-500"
              />
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                type="button"
                onClick={() => setShowTestModal(false)}
                className="px-4 py-2 rounded-lg text-xs font-medium text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSendTest}
                className="px-4 py-2 rounded-lg text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white"
              >
                Send Test Email
              </button>
            </div>
            {testResult && (
              <div className={`mt-4 p-3 rounded bg-${
                testResult.success ? 'emerald-900/20' : 'red-900/20'
              } border-${
                testResult.success ? 'emerald-800/40' : 'red-800/40'
              } text-${testResult.success ? 'emerald-400' : 'red-400'} text-[11px]`}>
                {testResult.message}
              </div>
            )}
          </div>
        </div>
      )}
      {showResetConfirm && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" role="dialog" aria-modal="true">
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setShowResetConfirm(false)} />
          <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-4">
              Reset News Template
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-6">
              This will discard your custom template and revert to the default news digest template.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowResetConfirm(false)}
                className="px-4 py-2 rounded-lg text-xs font-medium text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmReset}
                className="px-4 py-2 rounded-lg text-xs font-medium bg-red-600 hover:bg-red-500 text-white"
              >
                Reset
              </button>
            </div>
          </div>
        </div>
      )}
      {saveToast && (
        <div
          role="status"
          className="fixed bottom-4 right-4 z-[70] flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-900/20 text-emerald-400 border border-emerald-800/40"
        >
          <CheckCircle2 className="w-3 h-3" />
          <span className="text-xs font-medium">News template applied to future digests</span>
        </div>
      )}
    </div>
  );
};

export default NewsTemplateView;
