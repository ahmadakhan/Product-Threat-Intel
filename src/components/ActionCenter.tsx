import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useApp } from '../context/AppContext';
import { useCollection } from '../hooks/useCollection';
import {
  Search,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  RefreshCw,
  Filter,
  TrendingUp,
  Send,
  Edit3,
  Archive,
  X,
  Activity,
  FileText,
  Mail,
  Eye,
} from 'lucide-react';
import { Pagination } from './Pagination';
import { formatDateTime as fmtDateTime } from '../utils/dateTime';
import type { EmailDeliveryLog, ReviewEdits } from '../types';
import { PageHeading } from './PageHeading';
import { isFindingDelivery } from '../utils/findingDelivery';

interface SLAMetrics {
  delivered: number;
  failed: number;
  queued: number;
  pendingAction: number;
  averageDeliveryTime: number;
  deliveryRate: number;
  slaCompliance: number;
  lastDeliveryWindow: { count: number; time: string };
}

interface FilterOptions {
  dateRange: 'today' | 'week' | 'month' | 'quarter' | 'year' | 'custom';
  status:
    | 'ALL'
    | 'DELIVERED'
    | 'ACCEPTED'
    | 'REVIEW_REQUIRED'
    | 'QUEUED'
    | 'SENDING'
    | 'RETRYING'
    | 'FAILED'
    | 'CANCELLED';
  provider: string;
  actionStatus: 'ALL' | 'PENDING' | 'ACTIONED';
  advisoryId?: string;
}

type RecipientMode = 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE';

/** Transport acceptance and legacy inbox confirmation both mean "delivered". */
const DELIVERED_STATUSES = new Set(['ACCEPTED', 'DELIVERED']);

const isDeliveredLog = (log: EmailDeliveryLog) => DELIVERED_STATUSES.has(log.status);

/**
 * A delivered finding email starts PENDING and stays there until an operator
 * acknowledges it or dispatches an updated copy. Legacy logs have no
 * `actionStatus`; they are PENDING by definition so older deliveries still
 * appear in the SLA queue.
 */
const isActionPending = (log: EmailDeliveryLog) =>
  isDeliveredLog(log) && (log.actionStatus ?? 'PENDING') === 'PENDING' && isFindingDelivery(log.advisoryId);

export const ActionCenter: React.FC = () => {
  const {
    settings,
    refresh,
    retryEmailDelivery,
    resendEmailDelivery,
    editEmailReview,
    previewEmailReview,
    previewEmailEdits,
    previewEmailPdf,
    acknowledgeEmailDelivery,
    updateAndSendEmail,
    approveEmailDelivery,
    deleteEmailQueueItem,
    advisories,
    findings,
  } = useApp();
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState<FilterOptions>({
    dateRange: 'week',
    status: 'ALL',
    provider: 'ALL',
    actionStatus: 'ALL',
  });
  const [selectedLogs, setSelectedLogs] = useState<Set<string>>(new Set());
  const [showBulkActions, setShowBulkActions] = useState(false);
  const [slaMetrics, setSLAMetrics] = useState<SLAMetrics | null>(null);
  const [isCalculatingSLA, setIsCalculatingSLA] = useState(false);
  const [editing, setEditing] = useState<EmailDeliveryLog | null>(null);
  const [edits, setEdits] = useState<ReviewEdits>({});
  const [subjectDraft, setSubjectDraft] = useState('');
  const [recipientMode, setRecipientMode] = useState<RecipientMode>('SECURITY_TEAM');
  const [customEmail, setCustomEmail] = useState('');
  const [reason, setReason] = useState('');
  const [previewHtml, setPreviewHtml] = useState<string>('');
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewTab, setPreviewTab] = useState<'email' | 'pdf'>('email');
  const [pdfUrl, setPdfUrl] = useState<string | null>(null);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const [editBusy, setEditBusy] = useState(false);
  const [livePreviewDebounce, setLivePreviewDebounce] = useState<ReturnType<typeof setTimeout> | null>(null);
  const pdfUrlRef = useRef<string | null>(null);
  const [resending, setResending] = useState<{ id: string; advisoryId: string; mode: RecipientMode; email: string; reason: string } | null>(null);
  const [resendBusy, setResendBusy] = useState(false);
  const [actionBusyId, setActionBusyId] = useState<string | null>(null);
  
  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const {
    items: emailLogs,
    total,
    loading,
    reload,
  } = useCollection<EmailDeliveryLog>('emailLogs', {
    page: currentPage,
    pageSize,
    search: searchTerm,
    filters: {
      status: filters.status,
      provider: filters.provider === 'ALL' ? null : filters.provider,
      actionStatus: filters.actionStatus,
      advisoryId: filters.advisoryId || undefined,
      dateRange: filters.dateRange,
    },
  });

  // Calculate SLA metrics
  useEffect(() => {
    const calculateSLAMetrics = async () => {
      setIsCalculatingSLA(true);
      try {
        // SLA metrics derived from the current page of delivery logs.
        // ACCEPTED is the status the delivery worker actually writes when the
        // transport accepts a message; DELIVERED is the legacy/confirmed value.
        const delivered = emailLogs.filter(isDeliveredLog).length;
        const pendingAction = emailLogs.filter(isActionPending).length;
        const failed = emailLogs.filter(log => log.status === 'FAILED').length;
        const queued = emailLogs.filter(log => ['QUEUED', 'SENDING', 'RETRYING', 'REVIEW_REQUIRED'].includes(log.status)).length;
        const totalLogs = emailLogs.length;
        
        // Calculate delivery rate
        const deliveryRate = totalLogs > 0 ? (delivered / totalLogs) * 100 : 0;

        const now = new Date();
        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        
        // Recent deliveries define the 24-hour sample everything below uses.
        const recentDeliveries = emailLogs
          .filter(log => isDeliveredLog(log) && log.sentAt && new Date(log.sentAt) >= yesterday)
          .slice(0, 50);

        // First-attempt success rate is real signal derivable from the log:
        // a job delivered on attempt 1 never needed the retry schedule.
        const firstAttemptDelivered = recentDeliveries.filter((log) => log.attemptCount === 1).length;
        const avgDeliveryTime = recentDeliveries.length > 0
          ? (firstAttemptDelivered / recentDeliveries.length) * 100
          : 0;

        // SLA compliance = deliveries that needed no retry at all, from the
        // same 24-hour sample (previously a hard-coded 100).
        const slaCompliance = avgDeliveryTime;

        const lastHour = new Date(now.getTime() - 60 * 60 * 1000);
        const lastHourDeliveries = emailLogs.filter(log =>
          isDeliveredLog(log) &&
          log.sentAt &&
          new Date(log.sentAt) >= lastHour
        );
        
        setSLAMetrics({
          delivered,
          failed,
          queued,
          pendingAction,
          averageDeliveryTime: avgDeliveryTime,
          deliveryRate,
          slaCompliance,
          lastDeliveryWindow: {
            count: lastHourDeliveries.length,
            time: lastHourDeliveries.length > 0 ? 
              `${lastHourDeliveries[0].sentAt} - ${now.toISOString()}` : 
              'No deliveries'
          }
        });
      } catch (error) {
        console.error('Error calculating SLA metrics:', error);
      } finally {
        setIsCalculatingSLA(false);
      }
    };
    
    calculateSLAMetrics();
  }, [emailLogs]);

  const handleRetry = async (logId: string) => {
    try {
      await retryEmailDelivery(logId);
      await reload();
    } catch (error) {
      console.error('Error retrying delivery:', error);
    }
  };

  const handleBulkAction = async (action: 'retry' | 'cancel' | 'send-now') => {
    // "Retry" and "send now" both force the job back onto the queue (the
    // server refuses in-flight/due jobs so this cannot double-send); "cancel"
    // removes the queued job. Failures for one id must not abandon the rest.
    const results = await Promise.allSettled(
      [...selectedLogs].map((logId) =>
        action === 'cancel'
          ? deleteEmailQueueItem(logId)
          : retryEmailDelivery(logId),
      ),
    );
    const failures = results.filter((r) => r.status === 'rejected').length;
    if (failures)
      console.error(`Bulk ${action}: ${failures} of ${selectedLogs.size} operations failed`);
    setSelectedLogs(new Set());
    setShowBulkActions(false);
    await reload();
  };

  /** Releases the blob URL backing the PDF preview. */
  const revokePdf = useCallback(() => {
    if (pdfUrlRef.current) {
      URL.revokeObjectURL(pdfUrlRef.current);
      pdfUrlRef.current = null;
    }
    setPdfUrl(null);
  }, []);

  const buildEdits = useCallback(
    (): ReviewEdits => ({
      ...edits,
      subject: subjectDraft.trim() || undefined,
      recipientMode,
      customEmail: recipientMode === 'SINGLE_EMAIL' ? customEmail.trim() || undefined : undefined,
    }),
    [edits, subjectDraft, recipientMode, customEmail],
  );

  const saveEdit = useCallback(async () => {
    if (!editing) return;
    setEditBusy(true);
    try {
      const result = await editEmailReview(editing.id, buildEdits());
      if (result) {
        setEditing(null);
        await reload();
      }
    } finally {
      setEditBusy(false);
    }
  }, [editing, buildEdits, editEmailReview, reload]);

  /** Approve a held review job, or dispatch an updated copy of a delivered one. */
  const sendUpdated = useCallback(async () => {
    if (!editing) return;
    setEditBusy(true);
    try {
      if (editing.status === 'REVIEW_REQUIRED') {
        const saved = await editEmailReview(editing.id, buildEdits());
        if (!saved) return;
        const approved = await approveEmailDelivery(editing.id);
        if (approved) {
          setEditing(null);
          await reload();
        }
        return;
      }
      const result = await updateAndSendEmail(editing.id, {
        subject: subjectDraft.trim() || undefined,
        audienceNotice: edits.audienceNotice,
        reviewerComment: edits.reviewerComment,
        reviewerName: edits.reviewerName,
        customBodyOverride: edits.customBodyOverride,
        recipientMode,
        customEmail:
          recipientMode === 'SINGLE_EMAIL' ? customEmail.trim() || undefined : undefined,
        reason: reason.trim() || undefined,
      });
      if (result) {
        setEditing(null);
        await reload();
      }
    } finally {
      setEditBusy(false);
    }
  }, [
    editing,
    buildEdits,
    approveEmailDelivery,
    updateAndSendEmail,
    subjectDraft,
    edits,
    recipientMode,
    customEmail,
    reason,
    reload,
  ]);

  const refreshPdf = useCallback(async () => {
    if (!editing) return;
    setPdfLoading(true);
    setPdfError(null);
    try {
      const blob = await previewEmailPdf(editing.id, buildEdits());
      if (!blob) {
        setPdfError('PDF preview could not be generated. See the error banner for details.');
        return;
      }
      if (pdfUrlRef.current) URL.revokeObjectURL(pdfUrlRef.current);
      const url = URL.createObjectURL(blob);
      pdfUrlRef.current = url;
      setPdfUrl(url);
    } catch (caught) {
      setPdfError(caught instanceof Error ? caught.message : 'PDF preview failed');
    } finally {
      setPdfLoading(false);
    }
  }, [editing, buildEdits, previewEmailPdf]);

  const triggerLivePreview = useCallback(
    (newEdits: ReviewEdits, newSubject?: string) => {
      if (!editing) return;
      // Any edit invalidates the rendered PDF; the operator re-renders on demand.
      revokePdf();
      setPdfError(null);
      if (livePreviewDebounce) clearTimeout(livePreviewDebounce);
      const timer = setTimeout(() => {
        setPreviewLoading(true);
        void previewEmailEdits(editing.id, {
          ...newEdits,
          subject: (newSubject ?? subjectDraft).trim() || undefined,
        }).then((result) => {
          if (result) setPreviewHtml(result.html);
          setPreviewLoading(false);
        });
      }, 500);
      setLivePreviewDebounce(timer);
    },
    // livePreviewDebounce is intentionally not a dependency: the callback only
    // cancels the previous timer and setState makes the new one visible to the
    // cleanup effect without re-creating this closure.
    [editing, subjectDraft, previewEmailEdits, revokePdf],
  );

  // Pending live-preview request, debounce timer and PDF blob must not outlive
  // the editor: clear/release all three on unmount and when the editor closes.
  useEffect(() => {
    if (editing) return;
    if (livePreviewDebounce) clearTimeout(livePreviewDebounce);
    setPreviewHtml('');
    revokePdf();
  }, [editing, livePreviewDebounce, revokePdf]);
  useEffect(
    () => () => {
      if (livePreviewDebounce) clearTimeout(livePreviewDebounce);
      if (pdfUrlRef.current) URL.revokeObjectURL(pdfUrlRef.current);
    },
    [livePreviewDebounce],
  );

  const isEditable = (log: EmailDeliveryLog) =>
    log.status === 'REVIEW_REQUIRED' || log.status === 'QUEUED';

  /** Delivered finding emails remain actionable until an operator closes them. */
  const isFollowUpEligible = (log: EmailDeliveryLog) =>
    (isDeliveredLog(log) || log.status === 'FAILED') && isFindingDelivery(log.advisoryId);

  const isActionable = (log: EmailDeliveryLog) => 
    log.status === 'FAILED' || 
    (log.status === 'QUEUED' && log.attemptCount > 0) ||
    (log.status === 'RETRYING' && new Date(log.nextRetryTime || '').getTime() <= Date.now());

  /** CVEs tracked by this delivery: advisory CVE ids plus the CVEs of its findings. */
  const trackedCves = useMemo(() => {
    const byAdvisory = new Map<string, string[]>();
    for (const advisory of advisories) {
      const cves = new Set<string>(advisory.cveIds);
      for (const finding of findings) {
        if (advisory.findingIds.includes(finding.id)) cves.add(finding.cveId);
      }
      byAdvisory.set(advisory.id, [...cves].sort());
    }
    return (advisoryId: string): string[] => byAdvisory.get(advisoryId) ?? [];
  }, [advisories, findings]);

  const cveChips = (advisoryId: string) => {
    const cves = trackedCves(advisoryId);
    return cves.slice(0, 3).map((cve) => (
      <span key={cve} className="mx-0.5 inline-flex items-center rounded bg-zinc-800/60 dark:bg-zinc-800/60 light:bg-zinc-200 px-1.5 py-0.5 text-[10px] font-mono font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-900" title={`Tracking ${cve}`}>
        {cve}
      </span>
    ));
  };

  const cveOverflow = (advisoryId: string) => {
    const cves = trackedCves(advisoryId);
    return cves.length > 3 ? ` +${cves.length - 3}` : null;
  };

  const openEmailEditor = useCallback(
    (log: EmailDeliveryLog) => {
      setEditing(log);
      setEdits({});
      setSubjectDraft(log.subject);
      setReason('');
      setRecipientMode('SECURITY_TEAM');
      setCustomEmail(log.recipientEmail);
      setPreviewTab('email');
      setPdfError(null);
      revokePdf();
      setPreviewLoading(true);
      void previewEmailReview(log.id).then((preview) => {
        if (preview) {
          setPreviewHtml(preview.html);
          setEdits(preview.edits);
          // A saved subject override is what the recipient actually sees.
          setSubjectDraft(preview.subject || log.subject);
          if (preview.edits.recipientMode) setRecipientMode(preview.edits.recipientMode);
          if (preview.edits.customEmail) setCustomEmail(preview.edits.customEmail);
        }
        setPreviewLoading(false);
      });
    },
    [previewEmailReview, revokePdf],
  );

  const handleAcknowledge = useCallback(
    async (log: EmailDeliveryLog) => {
      setActionBusyId(log.id);
      try {
        const ok = await acknowledgeEmailDelivery(log.id);
        if (ok) await reload();
      } finally {
        setActionBusyId(null);
      }
    },
    [acknowledgeEmailDelivery, reload],
  );

  const slaStatusColor = (compliance: number) => {
    if (compliance >= 95) return 'text-emerald-400';
    if (compliance >= 90) return 'text-amber-400';
    return 'text-rose-400';
  };

  const deliveryStatusBadge = (log: EmailDeliveryLog) => {
    if (isDeliveredLog(log)) {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <CheckCircle2 className="w-3 h-3" />
          <span>{log.status === 'ACCEPTED' ? 'ACCEPTED' : 'DELIVERED'}</span>
        </span>
      );
    }
    if (log.status === 'FAILED') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
          <AlertTriangle className="w-3 h-3" />
          <span>FAILED</span>
        </span>
      );
    }
    if (log.status === 'REVIEW_REQUIRED') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-violet-500/10 text-violet-400 border border-violet-500/20">
          <Eye className="w-3 h-3" />
          <span>REVIEW</span>
        </span>
      );
    }
    if (log.status === 'CANCELLED') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
          <Archive className="w-3 h-3" />
          <span>CANCELLED</span>
        </span>
      );
    }
    if (isActionable(log) || log.status === 'RETRYING') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
          <RefreshCw className="w-3 h-3" />
          <span>{log.status === 'RETRYING' ? 'RETRYING' : 'RETRY DUE'}</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
        <Clock3 className="w-3 h-3" />
        <span>{log.status === 'SENDING' ? 'SENDING' : 'QUEUED'}</span>
      </span>
    );
  };

  /**
   * Action SLA state shown in the table. A delivered finding email is PENDING
   * until an operator acknowledges it or sends an updated copy; only failed,
   * bounced, or cancelled deliveries count as SLA violations.
   */
  const actionSlaState = (log: EmailDeliveryLog): 'PENDING' | 'COMPLIANT' | 'VIOLATION' | 'N/A' => {
    if (log.status === 'CANCELLED') return 'N/A';
    if (log.status === 'FAILED' || log.status === 'BOUNCED') return 'VIOLATION';
    if (!isDeliveredLog(log)) return 'PENDING';
    return isActionPending(log) ? 'PENDING' : 'COMPLIANT';
  };

  const actionStatusBadge = (log: EmailDeliveryLog) => {
    if (!isDeliveredLog(log) || !isFindingDelivery(log.advisoryId)) return null;
    return isActionPending(log) ? (
      <span className="inline-flex items-center space-x-1 rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-400">
        <Clock3 className="h-3 w-3" />
        <span>ACTION PENDING</span>
      </span>
    ) : (
      <span className="inline-flex items-center space-x-1 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
        <CheckCircle2 className="h-3 w-3" />
        <span>ACTIONED</span>
      </span>
    );
  };

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedLogs(new Set(emailLogs.map(log => log.id)));
      setShowBulkActions(true);
    } else {
      setSelectedLogs(new Set());
      setShowBulkActions(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="ui-page-header">
        <PageHeading page="action-center">
          Delivered finding emails stay here as PENDING actions until an operator
          acknowledges them or edits and re-sends a corrected copy.
        </PageHeading>
        
        <div className="flex flex-wrap items-center gap-3">
          {/* SLA Status Indicator */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
            <TrendingUp className="w-4 h-4 text-zinc-400" />
            <span className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700">SLA: {slaMetrics?.slaCompliance.toFixed(1)}%</span>
            <span className={`text-xs font-medium ${slaStatusColor(slaMetrics?.slaCompliance || 0)}`}>
              {slaMetrics?.averageDeliveryTime.toFixed(1)}% first-attempt
            </span>
          </div>
          
          {/* Delivery Metrics */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
            <Shield className="w-4 h-4 text-zinc-400" />
            <span className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              {slaMetrics?.delivered || 0} / {slaMetrics?.failed || 0} / {slaMetrics?.queued || 0}
            </span>
          </div>

          {/* Pending operator actions */}
          <button
            type="button"
            onClick={() =>
              setFilters((prev) => ({
                ...prev,
                actionStatus: prev.actionStatus === 'PENDING' ? 'ALL' : 'PENDING',
              }))
            }
            className={`flex items-center space-x-2 rounded-xl border px-3 py-1.5 transition ${
              filters.actionStatus === 'PENDING'
                ? 'border-amber-500/40 bg-amber-500/10'
                : 'border-zinc-800 bg-zinc-900/50 light:border-zinc-200 light:bg-white'
            }`}
            title="Filter deliveries awaiting an operator action"
          >
            <Mail className="w-4 h-4 text-amber-400" />
            <span className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              {slaMetrics?.pendingAction || 0} pending action
            </span>
          </button>

          {/* Last Hour Delivery */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
            <Activity className="w-4 h-4 text-zinc-400" />
            <span className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              {slaMetrics?.lastDeliveryWindow.count} delivered in last hour
            </span>
          </div>
          
          {/* Refresh Button */}
          <button
            type="button"
            onClick={() => void refresh()}
            disabled={loading}
            className="ui-secondary min-h-8 px-3 py-1.5 text-[11px]"
            title="Refresh metrics and logs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 transition-colors">
        <div className="flex flex-wrap items-center gap-4">
          {/* Search */}
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by recipient, subject, or advisory..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition"
            />
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center space-x-2">
              <Filter className="w-4 h-4 text-zinc-400" />
              <span className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600">Filters:</span>
            </div>
            
            {/* Status Filter */}
            <select
              value={filters.status}
              onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value as FilterOptions['status'] }))}
              className="px-3 py-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
            >
              <option value="ALL">All Statuses</option>
              <option value="ACCEPTED">Accepted (delivered)</option>
              <option value="DELIVERED">Delivered (confirmed)</option>
              <option value="REVIEW_REQUIRED">Awaiting review</option>
              <option value="QUEUED">Queued</option>
              <option value="SENDING">Sending</option>
              <option value="RETRYING">Retrying</option>
              <option value="FAILED">Failed</option>
              <option value="CANCELLED">Cancelled</option>
            </select>

            {/* Action Status Filter */}
            <select
              value={filters.actionStatus}
              onChange={(e) =>
                setFilters((prev) => ({
                  ...prev,
                  actionStatus: e.target.value as FilterOptions['actionStatus'],
                }))
              }
              className="px-3 py-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
            >
              <option value="ALL">All Actions</option>
              <option value="PENDING">Action pending</option>
              <option value="ACTIONED">Actioned</option>
            </select>

            {/* Provider Filter */}
            <select
              value={filters.provider}
              onChange={(e) => setFilters(prev => ({ ...prev, provider: e.target.value }))}
              className="px-3 py-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
            >
              <option value="ALL">All Providers</option>
              {[...new Set(emailLogs.map(log => log.provider))].map(provider => (
                <option key={provider} value={provider}>{provider}</option>
              ))}
            </select>

            {/* Date Range Filter */}
            <select
              value={filters.dateRange}
              onChange={(e) => setFilters(prev => ({ ...prev, dateRange: e.target.value as FilterOptions['dateRange'] }))}
              className="px-3 py-1.5 rounded-xl bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:outline-none focus:border-zinc-600"
            >
              <option value="today">Today</option>
              <option value="week">This Week</option>
              <option value="month">This Month</option>
              <option value="quarter">This Quarter</option>
              <option value="year">This Year</option>
            </select>
          </div>

          {/* Bulk Actions */}
          {selectedLogs.size > 0 && (
            <div className="flex items-center space-x-2 ml-auto">
              <span className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                {selectedLogs.size} selected
              </span>
              <button
                onClick={() => setShowBulkActions(!showBulkActions)}
                className="ui-primary px-3 py-1.5 text-xs"
              >
                Bulk Actions
              </button>
            </div>
          )}
        </div>

        {/* Expanded Bulk Actions */}
        {showBulkActions && selectedLogs.size > 0 && (
          <div className="mt-4 p-4 bg-zinc-950/50 dark:bg-zinc-950/50 light:bg-zinc-100 rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => handleBulkAction('retry')}
                className="px-3 py-1.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20 hover:bg-amber-500/20 text-xs font-medium transition"
              >
                <RefreshCw className="w-3 h-3 inline mr-1" /> Retry Selected
              </button>
              <button
                onClick={() => handleBulkAction('send-now')}
                className="px-3 py-1.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20 hover:bg-blue-500/20 text-xs font-medium transition"
              >
                <Send className="w-3 h-3 inline mr-1" /> Send Now
              </button>
              <button
                onClick={() => handleBulkAction('cancel')}
                className="px-3 py-1.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 text-xs font-medium transition"
              >
                <Archive className="w-3 h-3 inline mr-1" /> Cancel Selected
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Email Delivery Table */}
      <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4 w-8">
                  <input
                    type="checkbox"
                    checked={selectedLogs.size === emailLogs.length && emailLogs.length > 0}
                    onChange={(e) => handleSelectAll(e.target.checked)}
                    className="w-4 h-4 rounded border-zinc-700 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                  />
                </th>
                <th className="py-3 px-4">Recipient Email</th>
                <th className="py-3 px-4">Subject &amp; Advisory</th>
                <th className="py-3 px-4">CVE(s) · Tracking</th>
                <th className="py-3 px-4">Provider</th>
                <th className="py-3 px-4">Delivery Status</th>
                <th className="py-3 px-4">Action SLA</th>
                <th className="py-3 px-4">Dispatched</th>
                <th className="py-3 px-4">Next Attempt</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && emailLogs.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-zinc-500">
                    Loading delivery logs...
                  </td>
                </tr>
              ) : emailLogs.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-zinc-500">
                    No delivery records found.
                  </td>
                </tr>
              ) : (
                emailLogs.map((log) => {
                  const isSelected = selectedLogs.has(log.id);
                  const isDelivered = isDeliveredLog(log);
                  const isFailed = log.status === 'FAILED' || log.status === 'BOUNCED';
                  const isRetryable = isActionable(log);
                  const slaStatus = actionSlaState(log);
                  const slaColor =
                    slaStatus === 'COMPLIANT'
                      ? 'text-emerald-400'
                      : slaStatus === 'VIOLATION'
                        ? 'text-rose-400'
                        : slaStatus === 'N/A'
                          ? 'text-zinc-500'
                          : 'text-amber-400';
                  const canOpenEditor = isEditable(log) || isFollowUpEligible(log);

                  return (
                    <tr
                      key={log.id}
                      className={`hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition ${isSelected ? 'bg-blue-500/10 dark:bg-blue-500/10 light:bg-blue-50' : ''} ${canOpenEditor ? 'cursor-pointer' : ''}`}
                      onClick={() => {
                        if (canOpenEditor) openEmailEditor(log);
                      }}
                    >
                      {/* Select */}
                      <td className="py-3 px-4">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onClick={(e) => e.stopPropagation()}
                          onChange={(e) => {
                            const newSelected = new Set(selectedLogs);
                            if (e.target.checked) {
                              newSelected.add(log.id);
                            } else {
                              newSelected.delete(log.id);
                            }
                            setSelectedLogs(newSelected);
                            setShowBulkActions(newSelected.size > 0);
                          }}
                          className="w-4 h-4 rounded border-zinc-700 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                        />
                      </td>

                      {/* Recipient */}
                      <td className="py-3 px-4 font-mono font-medium text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                        {log.recipientEmail}
                      </td>

                      {/* Subject & Advisory */}
                      <td className="py-3 px-4">
                        <div className="font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-800 line-clamp-1 max-w-sm">
                          {log.subject}
                        </div>
                        <div className="text-[10px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono mt-0.5">
                          Ref: {log.advisoryId}
                        </div>
                      </td>

                      {/* CVE tracking */}
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {cveChips(log.advisoryId)}
                          {cveOverflow(log.advisoryId) && (
                            <span className="text-[10px] text-zinc-500 font-mono">{cveOverflow(log.advisoryId)}</span>
                          )}
                          {trackedCves(log.advisoryId).length === 0 && (
                            <span className="text-[10px] text-zinc-500 font-mono">No CVEs</span>
                          )}
                        </div>
                      </td>

                      {/* Provider */}
                      <td className="py-3 px-4 font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[11px]">
                        {log.provider}
                      </td>

                      {/* Status */}
                      <td className="py-3 px-4 font-mono">
                        {deliveryStatusBadge(log)}
                      </td>

                      {/* Action SLA */}
                      <td className="py-3 px-4 font-mono text-[11px]">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className={`font-medium ${slaColor}`}>{slaStatus}</span>
                          {isDelivered && !isActionPending(log) && (
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          )}
                          {isDelivered && isActionPending(log) && (
                            <Clock3 className="w-3 h-3 text-amber-400" />
                          )}
                          {isFailed && <AlertTriangle className="w-3 h-3 text-rose-400" />}
                        </div>
                        <div className="mt-1">{actionStatusBadge(log)}</div>
                        <div className="text-[10px] text-zinc-500 mt-0.5">
                          Attempt #{log.attemptCount}
                          {log.actionedAt && ` · actioned ${fmtDateTime(log.actionedAt, settings.timezone)}`}
                        </div>
                      </td>

                      {/* Timestamp */}
                      <td className="py-3 px-4 font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[11px]">
                        {log.sentAt ? fmtDateTime(log.sentAt, settings.timezone) : 'Not accepted yet'}
                      </td>

                      {/* Next Attempt */}
                      <td className="py-3 px-4 font-mono text-[11px]">
                        {log.nextRetryTime ? (
                          <div>
                            <span className={new Date(log.nextRetryTime).getTime() <= Date.now() ? 'text-rose-400' : 'text-amber-400'}>
                              {fmtDateTime(log.nextRetryTime, settings.timezone)}
                            </span>
                            <div className="text-[10px] text-zinc-500 mt-0.5">
                              {new Date(log.nextRetryTime).getTime() <= Date.now() ? 
                                'Due now' : 
                                `In ${Math.round((new Date(log.nextRetryTime).getTime() - Date.now()) / 60000)}m`
                              }
                            </div>
                          </div>
                        ) : (
                          <span className="text-zinc-500">No retry scheduled</span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right">
                        <div className="flex flex-wrap items-center justify-end gap-1.5">
                          {isFollowUpEligible(log) && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                openEmailEditor(log);
                              }}
                              className="inline-flex items-center space-x-1 rounded-lg border border-sky-500/20 bg-sky-500/10 px-2.5 py-1 text-xs font-medium text-sky-400 transition hover:bg-sky-500/20"
                            >
                              <Edit3 className="h-3 w-3" />
                              <span>Update &amp; send</span>
                            </button>
                          )}
                          {isDelivered && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                setResending({
                                  id: log.id,
                                  advisoryId: log.advisoryId,
                                  mode: 'SECURITY_TEAM',
                                  email: log.recipientEmail,
                                  reason: '',
                                });
                              }}
                              disabled={resendBusy}
                              className="inline-flex items-center space-x-1 rounded-lg border border-violet-500/20 bg-violet-500/10 px-2.5 py-1 text-xs font-medium text-violet-400 transition hover:bg-violet-500/20"
                            >
                              <Send className="h-3 w-3" />
                              <span>Resend</span>
                            </button>
                          )}
                          {isActionPending(log) && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                void handleAcknowledge(log);
                              }}
                              disabled={actionBusyId === log.id}
                              title="Mark this delivery's follow-up action as done"
                              className="inline-flex items-center space-x-1 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-50"
                            >
                              <CheckCircle2 className="h-3 w-3" />
                              <span>{actionBusyId === log.id ? 'Saving…' : 'Done'}</span>
                            </button>
                          )}
                          {!isDelivered && isEditable(log) && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                openEmailEditor(log);
                              }}
                              className="inline-flex items-center space-x-1 rounded-lg border border-sky-500/20 bg-sky-500/10 px-2.5 py-1 text-xs font-medium text-sky-400 transition hover:bg-sky-500/20"
                            >
                              <Edit3 className="h-3 w-3" />
                              <span>Edit</span>
                            </button>
                          )}
                          {!isDelivered && !isEditable(log) && isRetryable && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleRetry(log.id);
                              }}
                              className="inline-flex items-center space-x-1 rounded-lg border border-amber-500/20 bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-400 transition hover:bg-amber-500/20"
                            >
                              <RefreshCw className="h-3 w-3" />
                              <span>Retry</span>
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <Pagination
          currentPage={currentPage}
          totalItems={total}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
          pageSizeOptions={[10, 25, 50, 100]}
        />
        {editing && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget && !editBusy) setEditing(null);
            }}
          >
            <section
              role="dialog"
              aria-modal="true"
              aria-labelledby="edit-email-title"
              className={`flex max-h-[90vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white`}
            >
              <div className="flex items-start justify-between gap-4 p-5 pb-3">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-sky-300 light:text-sky-700">
                    Edit email before sending
                  </p>
                  <h2 id="edit-email-title" className="mt-1 text-base font-semibold">
                    {editing.subject}
                  </h2>
                  <p className="mt-1 text-xs text-zinc-500">
                    To {editing.recipientEmail} · Advisory {editing.advisoryId}
                  </p>
                </div>
                <button
                  type="button"
                  aria-label="Close editor"
                  className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800"
                  disabled={editBusy}
                  onClick={() => {
                    if (!editBusy) setEditing(null);
                  }}
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto">
                <div className="grid grid-cols-1 gap-0 p-5 pt-3 xl:grid-cols-2">
                  <div className="xl:pr-4 xl:border-r xl:border-zinc-800/80 light:xl:border-zinc-200">
                    <div className="space-y-4">
                      <div>
                        <label
                          htmlFor="email-subject"
                          className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                        >
                          Subject
                        </label>
                        <input
                          id="email-subject"
                          type="text"
                          maxLength={200}
                          placeholder="Email subject line"
                          value={subjectDraft}
                          onChange={(e) => {
                            setSubjectDraft(e.target.value);
                            triggerLivePreview(edits, e.target.value);
                          }}
                          className="mt-1 w-full text-xs"
                        />
                      </div>

                      <div>
                        <label
                          htmlFor="audience-notice"
                          className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                        >
                          Audience notice
                        </label>
                        <textarea
                          id="audience-notice"
                          rows={4}
                          placeholder="Notice shown above the advisory body for all recipients"
                           value={edits.audienceNotice || ''}
                          onChange={(e) => {
                            const updated = { ...edits, audienceNotice: e.target.value || undefined };
                            setEdits(updated);
                            triggerLivePreview(updated);
                          }}
                          className="mt-1 w-full resize-y font-mono text-xs"
                        />
                      </div>

                      <div>
                        <label
                          htmlFor="reviewer-comment"
                          className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                        >
                          Reviewer comment
                        </label>
                        <textarea
                          id="reviewer-comment"
                          rows={3}
                          placeholder="Optional context added at the bottom of the email"
                           value={edits.reviewerComment || ''}
                          onChange={(e) => {
                            const updated = { ...edits, reviewerComment: e.target.value || undefined };
                            setEdits(updated);
                            triggerLivePreview(updated);
                          }}
                          className="mt-1 w-full resize-y font-mono text-xs"
                        />
                      </div>

                      <div>
                        <label
                          htmlFor="reviewer-name"
                          className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                        >
                          Reviewer name
                        </label>
                        <input
                          id="reviewer-name"
                          type="text"
                           maxLength={100}
                          placeholder="Name attached to the reviewer comment"
                           value={edits.reviewerName || ''}
                          onChange={(e) => {
                            const updated = { ...edits, reviewerName: e.target.value || undefined };
                            setEdits(updated);
                            triggerLivePreview(updated);
                          }}
                          className="mt-1 w-full text-xs"
                        />
                      </div>

                      <div>
                        <label
                          htmlFor="custom-body"
                          className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                        >
                          Custom body override (advanced)
                        </label>
                        <textarea
                          id="custom-body"
                          rows={6}
                           placeholder="Override the entire HTML body — leave empty to keep the template"
                           value={edits.customBodyOverride || ''}
                          onChange={(e) => {
                            const updated = { ...edits, customBodyOverride: e.target.value || undefined };
                            setEdits(updated);
                            triggerLivePreview(updated);
                          }}
                          className="mt-1 w-full resize-y font-mono text-xs"
                        />
                      </div>

<div>
                        <label
                          htmlFor="recipient-mode"
                          className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                        >
                          Send to
                        </label>
                        <select
                          id="recipient-mode"
                          value={recipientMode}
                          onChange={(e) => setRecipientMode(e.target.value as 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE')}
                          className="mt-1 w-full text-xs"
                        >
                          <option value="SINGLE_EMAIL">Single recipient</option>
                          <option value="SECURITY_TEAM">Security team</option>
                          <option value="EVERYONE">Everyone</option>
                        </select>
                        {recipientMode === 'SINGLE_EMAIL' && (
                          <input
                            type="email"
                            placeholder="Recipient email address"
                            value={customEmail}
                            onChange={(e) => setCustomEmail(e.target.value)}
                            className="mt-2 w-full text-xs"
                          />
                        )}
                      </div>

                      <div>
                        <label
                          htmlFor="update-reason"
                          className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                        >
                          Reason for update
                        </label>
                        <input
                          id="update-reason"
                          type="text"
                          maxLength={240}
                          placeholder="Recorded in the delivery audit trail"
                          value={reason}
                          onChange={(e) => setReason(e.target.value)}
                          className="mt-1 w-full text-xs"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="xl:pl-4">
                    <div className="mb-2 flex items-center justify-between gap-2">
                      <div
                        role="tablist"
                        aria-label="Preview format"
                        className="inline-flex rounded-lg border border-zinc-800/80 p-0.5 light:border-zinc-200"
                      >
                        <button
                          type="button"
                          role="tab"
                          aria-selected={previewTab === 'email'}
                          onClick={() => setPreviewTab('email')}
                          className={`rounded-md px-2.5 py-1 text-[11px] font-medium ${
                            previewTab === 'email'
                              ? 'bg-sky-600 text-white'
                              : 'text-zinc-400 hover:text-zinc-200'
                          }`}
                        >
                          <Mail className="mr-1 inline h-3 w-3" /> Email
                        </button>
                        <button
                          type="button"
                          role="tab"
                          aria-selected={previewTab === 'pdf'}
                          onClick={() => {
                            setPreviewTab('pdf');
                            void refreshPdf();
                          }}
                          className={`rounded-md px-2.5 py-1 text-[11px] font-medium ${
                            previewTab === 'pdf'
                              ? 'bg-sky-600 text-white'
                              : 'text-zinc-400 hover:text-zinc-200'
                          }`}
                        >
                          <FileText className="mr-1 inline h-3 w-3" /> PDF
                        </button>
                      </div>
                      {previewTab === 'pdf' && (
                        <button
                          type="button"
                          className="ui-secondary inline-flex items-center gap-1 px-2 py-1 text-[11px]"
                          disabled={pdfLoading}
                          onClick={() => void refreshPdf()}
                        >
                          <RefreshCw className={`h-3 w-3 ${pdfLoading ? 'animate-spin' : ''}`} />
                          Refresh PDF
                        </button>
                      )}
                    </div>

                    {previewTab === 'email' ? (
                      previewLoading ? (
                        <div className="flex h-[480px] items-center justify-center text-xs text-zinc-500">
                          <RefreshCw className="h-4 w-4 animate-spin" /> Generating preview…
                        </div>
                      ) : (
                        <iframe
                          title="Email preview"
                          sandbox="allow-same-origin"
                          className="h-[480px] w-full rounded-xl border border-zinc-800/80 light:border-zinc-200"
                          srcDoc={previewHtml}
                        />
                      )
                    ) : (
                      <div className="h-[480px] w-full overflow-hidden rounded-xl border border-zinc-800/80 light:border-zinc-200">
                        {pdfLoading ? (
                          <div className="flex h-full items-center justify-center text-xs text-zinc-500">
                            <RefreshCw className="h-4 w-4 animate-spin" /> Rendering PDF…
                          </div>
                        ) : pdfError ? (
                          <div className="flex h-full items-center justify-center p-6 text-center text-xs text-rose-400">
                            {pdfError}
                          </div>
                        ) : pdfUrl ? (
                          <iframe
                            title="PDF preview"
                            className="h-full w-full bg-white"
                            src={`${pdfUrl}#toolbar=0`}
                          />
                        ) : (
                          <div className="flex h-full items-center justify-center text-xs text-zinc-500">
                            Open the PDF tab to render the attachment.
                          </div>
                        )}
                      </div>
                    )}
                    <p className="mt-2 text-[11px] text-zinc-500">
                      The PDF attachment is generated from this same edited body, so both stay in sync.
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex justify-end gap-2 border-t border-zinc-800/80 p-4 light:border-zinc-200">
                <button
                  type="button"
                  className="ui-secondary"
                  disabled={editBusy}
                  onClick={() => setEditing(null)}
                >
                  Cancel
                </button>
                {editing.status === 'REVIEW_REQUIRED' ? (
                  <button
                    type="button"
                    className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-60"
                    disabled={editBusy}
                    onClick={sendUpdated}
                  >
                    <Send className="h-3.5 w-3.5" />
                    {editBusy ? 'Sending…' : 'Approve & send'}
                  </button>
                ) : editing.status === 'QUEUED' ? (
                  <button
                    type="button"
                    className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-60"
                    disabled={editBusy}
                    onClick={saveEdit}
                  >
                    <Edit3 className="h-3.5 w-3.5" />
                    {editBusy ? 'Saving…' : 'Save edits'}
                  </button>
                ) : (
                  <button
                    type="button"
                    className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-sky-600 px-4 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-60"
                    disabled={
                      editBusy ||
                      (recipientMode === 'SINGLE_EMAIL' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(customEmail.trim()))
                    }
                    onClick={sendUpdated}
                  >
                    <Send className="h-3.5 w-3.5" />
                    {editBusy ? 'Sending…' : 'Update & send'}
                  </button>
                )}
              </div>
            </section>
          </div>
        )}
        {resending && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget && !resendBusy) setResending(null);
            }}
          >
            <section
              role="dialog"
              aria-modal="true"
              aria-labelledby="resend-email-title"
              className="rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white w-full max-w-md p-5"
            >
              <div className="flex items-start justify-between gap-4 p-5 pb-3">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-sky-300 light:text-sky-700">
                    Resend delivered email
                  </p>
                  <h2 id="resend-email-title" className="mt-1 text-base font-semibold">
                    Resend to {resending.mode === 'SINGLE_EMAIL' ? resending.email : resending.mode === 'SECURITY_TEAM' ? 'Security team' : 'Everyone'}
                  </h2>
                  <p className="mt-1 text-xs text-zinc-500">
                    Advisory {resending.advisoryId} · queues a new PENDING delivery
                  </p>
                </div>
                <button
                  type="button"
                  aria-label="Close resend"
                  className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800"
                  disabled={resendBusy}
                  onClick={() => {
                    if (!resendBusy) setResending(null);
                  }}
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-5 pt-3">
                <div className="space-y-4">
                  <div>
                    <label
                      htmlFor="resend-mode"
                      className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                    >
                      Send to
                    </label>
                    <select
                      id="resend-mode"
                      value={resending.mode}
                      onChange={(e) => setResending((prev) => (prev ? { ...prev, mode: e.target.value as 'SINGLE_EMAIL' | 'SECURITY_TEAM' | 'EVERYONE' } : null))}
                      className="mt-1 w-full text-xs"
                    >
                      <option value="SINGLE_EMAIL">Single recipient</option>
                      <option value="SECURITY_TEAM">Security team</option>
                      <option value="EVERYONE">Everyone</option>
                    </select>
                    {resending.mode === 'SINGLE_EMAIL' && (
                      <input
                        type="email"
                        placeholder="Recipient email address"
                        value={resending.email}
                        onChange={(e) => setResending((prev) => (prev ? { ...prev, email: e.target.value } : null))}
                        className="mt-2 w-full text-xs"
                      />
                    )}
                  </div>

                  <div>
                    <label
                      htmlFor="resend-reason"
                      className="block text-xs font-medium text-zinc-300 light:text-zinc-700"
                    >
                      Reason (audit note)
                    </label>
                    <textarea
                      id="resend-reason"
                      rows={3}
                      placeholder="Why this advisory is being resent..."
                      value={resending.reason}
                      onChange={(e) => setResending((prev) => (prev ? { ...prev, reason: e.target.value } : null))}
                      className="mt-1 w-full resize-y font-mono text-xs"
                    />
                  </div>

                  <div className="text-xs text-zinc-500">
                    A new delivery job is queued for the selected group. Use the edit action on the new job to
                    adjust the audience or content before it ships.
                  </div>

                  <button
                    type="button"
                    onClick={async () => {
                      if (!resending) return;
                      setResendBusy(true);
                      try {
                        const result = await resendEmailDelivery(resending.id, {
                          recipientMode: resending.mode,
                          customEmail: resending.mode === 'SINGLE_EMAIL' ? resending.email : undefined,
                          reason: resending.reason || undefined,
                        });
                        if (result) {
                          setResending(null);
                          await reload();
                        }
                      } finally {
                        setResendBusy(false);
                      }
                    }}
                    disabled={resendBusy || (resending.mode === 'SINGLE_EMAIL' && !resending.email)}
                    className="ui-secondary w-full"
                  >
                    {resendBusy ? 'Queueing…' : 'Queue resend'}
                  </button>
                </div>
              </div>

              <div className="flex justify-end border-t border-zinc-800/80 p-4 light:border-zinc-200">
                <button
                  type="button"
                  className="ui-secondary"
                  disabled={resendBusy}
                  onClick={() => setResending(null)}
                >
                  Cancel
                </button>
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
};