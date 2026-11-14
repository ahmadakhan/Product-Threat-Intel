import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Clock3,
  Database,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  X,
} from 'lucide-react';
import { PageHeading } from './PageHeading';
import { useApp } from '../context/AppContext';
import { useDialogFocus } from '../hooks/useDialogFocus';
import type {
  ExploitRiskLevel,
  Finding,
  MlFindingFeedbackInput,
  MlModelStatus,
  MlReviewQueueResponse,
  MlStatusResponse,
} from '../types';
import { formatDateTime } from '../utils/dateTime';

const FEEDBACK_SOURCES: Record<string, string> = {
  calibrationPairs: 'Calibration pairs',
  exploitRiskSamples: 'Exploit-risk labels',
  severityTierSamples: 'Severity-tier labels',
  digestSelectionSamples: 'Digest selection labels',
  zeroDayRateLimitSamples: 'Zero-day cap labels',
  emailCompositionSamples: 'Email composition labels',
};

const RISK_LEVELS: ExploitRiskLevel[] = [
  'CISA_KEV_EXPLOITED',
  'REPORTED_IN_WILD_EXPLOIT',
  'WEAPONIZED_EXPLOIT',
  'HIGH_EPSS_PROBABILITY',
  'ELEVATED',
  'STANDARD',
];

const SEVERITY_TIERS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'] as const;

const statusTone = (status: MlModelStatus['status']) => {
  if (status === 'ACTIVE') return 'border-emerald-800/70 bg-emerald-950/40 text-emerald-300';
  if (status === 'DEGRADED') return 'border-rose-800/70 bg-rose-950/40 text-rose-300';
  if (status === 'STANDBY_ROLLBACK') return 'border-amber-800/70 bg-amber-950/40 text-amber-300';
  return 'border-zinc-700 bg-zinc-900 text-zinc-400';
};

const formatMetric = (value: number | undefined) => {
  if (value === undefined || !Number.isFinite(value)) return '—';
  return Math.abs(value) >= 100 ? value.toFixed(0) : value.toFixed(3);
};

const trainingSummary = (latest: Record<string, unknown> | null) => {
  if (!latest) return null;
  const total = Number(latest.totalModels ?? latest.total ?? 0);
  const trained = Number(latest.trained ?? 0);
  const failed = Number(latest.failed ?? 0);
  const saved = Number(latest.saved ?? 0);
  return { total, trained, failed, saved, occurredAt: String(latest.occurredAt ?? '') };
};

export const MlOperationsView: React.FC = () => {
  const {
    session,
    settings,
    mlStatus,
    mlReviewQueue,
    recordMlFindingFeedback,
    setSelectedFinding,
    setActiveTab,
  } = useApp();
  const canLabel = session?.role === 'ADMIN' || session?.role === 'OPERATOR';
  const [status, setStatus] = useState<MlStatusResponse | null>(null);
  const [queue, setQueue] = useState<MlReviewQueueResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [target, setTarget] = useState<Finding | null>(null);
  const [disposition, setDisposition] = useState<'TRUE_POSITIVE' | 'FALSE_POSITIVE'>('TRUE_POSITIVE');
  const [correctedRisk, setCorrectedRisk] = useState('');
  const [correctedTier, setCorrectedTier] = useState('');
  const [notes, setNotes] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async (quiet = false) => {
    if (quiet) setRefreshing(true);
    else setLoading(true);
    try {
      const [statusResult, queueResult] = await Promise.all([mlStatus(), mlReviewQueue(25)]);
      setStatus(statusResult);
      setQueue(queueResult);
      setError('');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'ML operations data unavailable');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [mlReviewQueue, mlStatus]);

  useEffect(() => {
    let disposed = false;
    const refresh = async () => {
      if (disposed) return;
      await load(true);
    };
    // The page opens with a visible skeleton rather than waiting for the timer.
    void load(false);
    const timer = setInterval(() => void refresh(), 30_000);
    return () => {
      disposed = true;
      clearInterval(timer);
    };
    // Intentionally bind to the context functions available at mount; the
    // provider recreates them on every snapshot and should not restart polling.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const summary = trainingSummary(status?.latestTraining ?? null);

  const closeDialog = () => {
    if (saving) return;
    setTarget(null);
    setNotes('');
    setCorrectedRisk('');
    setCorrectedTier('');
    setDisposition('TRUE_POSITIVE');
  };
  const dialogRef = useDialogFocus(closeDialog, Boolean(target));

  const submitFeedback = async () => {
    if (!target || saving) return;
    setSaving(true);
    setNotice('');
    const payload: MlFindingFeedbackInput = {
      disposition,
      ...(correctedRisk ? { correctedExploitRisk: correctedRisk as ExploitRiskLevel } : {}),
      ...(correctedTier ? { correctedSeverityTier: correctedTier as (typeof SEVERITY_TIERS)[number] } : {}),
      ...(notes.trim() ? { notes: notes.trim() } : {}),
    };
    const result = await recordMlFindingFeedback(target.id, payload);
    setSaving(false);
    if (!result) return;
    setNotice(
      `${target.cveId}: ${result.recorded} training sample${result.recorded === 1 ? '' : 's'} queued for the next retraining cycle.`,
    );
    setTarget(null);
    setNotes('');
    setCorrectedRisk('');
    setCorrectedTier('');
    setDisposition('TRUE_POSITIVE');
    await load(true);
  };

  const openFinding = (finding: Finding) => {
    setSelectedFinding(finding);
    setActiveTab('findings');
  };

  return (
    <div className="space-y-5">
      <PageHeading page="ml-operations">
        Model health, the active review queue, and analyst labels that feed the next retraining cycle.
        ML outputs are decision support: they never override applicability, VEX, or operator policy.
      </PageHeading>

      {error && (
        <div role="alert" className="ui-card border-rose-800/60 bg-rose-950/30 p-3 text-xs text-rose-200">
          <AlertTriangle className="mr-1.5 inline h-4 w-4" />
          {error}
        </div>
      )}
      {notice && (
        <div role="status" className="ui-card border-emerald-800/60 bg-emerald-950/30 p-3 text-xs text-emerald-200">
          <CheckCircle2 className="mr-1.5 inline h-4 w-4" />
          {notice}
        </div>
      )}

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          {
            label: 'Runtime',
            value: status?.initialized ? 'Loaded' : 'Not initialized',
            detail: status ? `${status.trainedModels} of ${status.totalModels} models trained` : 'Loading model registry',
            icon: BrainCircuit,
          },
          {
            label: 'Review queue',
            value: queue ? String(queue.total) : '—',
            detail: queue ? `Held below ${queue.threshold}% confidence or marked review-required` : 'Loading findings',
            icon: ShieldAlert,
          },
          {
            label: 'Latest training',
            value: summary ? `${summary.saved} saved` : 'No run recorded',
            detail: summary
              ? `${summary.trained} trained · ${summary.failed} failed${summary.occurredAt ? ` · ${formatDateTime(summary.occurredAt, settings.timezone)}` : ''}`
              : 'The scheduler will record the first cycle here',
            icon: Clock3,
          },
          {
            label: 'Training samples',
            value: status
              ? String(Object.values(status.feedbackCounts).reduce((sum, count) => sum + count, 0))
              : '—',
            detail: `Analyst-derived samples in the last ${status?.feedbackWindowDays ?? 30} days`,
            icon: Database,
          },
        ].map((card) => {
          const Icon = card.icon;
          return (
            <div key={card.label} className="ui-card p-4">
              <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-zinc-500">
                <span>{card.label}</span>
                <Icon className="h-4 w-4" aria-hidden="true" />
              </div>
              <div className="mt-2 text-xl font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                {card.value}
              </div>
              <div className="mt-1 text-[11px] leading-relaxed text-zinc-500">{card.detail}</div>
            </div>
          );
        })}
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="ui-card overflow-hidden">
          <div className="flex items-center justify-between gap-3 border-b border-zinc-800/80 px-4 py-3 dark:border-zinc-800/80 light:border-zinc-200">
            <div>
              <h2 className="text-sm font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">Model registry</h2>
              <p className="text-[11px] text-zinc-500">
                Deployed artifacts, quality-gate minimums, and the latest validation result.
              </p>
            </div>
            <button
              type="button"
              onClick={() => void load(true)}
              disabled={refreshing}
              className="inline-flex items-center gap-1.5 rounded-xl border border-zinc-700 px-2.5 py-1.5 text-xs text-zinc-300 transition hover:bg-zinc-800 disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-zinc-800/80 bg-zinc-950/40 text-[10px] uppercase tracking-wider text-zinc-500 dark:border-zinc-800/80 dark:bg-zinc-950/40 light:border-zinc-200 light:bg-zinc-50">
                <tr>
                  <th className="px-4 py-2.5">Model</th>
                  <th className="px-3 py-2.5">State</th>
                  <th className="px-3 py-2.5">Version</th>
                  <th className="px-3 py-2.5">Gate</th>
                  <th className="px-3 py-2.5">Last training</th>
                  <th className="px-3 py-2.5">Performance</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 dark:divide-zinc-800/60 light:divide-zinc-200">
                {(status?.models ?? []).map((model) => (
                  <tr key={model.id} className="align-top">
                    <td className="px-4 py-3">
                      <div className="font-mono font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-900">
                        {model.id}
                      </div>
                      <div className="mt-0.5 max-w-[340px] text-[10px] leading-relaxed text-zinc-500">
                        {model.description}
                      </div>
                      {model.latestMetrics && Object.keys(model.latestMetrics).length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1.5 text-[10px] text-zinc-400">
                          {Object.entries(model.latestMetrics).map(([name, value]) => (
                            <span key={name} className="rounded border border-zinc-700/70 px-1.5 py-0.5 font-mono">
                              {name.replace(/^vulnstream_ml_/, '')}={value}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-3">
                      <span className={`inline-block rounded-full border px-2 py-0.5 text-[10px] font-mono ${statusTone(model.status)}`}>
                        {model.status}
                      </span>
                      <div className="mt-1 text-[10px] text-zinc-500">{model.featureCount ?? 0} features</div>
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-zinc-300">
                      {model.version ?? '—'}
                      <div className="mt-1 text-[10px] text-zinc-500">
                        {model.trainedAt ? formatDateTime(model.trainedAt, settings.timezone) : 'never deployed'}
                      </div>
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-zinc-400">
                      ≥ {model.minimumSamples} samples
                    </td>
                    <td className="px-3 py-3 text-[11px]">
                      {model.lastTraining ? (
                        <>
                          <div className="text-zinc-300">{model.lastTraining.status}</div>
                          <div className="text-[10px] text-zinc-500">
                            {model.lastTraining.samplesCollected} samples ·{' '}
                            {model.lastTraining.validationPassed === false ? 'gate failed' : 'gate passed'}
                          </div>
                          {model.lastTraining.failureReason && (
                            <div className="mt-1 max-w-[220px] text-[10px] text-amber-400">
                              {model.lastTraining.failureReason}
                            </div>
                          )}
                        </>
                      ) : (
                        <span className="text-zinc-500">No cycle data</span>
                      )}
                    </td>
                    <td className="px-3 py-3">
                      {model.performance ? (
                        <div className="flex flex-wrap gap-1.5 font-mono text-[10px] text-zinc-400">
                          {Object.entries(model.performance).map(([name, value]) => (
                            <span key={name} className="rounded bg-zinc-900 px-1.5 py-0.5">
                              {name}={formatMetric(value)}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-[10px] text-zinc-500">No validation metrics</span>
                      )}
                    </td>
                  </tr>
                ))}
                {loading && !status && (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-zinc-500">
                      Loading model registry…
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="ui-card p-4">
          <h2 className="text-sm font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">Feedback sources</h2>
          <p className="mt-1 text-[11px] text-zinc-500">
            Labels are stored as training events. A sample only reaches a model after the next scheduled cycle
            passes its quality gate.
          </p>
          <div className="mt-3 space-y-2">
            {Object.entries(FEEDBACK_SOURCES).map(([source, label]) => {
              const count = status?.feedbackCounts[source] ?? 0;
              return (
                <div key={source} className="flex items-center justify-between gap-3 border-b border-zinc-800/50 pb-2 last:border-0">
                  <div>
                    <div className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700">{label}</div>
                    <div className="font-mono text-[10px] text-zinc-500">{source}</div>
                  </div>
                  <span className="rounded-full border border-zinc-700 px-2 py-0.5 font-mono text-[11px] text-zinc-300">
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
          <div className="mt-4 rounded-xl border border-zinc-800/80 bg-zinc-950/50 p-3 text-[11px] leading-relaxed text-zinc-500">
            <Sparkles className="mr-1.5 inline h-3.5 w-3.5 text-blue-400" />
            Auto-dispatch threshold recommendations are{' '}
            <strong className="text-zinc-300">
              {settings.mlAutoDispatchThresholdEnabled ? 'enabled' : 'disabled'}
            </strong>
            . Review-routing recommendations are{' '}
            <strong className="text-zinc-300">{settings.mlReviewRoutingEnabled ? 'enabled' : 'disabled'}</strong>.
            Change both in Settings → Finding dispatch.
          </div>
        </div>
      </section>

      <section className="ui-card overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800/80 px-4 py-3 dark:border-zinc-800/80 light:border-zinc-200">
          <div>
            <h2 className="text-sm font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">Active-learning review queue</h2>
            <p className="text-[11px] text-zinc-500">
              Lowest-confidence review findings first. Label the outcome you actually observed; do not label an
              uninvestigated finding.
            </p>
          </div>
          <span className="rounded-full border border-zinc-700 px-2.5 py-1 font-mono text-[10px] text-zinc-400">
            {queue?.items.length ?? 0} shown · {queue?.total ?? 0} total
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-zinc-800/80 bg-zinc-950/40 text-[10px] uppercase tracking-wider text-zinc-500 dark:border-zinc-800/80 dark:bg-zinc-950/40 light:border-zinc-200 light:bg-zinc-50">
              <tr>
                <th className="px-4 py-2.5">Finding</th>
                <th className="px-3 py-2.5">Match</th>
                <th className="px-3 py-2.5">ML assessment</th>
                <th className="px-3 py-2.5">Notification</th>
                <th className="px-3 py-2.5 text-right">Label</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 dark:divide-zinc-800/60 light:divide-zinc-200">
              {(queue?.items ?? []).map((finding) => (
                <tr key={finding.id} className="align-top">
                  <td className="px-4 py-3">
                    <div className="font-mono font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-900">
                      {finding.cveId}
                    </div>
                    <div className="mt-0.5 max-w-[360px] truncate text-[11px] text-zinc-400" title={finding.cve?.title}>
                      {finding.cve?.title}
                    </div>
                    <div className="font-mono text-[10px] text-zinc-500">{finding.matchedAssetName}</div>
                  </td>
                  <td className="px-3 py-3 font-mono text-[11px] text-zinc-300">
                    {finding.confidence ?? 0}%
                    <div className="text-[10px] text-zinc-500">{finding.matchingMethod}</div>
                  </td>
                  <td className="px-3 py-3">
                    {finding.mlAssessment ? (
                      <div className="space-y-1 text-[10px] text-zinc-400">
                        <div>Match confidence: {Math.round(finding.mlAssessment.matchConfidence)}%</div>
                        <div>Alias confidence: {Math.round(finding.mlAssessment.aliasConfidence * 100)}%</div>
                        <div>
                          Risk: <span className="font-mono text-zinc-300">{finding.mlAssessment.exploitRisk.replace(/_/g, ' ')}</span>
                        </div>
                        <div>
                          Tier: <span className="font-mono text-zinc-300">{finding.mlAssessment.severityTier}</span>
                        </div>
                        <div>Remediation: {finding.mlAssessment.remediationCompleteness}</div>
                      </div>
                    ) : (
                      <span className="text-[10px] text-zinc-500">No assessment recorded</span>
                    )}
                  </td>
                  <td className="px-3 py-3 font-mono text-[10px] text-zinc-400">
                    {finding.notificationStatus.replace(/_/g, ' ')}
                    <div className="mt-1">
                      <button
                        type="button"
                        onClick={() => openFinding(finding)}
                        className="text-[10px] text-blue-400 underline-offset-2 hover:underline"
                      >
                        Open finding
                      </button>
                    </div>
                  </td>
                  <td className="px-3 py-3 text-right">
                    <button
                      type="button"
                      disabled={!canLabel}
                      title={canLabel ? 'Record an analyst label' : 'ADMIN or OPERATOR role required'}
                      onClick={() => {
                        setTarget(finding);
                        setNotes('');
                        setCorrectedRisk('');
                        setCorrectedTier('');
                        setDisposition('TRUE_POSITIVE');
                      }}
                      className="rounded-xl border border-zinc-700 px-2.5 py-1.5 text-[11px] text-zinc-300 transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      Record label
                    </button>
                  </td>
                </tr>
              ))}
              {!loading && (queue?.items.length ?? 0) === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-zinc-500">
                    No findings currently need review.
                  </td>
                </tr>
              )}
              {loading && !queue && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-zinc-500">
                    Loading review queue…
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {target && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div
            ref={dialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="ml-feedback-title"
            tabIndex={-1}
            className="ui-panel w-full max-w-lg rounded-2xl border border-zinc-800 bg-zinc-900 p-5 shadow-2xl light:border-zinc-200 light:bg-white"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 id="ml-feedback-title" className="text-sm font-semibold text-zinc-100 light:text-zinc-900">
                  Record analyst label
                </h3>
                <p className="mt-1 font-mono text-[11px] text-zinc-400">
                  {target.cveId} · {target.matchedAssetName}
                </p>
              </div>
              <button
                type="button"
                onClick={closeDialog}
                className="text-zinc-500 hover:text-zinc-200"
                aria-label="Close feedback dialog"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="mt-4 space-y-3">
              <label className="block text-xs text-zinc-300">
                <span className="mb-1 block font-medium">Observed outcome</span>
                <select
                  data-dialog-autofocus
                  value={disposition}
                  onChange={(event) => setDisposition(event.target.value as 'TRUE_POSITIVE' | 'FALSE_POSITIVE')}
                  className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs text-zinc-200"
                >
                  <option value="TRUE_POSITIVE">True positive — the asset is affected</option>
                  <option value="FALSE_POSITIVE">False positive — the asset is not affected</option>
                </select>
              </label>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="block text-xs text-zinc-300">
                  <span className="mb-1 block font-medium">Corrected exploit risk (optional)</span>
                  <select
                    value={correctedRisk}
                    onChange={(event) => setCorrectedRisk(event.target.value)}
                    className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs text-zinc-200"
                  >
                    <option value="">No correction</option>
                    {RISK_LEVELS.map((level) => (
                      <option key={level} value={level}>
                        {level.replace(/_/g, ' ')}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="block text-xs text-zinc-300">
                  <span className="mb-1 block font-medium">Corrected severity tier (optional)</span>
                  <select
                    value={correctedTier}
                    onChange={(event) => setCorrectedTier(event.target.value)}
                    className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs text-zinc-200"
                  >
                    <option value="">No correction</option>
                    {SEVERITY_TIERS.map((tier) => (
                      <option key={tier} value={tier}>
                        {tier}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <label className="block text-xs text-zinc-300">
                <span className="mb-1 block font-medium">Analyst notes (optional)</span>
                <textarea
                  value={notes}
                  onChange={(event) => setNotes(event.target.value)}
                  maxLength={1000}
                  rows={3}
                  placeholder="Evidence checked, scope decision, or why the model was wrong"
                  className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs text-zinc-200"
                />
              </label>
              <div className="rounded-xl border border-amber-800/50 bg-amber-950/20 p-3 text-[11px] leading-relaxed text-amber-200/80">
                <AlertTriangle className="mr-1.5 inline h-3.5 w-3.5" />
                Submitting a label does not change the finding status or dispatch policy. It only records a
                training sample for the next quality-gated retraining cycle.
              </div>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                onClick={closeDialog}
                disabled={saving}
                className="rounded-xl border border-zinc-700 px-3.5 py-2 text-xs font-medium text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void submitFeedback()}
                disabled={saving}
                className="inline-flex items-center gap-1.5 rounded-xl bg-blue-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
              >
                {saving ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
                Save label
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
