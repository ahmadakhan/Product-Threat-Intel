import { PageHeading } from './PageHeading';
import React, { useEffect, useState } from 'react';
import { formatDateTime as fmtDateTime } from '../utils/dateTime';
import {
  Activity,
  ArrowDown,
  ArrowRight,
  CheckCircle2,
  Clock,
  Cpu,
  Download,
  LoaderCircle,
  Radio,
  Send,
  Square,
  TriangleAlert,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import type { PipelineExecution, PipelinePhase } from '../types';
import { Pagination } from './Pagination';
import { useCollection } from '../hooks/useCollection';
import { DEFAULT_INGESTION_WINDOW_HOURS } from '../utils/scopePresets';
import { formatExecutionName } from '../utils/executionName';

const stages = [
  {
    name: 'Feed ingestion',
    icon: Radio,
    description:
      'Retrieve enabled feeds. NVD requests are limited to CVEs modified inside this ingestion window.',
  },
  {
    name: 'Normalize & deduplicate',
    icon: Cpu,
    description: 'Canonicalize vulnerability records and resolve duplicate source revisions.',
  },
  {
    name: 'Product matching',
    icon: Cpu,
    description: 'Match CPE and package identifiers, versions, and ranges against monitored products.',
  },
  {
    name: 'Delivery queue',
    icon: Send,
    description: 'Prepare advisories and persist eligible notification jobs.',
  },
];
const tone = (status: string) =>
  status === 'SUCCESS' || status === 'COMPLETED'
    ? 'text-emerald-400 light:text-emerald-700'
    : status === 'FAILED'
      ? 'text-rose-400 light:text-rose-700'
      : status === 'RUNNING' || status === 'WARNING'
        ? 'text-amber-400 light:text-amber-800'
        : 'text-zinc-400 light:text-zinc-600';
const StatusIcon = ({ status }: { status: string }) =>
  status === 'RUNNING' ? (
    <LoaderCircle className="h-4 w-4 animate-spin" />
  ) : status === 'SUCCESS' || status === 'COMPLETED' ? (
    <CheckCircle2 className="h-4 w-4" />
  ) : status === 'FAILED' || status === 'WARNING' ? (
    <TriangleAlert className="h-4 w-4" />
  ) : status === 'CANCELLED' ? (
    <Square className="h-4 w-4" />
  ) : (
    <Clock className="h-4 w-4" />
  );
const panel =
  'rounded-2xl border border-zinc-800 light:border-zinc-200 bg-zinc-900/60 light:bg-white shadow-sm';

export const PipelineExecutionsView: React.FC = () => {
  const {
    isPipelineRunning,
    latestExecution,
    triggerPipelineRun,
    stopPipelineRun,
    session,
    pending,
  } = useApp();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const scopeHours = DEFAULT_INGESTION_WINDOW_HOURS;
  const [incrementalFeeds, setIncrementalFeeds] = useState(true);
  const [selectedStage, setSelectedStage] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(5);
  const [now, setNow] = useState(Date.now());
  // Execution history is paginated server-side; the snapshot only carries the
  // newest few runs, so it cannot be used for the history table or its total.
  const { items: executions, total } = useCollection<PipelineExecution>('executions', {
    page,
    pageSize,
  });
  const running = isPipelineRunning ? latestExecution : null;
  // Every branch is nullable: an execution selected from the snapshot may age out
  // of the fetched page, and the page itself is empty until the first run.
  const execution = executions.find((e) => e.id === selectedId) ?? running ?? executions[0] ?? null;
  const canOperate = session?.role === 'ADMIN' || session?.role === 'OPERATOR';
  useEffect(() => {
    if (!isPipelineRunning) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [isPipelineRunning]);
  const elapsed = execution
    ? Math.max(
        0,
        Math.round(
          ((execution.endTime ? Date.parse(execution.endTime) : now) - Date.parse(execution.startTime)) /
            1000,
        ),
      )
    : 0;
  const phases: PipelinePhase[] = stages.map(
    (stage) =>
      execution?.phases.find((p) => p.name === stage.name) || {
        name: stage.name,
        status: execution?.status === 'CANCELLED' ? 'CANCELLED' : 'PENDING',
        durationMs: 0,
        details: stage.description,
      },
  );
  const selectedPhase = phases.find((p) => p.name === selectedStage);
  const logs = execution?.logs || [];
  const download = () => {
    if (!execution) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(execution, null, 2)], { type: 'application/json' }),
    );
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `pipeline-${execution.id}.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <div className="space-y-6">
      <div className="ui-page-header">
        <PageHeading page="pipeline">
          Track intelligence ingestion, correlation and notification preparation.
        </PageHeading>
        <div className="flex flex-wrap items-center gap-2">
          <div
            aria-label="Ingestion window: 1 day"
            className="rounded-lg border border-zinc-700 light:border-zinc-300 bg-zinc-950 light:bg-white px-3 py-2 text-xs text-zinc-400 light:text-zinc-600"
          >
            Ingestion window <span className="ml-1 font-semibold text-zinc-100 light:text-zinc-900">1 day</span>
          </div>
          <label className="flex items-center gap-2 text-xs text-zinc-400 light:text-zinc-600">
            <input
              type="checkbox"
              checked={incrementalFeeds}
              onChange={(e) => setIncrementalFeeds(e.target.checked)}
              disabled={isPipelineRunning}
              className="accent-blue-500"
            />
            <span title="Resume each supported feed from its last successful checkpoint. Turn this off to scan the selected lookback window again.">
              Use source checkpoints
            </span>
          </label>
          {running && canOperate ? (
            <button
              disabled={!!running.stopRequestedAt || pending > 0}
              onClick={() => void stopPipelineRun(running.id)}
              className="flex items-center gap-2 rounded-lg border border-rose-500/50 px-3 py-2 text-sm font-medium text-rose-400 light:text-rose-700 disabled:opacity-50"
            >
              <Square className="h-4 w-4" />
              {running.stopRequestedAt ? 'Stopping…' : 'Stop pipeline'}
            </button>
          ) : (
            <button
              disabled={!canOperate || isPipelineRunning || pending > 0}
              onClick={async () => {
                const run = await triggerPipelineRun(scopeHours, incrementalFeeds);
                if (run) {
                  setSelectedId(run.id);
                  setSelectedStage(null);
                  setPage(1);
                }
              }}
              className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
            >
              <Activity className="h-4 w-4" />
              Run pipeline
            </button>
          )}
        </div>
      </div>
      {running?.stopRequestedAt && (
        <div
          role="status"
          className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-400 light:text-amber-800"
        >
          Stop requested. The worker will discard uncommitted results at its next checkpoint. An active
          network request may take up to its configured timeout. Scheduled future runs remain enabled if
          configured.
        </div>
      )}
      <section className={`${panel} p-5 sm:p-6`} aria-label="Pipeline execution graph">
        <div className="flex flex-wrap justify-between gap-3 mb-6">
          <div>
            <h2 className="font-semibold text-zinc-100 light:text-zinc-900">
              Graphical stage execution DAG &amp; status
            </h2>
            <p className="text-xs text-zinc-400 light:text-zinc-600 mt-1">
              Select a stage to inspect its measurements. Arrows show execution dependencies.
            </p>
          </div>
          <span
            role="status"
            className={`flex items-center gap-2 text-xs font-semibold ${tone(execution?.status || 'PENDING')}`}
          >
            <StatusIcon status={execution?.status || 'PENDING'} />
            {execution?.status || 'READY'}
            {execution ? ` · ${elapsed}s` : ''}
          </span>
        </div>
        <ol className="flex flex-col md:flex-row gap-3 items-stretch">
          {stages.map((stage, index) => {
            const phase = phases[index],
              Icon = stage.icon;
            return (
              <React.Fragment key={stage.name}>
                <li className="flex-1 min-w-0">
                  <button
                    aria-pressed={selectedStage === stage.name}
                    onClick={() => setSelectedStage(selectedStage === stage.name ? null : stage.name)}
                    className={`h-full w-full text-left rounded-xl border p-5 transition ${selectedStage === stage.name ? 'border-blue-500 ring-1 ring-blue-500/40' : phase.status === 'RUNNING' ? 'border-amber-500/60' : 'border-zinc-700/70 light:border-zinc-200'} bg-zinc-950/70 light:bg-zinc-50 hover:border-blue-400`}
                  >
                    <div className="flex items-center justify-between mb-5">
                      <Icon className={`h-6 w-6 ${tone(phase.status)}`} />
                      <span className="text-xs font-mono text-zinc-500">0{index + 1}</span>
                    </div>
                    <h3 className="text-sm font-semibold text-zinc-100 light:text-zinc-900">{stage.name}</h3>
                    <p className="mt-2 text-xs leading-relaxed text-zinc-400 light:text-zinc-600">
                      {stage.description}
                    </p>
                    <div
                      className={`mt-5 flex items-center gap-2 text-xs font-semibold ${tone(phase.status)}`}
                    >
                      <StatusIcon status={phase.status} />
                      {phase.status}
                      <span className="ml-auto font-mono">
                        {phase.status === 'PENDING'
                          ? '—'
                          : phase.status === 'RUNNING' && index === 0
                            ? `${elapsed}s elapsed`
                            : `${phase.durationMs.toLocaleString()} ms`}
                      </span>
                    </div>
                  </button>
                </li>
                {index < stages.length - 1 && (
                  <li aria-hidden="true" className="flex items-center justify-center text-zinc-500">
                    <ArrowRight className="hidden md:block h-5 w-5" />
                    <ArrowDown className="md:hidden h-5 w-5" />
                  </li>
                )}
              </React.Fragment>
            );
          })}
        </ol>
        <div className="mt-4 text-xs text-zinc-400 light:text-zinc-600 leading-relaxed" aria-live="polite">
          {selectedPhase
            ? `${selectedPhase.name}: ${selectedPhase.details}`
            : 'Feed requests may run concurrently. Notification transport runs independently after jobs are committed.'}
        </div>
      </section>
      {execution && (
        <section className="grid grid-cols-2 lg:grid-cols-4 gap-3" aria-label="Execution metrics">
          {[
            ['Records read', execution.stats?.rawIngested ?? 0],
            ['Normalized CVEs', execution.stats?.normalized ?? 0],
            ['New vulnerabilities detected', execution.stats?.matchedWatchlist ?? 0],
            ['Notifications queued', execution.stats?.notificationsQueued || 0],
          ].map(([label, value]) => (
            <div key={label} className={`${panel} p-4`}>
              <p className="text-xs text-zinc-400 light:text-zinc-600">{label}</p>
              <p className="mt-2 text-2xl font-semibold tabular-nums text-zinc-100 light:text-zinc-900">
                {value}
              </p>
            </div>
          ))}
        </section>
      )}
      <section className={`${panel} p-5`}>
        <h2 className="font-semibold text-zinc-100 light:text-zinc-900 mb-4">Execution history</h2>
        {!executions.length ? (
          <p className="text-sm text-zinc-400 light:text-zinc-600">
            No executions yet. Run the pipeline to begin collecting telemetry.
          </p>
        ) : (
          <>
            <div className="space-y-2">
              {executions.map((run) => (
                <button
                  key={run.id}
                  aria-pressed={execution?.id === run.id}
                  onClick={() => {
                    setSelectedId(run.id);
                    setSelectedStage(null);
                  }}
                  className={`w-full flex flex-wrap items-center justify-between gap-2 rounded-xl border px-4 py-3 text-left ${execution?.id === run.id ? 'border-blue-500/60 bg-blue-500/5' : 'border-zinc-800 light:border-zinc-200'}`}
                >
                  <div>
                    <p className="text-sm font-semibold text-zinc-100 light:text-zinc-900 break-all">
                      {run.name || formatExecutionName(run.id)}
                    </p>
                    <p className="mt-1 text-xs text-zinc-400 light:text-zinc-600">
                      {fmtDateTime(run.startTime)} · {run.stats?.matchedWatchlist ?? 0}{' '}
                      {run.stats?.matchedWatchlist === 1 ? 'new finding' : 'new findings'}
                    </p>
                  </div>
                  <span className={`flex items-center gap-2 text-xs font-medium ${tone(run.status)}`}>
                    <StatusIcon status={run.status} />
                    {run.status}
                  </span>
                </button>
              ))}
            </div>
            <Pagination
              currentPage={page}
              totalItems={total}
              pageSize={pageSize}
              onPageChange={(nextPage) => {
                setPage(nextPage);
                setSelectedId(null);
              }}
              onPageSizeChange={(n) => {
                setPageSize(n);
                setPage(1);
              }}
              pageSizeOptions={[5, 10, 20]}
            />
          </>
        )}
      </section>
      {execution && (
        <section className={`${panel} p-5`}>
          <div className="flex items-center justify-between gap-3 mb-4">
            <h2 className="font-semibold text-zinc-100 light:text-zinc-900">Execution log</h2>
            <button
              onClick={download}
              className="flex items-center gap-2 text-xs text-blue-400 light:text-blue-700"
            >
              <Download className="h-4 w-4" />
              Export JSON
            </button>
          </div>
          <div className="max-h-72 overflow-auto rounded-xl bg-zinc-950 light:bg-zinc-50 p-4 font-mono text-xs leading-relaxed text-zinc-300 light:text-zinc-700">
            {logs.length ? (
              logs.map((log, index) => (
                <p key={index} className="break-words py-1">
                  {log}
                </p>
              ))
            ) : (
              <p>Waiting for worker telemetry…</p>
            )}
          </div>
        </section>
      )}
    </div>
  );
};
