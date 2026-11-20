import { WorkerLeadership } from './leadership.ts';
import { existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { getHeapStatistics } from 'node:v8';
import { totalmem } from 'node:os';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
// `npm start` does not pass --env-file, so keep the historical convenience of
// reading ./.env when the process was started without a DATABASE_URL. Use the
// runtime parser instead of a hand-rolled one: it handles quoting, escaped
// newlines, and comments the same way as `--env-file`, and it does not
// overwrite variables already present in the environment.
const _envPath = join(process.cwd(), '.env');
if (existsSync(_envPath) && !process.env.DATABASE_URL) {
  process.loadEnvFile(_envPath);
}

import { backfillCorrelationInventory } from './correlation/inventory.ts';
import { CorrelationRuntime } from './correlation/runtime.ts';
import { describeError, writeEvent } from './events';
import type { Finding } from '../src/types/index.ts';
import { loadConfig } from './config';
import { createPool, migrate, transaction, get, put, list, REQUIRED_SCHEMA_VERSION } from './db';
import { createApp } from './app';
import { createRequester } from './network';
import { createMailSender, deliverNext } from './delivery';
import { releaseExpiredClaims } from './deliveryClaims';
import { flushDueDigest } from './digest';
import { runDailyDigest } from './dailyDigest';
import { closePdfRenderer } from './pdf';
import { initMlRuntime } from './ml/integration.ts';
import { encryptionKeys } from './secrets';
import { runScheduledTraining, TrainingAlreadyRunningError } from './ml/train/cron.ts';
import { enrichmentBacklogCandidates } from '../src/engine/pipelineEngine';
import type { TrainingSummary } from './ml/train/orchestrator.ts';
import { isTelemetryAnomaly, shouldSampleMlTelemetry } from './ml/integration.ts';
import type { Db } from './db';
import { processPipeline, setAbortReason, ABORT_REASON, PipelinePoolStarved } from './pipeline';
import { runSelfHealCheck } from './selfHealing';
import { runRetention } from './retention';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { AppSettings } from '../src/types/index.ts';

const config = loadConfig(),
  pool = createPool(config.DATABASE_URL);
const mlStorageOptions = {
  directory: config.ML_DIRECTORY,
  signingKey: config.ML_SIGNING_KEY,
  ...(config.ML_STORAGE_MODE === 'database' ? { database: pool } : {}),
};
const VERBOSE = config.LOG_LEVEL === 'verbose';
const verboseLog = (event: string, context: Record<string, unknown> = {}) => {
  if (VERBOSE) console.log(JSON.stringify({ level: 'info', event, ...context }));
};
pool.on('error', (error) =>
  console.error(JSON.stringify({ level: 'error', event: 'database-connection', code: (error as any).code })),
);
if (config.NODE_ENV === 'production') {
  const initialized = await pool.query("SELECT to_regclass('schema_migrations') AS name");
  if (!initialized.rows[0]?.name)
    throw new Error('Database schema is not initialized; run migrations before starting');
  const result = await pool.query('SELECT COALESCE(MAX(version), 0)::int AS version FROM schema_migrations');
  const version = Number(result.rows[0]?.version || 0);
  if (version < REQUIRED_SCHEMA_VERSION)
    throw new Error(
      `Database schema version ${version} is older than required version ${REQUIRED_SCHEMA_VERSION}; run migrations before starting`,
    );
} else await migrate(pool);
await transaction(
  pool,
  async (db) => {
    if (await get(db, 'systemState', 'native-inventory-v1')) return;
    await backfillCorrelationInventory(db);
    await put(db, 'systemState', 'native-inventory-v1', { completedAt: new Date().toISOString() });
  },
  undefined,
  { locks: ['native-inventory-bootstrap'] },
);
// Seed data (recommended feeds and monitored products) is never applied at
// startup. It is imported only by the manual `npm run seed` command, so a
// fresh database stays empty until an operator deliberately seeds it.
await writeEvent(pool, {
  category: 'SYSTEM',
  code: 'system.started',
  message: 'Application initialized',
  context: { workerEnabled: config.WORKER_ENABLED === 'true' },
});
const request = createRequester(config),
  sendMail = createMailSender(config, pool, request);
// The correlation runtime fetches settings at runtime (via refreshSchedulerState)
  // to keep the 60-minute scheduler aligned with the pipeline's interval.
  const correlation = new CorrelationRuntime(
    pool,
    encryptionKeys(config),
    config.CORRELATION_DLQ_DIRECTORY,
    {
      url: config.HEARTBEAT_URL,
      intervalSeconds: config.HEARTBEAT_INTERVAL_SECONDS,
      logLevel: config.LOG_LEVEL === 'verbose' ? 'verbose' : 'standard',
      scheduledStateRefreshIntervalSeconds: 60,
      deadLetterStorageMode: config.CORRELATION_DLQ_STORAGE_MODE,
    },
  );
  if (config.CORRELATION_DLQ_STORAGE_MODE === 'database') await correlation.flushLegacyDeadLetters();
if (config.WORKER_ENABLED === 'true') correlation.start();
else correlation.supervisor.start();

const mlRuntime = await initMlRuntime(pool, mlStorageOptions)
  .catch((error) => {
    console.error('ML runtime init failed:', error);
    void writeEvent(pool, {
      category: 'ML',
      level: 'WARNING',
      code: 'ml.runtime_init_failed',
      message: 'ML runtime failed to initialize; confidence scoring and retry-delay optimization will degrade',
      context: { error: (error as Error).message },
    }).catch(() => undefined);
    return undefined;
  });
const app = createApp(pool, config, request, { correlation, mlRuntime,
  // The liveness probe only performs the stall check where the probe timeout is
  // comfortably above the block threshold; see the option's documentation.
  hangDetection: config.HANG_DETECTION_ENABLED === 'true',
});
// A dedicated database session owns worker leadership for its entire term.
const leadership = new WorkerLeadership(pool, config.INSTANCE_ID || randomUUID(), () => {
  // An abort needs an engine reason too, or `transaction()` cannot tell the
  // loss from its own deadline (see `setAbortReason`).
  if (pipelineController) {
    setAbortReason(pipelineController);
    const leadershipLost = new Error('Worker leadership lost');
    (leadershipLost as { [ABORT_REASON]?: boolean })[ABORT_REASON] = true;
    pipelineController.abort(leadershipLost);
  }
});
const checkLeadership = () => leadership.check().catch(report('leader-election'));
/**
 * Start listening on `port`, retrying up to `maxAttempts` times when the port
 * is already in use (for example a `tsx watch` restart race). The process that
 * holds the port is never terminated: it may be an unrelated service or another
 * healthy instance, so after the retries are exhausted the failure names the
 * conflicting port and is left for the operator to resolve.
 */
async function listenWithRetry(port: number, host: string, maxAttempts = 5): Promise<Server> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const server = createServer(app);
    try {
      await new Promise<void>((resolve, reject) => {
        const onError = (error: Error) => reject(error);
        server.on('error', onError);
        server.listen(port, host, () => {
          server.removeListener('error', onError);
          console.log(JSON.stringify({ event: 'listening', port }));
          resolve();
        });
      });
      return server;
    } catch (error: unknown) {
      const code = (error as NodeJS.ErrnoException)?.code;
      // Dispose the failed listener before retrying. A socket that failed to
      // bind holds handles (and its 'error' listener) until closed; without
      // this, each retry leaves one behind for the lifetime of the attempt.
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (code !== 'EADDRINUSE') throw error;
      lastError = error;
      if (attempt === maxAttempts) break;
      await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
    }
  }
  const error = new Error(
    `Port ${port} is already in use on ${host} (EADDRINUSE) after ${maxAttempts} attempts. ` +
      'Stop the process using this port or configure a different PORT; no process was terminated.',
  );
  (error as NodeJS.ErrnoException).code = 'EADDRINUSE';
  (error as Error & { cause?: unknown }).cause = lastError;
  throw error;
}
const server = await listenWithRetry(config.PORT, '0.0.0.0');
server.requestTimeout = 30000;
server.headersTimeout = 15000;
let stopping = false,
  pipeline: Promise<unknown> | null = null,
  outbox: Promise<unknown> | null = null,
  digest: Promise<unknown> | null = null;
const report = (event: string) => (error: unknown) => {
  const detail = describeError(error);
  void writeEvent(pool, {
    category: 'ISSUE',
    level: 'ERROR',
    code: 'worker.failed',
    message: 'Background worker failed',
    context: { component: event, ...detail },
  }).catch((writeError: unknown) => {
    console.error(
      JSON.stringify({
        level: 'error',
        event: 'event.write_failed',
        component: event,
        message: writeError instanceof Error ? writeError.message : String(writeError),
      }),
    );
  });
  console.error(JSON.stringify({ level: 'error', event, ...detail }));
};
/**
 * Is this rejection an operator/shutdown/watchdog abort rather than a failure?
 *
 * Cancellation is signalled only through the AbortController LIFECYCLE: every
 * external abort call site below stamps its AbortController with an abort
 * reason. Once an attempt was cancelled, that signal is cancelled for the whole
 * rejection, so a transient failure that merely lost the same signal is
 * classified as an abort too. A rejection that reaches the worker without its
 * attempt being aborted is never classified as an abort.
 */
/** Sentinel stamped on abort reasons so they can be recognized regardless of
 *  constructor or message text. Used by `reasonAborted` to distinguish
 *  intentional cancellations (shutdown, leadership loss, watchdog) from
 *  genuine failures. (Defined and exported from pipeline.ts as ABORT_REASON.)
 */

const reasonAborted = (reason: unknown): boolean => {
  // The run's own attempt was cancelled (shutdown, leadership loss, watchdog).
  if (pipelineController?.signal.aborted) return true;
  // The run never started because the pool had no free connection. That is a
  // deferral, not a failure; writing `worker.failed` for it every tick turned
  // transient pool pressure into a permanent ERROR stream.
  if (reason instanceof PipelinePoolStarved) return true;
  // Sentinel stamped by our own abort call sites.
  if (reason && typeof reason === 'object' && (reason as { [ABORT_REASON]?: boolean })[ABORT_REASON])
    return true;
  // A WHATWG timeout reason (AbortSignal.timeout) has name "TimeoutError".
  const name = reason && typeof reason === 'object' ? (reason as { name?: unknown }).name : undefined;
  if (name === 'TimeoutError') return true;
  // DOMException from signal.throwIfAborted() has name "Aborted".
  if (name === 'Aborted') return true;
  return false;
};

const stampAborted = (reason: Error): Error => {
  (reason as { [ABORT_REASON]?: boolean })[ABORT_REASON] = true;
  return reason;
};


/**
 * Writes a structured ML training result event to the operational log.
 * Non-blocking: any failure is swallowed so a logging hiccup never blocks the training pipeline.
 */
async function logMlTrainingResult(pool: Db, summary: TrainingSummary): Promise<void> {
  const failed = summary.results.filter((r) => r.status === 'failed');
  const trained = summary.results.filter((r) => r.status === 'trained');
  try {
    await writeEvent(pool, {
      category: 'ML',
      code: 'ml.training.completed',
      message: `ML training cycle finished: ${trained.length} trained, ${failed.length} failed, ${summary.summary.saved} saved`,
      level: failed.length > 0 ? 'WARNING' : 'INFO',
      context: {
        timestamp: summary.timestamp,
        totalModels: summary.summary.total,
        trained: trained.length,
        failed: failed.length,
        saved: summary.summary.saved,
        skipped: summary.summary.skipped ?? 0,
        results: summary.results.map((r) => ({
          modelId: r.modelId,
          status: r.status,
          samplesCollected: r.samplesCollected,
          validationPassed: r.validation.passed,
          failureReason: r.validation.failureReason,
          saved: r.saved,
        })),
      },
    });
  } catch {
    /* ML logging never blocks the training pipeline */
  }
}
/**
 * Backstop for a guarded operation that never settles despite its own deadline.
 * Retention and the digest renderer have explicit cancellation; this only covers
 * the case where cancellation itself cannot complete, so it is deliberately
 * longer than any legitimate gap and is a last resort, not the deadline.
 *
 * The pipeline reports progress from its 15-second heartbeat as well as at each
 * checkpoint, so a healthy run signals far more often than this. The default
 * still has to clear the LONGEST silent stretch a healthy run can produce: a
 * single in-flight source request. NVD pages are the slowest (120 s request
 * timeout, 60 s socket timeout, 5 s provider pacing between pages), and a
 * statement that hits the pool's timeout can add its own round trip. 5 minutes
 * leaves that maximum several times over while still replacing a wedged
 * instance in a bounded time. Configurable via STUCK_PROMISE_MS; the effective
 * value and the feed duration budget are logged once at startup so operators
 * can spot a threshold that is below a legitimate silent phase.
 */
const STUCK_PROMISE_MS = config.STUCK_PROMISE_MS;
console.log(
  JSON.stringify({
    level: 'info',
    event: 'config.watchdog',
    stuckPromiseMs: STUCK_PROMISE_MS,
    feedMaxDurationSeconds: config.FEED_MAX_DURATION_SECONDS,
    timestamp: new Date().toISOString(),
  }),
);
let digestStartedAt = 0;
let pipelineStartedAt = 0;
let outboxStartedAt = 0;
let digestGeneration = 0;
let pipelineController: AbortController | undefined;
let outboxGeneration = 0;
/** In-flight self-healing check; prevents overlapping watchdog runs per tick. */
let selfHealRunning: Promise<void> | null = null;
/** In-flight memory pressure response; prevents overlapping restart attempts. */
let memoryPressureRunning: Promise<void> | null = null;

/**
 * Memory pressure auto-response: hint GC at 90%, graceful restart at 95%.
 *
 * Runs on every instance regardless of leadership. `process.memoryUsage()` and
 * `getHeapStatistics()` are synchronous and cheap, so the per-tick cost is
 * negligible, and the guard prevents overlapping restart attempts.
 *
 * The GC hint only exists with `--expose-gc` (set in compose.yaml alongside
 * `--max-old-space-size`), which is why it is feature-detected rather than
 * assumed.
 */
function checkMemoryPressure(): void {
  if (memoryPressureRunning || stopping) return;
  memoryPressureRunning = (async () => {
    try {
      const mem = process.memoryUsage();
      const heapLimit = getHeapStatistics().heap_size_limit;
      const memoryLimit = process.constrainedMemory?.() || totalmem();
      const heapPct =
        Math.max(heapLimit > 0 ? mem.heapUsed / heapLimit : 0, memoryLimit > 0 ? mem.rss / memoryLimit : 0) * 100;
      if (heapPct >= 90 && typeof globalThis.gc === 'function') {
        // Hint V8 to collect garbage; not guaranteed to run but reduces pressure
        // without restarting. Only available with --expose-gc.
        globalThis.gc();
        verboseLog(`memory.gc heapPct=${heapPct.toFixed(0)}`);
      }
      if (heapPct >= 95) {
        void report('memory.pressure')(new Error(`Heap at ${heapPct.toFixed(0)}%; initiating graceful restart`));
        await shutdown();
        process.exit(1);
      }
    } catch (error) {
      void report('memory.pressure')(error);
    } finally {
      memoryPressureRunning = null;
    }
  })();
}

/** Pipeline start time whose half-budget warning has already been emitted. */
let warnedStallRunAt = 0;

const tick = () => {
  if (stopping || config.WORKER_ENABLED !== 'true') return;
  verboseLog('worker.tick');
  // Periodically check/acquire leadership so followers can take over when the
  // leader dies. Only the leader runs background jobs.
  void checkLeadership();
  // The memory guard runs on EVERY instance, not just the leader. It used to be
  // below the `isLeader` return, so a follower polling for leadership never
  // checked its own heap and could only die by the kernel's OOM killer - with no
  // graceful restart, no event, and no shutdown drain. Process health is not a
  // leadership concern.
  checkMemoryPressure();
  if (!leadership.isLeader) return;
  // Approaching the stall budget is a capacity signal: a healthy run that comes
  // within 50% of the threshold means one slow source response will abort the
  // next one. Warn once per run (keyed by its start time) so operators raise
  // STUCK_PROMISE_MS from evidence instead of discovering it as a mid-run abort.
  if (pipeline && !pipelineController?.signal.aborted && pipelineStartedAt !== warnedStallRunAt) {
    const silentMs = Date.now() - pipelineStartedAt;
    if (silentMs > STUCK_PROMISE_MS / 2) {
      warnedStallRunAt = pipelineStartedAt;
      void writeEvent(pool, {
        category: 'PIPELINE',
        level: 'WARNING',
        code: 'pipeline.stall_approaching',
        message: `Pipeline has been silent for ${Math.round(silentMs / 1000)}s, over half of the ${Math.round(STUCK_PROMISE_MS / 1000)}s stall budget`,
        context: { silentMs, stuckPromiseMs: STUCK_PROMISE_MS, feedMaxDurationSeconds: config.FEED_MAX_DURATION_SECONDS },
      }).catch(() => undefined);
    }
  }
  if (pipeline && !pipelineController?.signal.aborted && Date.now() - pipelineStartedAt > STUCK_PROMISE_MS) {
    const silentMs = Date.now() - pipelineStartedAt;
    const reason = new Error(
      `Pipeline produced no progress for ${silentMs}ms (STUCK_PROMISE_MS=${STUCK_PROMISE_MS}); cancelling the current attempt`,
    );
    void report('pipeline')(reason);
    // The stall is the engine's external cancel, not an internal error: stamp
    // the sentinel so `reasonAborted` classifies it as an abort rather than a
    // failure. `setAbortReason` deliberately does not abort (an earlier version
    // aborted here and silently discarded the message below), so the reason that
    // reaches the engine is the one built above, carrying the measured stall.
    if (pipelineController) {
      setAbortReason(pipelineController);
      pipelineController.abort(stampAborted(reason));
    }
  }
  if (!pipeline) {
    pipelineStartedAt = Date.now();
    const controller = new AbortController();
    pipelineController = controller;
    pipeline = processPipeline(pool, config, request, controller.signal, () => {
      if (pipelineController === controller) pipelineStartedAt = Date.now();
    })
      .then((result) => {
        verboseLog('pipeline.completed', { processed: result });
        return result;
      })
      // Aborts are expected: shutdown, losing leadership, or the stall watchdog
      // all cancel the current attempt. Reporting one as a worker failure writes
      // an ERROR event (and queues a security alert) for work the operator or
      // the watchdog deliberately stopped, so `reasonAborted` classifies them
      // and every other rejection is still reported as a failure.
      .catch((error) => {
        if (!reasonAborted(error)) report('pipeline')(error);
      })
      .finally(() => {
        if (pipelineController === controller) {
          pipeline = null;
          pipelineController = undefined;
        }
      });
  }
  if (outbox && Date.now() - outboxStartedAt > STUCK_PROMISE_MS) {
    void report('outbox')(new Error('Previous outbox promise is still running; starting a fresh attempt'));
    outboxGeneration++;
    outbox = null;
  }
  if (!outbox) {
    outboxStartedAt = Date.now();
    const generation = ++outboxGeneration;
    outbox = (async () => {
      for (let i = 0; i < 20 && !stopping; i++) {
        const delivered = await deliverNext(pool, config, request, sendMail);
        if (!delivered) break;
        verboseLog('outbox.delivered');
      }
      // Audit V-2: reclaim expired delivery claims once per outbox pass.
      // Correctness never depended on this sweep (claimItems re-judges expiry),
      // but expired CLAIMED rows whose job was retention-deleted were never
      // deleted by anything, so the table grew without bound. Running it at the
      // end of the delivery pass keeps it off the hot path and gives it the
      // same leadership/stopping guards as the pass itself.
      try {
        const reclaimed = await transaction(pool, (db) => releaseExpiredClaims(db));
        if (reclaimed > 0)
          verboseLog(`claims.swept ${reclaimed}`);
      } catch (error) {
        void report('claims.sweep')(error);
      }
    })()
      .catch(report('outbox'))
      .finally(() => {
        if (outboxGeneration === generation) outbox = null;
      });
  }
  // An in-flight promise must never become a reason to stop running. Both jobs
  // below guard against overlapping with themselves; if such a promise never
  // settles (for example a statement stuck beyond its timeout on a wedged
  // connection), the `.finally` that clears it never runs and the job is
  // skipped for the rest of the process lifetime. Clearing a guard that has been
  // held far longer than any legal operation lets the next tick start a fresh
  // attempt, which is what "always keep running" requires.
  if (digest && Date.now() - digestStartedAt > STUCK_PROMISE_MS) {
    void report('digest')(new Error('Previous digest flush is still running; starting a new attempt'));
    digestGeneration++;
    digest = null;
  }
  if (!digest) {
    digestStartedAt = Date.now();
    const generation = ++digestGeneration;
    digest = flushDueDigest(pool)
      .then((count) => {
        verboseLog('digest.flushed', { count });
        return count;
      })
      .catch(report('digest'))
  .finally(() => {
        if (digestGeneration === generation) digest = null;
      });
  }

  // Memory pressure auto-response: hint GC at 90%, graceful restart at 95%.
  // Running every tick is cheap (memoryUsage() is synchronous) and the guard
  // prevents overlapping restart attempts. The 95% restart only triggers when
  // the heap is critically full and self-healing's alert alone is insufficient.
  checkMemoryPressure();

  // Self-healing auto-recovery check - runs on every worker tick.
  // Monitors pipeline, feeds, and scheduler; triggers recovery and sends
  // immediate alerts to the Security team group when issues are found.
  // Self-healing auto-recovery check — runs on every worker tick. Monitors the
  // pipeline, feeds, system health and scheduler; recovers from degraded states
  // and queues an alert through the durable outbox for the Security team.
  // Guarded against overlap: a slow check would otherwise pile a new promise on
  // every 5 s tick until the pool is exhausted.
  if (!selfHealRunning) {
    selfHealRunning = runSelfHealCheck(pool)
      .catch((err) => {
        verboseLog('selfHeal.check_failed', { error: err instanceof Error ? err.message : String(err) });
      })
      .finally(() => {
        selfHealRunning = null;
      });
  }
};
const WORKER_TICK_MS = Number(process.env.WORKER_TICK_MS ?? 5000);
const timer = setInterval(tick, WORKER_TICK_MS);
// These timers only exist to drive background work. They must not be the
// reason the event loop stays alive: a harness (or a supervisor draining the
// process) that has otherwise finished would be pinned open forever.
timer.unref();
tick();
// Initial leadership election attempt. All replicas start as followers and
// compete for the advisory lock; only the winner runs background jobs.
if (config.WORKER_ENABLED === 'true') void checkLeadership();
// Retention runs on its own cadence because the policy is operator-configurable
// and can be much slower than the worker tick. The last successful run is
// persisted in the database so replicas do not each schedule the same cleanup,
// and a failed run releases its claim so the next tick can retry immediately.
const RETENTION_SCHEDULE_ID = 'retention-schedule';
/** A retention sweep is abandoned (and its claim released) after this long. */
const RETENTION_RUN_LIMIT_MS = 10 * 60_000;
/** The claim must outlive the run limit, or a second replica steals the claim
 * from a legitimately slow sweep and runs a concurrent cleanup under the same
 * schedule row. It is 2x the run limit so a run that finishes near its deadline
 * is never raced. */
const RETENTION_CLAIM_TTL_MS = 3 * RETENTION_RUN_LIMIT_MS;
async function claimRetention(policy: AppSettings['retentionConfig']): Promise<boolean> {
  return transaction(
    pool,
    async (db) => {
      const row = await db.query("SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE", [
        RETENTION_SCHEDULE_ID,
      ]);
      const data = row.rows[0]?.data ?? {};
      const now = Date.now();
      const lastRun = typeof data.lastRun === 'string' ? Date.parse(data.lastRun) : NaN;
      const claimedAt = typeof data.claimedAt === 'string' ? Date.parse(data.claimedAt) : NaN;
      if (Number.isFinite(lastRun) && now - lastRun < policy.cleanupIntervalMinutes * 60_000) return false;
      if (Number.isFinite(claimedAt) && now - claimedAt < RETENTION_CLAIM_TTL_MS) return false;
      await put(db, 'systemState', RETENTION_SCHEDULE_ID, {
        ...data,
        claimedAt: new Date(now).toISOString(),
      });
      return true;
    },
    undefined,
    // The schedule row may not exist yet; a scoped advisory lock serializes the
    // first claim from multiple replicas before there is a row to lock.
    { locks: ['retention-claim'] },
  );
}
async function releaseRetention(success: boolean, nextRetryAt?: string) {
  await transaction(
    pool,
    async (db) => {
      const row = await db.query("SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE", [
        RETENTION_SCHEDULE_ID,
      ]);
      const data = row.rows[0]?.data ?? {};
      await put(db, 'systemState', RETENTION_SCHEDULE_ID, {
        ...data,
        claimedAt: null,
        lastRun: success ? new Date().toISOString() : (data.lastRun ?? null),
        lastFailedAt: success ? null : new Date().toISOString(),
        nextRetryAt: success ? null : nextRetryAt || new Date(Date.now() + 60_000).toISOString(),
      });
    },
    undefined,
    { locks: ['retention-claim'] },
  );
}
let retentionRunning: Promise<unknown> | null = null;
let retentionStartedAt = 0;
let retentionGeneration = 0;
const retentionTick = () => {
  if (retentionRunning && Date.now() - retentionStartedAt > STUCK_PROMISE_MS) {
    void report('retention')(new Error('Previous retention run is still running; starting a new attempt'));
    retentionGeneration++;
    retentionRunning = null;
  }
  if (stopping || config.WORKER_ENABLED !== 'true' || !leadership.isLeader || retentionRunning) return;
  retentionStartedAt = Date.now();
  const generation = ++retentionGeneration;
  retentionRunning = (async () => {
    const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
    const policy = settings.retentionConfig;
    if (!policy?.enabled || !policy.autoCleanup) return;
    const row = await pool.query("SELECT data FROM records WHERE kind='systemState' AND id=$1", [
      RETENTION_SCHEDULE_ID,
    ]);
    const data = row.rows[0]?.data ?? {};
    const now = Date.now();
    // Honor nextRetryAt for failed runs to enable immediate retry.
    if (typeof data.nextRetryAt === 'string' && Date.parse(data.nextRetryAt) > now) return;
    if (!(await claimRetention(policy))) return;
    // Bounded independently of the connection's statement timeout, and the
    // cancellation is delivered to PostgreSQL rather than only abandoning the
    // promise: an abandoned transaction keeps its pool connection until the
    // statement finishes, and a wedged one never does. The claim is released on
    // every failure so another replica (or the next tick here) can retry.
    const controller = new AbortController();
    const timer = setTimeout(
      () =>
        controller.abort(
          new Error(`Retention run exceeded ${RETENTION_RUN_LIMIT_MS}ms; cancellation requested`),
        ),
      RETENTION_RUN_LIMIT_MS,
    );
    timer.unref();
    verboseLog('retention.start');
    try {
      await runRetention(pool, 'system-retention', '', controller.signal);
      await releaseRetention(true);
      verboseLog('retention.completed');
    } catch (error) {
      await releaseRetention(false).catch(() => {});
      throw error;
    } finally {
      clearTimeout(timer);
    }
  })()
    .catch(report('retention'))
    .finally(() => {
      if (retentionGeneration === generation) retentionRunning = null;
    });
};
const retentionTimer = setInterval(retentionTick, 60000);
retentionTimer.unref();
retentionTick();
// The daily digest is a calendar job (daily summary + health report at the
// configured time/timezone). It is polled on the same cadence as retention and
// self-claims the calendar day, so it needs no separate clock.
let dailyDigestRunning: Promise<unknown> | null = null;
let dailyDigestStartedAt = 0;
let dailyDigestGeneration = 0;
let dailyDigestController: AbortController | undefined;
const dailyDigestTick = () => {
  if (dailyDigestRunning && Date.now() - dailyDigestStartedAt > STUCK_PROMISE_MS) {
    void report('dailyDigest')(new Error('Previous daily digest run is still running; starting a new attempt'));
    dailyDigestGeneration++;
    dailyDigestRunning = null;
    dailyDigestController?.abort(new Error('Daily digest stalled; cancelled'));
    dailyDigestController = undefined;
  }
  if (stopping || config.WORKER_ENABLED !== 'true' || !leadership.isLeader || dailyDigestRunning) return;
  dailyDigestStartedAt = Date.now();
  const generation = ++dailyDigestGeneration;
  dailyDigestController = new AbortController();
  const stuckTimer = setTimeout(() => {
    dailyDigestController?.abort(new Error(`Daily digest exceeded ${STUCK_PROMISE_MS}ms`));
  }, STUCK_PROMISE_MS);
  stuckTimer.unref();
  dailyDigestRunning = (async () => {
    verboseLog('dailyDigest.start');
    await runDailyDigest(pool, dailyDigestController.signal);
    verboseLog('dailyDigest.completed');
  })()
    .catch(report('dailyDigest'))
    .finally(() => {
      clearTimeout(stuckTimer);
      if (dailyDigestGeneration === generation) dailyDigestRunning = null;
      dailyDigestController = undefined;
    });
};
const ML_TRAINING_INTERVAL_MS = Number(process.env.ML_TRAINING_INTERVAL_MS ?? 60 * 60_000);
const ML_TRAINING_SCHEDULE_ID = 'ml-training-schedule';
const ENRICHMENT_BACKLOG_INTERVAL_MS = Number(process.env.ENRICHMENT_BACKLOG_INTERVAL_MS ?? 6 * 60 * 60_000);
const ENRICHMENT_BACKLOG_SCHEDULE_ID = 'enrichment-backlog-schedule';
let trainingRunning: Promise<unknown> | null = null;
let trainingStartedAt = 0;
let trainingGeneration = 0;
const mlTrainingTick = () => {
  if (stopping || config.WORKER_ENABLED !== 'true' || !leadership.isLeader) return;
  if (trainingRunning && Date.now() - trainingStartedAt > STUCK_PROMISE_MS) {
    void report('ml.training')(new Error('Previous ML training run is still running; starting a new attempt'));
    trainingGeneration++;
    trainingRunning = null;
  }
  if (trainingRunning) return;
  trainingStartedAt = Date.now();
  const generation = ++trainingGeneration;
  trainingRunning = (async () => {
    const claimToken = randomUUID();
    const claimed = await transaction(
      pool,
      async (db) => {
        const row = await db.query("SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE", [
          ML_TRAINING_SCHEDULE_ID,
        ]);
        const data = row.rows[0]?.data ?? {};
        const now = Date.now();
        const lastRun = typeof data.lastRun === 'string' ? Date.parse(data.lastRun) : NaN;
        if (Number.isFinite(lastRun) && now - lastRun < ML_TRAINING_INTERVAL_MS) return false;
        // The advisory lock also serializes the first claim before its row exists.
        const claimedAt = typeof data.claimedAt === 'string' ? Date.parse(data.claimedAt) : NaN;
        if (Number.isFinite(claimedAt) && now - claimedAt < 2 * STUCK_PROMISE_MS) return false;
        await put(db, 'systemState', ML_TRAINING_SCHEDULE_ID, {
          ...data,
          claimedAt: new Date(now).toISOString(),
          claimToken,
        });
        return true;
      },
      undefined,
      { locks: ['ml-training-claim'] },
    );
    if (!claimed) return;
    verboseLog('ml.training.start');
    const summary = await runScheduledTraining(pool, {
      directory: config.ML_DIRECTORY,
      signingKey: config.ML_SIGNING_KEY,
      ...(config.ML_STORAGE_MODE === 'database' ? { database: pool } : {}),
      lookbackDays: config.ML_LOOKBACK_DAYS,
    }).catch((error) => {
      // Release the claim on failure so the next tick (or another replica) can
      // retry immediately instead of waiting out the claim TTL. A stale run
      // must not clear a newer owner's claim.
      const releaseClaim = pool
        .query(
          "UPDATE records SET data=data || jsonb_build_object('claimedAt',NULL,'claimToken',NULL) WHERE kind='systemState' AND id=$1 AND data->>'claimToken'=$2",
          [ML_TRAINING_SCHEDULE_ID, claimToken],
        )
        .catch(() => undefined);
      return releaseClaim
        .catch(() => undefined)
        .then(() => {
          if (error instanceof TrainingAlreadyRunningError) return null;
          throw error;
        });
    });
    if (!summary) return;
    if (summary.summary.saved > 0) {
      await initMlRuntime(pool, mlStorageOptions);
    }
    await pool.query(
      "UPDATE records SET data=jsonb_set(data,'{\"lastRun\"}',to_jsonb(now())) || jsonb_build_object('claimedAt',NULL,'claimToken',NULL) WHERE kind='systemState' AND id=$1 AND data->>'claimToken'=$2",
      [ML_TRAINING_SCHEDULE_ID, claimToken],
    );
    void logMlTrainingResult(pool, summary);
    verboseLog('ml.training.completed', { result: summary.results.map((r) => ({ modelId: r.modelId, status: r.status })) });
  })()
    .catch(report('ml.training'))
    .finally(() => {
      if (trainingGeneration === generation) trainingRunning = null;
    });
};
const dailyDigestTimer = setInterval(dailyDigestTick, 60000);
dailyDigestTimer.unref();
dailyDigestTick();
const mlTrainingTimer = setInterval(mlTrainingTick, 60000);
mlTrainingTimer.unref();
mlTrainingTick();

let enrichmentBacklogRunning: Promise<unknown> | null = null;
// records.data is jsonb, which node-pg already decodes to an object. Accept a
// text value too, so this does not depend on the driver's type mapping.
const parseRecordData = <T,>(data: unknown): T =>
  (typeof data === 'string' ? JSON.parse(data) : data) as T;

/** Upper bound for one enrichment-backlog scan (audit V-1: bounded tick).
 *  Far above any realistic pending-enrichment count; when the backlog exceeds
 *  this, the reported count is a floor, which is the correct semantics for an
 *  observability signal. */
const ENRICHMENT_BACKLOG_SCAN_LIMIT = 500;
const enrichmentBacklogTick = async () => {
  if (stopping || config.WORKER_ENABLED !== 'true' || !leadership.isLeader || enrichmentBacklogRunning) return;
  enrichmentBacklogRunning = (async () => {
    try {
      // Push the cheap predicates (kind, dispatch status) into the database so
      // the scan narrows to queued findings only; the missing-CPE check stays
      // in JS because the JSONB shape varies between finding generations.
      // Audit V-1: the backlog is bounded. This is an observability-only tick
      // (it reports the count, it does not enrich), so a cap costs nothing —
      // an unbounded scan over the whole findings table made tick latency grow
      // with deployment age and held the pool connection for that whole read.
      const rows = await pool.query<{ data: unknown }>(
        `SELECT data FROM records
          WHERE kind='findings'
            AND data->>'notificationStatus' = 'QUEUED_FOR_DISPATCH'
          ORDER BY created_at ASC
          LIMIT $1`,
        [ENRICHMENT_BACKLOG_SCAN_LIMIT],
      );
      const queued = rows.rows.map((row) => parseRecordData<Finding>(row.data));
      const candidates = enrichmentBacklogCandidates(queued);
      if (candidates.length > 0) {
        await writeEvent(pool, {
          category: 'PIPELINE',
          level: 'INFO',
          code: 'enrichment.backlog',
          message: `${candidates.length}${rows.rows.length >= ENRICHMENT_BACKLOG_SCAN_LIMIT ? '+' : ''} finding(s) dispatched via authoritative source without CPE data are pending enrichment re-evaluation`,
          context: { count: candidates.length, cveIds: candidates.map((f) => f.cveId), scanLimit: ENRICHMENT_BACKLOG_SCAN_LIMIT },
        });
      }
    } catch (error) {
      void report('enrichment.backlog')(error);
    } finally {
      enrichmentBacklogRunning = null;
    }
  })();
  return enrichmentBacklogRunning;
};
const enrichmentBacklogTimer = setInterval(enrichmentBacklogTick, ENRICHMENT_BACKLOG_INTERVAL_MS);
enrichmentBacklogTimer.unref();
enrichmentBacklogTick();

// Dead-letter auto-retry: re-process delivery_dead_letters on a cadence so
// findings whose transport failed are retried automatically instead of
// waiting for operator intervention. Only the leader runs this.
//
// Bounded per finding. The previous loop reset every unresolved dead letter to
// QUEUED_FOR_DISPATCH exactly once and then marked the letter resolved, so a
// finding could be dead-lettered, re-dispatched, dead-lettered and retried again
// with nothing counting the attempts. That made a bounded retry budget (the
// outbox's `maxAttempts`) unbounded in practice, and a recipient that will never
// accept mail produced an endless retry loop. The attempt count now lives on the
// finding, survives every reset (reconcileFindings keeps `deadLetterCount`), and
// a finding that exhausts it is parked for operator action with a single alert
// instead of being requeued.
let deadLetterRetryRunning: Promise<unknown> | null = null;
const DEAD_LETTER_RETRY_INTERVAL_MS = Number(process.env.DEAD_LETTER_RETRY_INTERVAL_MS ?? 15 * 60_000);
const MAX_DEAD_LETTER_RETRIES = Number(process.env.MAX_DEAD_LETTER_RETRIES ?? 3);
const deadLetterRetryTick = async () => {
  if (stopping || config.WORKER_ENABLED !== 'true' || !leadership.isLeader || deadLetterRetryRunning) return;
  deadLetterRetryRunning = (async () => {
    try {
      const rows = await pool.query<{ id: string; data: unknown }>(
        `SELECT id, data FROM records WHERE kind='delivery_dead_letters'
         AND COALESCE(data->>'resolvedAt','')=''
         ORDER BY created_at ASC LIMIT 50`,
      );
      if (rows.rows.length === 0) return;
      let retried = 0;
      let exhausted = 0;
      for (const row of rows.rows) {
        try {
          const deadLetter = parseRecordData<{ findingId?: string; id?: string }>(row.data);
          const findingId = deadLetter.findingId || deadLetter.id;
          await transaction(pool, async (db) => {
            // Re-queue the finding through the normal pipeline path by marking
            // the finding as not-yet-dispatched so the next pipeline run picks it up.
            const finding = findingId ? await get<Finding>(db, 'findings', findingId) : undefined;
            // The dead letter is always resolved: leaving it open would retry it
            // every tick forever, and its retry budget lives on the finding, not
            // on this row. An orphaned letter (no finding) has nothing to retry.
            if (finding) {
              const attempts = (finding.deadLetterCount ?? 0) + 1;
              // A resolved, dismissed or patched finding is a terminal operator
              // decision; re-queueing it would resurrect a finding they closed.
              const terminal = ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status);
              if (terminal) {
                // Nothing to do beyond closing the letter.
              } else if (attempts > MAX_DEAD_LETTER_RETRIES) {
                exhausted++;
                await put(db, 'findings', findingId!, {
                  ...finding,
                  // The budget is left exactly as it is: it is spent, and a later
                  // requeue must not inherit a larger allowance than it had.
                  // Park it as a terminal, operator-visible failure. The next
                  // pipeline run must not silently turn this back into a resend;
                  // reconcileFindings preserves DELIVERY_FAILED (see its comment).
                  notificationStatus: 'DELIVERY_FAILED',
                  dispatchDeferred: true,
                  timeline: [
                    ...(finding.timeline ?? []),
                    {
                      timestamp: new Date().toISOString(),
                      action: 'Dead-letter retry budget exhausted',
                      system: 'Delivery worker',
                      details: `${MAX_DEAD_LETTER_RETRIES} automatic retries did not reach the recipient; operator action required`,
                    },
                  ],
                });
                await writeEvent(db, {
                  category: 'EMAIL',
                  level: 'ERROR',
                  code: 'deadLetter.retry_exhausted',
                  message: `Finding ${findingId} exhausted ${MAX_DEAD_LETTER_RETRIES} dead-letter retries; parked for operator action`,
                  context: { findingId: findingId, cveId: finding.cveId, attempts },
                }).catch(() => undefined);
              } else {
                await put(db, 'findings', findingId!, {
                  ...finding,
                  deadLetterCount: attempts,
                  notificationStatus: 'QUEUED_FOR_DISPATCH',
                  autoDispatchedAt: null,
                  reviewNotifiedAt: null,
                });
                retried++;
              }
            }
            // Mark the dead letter as resolved (handled: retried, parked, or orphaned).
            // Re-queue happens before resolve in the same transaction so a crash
            // between the two leaves the finding re-queued (idempotent via
            // delivery dedupe) and the dead letter unresolved (retried next tick).
            await put(db, 'delivery_dead_letters', row.id, {
              ...deadLetter,
              resolvedAt: new Date().toISOString(),
              resolvedBy: 'auto-retry',
            });
          });
        } catch (error) {
          void report('deadLetter.retry')(error);
        }
      }
      if (retried > 0) {
        await writeEvent(pool, {
          category: 'EMAIL',
          level: 'INFO',
          code: 'deadLetter.auto_retry',
          message: `Auto-retried ${retried} delivery dead letter(s)`,
          context: { retried, exhausted },
        }).catch(() => undefined);
      }
    } catch (error) {
      void report('deadLetter.retry')(error);
    } finally {
      deadLetterRetryRunning = null;
    }
  })();
  return deadLetterRetryRunning;
};
const deadLetterRetryTimer = setInterval(deadLetterRetryTick, DEAD_LETTER_RETRY_INTERVAL_MS);
deadLetterRetryTimer.unref();
deadLetterRetryTick();
let mlTelemetryRunning: Promise<void> | null = null;
let mlTelemetryPrevious = { time: Date.now(), completed: correlation.supervisor.ingestor.telemetry.completed };
const mlTelemetryTimer = setInterval(() => {
  if (stopping || config.WORKER_ENABLED !== 'true' || !leadership.isLeader || mlTelemetryRunning ||
      !shouldSampleMlTelemetry(correlation.pendingDepth, correlation.pendingSampledAt)) return;
  const telemetry = correlation.supervisor.ingestor.telemetry;
  const now = Date.now();
  const metrics = {
    memoryPercent: correlation.supervisor.memoryPercent(),
    activeWorkers: correlation.supervisor.active.size,
    concurrencyLimit: correlation.supervisor.concurrencyLimit,
    latencyMs: telemetry.completed ? telemetry.latencyTotal / telemetry.completed : 0,
    deadLetters: telemetry.deadLetters,
    pendingClaims: Math.max(0, correlation.pendingDepth),
    itemsPerSecond: Math.max(0, telemetry.completed - mlTelemetryPrevious.completed) / Math.max(1, (now - mlTelemetryPrevious.time) / 1000),
    poolWaiting: pool.waitingCount,
  };
  mlTelemetryPrevious = { time: now, completed: telemetry.completed };
  mlTelemetryRunning = writeEvent(pool, {
    category: 'ML', code: 'ml.telemetry.sample', message: 'Observed ML telemetry training sample', context: metrics,
  }).then(() => {
    if (isTelemetryAnomaly(metrics))
      return writeEvent(pool, {
        category: 'ML', level: 'WARNING', code: 'ml.telemetry.anomaly',
        message: 'ML telemetry anomaly detected', context: metrics,
      });
  })
    .catch(report('ml.telemetry'))
    .finally(() => { mlTelemetryRunning = null; });
}, 60000);
mlTelemetryTimer.unref();
const cleanup = setInterval(() => {
  // Housekeeping, not work: every replica running it just serialises the same
  // DELETE statements against the same rows. Only the worker replica owns it,
  // like every other periodic job below, so the API replica stays free of
  // background write load.
  if (config.WORKER_ENABLED !== 'true' || !leadership.isLeader) return;
  // Session and login-attempt expiry are security invariants, not retained
  // business data. Queue rows and operational events follow the retention
  // policy in runRetention so an operator's configured window stays authoritative.
  void pool
    .query(
      `DELETE FROM sessions WHERE expires_at<now();
       DELETE FROM login_attempts WHERE window_start<now()-interval '1 day';
       DELETE FROM password_reset_tokens WHERE expires_at<now();`,
    )
    .then((result) => {
      verboseLog('session.cleanup', { removed: result?.rowCount ?? 0 });
    })
    .catch(report('session-cleanup'));
}, 60000);
cleanup.unref();
async function shutdown() {
  if (stopping) return;
  stopping = true;
  if (pipelineController) {
    setAbortReason(pipelineController);
    const shutdownReason = new Error('Pipeline cancelled during shutdown');
    (shutdownReason as { [ABORT_REASON]?: boolean })[ABORT_REASON] = true;
    pipelineController.abort(shutdownReason);
  }
  clearInterval(timer);
  clearInterval(retentionTimer);
  clearInterval(dailyDigestTimer);
  clearInterval(mlTrainingTimer);
  clearInterval(mlTelemetryTimer);
  clearInterval(cleanup);
  // Later worker jobs are unref'd so they do not hold the event loop open,
  // but they must still be cancelled: a timer that fires after `stopping =
  // true` would skip (guards handle it) yet keep running during teardown and
  // could race the pool drain below.
  clearInterval(enrichmentBacklogTimer);
  clearInterval(deadLetterRetryTimer);
  const deadline = setTimeout(() => process.exit(1), 30000);
  deadline.unref();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await Promise.allSettled(
    [pipeline, outbox, digest, retentionRunning, dailyDigestRunning, trainingRunning, mlTelemetryRunning].filter(Boolean) as Promise<unknown>[],
  );
  await correlation.stop();
  await closePdfRenderer();
  await leadership.close();
  await pool.end();
  clearTimeout(deadline);
}
process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
// Node terminates the process immediately on an uncaught exception
// with no listener registered. That would skip shutdown() entirely, leaving the
// HTTP server and any in-flight pipeline/outbox work to die mid-transaction
// without the structured event log entry operators rely on to diagnose it.
// PostgreSQL releases the session-level pipeline advisory lock when the
// connection closes, so a crash here is still safe for the next worker to
// recover from; this handler only makes the failure visible and gives
// in-flight work a chance at a clean stop before the process exits.
//
// uncaughtException: process state is unknown — must exit after best-effort
// shutdown. unhandledRejection is treated the same way: a rejected promise with
// no handler means some async operation was abandoned mid-flight, and this
// process cannot know what it left half-applied (an outbox job claimed but not
// finalised, a transaction opened but not committed). Continuing to serve and to
// claim deliveries from that state is what turns one bug into a duplicate email
// or a lost finding that is impossible to reconstruct. The process drains,
// exits, and the supervisor/leader election hands its work to a replacement —
// which is the self-healing behaviour, not running on in an unknown state.
const exitAfterDrain = (error: unknown) => {
  report('unhandled-rejection')(error);
  if (stopping) return;
  void shutdown()
    .then(() => process.exit(1))
    .catch(() => process.exit(1));
};

const handleUncaughtException = (error: unknown) => {
  correlation.supervisor.ingestor.telemetry.log('CRITICAL', 'uncaught-exception');
  exitAfterDrain(error);
};

const handleUnhandledRejection = (reason: unknown) => {
  correlation.supervisor.ingestor.telemetry.log('ERROR', 'unhandled-rejection');
  exitAfterDrain(reason);
};

process.on('uncaughtException', handleUncaughtException);
process.on('unhandledRejection', handleUnhandledRejection);
