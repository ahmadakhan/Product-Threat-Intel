import { WorkerLeadership } from './leadership.ts';
import { randomUUID } from 'node:crypto';
import { getHeapStatistics } from 'node:v8';
import { totalmem } from 'node:os';
import type pg from 'pg';
import { loadConfig, boundedEnvInt } from './config';
import { createPool, migrate, transaction, get, getForUpdate, put, REQUIRED_SCHEMA_VERSION } from './db';
import type { Db } from './db';
import { createRequester } from './network';
import { createMailSender, deliverNext } from './delivery';
import { releaseExpiredClaims } from './deliveryClaims';
import { flushDueDigest } from './digest';
import { runDailyDigest } from './dailyDigest';
import { initMlRuntime } from './ml/integration.ts';
import { encryptionKeys } from './secrets';
import { runScheduledTraining, TrainingAlreadyRunningError } from './ml/train/cron.ts';
import { enrichmentBacklogCandidates } from '../src/engine/pipelineEngine';
import type { Finding } from '../src/types/index.ts';
import type { TrainingSummary } from './ml/train/orchestrator.ts';
import { isTelemetryAnomaly, shouldSampleMlTelemetry } from './ml/integration.ts';
import {
  processPipeline,
  setAbortReason,
  ABORT_REASON,
  PipelinePoolStarved,
  releaseOrphanedRunningExecutions,
} from './pipeline';
import { runSelfHealCheck } from './selfHealing';
import { runRetention } from './retention';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { AppSettings } from '../src/types/index.ts';
import { initShared } from './bootstrap';

const { pool, config, request, sendMail, correlation, mlRuntime, writeEvent, describeError } =
  await initShared();

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

/** How long a cancelled pipeline attempt may take to settle before it is detached. */
const PIPELINE_ABORT_GRACE_MS = 30_000;
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
let stopping = false;
let digestStartedAt = 0;
let pipelineStartedAt = 0;
/**
 * When the current pipeline attempt was first observed cancelled. A cancelled
 * attempt normally rejects within its own checkpoint, but a promise that ignores
 * the abort must not pin the worker forever: after this grace period the
 * attempt is detached and a fresh one may start. The session advisory lock was
 * already released by the abort path, so a replacement worker can safely
 * recover the interrupted execution.
 */
let pipelineAbortedAt = 0;
let outboxStartedAt = 0;
let digestGeneration = 0;
let pipelineController: AbortController | undefined;
let outboxGeneration = 0;
/** Cancels the in-flight outbox pass when it is superseded or the worker stops. */
let outboxController: AbortController | undefined;
/** In-flight pipeline promise. */
let pipeline: Promise<unknown> | null = null;
/** In-flight outbox promise. */
let outbox: Promise<unknown> | null = null;
/** In-flight digest promise. */
let digest: Promise<unknown> | null = null;
/** In-flight self-healing check; prevents overlapping watchdog runs per tick. */
let selfHealRunning: Promise<void> | null = null;
/** In-flight memory pressure response; prevents overlapping restart attempts. */
let memoryPressureRunning: Promise<void> | null = null;
/** Pipeline start time whose half-budget warning has already been emitted. */
let warnedStallRunAt = 0;

function checkMemoryPressure(): void {
  if (memoryPressureRunning) return;
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
      }
      if (heapPct >= 95) {
        void report('memory.pressure')(new Error(`Heap at ${heapPct.toFixed(0)}%; initiating graceful restart`));
        // Hard-exit backstop. `shutdown()` can itself block (a hung query on the
        // pool, an in-flight delivery that never settles, a wedged timer), and
        // while it blocks the process keeps climbing toward an OOM kill that the
        // orchestrator sees as a crash instead of the graceful restart this path
        // intends. Arm an independent timer BEFORE awaiting shutdown so the exit
        // is bounded even when shutdown never resolves. `unref()` keeps the timer
        // from on its own holding the event loop open if shutdown finishes first.
        const hardExit = setTimeout(() => {
          console.error(JSON.stringify({ level: 'error', event: 'memory.pressure.hard_exit' }));
          process.exit(1);
        }, 10_000);
        hardExit.unref();
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

const tick = () => {
  if (stopping) return;
  void checkLeadership();
  checkMemoryPressure();
  if (!leadership.isLeader) return;
  // Approaching the stall budget is a capacity signal: a healthy run that comes
  // within 50% of the threshold means one slow source response will abort the
  // next one. Warn once per run (keyed by its start time) so operators raise
  // STUCK_PROMISE_MS from evidence instead of discovering it as a mid-run abort.
  if (pipeline && pipelineStartedAt !== warnedStallRunAt) {
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
  if (pipeline && Date.now() - pipelineStartedAt > STUCK_PROMISE_MS) {
    const silentMs = Date.now() - pipelineStartedAt;
    const reason = new Error(
      `Pipeline produced no progress for ${silentMs}ms (STUCK_PROMISE_MS=${STUCK_PROMISE_MS}); cancelling the current attempt`,
    );
    void report('pipeline')(reason);
    if (pipelineController) {
      setAbortReason(pipelineController);
      pipelineController.abort(stampAborted(reason));
    }
  }
  // A cancelled attempt normally rejects at its next checkpoint, but the abort
  // signal cannot interrupt a synchronous stretch or a promise that ignores it.
  // Left alone, such an attempt keeps `pipeline` set and blocks every future
  // run for the life of the process. After a bounded grace period, detach it:
  // the abort path already released the session advisory lock, so the fresh
  // attempt started below can safely recover the interrupted execution.
  if (pipeline && pipelineController?.signal.aborted) {
    if (!pipelineAbortedAt) {
      pipelineAbortedAt = Date.now();
    } else if (Date.now() - pipelineAbortedAt > PIPELINE_ABORT_GRACE_MS) {
      void report('pipeline')(
        new Error(
          `Cancelled pipeline did not settle within ${PIPELINE_ABORT_GRACE_MS}ms; detaching the attempt so the worker can recover`,
        ),
      );
      pipeline = null;
      pipelineController = undefined;
      pipelineAbortedAt = 0;
      void releaseOrphanedRunningExecutions(
        pool,
        'worker detached a cancelled pipeline attempt that did not settle',
      ).catch((error: unknown) => {
        void report('pipeline')(error);
      });
    }
  }
  if (!pipeline) {
    pipelineStartedAt = Date.now();
    pipelineAbortedAt = 0;
    const controller = new AbortController();
    pipelineController = controller;
    pipeline = processPipeline(pool, config, request, controller.signal, () => {
      if (pipelineController === controller) pipelineStartedAt = Date.now();
    })
      .then((result) => {
        // handled below
      })
      .catch((error) => {
        if (!reasonAborted(error)) report('pipeline')(error);
      })
      .finally(() => {
        if (pipelineController === controller) {
          pipeline = null;
          pipelineController = undefined;
          pipelineAbortedAt = 0;
        }
      });
  }
  if (outbox && Date.now() - outboxStartedAt > STUCK_PROMISE_MS) {
    void report('outbox')(new Error('Previous outbox promise is still running; starting a fresh attempt'));
    // Abort the detached pass before dropping the reference. Without this the
    // superseded loop kept claiming and sending for up to 20 jobs, competing with
    // the replacement for the same queue and holding pool connections, while
    // both were reported as "the" outbox worker. The pipeline, retention and
    // digest loops all stop through their signal; the outbox loop was the one
    // that could not.
    outboxController?.abort(stampAborted(new Error('Outbox pass superseded by a fresh attempt')));
    outboxController = undefined;
    outboxGeneration++;
    outbox = null;
  }
  if (!outbox) {
    outboxStartedAt = Date.now();
    const generation = ++outboxGeneration;
    const controller = new AbortController();
    outboxController = controller;
    outbox = (async () => {
      for (let i = 0; i < 20 && !stopping && !controller.signal.aborted; i++) {
        // `deliverNext` re-throws the abort, which ends this pass. The catch below
        // classifies it through `reasonAborted`, so a deliberate stop is not
        // reported as an outbox failure. Checking the signal between jobs is what
        // makes the pass abortable at all: one delivery can legitimately occupy
        // the whole STUCK_PROMISE_MS budget (SMTP timeout plus a provider
        // delivery lookup), and a superseded pass must stop claiming and sending
        // the moment it is aborted rather than after its remaining 19 jobs.
        const delivered = await deliverNext(pool, config, request, sendMail, controller.signal);
        if (!delivered) break;
      }
      if (controller.signal.aborted) return;
      try {
        const reclaimed = await transaction(pool, (db) => releaseExpiredClaims(db));
        if (reclaimed > 0) {
          // eslint-disable-next-line no-console
          console.log(JSON.stringify({ level: 'info', event: 'claims.swept', reclaimed }));
        }
      } catch (error) {
        void report('claims.sweep')(error);
      }
    })()
      .catch((error) => {
        if (!reasonAborted(error)) report('outbox')(error);
      })
      .finally(() => {
        if (outboxController === controller) outboxController = undefined;
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
        // eslint-disable-next-line no-console
        console.log(JSON.stringify({ level: 'info', event: 'digest.flushed', count }));
      })
      .catch(report('digest'))
      .finally(() => {
        if (digestGeneration === generation) digest = null;
      });
  }
  checkMemoryPressure();
  // Self-healing auto-recovery check - runs on every worker tick.
  // Monitors pipeline, feeds, and scheduler; triggers recovery and sends
  // immediate alerts to the Security team group.
  // Guarded against overlap: a slow check would otherwise pile a new promise on
  // every tick until the pool is exhausted.
  if (!selfHealRunning) {
    // Only the leader self-heals. The memory guard above still runs everywhere,
    // but a self-heal check opens its own connections for the reachability probe
    // and the recovery claims, so on a follower it spends pool capacity on work
    // the leader already performs — and the alerts it queues can fire before the
    // advisory locks serialise it. One check per tick on the leader is the whole
    // contract.
    if (!leadership.isLeader) return;
    selfHealRunning = runSelfHealCheck(pool)
      .catch((err) => {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify({ level: 'info', event: 'selfHeal.check_failed', error: err instanceof Error ? err.message : String(err) }));
      })
      .finally(() => {
        selfHealRunning = null;
      });
  }
};

const WORKER_TICK_MS = boundedEnvInt(process.env.WORKER_TICK_MS, 5000, 250, 3_600_000);
const timer = setInterval(tick, WORKER_TICK_MS);
// These timers only exist to drive background work. They must not be the
// reason the event loop stays alive: a harness (or a supervisor draining the
// process) that has otherwise finished would be pinned open forever.
timer.unref();
tick();
// Initial leadership election attempt. All replicas start as followers and
// compete for the advisory lock; only the winner runs background jobs.
void checkLeadership();
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
  if (stopping || retentionRunning) return;
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
    try {
      await runRetention(pool, 'system-retention', '', controller.signal);
      await releaseRetention(true);
      // eslint-disable-next-line no-console
      console.log(JSON.stringify({ level: 'info', event: 'retention.completed' }));
    } catch (error) {
      // The claim MUST come back. If this release is lost, the row keeps
      // `claimedAt` set until RETENTION_CLAIM_TTL_MS expires, and a failed release
      // that nobody reported meant retention silently stopped running for that
      // whole window. Report it, and retry once on a fresh connection: a release
      // that failed because its transaction aborted succeeds immediately on a new
      // one, while a genuine database outage is reported rather than swallowed.
      await releaseRetention(false).catch(async (releaseError) => {
        void report('retention.release')(releaseError);
        await new Promise((resolve) => setTimeout(resolve, 1000));
        await releaseRetention(false).catch((retryError) => {
          void report('retention.release')(retryError);
        });
      });
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
  if (stopping || dailyDigestRunning) return;
  dailyDigestStartedAt = Date.now();
  const generation = ++dailyDigestGeneration;
  dailyDigestController = new AbortController();
  const stuckTimer = setTimeout(() => {
    dailyDigestController?.abort(new Error(`Daily digest exceeded ${STUCK_PROMISE_MS}ms`));
  }, STUCK_PROMISE_MS);
  stuckTimer.unref();
  dailyDigestRunning = (async () => {
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ level: 'info', event: 'dailyDigest.start' }));
    await runDailyDigest(pool, dailyDigestController.signal);
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ level: 'info', event: 'dailyDigest.completed' }));
  })()
    .catch(report('dailyDigest'))
    .finally(() => {
      clearTimeout(stuckTimer);
      if (dailyDigestGeneration === generation) dailyDigestRunning = null;
      dailyDigestController = undefined;
    });
};
const ML_TRAINING_INTERVAL_MS = boundedEnvInt(process.env.ML_TRAINING_INTERVAL_MS, 60 * 60_000, 60_000, 24 * 60 * 60_000);
const ML_TRAINING_SCHEDULE_ID = 'ml-training-schedule';
const ENRICHMENT_BACKLOG_INTERVAL_MS = boundedEnvInt(process.env.ENRICHMENT_BACKLOG_INTERVAL_MS, 6 * 60 * 60_000, 60_000, 24 * 60 * 60_000);
const ENRICHMENT_BACKLOG_SCHEDULE_ID = 'enrichment-backlog-schedule';
let trainingRunning: Promise<unknown> | null = null;
let trainingStartedAt = 0;
let trainingGeneration = 0;
const mlTrainingTick = () => {
  if (stopping || (trainingRunning && Date.now() - trainingStartedAt > STUCK_PROMISE_MS)) {
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
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ level: 'info', event: 'ml.training.start' }));
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
      await initMlRuntime(pool, {
        directory: config.ML_DIRECTORY,
        signingKey: config.ML_SIGNING_KEY,
        ...(config.ML_STORAGE_MODE === 'database' ? { database: pool } : {}),
      });
    }
    await pool.query(
      "UPDATE records SET data=jsonb_set(data,'{\"lastRun\"}',to_jsonb(now())) || jsonb_build_object('claimedAt',NULL,'claimToken',NULL) WHERE kind='systemState' AND id=$1 AND data->>'claimToken'=$2",
      [ML_TRAINING_SCHEDULE_ID, claimToken],
    );
    void logMlTrainingResult(pool, summary);
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ level: 'info', event: 'ml.training.completed', result: summary.results.map((r) => ({ modelId: r.modelId, status: r.status })) }));
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

/** Upper bound for one enrichment-backlog scan (audit V-1: bounded tick). */
const ENRICHMENT_BACKLOG_SCAN_LIMIT = 500;
const enrichmentBacklogTick = async () => {
  if (stopping || enrichmentBacklogRunning) return;
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
let deadLetterRetryRunning: Promise<unknown> | null = null;
const DEAD_LETTER_RETRY_INTERVAL_MS = Number(process.env.DEAD_LETTER_RETRY_INTERVAL_MS ?? 15 * 60_000);
const MAX_DEAD_LETTER_RETRIES = Number(process.env.MAX_DEAD_LETTER_RETRIES ?? 3);
const deadLetterRetryTick = async () => {
  if (stopping || deadLetterRetryRunning) return;
  deadLetterRetryRunning = (async () => {
    try {
      const rows = await pool.query<{ id: string; data: unknown }>(
        `SELECT id, data FROM records WHERE kind='delivery_dead_letters'
         AND COALESCE(data->>'resolvedAt','')=''
         ORDER BY created_at ASC LIMIT 50`,
      );
      if (rows.rows.length === 0) return;
      const outcomes = await transaction(pool, async (db) => {
        let retried = 0;
        let exhausted = 0;
        const claimed = await db.query<{ id: string; data: unknown }>(
          `SELECT id, data FROM records WHERE kind='delivery_dead_letters'
           AND id = ANY($1::text[]) AND COALESCE(data->>'resolvedAt','')=''
           ORDER BY id FOR UPDATE SKIP LOCKED`,
          [rows.rows.map((row) => row.id)],
        );
        if (!claimed.rows.length) return { retried: 0, exhausted: 0 };
        for (const row of claimed.rows) {
          await db.query('SAVEPOINT dead_letter_row');
          try {
            const deadLetter = parseRecordData<{ findingId?: string; id?: string }>(row.data);
            const findingId = deadLetter.findingId || deadLetter.id;
            if (findingId) {
              const finding = findingId ? await getForUpdate<Finding>(db, 'findings', findingId) : undefined;
              const terminal = ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding?.status ?? '');
              if (terminal) {
                // Nothing to do beyond closing the letter.
              } else {
                const attempts = (finding?.deadLetterCount ?? 0) + 1;
                if (attempts > MAX_DEAD_LETTER_RETRIES) {
                  exhausted++;
                  await put(db, 'findings', findingId!, {
                    ...finding,
                    notificationStatus: 'DELIVERY_FAILED',
                    dispatchDeferred: true,
                    timeline: [
                      ...(finding?.timeline ?? []),
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
                    context: { findingId, cveId: finding?.cveId, attempts },
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
            }
            await put(db, 'delivery_dead_letters', row.id, {
              ...deadLetter,
              resolvedAt: new Date().toISOString(),
              resolvedBy: 'auto-retry',
            });
            await db.query('RELEASE SAVEPOINT dead_letter_row').catch(() => {});
          } catch (error) {
            await db.query('ROLLBACK TO SAVEPOINT dead_letter_row').catch(() => {});
            // A letter that cannot be processed is left unresolved deliberately: it
            // is retried on the next tick, and because the batch shares one
            // transaction, a per-letter failure must not discard the letters already
            // handled. The failed row's own writes were discarded by the savepoint
            // rollback above, so a partially applied letter never commits.
            void report('deadLetter.retry')(error);
          }
        }
        return { retried, exhausted };
      });
      const { retried, exhausted } = outcomes;
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
  if (stopping || mlTelemetryRunning ||
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
  // Session and login-attempt expiry are security invariants, not retained
  // business data. Queue rows and operational events follow the retention
  // policy in runRetention so an operator's configured window stays authoritative.
  //
  // One explicit transaction, not three independent statements: a multi-statement
  // `query()` is a simple-query batch that PostgreSQL runs as its own implicit
  // transaction, so a failure part-way could leave expired sessions purged while
  // login attempts were not. Wrapping them makes the sweep all-or-nothing and
  // lets a single statement timeout fail it cleanly.
  void transaction(pool, async (db) => {
    await db.query('DELETE FROM sessions WHERE expires_at<now()');
    await db.query("DELETE FROM login_attempts WHERE window_start<now()-interval '1 day'");
    await db.query('DELETE FROM password_reset_tokens WHERE expires_at<now()');
  })
    .then(() => {
      // eslint-disable-next-line no-console
      console.log(JSON.stringify({ level: 'info', event: 'session.cleanup' }));
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
  // Stop the outbox pass too. Without this a shutdown could still send up to 20
  // queued notifications after the operator asked the process to stop, and the
  // pool would be closed underneath it.
  if (outboxController) {
    const outboxReason = new Error('Outbox pass cancelled during shutdown');
    (outboxReason as { [ABORT_REASON]?: boolean })[ABORT_REASON] = true;
    outboxController.abort(outboxReason);
    outboxController = undefined;
  }
  clearInterval(timer);
  clearInterval(retentionTimer);
  clearInterval(dailyDigestTimer);
  clearInterval(mlTrainingTimer);
  clearInterval(mlTelemetryTimer);
  clearInterval(cleanup);
  clearInterval(enrichmentBacklogTimer);
  clearInterval(deadLetterRetryTimer);
  const deadline = setTimeout(() => process.exit(1), 30000);
  deadline.unref();
  const workerEntries: Array<[string, Promise<unknown> | null]> = [
    ['pipeline', pipeline],
    ['outbox', outbox],
    ['digest', digest],
    ['retention', retentionRunning],
    ['dailyDigest', dailyDigestRunning],
    ['mlTraining', trainingRunning],
    ['mlTelemetry', mlTelemetryRunning],
  ];
  const settled = await Promise.allSettled(
    workerEntries.filter(([, p]): p is Promise<unknown> => p !== null).map(([, p]) => p),
  );
  let settledIndex = 0;
  for (const [name, promise] of workerEntries) {
    if (promise === null) continue;
    const result = settled[settledIndex++];
    if (result.status === 'rejected') {
      report(`shutdown.${name}`)(result.reason);
    }
  }
  await correlation.stop();
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
