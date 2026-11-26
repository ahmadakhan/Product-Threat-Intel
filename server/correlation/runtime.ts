import { transaction } from '../db.ts';
import { queueNativeNotifications } from './notifications.ts';
import { retainCorrelationData, cleanupStaleMatches } from './operations.ts';
import { Readable } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import type { Pool } from 'pg';
import { CorrelationTelemetry } from './telemetry.ts';
import { DeadLetterQueue } from './deadLetter.ts';
import { AdvisoryIngestor } from './ingest.ts';
import { PipelineSupervisor } from './supervisor.ts';
import { AdvisoryStreamProcessor } from './stream.ts';
import {
  claimPending,
  renewPending,
  acknowledgePending,
  acknowledgePendingExcept,
  MAX_PENDING_ATTEMPTS,
  sweepExhaustedPending,
} from './pending.ts';

/** Structural equality for pending payloads (plain JSON values only). */
const samePayload = (left: unknown, right: unknown): boolean => {
  if (left === right) return true;
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
};

/**
 * How long one drain pass may go without reporting progress.
 *
 * A drain that never settles used to pin `this.draining` forever: every later
 * tick returned early on the `this.draining` guard, so ingestion, notification
 * queueing, stale-match cleanup and the retention sweeps all stopped, silently,
 * while the worker still looked healthy. The guard is necessary (one pass at a
 * time), so the fix is to bound the pass rather than drop the guard.
 *
 * The budget is measured from the last progress checkpoint, not from the start
 * of the pass. A wall-clock ceiling could not distinguish a wedged statement
 * from a pass that simply was not scheduled: when the event loop is busy - for
 * example while startup ingestion parses feeds on the main thread - both the
 * awaited continuation and the watchdog are delayed, so a healthy pass was
 * reported as CRITICAL `pending.drain_timeout`. Progress accounting only trips
 * when the pass has genuinely stopped advancing between awaits.
 *
 * Deliberately generous: a legitimate pass reports a checkpoint after every
 * awaited step, so five seconds without a single checkpoint only happens when
 * work is wedged (a statement parked on a dead socket).
 */
const DRAIN_TIMEOUT_MS = 5_000;
/** How often the stall watchdog re-checks the last progress checkpoint. */
const DRAIN_WATCHDOG_POLL_MS = 500;
/** Pause between successful drain batches so the loop cannot spin hot. */
const DRAIN_INTER_BATCH_MS = 100;

/** Signals that a bounded operation made no progress within its deadline. */
class DrainTimeoutError extends Error {
  constructor(
    readonly label: string,
    readonly timeoutMs: number,
  ) {
    super(`${label} made no progress for ${timeoutMs}ms`);
    this.name = 'DrainTimeoutError';
  }
}

/**
 * Resolve/reject with `work`, or reject once `timeoutMs` has elapsed without a
 * progress checkpoint.
 *
 * `work` must call the supplied `onProgress` after every awaited step. The
 * watchdog polls that checkpoint instead of racing a one-shot timer against the
 * whole pass, so an event-loop stall cannot make a healthy pass look wedged. It
 * also waits for two consecutive overdue polls before rejecting: if the loop
 * resumes and the pass reports progress, the deadline is extended rather than
 * the pass being abandoned in the same tick.
 *
 * The loser is NOT cancelled - `work` keeps running - so this only bounds how
 * long the caller waits. It does not by itself release a liveness guard: the
 * caller must keep observing the abandoned work (or cancel it) until it really
 * exits, which is what `cancelDrain` and the per-pass guard in `start()` do. Any
 * rejection the abandoned promise produces later is swallowed by the pass's
 * `.catch`, so a timed-out drain can never surface as an unhandled rejection
 * (which would terminate the worker).
 */
export async function withProgressTimeout<T>(
  work: (signal: AbortSignal, onProgress: () => void) => Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  const controller = new AbortController();
  let lastProgressAt = Date.now();
  const onProgress = () => {
    lastProgressAt = Date.now();
  };
  let timer: ReturnType<typeof setInterval> | undefined;
  try {
    return await Promise.race([
      work(controller.signal, onProgress),
      new Promise<never>((_, reject) => {
        // Poll often enough to notice a stall promptly without adding
        // meaningful load; small test budgets get a proportionally small poll.
        const pollMs = Math.max(10, Math.min(DRAIN_WATCHDOG_POLL_MS, Math.floor(timeoutMs / 2)));
        let overduePolls = 0;
        timer = setInterval(() => {
          if (Date.now() - lastProgressAt < timeoutMs) {
            overduePolls = 0;
            return;
          }
          // Give the pass one more poll to report progress. A resumed event loop
          // can run the pending continuation just after the watchdog callback;
          // rejecting on the first late observation would recreate the false
          // positive this watchdog exists to avoid.
          overduePolls++;
          if (overduePolls < 2) return;
          controller.abort();
          reject(new DrainTimeoutError(label, timeoutMs));
        }, pollMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearInterval(timer);
  }
}
import { Heartbeat } from './heartbeat.ts';
export class CorrelationRuntime {
  readonly supervisor: PipelineSupervisor;
  readonly processor: AdvisoryStreamProcessor;
  /** Publishes liveness to an external receiver; disabled when no URL is set. */
  readonly heartbeat: Heartbeat;
  private timer?: ReturnType<typeof setInterval>;
  private schedulerTimer?: ReturnType<typeof setInterval>;
  private draining?: Promise<void>;
  /**
   * Cancels the pass currently holding `draining`.
   *
   * `withHardTimeout` stops awaiting a wedged pass but cannot stop it, so the
   * timeout handler calls this and then keeps the guard set until the pass has
   * genuinely finished. Without that, an abandoned pass and its replacement ran
   * concurrently, each claiming batches and holding a lease heartbeat.
   */
  private cancelDrain?: () => void;
  private stopped = false;
  private lastMaintenance = 0;
  /**
   * Durable queue depth, sampled by the drain loop rather than by /metrics.
   * /metrics must stay database-independent (it is scraped during outages, which
   * is exactly when the database is unavailable), so the sampler lives here and
   * the route just reads the cached number.
   */
  pendingDepth = -1;
  /** When `pendingDepth` was last refreshed; 0 means never. */
  pendingSampledAt = 0;
  /** Set when a stale-match sweep or retention run last succeeded or failed. */
  private lastMaintenanceAttempt = 0;
  /** Set when the consumer is disabled, so readiness does not claim it runs. */
  readonly workerEnabled: boolean;
  /**
   * Epoch ms of the last pipeline scheduled-run, cached from scheduler_state.
   * /metrics is scraped during outages (when the DB may be unreachable), so the
   * value is sampled by a timer and the route reads the cache. 0 means "never
   * ran or not yet sampled"; the consumer recomputes age at scrape time.
   */
  pipelineLastRun = 0;
  /** When `pipelineLastRun` was last sampled; 0 means never. */
  pipelineLastRunSampledAt = 0;
  /** Cached from the settings record — 1 means the in-app scheduler is enabled. */
  pipelineSchedulerEnabled = false;
  /**
   * Refresh interval for scheduler state (seconds); defaults to intervalSeconds.
   * Must be at least 60 seconds to avoid overwhelming the database with refreshes.
   */
  private scheduledStateRefreshIntervalSeconds: number;
  constructor(
    private readonly pool: Pool,
    keys: string[],
    directory: string,
    options: {
      url: string;
      intervalSeconds: number;
      logLevel?: 'standard' | 'verbose';
      scheduledStateRefreshIntervalSeconds?: number;
      deadLetterStorageMode?: 'database' | 'filesystem';
    } = { url: '', intervalSeconds: 60 },
  ) {
    const telemetry = new CorrelationTelemetry();
    telemetry.verbosity = options.logLevel ?? 'standard';
    const queue = new DeadLetterQueue(
      directory,
      keys,
      telemetry,
      options.deadLetterStorageMode === 'database',
    );
    this.supervisor = new PipelineSupervisor(pool, new AdvisoryIngestor(telemetry, queue));
    this.processor = new AdvisoryStreamProcessor(this.supervisor);
    this.heartbeat = new Heartbeat({
      url: options.url,
      intervalMs: options.intervalSeconds * 1000,
      suppressOnUnhealthy: true,
    });
    this.workerEnabled = process.env.WORKER_ENABLED !== 'false';
    // Default to the intervalSeconds, but allow override from callers
    this.scheduledStateRefreshIntervalSeconds =
      options.scheduledStateRefreshIntervalSeconds ?? options.intervalSeconds;
    if (this.scheduledStateRefreshIntervalSeconds < 60) {
      this.scheduledStateRefreshIntervalSeconds = 60;
    }
  }
  start(): void {
    if (this.timer) return;
    this.stopped = false;
    this.supervisor.start();
    // The ping reports on the pipeline, not on the HTTP process: a heartbeat
    // that fires while ingestion is refusing every advisory would tell the
    // external receiver that it is safe to stay silent.
    this.heartbeat.start(() => {
      if (!this.workerEnabled) return { healthy: true, reason: 'WORKER_DISABLED_MONITORING_ONLY' };
      if (this.supervisor.health !== 'HEALTHY') return { healthy: false, reason: this.supervisor.health };
      return { healthy: true, reason: 'HEALTHY' };
    });
    this.timer = setInterval(() => {
      if (this.draining || this.stopped || this.supervisor.health !== 'HEALTHY') return;
      // `withHardTimeout` now aborts the underlying work via AbortSignal when the
      // timeout fires, so an abandoned pass stops taking new work instead of
      // competing with its replacement. The pass's own rejection is always a
      // telemetry event, never a crash.
      const pass = this.drain();
      this.draining = pass;
      void pass
        .catch(() => undefined)
        .finally(() => {
          // Only the pass that owns the guard may clear it. A later pass can only
          // start once this one has exited, so this identity check also protects
          // against a slow `finally` of an earlier pass clearing a newer one.
          if (this.draining === pass) this.draining = undefined;
          // Refresh the queue depth the stuck-ingestion alert depends on. A
          // failure leaves the previous sample rather than reporting zero, which
          // would read as "nothing queued" during a database outage.
          void this.pool
            .query('SELECT count(*)::int AS depth FROM correlation_pending')
            .then((result) => {
              this.pendingDepth = Number(result.rows[0]?.depth ?? 0);
              this.pendingSampledAt = Date.now();
            })
            .catch(() => {});
        });
      void pass.catch((error) => {
        // Telemetry metrics are a fixed, scrubbed vocabulary; the timeout is
        // encoded in the event name (`pending.drain_timeout`) rather than an
        // ad-hoc field so it is queryable like every other correlation event.
        this.supervisor.ingestor.telemetry.log(
          error instanceof DrainTimeoutError ? 'CRITICAL' : 'ERROR',
          error instanceof DrainTimeoutError ? 'pending.drain_timeout' : 'pending.drain_failed',
        );
        // Ask the abandoned pass to stop taking new work at its next boundary.
        this.cancelDrain?.();
      });
    }, 1000);
    this.timer.unref();
    this.schedulerTimer = setInterval(() => {
      void this.refreshSchedulerState();
    }, this.scheduledStateRefreshIntervalSeconds * 1000);
    this.schedulerTimer.unref();
  }
  async flushLegacyDeadLetters(): Promise<void> {
    await this.supervisor.ingestor.flushDeadLetters(this.pool);
  }
  private async refreshSchedulerState(): Promise<void> {
    try {
      const row = (await this.pool.query('SELECT last_run FROM scheduler_state WHERE id=1')).rows[0];
      this.pipelineLastRun = row?.last_run ? Date.parse(row.last_run) : 0;
      this.pipelineLastRunSampledAt = Date.now();
      const settingsRow = (
        await this.pool.query<{ enabled: string }>(
          "SELECT data->>'schedulerEnabled' AS enabled FROM records WHERE kind='settings' AND id='main'",
        )
      ).rows[0];
      this.pipelineSchedulerEnabled = settingsRow?.enabled === 'true';
    } catch {
      // Keep previous values on database errors; the age gauge uses the last
      // successful sample, which is the correct semantics for outage scraping.
    }
  }

  /**
   * One drain pass, exposed for testing. `isCancelled` is polled at every point
   * where the pass could still take work, so an abandoned pass winds down instead
   * of competing. The pass is wrapped in `withProgressTimeout` so an abandoned
   * pass is aborted via AbortSignal rather than left running beside its
   * replacement, and a busy event loop cannot make it look wedged.
   */
  async drain(): Promise<void> {
    let cancelled = false;
    const markCancelled = () => {
      cancelled = true;
    };
    this.cancelDrain = markCancelled;
    try {
      await withProgressTimeout(
        (signal, onProgress) => this.drainPass(() => cancelled || signal.aborted, onProgress),
        DRAIN_TIMEOUT_MS,
        'correlation drain',
      );
    } finally {
      if (this.cancelDrain === markCancelled) this.cancelDrain = undefined;
    }
  }

  /**
   * One drain pass. `isCancelled` is polled at every point where the pass could
   * still take work, so an abandoned pass winds down instead of competing.
   * `onProgress` is reported after every awaited step so the stall watchdog can
   * tell a slow-but-advancing pass from a wedged one.
   */
  private async drainPass(isCancelled: () => boolean, onProgress: () => void = () => {}): Promise<void> {
    // First checkpoint is before any stage, not after the first one: a pass
    // abandoned before it began must not open a transaction at all.
    if (isCancelled()) return;
    onProgress();
    await this.cleanupStaleMatches();
    onProgress();
    if (isCancelled()) return;
    await this.queueNotifications();
    onProgress();
    if (isCancelled()) return;
    // Rows the claim no longer offers have exhausted MAX_PENDING_ATTEMPTS. Log
    // their count once per drain pass: silently leaving them in the table would
    // make a poisoned advisory invisible while `pending` still counts it.
    try {
      const exhausted = await this.pool.query<{ count: number }>(
        'SELECT count(*)::int AS count FROM correlation_pending WHERE attempts >= $1',
        [MAX_PENDING_ATTEMPTS],
      );
      const count = Number(exhausted.rows[0]?.count ?? 0);
      if (count) this.supervisor.ingestor.telemetry.log('CRITICAL', 'pending.attempts_exhausted', { count });
    } catch {
      // Metrics on a missing column (pre-032 database) must not block draining.
    }
    onProgress();
    // Retention is re-checked here rather than once per pass: a pass can keep
    // looping for far longer than a floor (one batch per 100ms), so a single
    // evaluation left a failing sweep retried on every iteration.
    await this.maybeRunRetention();
    onProgress();
    if (isCancelled()) return;
    // Sweep exhausted pending rows to prevent poison advisories from blocking the queue
    const swept = await sweepExhaustedPending(
      this.pool,
      this.supervisor.ingestor.deadLetterQueue,
    ).catch(() => 0);
    onProgress();
    if (swept) {
      this.supervisor.ingestor.telemetry.log('INFO', 'pending.exhausted_swept', { count: swept });
    }
    while (!this.stopped && this.supervisor.health === 'HEALTHY') {
      // Check cancellation BEFORE claiming. Claiming first meant an abandoned
      // pass still took a fresh lease and ingested one more batch after the tick
      // had already started a replacement — the overlap this pass exists to avoid.
      if (isCancelled()) return;
      // Leased SKIP LOCKED claims survive crashes; final ingestion is idempotent.
      // Claim at most concurrency slots, so leases don't expire behind a local queue.
      const batch = await claimPending(this.pool, this.supervisor.concurrencyLimit);
      onProgress();
      if (!batch.jobs.length) return;
      // Re-check after the (awaited) claim. Cancellation can arrive while the
      // claim query is in flight; the pre-claim check above cannot cover that
      // window. Without this, an abandoned pass ingests one last batch after the
      // replacement tick started — the overlap this pass exists to avoid. The
      // claimed rows are left leased: deleting them would discard durable
      // pending work, and the replacement pass re-claims them once the lease
      // expires, exactly as it does after a crash.
      if (isCancelled()) return;
      let renewing: Promise<unknown> | undefined;
      const heartbeat = setInterval(() => {
        if (isCancelled()) {
          clearInterval(heartbeat);
          return;
        }
        if (renewing) return;
        // Add timeout to prevent hung renewals from piling up
        const timeoutMs = 10_000;
        renewing = (async () => {
          try {
            await Promise.race([
              renewPending(this.pool, batch),
              new Promise<never>((_, reject) =>
                setTimeout(() => reject(new Error('LEASE_RENEWAL_TIMEOUT')), timeoutMs),
              ),
            ]);
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg === 'LEASE_RENEWAL_TIMEOUT') {
              this.supervisor.ingestor.telemetry.log('WARN', 'pending.lease_renewal_timeout');
            } else {
              this.supervisor.ingestor.telemetry.log('WARN', 'pending.lease_renewal_failed', { count: 1 });
            }
          } finally {
            renewing = undefined;
          }
        })();
      }, 20_000);
      heartbeat.unref();
      try {
        await this.processor.processAdvisoryStream(
          Readable.from(batch.jobs.map((job) => job.payload)),
          this.supervisor.concurrencyLimit,
          this.pool,
        );
        onProgress();
        await acknowledgePending(this.pool, batch);
        onProgress();
      } catch (error) {
        // At least one record could not be made durable. Its pending row is the
        // last copy, so it is retained — but only it. Acknowledging the whole
        // batch would delete the record; acknowledging none replays the entire
        // batch and re-runs every advisory that already committed. The stream
        // reports which payloads failed, and those are matched back to the jobs
        // by payload identity (pending payloads are JSON-round-tripped, so the
        // comparison is structural and stable).
        const failed = (error as { failedRecords?: unknown[] }).failedRecords ?? [];
        const retainedIds = failed.length
          ? batch.jobs
              .filter((job) => failed.some((record) => samePayload(record, job.payload)))
              .map((job) => job.id)
          : // The stream failed before it could attribute records (e.g. the
            // source itself threw): nothing may be acknowledged.
            batch.jobs.map((job) => job.id);
        if (retainedIds.length < batch.jobs.length) {
          await acknowledgePendingExcept(this.pool, batch, retainedIds).catch(() => 0);
        }
        onProgress();
        this.supervisor.ingestor.telemetry.log('CRITICAL', 'pending.batch_partially_acknowledged', {
          count: batch.jobs.length - retainedIds.length,
        });
        throw error;
      } finally {
        clearInterval(heartbeat);
        await renewing;
        onProgress();
      }
      if (isCancelled()) return;
      await this.queueNotifications();
      onProgress();
      // Retention is time-gated, so calling it each iteration is cheap when the
      // floor has not elapsed. Keeping it inside the loop is what bounds a
      // failing sweep to one attempt per floor even when the pass is long.
      await this.maybeRunRetention();
      onProgress();
      // Yield between batches. `acknowledgePending` deletes rows that are already
      // gone from the claim query, so a busy queue lets this loop re-enter
      // `claimPending` immediately and hold a pool connection (plus a claim and a
      // notification transaction) continuously. A short pause lets the tick timer
      // and other pool users run, and keeps the drain from starving them.
      await delay(DRAIN_INTER_BATCH_MS);
      onProgress();
    }
  }

  /**
   * Run the retention sweep at most once per floor.
   *
   * Floors: 60s after a success, 10s after a failure. `lastMaintenance` only
   * advances on SUCCESS, so the failure floor is derived from
   * `lastMaintenanceAttempt > lastMaintenance` and re-evaluated at every call —
   * evaluating it once per pass meant a long pass retried a failing sweep on
   * every 100ms iteration.
   */
  private async maybeRunRetention(): Promise<void> {
    const failingSweep = this.lastMaintenanceAttempt > this.lastMaintenance;
    const floorMs = failingSweep ? 10_000 : 60_000;
    if (Date.now() - this.lastMaintenanceAttempt < floorMs) return;
    this.lastMaintenanceAttempt = Date.now();
    const retained = await transaction(this.pool, (db) => retainCorrelationData(db)).then(
      () => true,
      () => {
        this.supervisor.ingestor.telemetry.log('ERROR', 'retention.failed');
        return false;
      },
    );
    if (retained) this.lastMaintenance = Date.now();
  }
  private async cleanupStaleMatches(): Promise<void> {
    await transaction(this.pool, (db) => cleanupStaleMatches(db)).catch(() => {
      this.supervisor.ingestor.telemetry.log('ERROR', 'stale_matches.cleanup_failed');
    });
  }
  private async queueNotifications(): Promise<void> {
    await transaction(this.pool, (db) => queueNativeNotifications(db)).catch(() => {
      this.supervisor.ingestor.telemetry.log('ERROR', 'notifications.queue_failed');
    });
  }
  async stop(): Promise<void> {
    this.stopped = true;
    clearInterval(this.timer);
    this.timer = undefined;
    clearInterval(this.schedulerTimer);
    this.schedulerTimer = undefined;
    this.heartbeat.stop();
    await this.supervisor.stop();
    await this.draining;
  }
}
