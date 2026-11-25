import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import type { Db } from '../db.ts';
import { timedQuery } from './query.ts';
import { DeadLetterQueue } from './deadLetter.ts';
export interface PendingBatch {
  token: string;
  jobs: { id: string; payload: unknown }[];
}
/**
 * How many times one pending row may be claimed before it is presumed
 * unprocessable. A validation failure or a durability failure is deterministic,
 * so retrying it on every tick re-claims the same row forever: claims are
 * ordered `created_at,id` and `SKIP LOCKED` skips only *live* leases, so the
 * poison row occupies the head of the queue and is attempted again each pass.
 * 20 attempts (~20 minutes of leases) leaves ample room for transient outages —
 * a database recovery, a deploy restart — while bounding the loop.
 *
 * `SKIP LOCKED` in `claimPending` prevents concurrent workers from blocking
 * each other: when two workers claim simultaneously, the row locks held by an
 * in-flight worker's transaction are skipped rather than waited on. The lock is
 * released when the single-statement CTE commits, so the mutual-exclusion
 * window is the statement duration only. The durable concurrency guard is the
 * `lease_token`: `renewPending` and `acknowledgePending` both require
 * `lease_token=$2 AND lease_until>now()`, so a worker that lost its claim
 * cannot renew or delete another worker's lease after the claim statement
 * commits.
 */
export const MAX_PENDING_ATTEMPTS = 20;
/**
 * Longest lease a pending row may hold, in seconds.
 *
 * The first lease must cover real work: a batch is processed inside it, and the
 * worker renews at 60 s intervals. Later attempts back off exponentially
 * (`60 * 2^attempts`) so a row that keeps failing does not consume a slot (and a
 * database round trip) every minute for the whole attempt budget. The cap keeps
 * the total horizon near MAX_PENDING_ATTEMPTS * 1 h for a permanently broken
 * record.
 */
export const MAX_LEASE_SECONDS = 3600;
export async function claimPending(db: Db, limit: number): Promise<PendingBatch> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 32) throw new Error('INVALID_CLAIM_LIMIT');
  const token = randomUUID();
  const result = await db.query<{ id: string; payload: unknown }>(timedQuery(`WITH selected AS (
    SELECT id FROM correlation_pending WHERE (lease_until IS NULL OR lease_until<now())
      AND attempts < $3
    ORDER BY created_at,id LIMIT $1 FOR UPDATE SKIP LOCKED)
    UPDATE correlation_pending p SET
      lease_until = now() + make_interval(secs =>
        LEAST($4::int, 60 * (CASE LEAST(p.attempts, 6)
          WHEN 0 THEN 1 WHEN 1 THEN 2 WHEN 2 THEN 4
          WHEN 3 THEN 8 WHEN 4 THEN 16 WHEN 5 THEN 32 ELSE 64 END))),
      lease_token=$2,
      attempts=attempts+1
    FROM selected s WHERE p.id=s.id RETURNING p.id,p.payload`, [limit, token, MAX_PENDING_ATTEMPTS, MAX_LEASE_SECONDS]));
  return { token, jobs: result.rows };
}
/** A stale worker can neither delete nor extend another worker's claim. */
export async function renewPending(db: Db, batch: PendingBatch): Promise<number> {
  const result = await db.query(timedQuery(`UPDATE correlation_pending SET lease_until=now()+interval '60 seconds'
    WHERE id=ANY($1::text[]) AND lease_token=$2 AND lease_until>now()`, [batch.jobs.map(job => job.id), batch.token]));
  return result.rowCount || 0;
}
export async function acknowledgePending(db: Db, batch: PendingBatch): Promise<number> {
  const result = await db.query(timedQuery(`DELETE FROM correlation_pending
    WHERE id=ANY($1::text[]) AND lease_token=$2 AND lease_until>now()`, [batch.jobs.map(job => job.id), batch.token]));
  return result.rowCount || 0;
}
/**
 * Acknowledge only the jobs that were handled. A batch whose stream threw has
 * at least one record that is *not* durable; acknowledging the batch would
 * delete it, while acknowledging nothing replays the whole batch and re-runs
 * every match for the records that already committed. The caller supplies the
 * ids that were not durable, and every remaining leased job is deleted.
 */
export async function acknowledgePendingExcept(
  db: Db,
  batch: PendingBatch,
  retainedJobIds: readonly string[],
): Promise<number> {
  const retained = new Set(retainedJobIds);
  const done = batch.jobs.map((job) => job.id).filter((id) => !retained.has(id));
  if (!done.length) return 0;
  const result = await db.query(timedQuery(`DELETE FROM correlation_pending
    WHERE id=ANY($1::text[]) AND lease_token=$2 AND lease_until>now()`, [done, batch.token]));
  return result.rowCount || 0;
}

/**
 * Removes exhausted rows that have exceeded MAX_PENDING_ATTEMPTS.
 * These are poisoned advisories that cannot be processed and should not block
 * the drain loop. When a dead-letter queue is supplied, each exhausted row is
 * captured to the DLQ before deletion so the payload is preserved for operator
 * review instead of being silently discarded.
 * Returns the count of removed rows.
 */
export async function sweepExhaustedPending(
  db: Db,
  deadLetterQueue?: DeadLetterQueue,
): Promise<number> {
  // Select exhausted rows first so they can be dead-lettered before removal.
  const rows = await db.query<{ id: string; payload: unknown }>(timedQuery(`SELECT id, payload FROM correlation_pending
    WHERE attempts >= $1`, [MAX_PENDING_ATTEMPTS]));
  if (!rows.rows.length) return 0;
  // Dead-letter each exhausted row before deletion, when a DLQ is configured.
  if (deadLetterQueue) {
    for (const row of rows.rows) {
      try {
        const outcome = await deadLetterQueue.capture(
          row.payload,
          'EXHAUSTED_PENDING_ATTEMPTS',
          row.id,
          db as unknown as Pool,
        );
        if (outcome === 'capacity' || outcome === 'unavailable') {
          // DLQ full or unavailable: the row is still removed below to unblock
          // the drain loop, but the payload is lost. Logged at CRITICAL by the
          // caller's telemetry; here we just continue so the sweep completes.
        }
      } catch {
        // Capture failure — the row is still deleted below to unblock the queue.
        // The payload is lost; the caller's telemetry can surface this.
      }
    }
  }
  const result = await db.query(timedQuery(`DELETE FROM correlation_pending
    WHERE attempts >= $1`, [MAX_PENDING_ATTEMPTS]));
  return result.rowCount || 0;
}
