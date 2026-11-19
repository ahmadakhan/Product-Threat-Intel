import { appendAudit, putMany, type Db } from './db';
import { writeEvent } from './events';
import { z } from 'zod';
import type { CVERejection } from './ingestion';

/**
 * Durable ingestion rejection accounting.
 *
 * A record a feed delivered but that failed normalization is a lost finding.
 * Before this module every adapter collected `rejections` into an array that the
 * pipeline then discarded, so a schema change upstream, a poisoned record, or a
 * pagination bug silently removed vulnerabilities from the corpus with no
 * operational trace.
 *
 * The contract now is:
 *
 *  - every rejection the adapters report is persisted, once per source record;
 *  - the record key is stable across runs (`feed:<feedId>:<hash>`), so the same
 *    unparseable record next run updates its `lastSeenAt` instead of creating a
 *    new row and the table stays bounded by the number of distinct bad records;
 *  - a nonzero count raises an ERROR event and an audit entry so the operator
 *    sees it in the same place pipeline failures appear;
 *  - a record that begins to parse is marked `resolvedAt` so the backlog
 *    reflects current breakage rather than history.
 *
 * Retention owns the table lifecycle (`kind='cveRejections'`), so this module
 * never deletes.
 */

/** Record kind holding one row per distinct rejected source record. */
export const REJECTION_KIND = 'cveRejections';

export interface RejectionRecord extends CVERejection {
  id: string;
  feedId: string;
  /** Number of runs that have reported this exact record. */
  occurrences: number;
  firstSeenAt: string;
  lastSeenAt: string;
  /** Run that last observed it, for correlation with the execution log. */
  lastRunId: string;
  /** Set when a later run ingests the same identity successfully. */
  resolvedAt?: string;
}

/**
 * Stable identity of a rejected record.
 *
 * The record hash is preferred because it identifies the exact payload: the same
 * CVE that later fails for a different reason is a different defect. The CVE id
 * is the fallback for adapters that cannot hash the record (for example a page
 * whose item could not be serialized), and a constant fallback keeps the write
 * total even for those.
 */
export function rejectionId(rejection: CVERejection): string {
  const subject = rejection.recordHash || rejection.cveId || 'unidentified';
  return `feed:${rejection.feedId}:${subject}`;
}

export interface PersistRejectionsResult {
  /** Distinct records reported by this run. */
  total: number;
  /** Records that already existed (previously reported by an earlier run). */
  recurring: number;
}

/**
 * Persists this run's rejections and raises the operational signal.
 *
 * `ingestedIds` is the set of CVE ids this run ingested successfully. A prior
 * rejection for one of those ids is closed, because the record is now readable
 * and keeping it open would report a fault that no longer exists.
 */
export async function persistIngestionRejections(
  db: Db,
  rejections: readonly CVERejection[],
  context: { runId: string; ingestedIds: ReadonlySet<string> },
): Promise<PersistRejectionsResult> {
  const now = new Date().toISOString();
  // Only rejections belonging to the feeds this run actually read may be closed
  // as "now parses". A CVE id is not globally unique evidence: NVD could reject
  // it while VulnCheck ingests it fine, and closing the NVD row would hide a
  // genuine upstream schema defect.
  const runFeeds = new Set(rejections.map((rejection) => rejection.feedId));
  const closeResolved = async (feedIds: ReadonlySet<string>) => {
    if (!context.ingestedIds.size || !feedIds.size) return;
    await resolveNowIngested(db, [...context.ingestedIds], [...feedIds], now);
  };
  if (!rejections.length) {
    // Even with nothing new to report, a record that now parses must be closed:
    // the run that fixes ingestion is usually the run that rejects nothing, so
    // this branch is the common recovery path, not an edge case. No rejection
    // list means no feed list, so close across every source this corpus came
    // from (the caller cannot name them here) — a resolved record that is still
    // open is re-reopened the next time it is actually rejected.
    await closeResolved(await allOpenFeedsFor(db, context.ingestedIds));
    return { total: 0, recurring: 0 };
  }
  const grouped = new Map<string, CVERejection & { occurrences: number }>();
  for (const rejection of rejections) {
    const id = rejectionId(rejection);
    const existing = grouped.get(id);
    grouped.set(id, { ...rejection, occurrences: (existing?.occurrences ?? 0) + 1 });
  }

  const ids = [...grouped.keys()];
  const prior = await getManyRecords(db, ids);
  let recurring = 0;
  const rows: { id: string; data: RejectionRecord }[] = [];
  for (const [id, rejection] of grouped) {
    const previous = prior.get(id);
    if (previous) recurring++;
    rows.push({
      id,
      data: {
        ...rejection,
        id,
        occurrences: (previous?.occurrences ?? 0) + rejection.occurrences,
        firstSeenAt: previous?.firstSeenAt ?? rejection.rejectedAt ?? now,
        lastSeenAt: now,
        lastRunId: context.runId,
        // A record reported again is still broken: reopen it if it had been closed.
        resolvedAt: undefined,
        rejectedAt: rejection.rejectedAt ?? now,
      },
    });
  }
  await putMany(db, REJECTION_KIND, rows);

  // Close earlier rejections whose identity is now ingested: the feed record was
  // fixed (or the parser was), so the backlog must not keep reporting it.
  await closeResolved(runFeeds);

  const byFeed = new Map<string, number>();
  for (const rejection of rejections) byFeed.set(rejection.feedId, (byFeed.get(rejection.feedId) ?? 0) + 1);
  const categories = [...new Set(rejections.map((rejection) => rejection.category))].sort();

  // Persistence is the durability guarantee; the event and audit are visibility.
  // A failure to *report* must never undo the record of the loss or abort the
  // pipeline commit, so both are best-effort while the row write above is not.
  const eventRunId = z.uuid().safeParse(context.runId).success ? context.runId : undefined;
  await writeEvent(db, {
    category: 'FEED',
    // A rejected record never reaches correlation, so this is an error, not a
    // warning: it is undispatched exposure, not degraded quality.
    level: 'ERROR',
    code: 'feed.records_rejected',
    message: `${rejections.length} feed record(s) failed normalization and were not correlated`,
    ...(eventRunId ? { runId: eventRunId } : {}),
    context: {
      runId: context.runId,
      total: rejections.length,
      distinct: rows.length,
      recurring,
      categories,
      byFeed: Object.fromEntries(byFeed),
      // Bounded sample so the event stays readable; the full set is in the table.
      sample: rows.slice(0, 10).map((row) => ({
        id: row.id,
        feedId: row.data.feedId,
        cveId: row.data.cveId,
        category: row.data.category,
        summary: row.data.summary,
      })),
    },
  }).catch(() => undefined);
  await appendAudit(
    db,
    'Feed records rejected',
    `${rejections.length} record(s) failed normalization in run ${context.runId} (${categories.join(', ')})`,
    'worker',
    'FEED',
    'ERROR',
  ).catch(() => undefined);

  return { total: rejections.length, recurring };
}

/** Closes open rejections for identities a run has now ingested successfully. */
async function resolveNowIngested(
  db: Db,
  ingestedIds: readonly string[],
  feedIds: readonly string[],
  now: string,
): Promise<void> {
  if (!ingestedIds.length || !feedIds.length) return;
  const open = await db.query<{ id: string; data: RejectionRecord }>(
    `SELECT id, data FROM records
      WHERE kind=$1 AND COALESCE(data->>'resolvedAt','')='' AND data->>'cveId' = ANY($2::text[])
        AND data->>'feedId' = ANY($3::text[])`,
    [REJECTION_KIND, ingestedIds, feedIds],
  );
  const updates: { id: string; data: RejectionRecord }[] = [];
  for (const row of open.rows) updates.push({ id: row.id, data: { ...row.data, resolvedAt: now } });
  if (updates.length) await putMany(db, REJECTION_KIND, updates);
}

/**
 * Feeds that currently hold an open rejection for any of these CVE ids.
 *
 * Used when a run reports no new rejections but still ingested records: the
 * resolution must be scoped to feeds that actually had a defect, and without a
 * rejection list the caller cannot name them.
 */
async function allOpenFeedsFor(db: Db, ingestedIds: ReadonlySet<string>): Promise<Set<string>> {
  if (!ingestedIds.size) return new Set();
  const result = await db.query<{ feedId: string }>(
    `SELECT DISTINCT data->>'feedId' AS "feedId" FROM records
      WHERE kind=$1 AND COALESCE(data->>'resolvedAt','')='' AND data->>'cveId' = ANY($2::text[])`,
    [REJECTION_KIND, [...ingestedIds]],
  );
  return new Set(result.rows.map((row) => row.feedId).filter(Boolean));
}

async function getManyRecords(db: Db, ids: readonly string[]): Promise<Map<string, RejectionRecord>> {
  if (!ids.length) return new Map();
  const result = await db.query<{ id: string; data: RejectionRecord }>(
    'SELECT id, data FROM records WHERE kind=$1 AND id = ANY($2::text[])',
    [REJECTION_KIND, ids],
  );
  return new Map(result.rows.map((row) => [row.id, row.data]));
}

/** Open (unresolved) rejection count, for /healthz and operator surfaces. */
export async function openRejectionCount(db: Db): Promise<number> {
  const result = await db.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM records
      WHERE kind=$1 AND COALESCE(data->>'resolvedAt','')=''`,
    [REJECTION_KIND],
  );
  return Number(result.rows[0]?.count ?? 0);
}

/**
 * Prior rejection counts for one feed, keyed by the same stable id the adapter
 * uses (`rejectionKey`). Feeds into the quarantine decision so a record the
 * source keeps returning unparseable is retried a bounded number of times rather
 * than blocking the window forever.
 */
export async function rejectionOccurrences(db: Db, feedId: string): Promise<Map<string, number>> {
  const result = await db.query<{ id: string; occurrences: string }>(
    `SELECT id, COALESCE((data->>'occurrences')::int, 1)::text AS occurrences
       FROM records
      WHERE kind=$1 AND data->>'feedId'=$2 AND COALESCE(data->>'resolvedAt','')=''`,
    [REJECTION_KIND, feedId],
  );
  return new Map(result.rows.map((row) => [row.id, Number(row.occurrences)]));
}
