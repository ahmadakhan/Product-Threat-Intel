/** Internal state, committed in the same transaction as the imported records. */
import type { NormalizedCVE } from '../src/types/index.ts';
export interface IngestionState {
  cursor?: string;
  hasMore?: boolean;
  revisions?: Record<string, string>;
  indexEtag?: string;
  epssScope?: string[];
  epssExpiresAt?: string;
  /** True when a multi-run catch-up is in progress after extended downtime. */
  catch_up?: boolean;
  /** Next time to start a catch-up run, used by the scheduler to prioritize catch-up. */
  next_catchup_at?: string;
  /**
   * Provider pagination cursor to resume a window that outgrew the per-run page
   * budget.
   *
   * The NVD++ adapter pages a whole window before returning, and its page cap
   * exists to bound one run's memory and duration. Reaching it used to throw,
   * discarding every page already fetched: a busy day could never be ingested at
   * all. The adapter now commits what it has and stores the next provider cursor
   * here so the following run continues the same window instead of starting over.
   */
  pageCursor?: string;
}
export interface FeedCursor extends IngestionState { fingerprint: string }
const HOUR = 3600000;
export const SYNC_OVERLAP_MS = 10 * 60000;
/** Bootstrap at most one day; resume older checkpoints in bounded daily slices. */
export function ingestionWindow(
  scopeHours: number,
  state: IngestionState = {},
  now = Date.now(),
  maxWindowHours = Number.POSITIVE_INFINITY,
) {
  const cursor = state.cursor ? Date.parse(state.cursor) : NaN;
  const valid = Number.isFinite(cursor) && cursor <= now;
  // The slice size is the operator's scope window, NOT a hard 24h.
  //
  // This used to default to 24, which silently overrode `scopeHours` for every
  // INCREMENTAL run: with a 168h scope the first run fetched 7 days and every
  // subsequent run fetched 24h, so a long window could never be honoured and a
  // catch-up after downtime was truncated to a day per run. The slice still
  // exists (a very wide window is read as consecutive resumable slices via
  // `hasMore`), but its size now comes from the configured scope.
  //
  // The first run is also bounded by the same slice, so a huge scope bootstraps
  // progressively instead of issuing one unbounded request.
  const sliceHours = Number.isFinite(maxWindowHours)
    ? Math.min(maxWindowHours, Math.max(1, Math.floor(scopeHours)))
    : Math.max(1, Math.floor(scopeHours));
  const start = valid ? cursor - SYNC_OVERLAP_MS : now - sliceHours * HOUR;
  const end = valid ? Math.min(now, cursor + sliceHours * HOUR - SYNC_OVERLAP_MS) : now;
  // `end` is clamped to `now` and otherwise stops one overlap short of the next
  // slice, so a catch-up window is incomplete exactly when `end` is before
  // `now`. The old `now - 60000` margin reported a checkpoint sitting exactly one
  // window behind as complete: the slice computed end === now, hasMore stayed
  // false, the catch-up loop stopped, and the remaining backlog was never read.
  return { start: new Date(start), end: new Date(end), incremental: valid, hasMore: end < now };
}
export function recentRevisions(revisions: Record<string, string>, since: Date) {
  const cutoff = since.getTime() - 24 * HOUR;
  return Object.fromEntries(Object.entries(revisions).filter(([, value]) => {
    const parsed = Date.parse(value);
    // An unparseable timestamp is kept, not dropped: the revision cache is
    // consulted to decide "have we already seen this revision?", so dropping a
    // garbage entry would silently re-ingest the record (and, worse, let a
    // corrupt cache entry be pruned as "old" when its true age is unknown).
    // Keeping it is the conservative direction — at worst we keep one extra
    // cache row until the next successful ingest overwrites it.
    return Number.isNaN(parsed) || parsed >= cutoff;
  }));
}
