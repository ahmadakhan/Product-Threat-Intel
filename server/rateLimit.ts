import type pg from 'pg';

/**
 * Continuous-refill token bucket used by the API mutation limiter.
 *
 * A window-based counter that resets its timestamp on every request can never
 * refill under sustained traffic: each call sees less than one full window of
 * elapsed time and discards the fraction. This implementation preserves the
 * fractional refill so a throttled client recovers deterministically.
 */
export interface TokenBucket {
  tokens: number;
  updatedAt: number;
}

export interface TokenBucketResult {
  allowed: boolean;
  bucket: TokenBucket;
  /** Milliseconds until one token is available; zero when allowed. */
  retryAfterMs: number;
}

export function consumeToken(
  bucket: TokenBucket | undefined,
  now: number,
  capacity: number,
  refillPerMs: number,
): TokenBucketResult {
  const current = bucket ?? { tokens: capacity, updatedAt: now };
  const elapsed = Math.max(0, now - current.updatedAt);
  const tokens = Math.min(capacity, current.tokens + elapsed * refillPerMs);
  if (tokens < 1)
    return {
      allowed: false,
      bucket: { tokens, updatedAt: now },
      retryAfterMs: Math.ceil((1 - tokens) / refillPerMs),
    };
  return {
    allowed: true,
    bucket: { tokens: tokens - 1, updatedAt: now },
    retryAfterMs: 0,
  };
}

/** Default mutation quota: a 100-request burst, refilling two tokens/minute. */
export const MUTATION_LIMIT_CAPACITY = 100;
export const MUTATION_LIMIT_REFILL_PER_MINUTE = 2;
export const MUTATION_LIMIT_REFILL_PER_MS = MUTATION_LIMIT_REFILL_PER_MINUTE / 60_000;

/** Per-operator ingest quota: tight burst (20), refilling 10 tokens/minute.
 * Prevents a single operator from saturating the correlation pipeline while
 * keeping the endpoint usable for interactive batch submissions. */
export const INGEST_LIMIT_CAPACITY = 20;
export const INGEST_LIMIT_REFILL_PER_MINUTE = 10;
export const INGEST_LIMIT_REFILL_PER_MS = INGEST_LIMIT_REFILL_PER_MINUTE / 60_000;

export interface RateLimitDecision {
  allowed: boolean;
  retryAfterMs: number;
}

export type MutationLimiter = (key: string) => Promise<RateLimitDecision>;

/**
 * What the limiter does when the database-backed decision cannot be made.
 *
 * There is no free choice here, only a trade-off, so it is made explicit and
 * configurable instead of being settled silently in the code:
 *
 *  - `'memory'` (default): fall back to a per-process token bucket with the same
 *    capacity and refill rate. Mutations keep working through a database blip,
 *    but the quota is per replica, not installation-wide, so a client spreading
 *    load across N replicas gets up to N times the quota for the duration. The
 *    database is also usually down for the reason a mutation would fail anyway,
 *    which bounds the exposure in practice.
 *  - `'closed'`: deny with a retry hint. The quota is never exceeded, at the
 *    cost of refusing every mutation for the length of the outage - including
 *    the operator actions that might dial the system back or inspect it.
 *
 * Hard-fail-open (permit with no accounting at all) is deliberately not an
 * option: it is the same as running without a limiter.
 */
export type RateLimitDegradedMode = 'memory' | 'closed';

/** Retry hint returned in `'closed'` mode, matching the limiter's refill rate. */
const DEGRADED_RETRY_HINT_MS = 1_000;
/**
 * Upper bound on remembered fallback buckets, so an outage cannot turn the
 * limiter itself into an unbounded allocation. Keys are operator ids, so this is
 * only reached by a very large account set; past it the oldest key is evicted,
 * which can grant one extra burst and never denies a legitimate caller.
 */
export const MAX_FALLBACK_BUCKETS = 10_000;

/**
 * Database-backed limiter shared by every application replica.
 *
 * The decision and the bucket update happen in one PostgreSQL function call, so
 * two replicas cannot both observe the last token. Keys are operator IDs, which
 * bounds the table to the number of accounts rather than the number of clients.
 *
 * `degradedMode` decides what happens when that call fails; see
 * {@link RateLimitDegradedMode}. Whichever mode is chosen, the failure is logged
 * so a degraded limiter is observable rather than assumed.
 */
export function createDatabaseRateLimiter(
  pool: pg.Pool,
  capacity = MUTATION_LIMIT_CAPACITY,
  refillPerMs = MUTATION_LIMIT_REFILL_PER_MS,
  degradedMode: RateLimitDegradedMode = 'memory',
): MutationLimiter {
  if (!(capacity > 0) || !(refillPerMs > 0))
    throw new Error('Rate limiter capacity and refill rate must be positive');
  // In-memory fallback used when the database-backed limiter is unreachable. In
  // `'memory'` mode it applies the same per-key token bucket so a database blip
  // does not lift the quota entirely; the limits are per replica until the
  // database recovers (see RateLimitDegradedMode).
  const fallbackBuckets = new Map<string, TokenBucket>();
  return async (key) => {
    try {
      const result = await pool.query<{ allowed: boolean; retry_after_ms: number }>(
        'SELECT allowed, retry_after_ms FROM consume_rate_limit_token($1, $2, $3)',
        [key, capacity, refillPerMs],
      );
      const row = result.rows[0];
      if (!row) throw new Error('Rate limiter returned no decision');
      return { allowed: row.allowed, retryAfterMs: Number(row.retry_after_ms) };
    } catch (error) {
      // Database unreachable: the installation-wide quota cannot be enforced. The
      // chosen posture decides what replaces it, and either way the change is
      // logged so a degraded limiter is visible to operators instead of assumed.
      console.error(
        JSON.stringify({
          level: 'error',
          event: degradedMode === 'closed' ? 'rate_limiter_db_denied' : 'rate_limiter_db_fallback',
          mode: degradedMode,
          key,
          error: (error as Error).message,
          timestamp: new Date().toISOString(),
        }),
      );
      if (degradedMode === 'closed') return { allowed: false, retryAfterMs: DEGRADED_RETRY_HINT_MS };
      const now = Date.now();
      const bucket = fallbackBuckets.get(key) ?? { tokens: capacity, updatedAt: now };
      const elapsed = Math.max(0, now - bucket.updatedAt);
      const tokens = Math.min(capacity, bucket.tokens + elapsed * refillPerMs);
      if (tokens < 1) {
        return {
          allowed: false,
          retryAfterMs: Math.ceil((1 - tokens) / refillPerMs),
        };
      }
      // Re-insert so Map iteration order stays least-recently-used-first for the
      // eviction below.
      fallbackBuckets.delete(key);
      fallbackBuckets.set(key, { tokens: tokens - 1, updatedAt: now });
      if (fallbackBuckets.size > MAX_FALLBACK_BUCKETS) {
        const oldest = fallbackBuckets.keys().next().value;
        if (oldest !== undefined) fallbackBuckets.delete(oldest);
      }
      return { allowed: true, retryAfterMs: 0 };
    }
  };
}
