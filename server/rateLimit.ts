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
 * Database-backed limiter shared by every application replica.
 *
 * The decision and the bucket update happen in one PostgreSQL function call, so
 * two replicas cannot both observe the last token. Keys are operator IDs, which
 * bounds the table to the number of accounts rather than the number of clients.
 */
export function createDatabaseRateLimiter(
  pool: pg.Pool,
  capacity = MUTATION_LIMIT_CAPACITY,
  refillPerMs = MUTATION_LIMIT_REFILL_PER_MS,
): MutationLimiter {
  if (!(capacity > 0) || !(refillPerMs > 0))
    throw new Error('Rate limiter capacity and refill rate must be positive');
  // In-memory fallback used when the database-backed limiter is unreachable.
  // Fail-open: allow the request through rather than blocking all mutations
  // during a temporary DB outage. The fallback is a simple per-key token bucket
  // that is eventually consistent with the database once it recovers.
  const fallbackBuckets = new Map<string, { tokens: number; updatedAt: number }>();
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
      // Database unreachable: fail-open using an in-memory bucket so mutations
      // are not all blocked by a non-critical safety feature. Log the fallback
      // so operators are aware the database-backed limiter is degraded.
      console.error(
        JSON.stringify({
          level: 'error',
          event: 'rate_limiter_db_fallback',
          key,
          error: (error as Error).message,
          timestamp: new Date().toISOString(),
        }),
      );
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
      bucket.tokens = tokens - 1;
      bucket.updatedAt = now;
      fallbackBuckets.set(key, bucket);
      return { allowed: true, retryAfterMs: 0 };
    }
  };
}
