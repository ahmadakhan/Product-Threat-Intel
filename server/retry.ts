/**
 * Configurable retry mechanism for handling transient failures.
 * Provides exponential backoff with jitter, configurable retry conditions,
 * and circuit breaker integration.
 */

import type { Db } from './db.ts';

export interface RetryOptions<T> {
  /** Maximum number of retry attempts (default: 3) */
  maxAttempts?: number;
  /** Base delay in milliseconds (default: 1000) */
  baseDelayMs?: number;
  /** Maximum delay in milliseconds (default: 30000) */
  maxDelayMs?: number;
  /** Jitter factor (0-1) to add randomness to delays (default: 0.2) */
  jitterFactor?: number;
  /** Function to determine if an error is retryable (default: network/timeout errors) */
  isRetryable?: (error: unknown) => boolean;
  /** Callback on each retry attempt */
  onRetry?: (attempt: number, error: unknown, delayMs: number) => void;
  /** Abort signal for cancellation */
  signal?: AbortSignal;
  /** Timeout for each attempt in milliseconds */
  attemptTimeoutMs?: number;
}

interface RetryOptionsInternal<T> extends RetryOptions<T> {
  signal: AbortSignal | undefined;
  attemptTimeoutMs: number | undefined;
}

const DEFAULT_OPTIONS: RetryOptionsInternal<unknown> = {
  maxAttempts: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  jitterFactor: 0.2,
  isRetryable: (error: unknown): boolean => {
    if (!error) return false;
    const code = (error as { code?: string }).code;
    // PostgreSQL transient error codes
    if (code === '57014' || // statement_timeout
        code === '55P03' || // lock_not_available
        code === '40P01' || // deadlock_detected
        code === '08006' || // connection_failure
        code === '08001' || // sqlclient_unable_to_establish_sqlconnection
        code === '08004' || // sqlserver_rejected_establishment_of_sqlconnection
        code === '40001' || // serialization_failure
        code === '40003' || // statement_completion_unknown
        code === '53000' || // insufficient_resources
        code === '57P01' || // admin_shutdown
        code === '57P02' || // crash_shutdown
        code === '57P03' || // cannot_connect_now
        code === 'XX000'   // internal_error
    ) return true;
    // Network errors
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      if (message.includes('timeout') ||
          message.includes('econnreset') ||
          message.includes('econnrefused') ||
          message.includes('enotfound') ||
          message.includes('socket') ||
          message.includes('network') ||
          message.includes('eof') ||
          error.name === 'TimeoutError' ||
          error.name === 'AbortError') {
        return true;
      }
    }
    return false;
  },
  onRetry: () => {},
  signal: undefined,
  attemptTimeoutMs: undefined,
};

/**
 * Calculates delay with exponential backoff and jitter.
 *
 * `attempt` is 0-based: the first retry waits ~baseDelayMs, not 2x it. The
 * jitter is uniform in [0, jitterFactor*delay] and is ADDED to the capped
 * delay, so it can never exceed `maxDelayMs` by more than the jitter fraction.
 */
function calculateDelay(attempt: number, options: Required<RetryOptions<unknown>>): number {
  const exponentialDelay = options.baseDelayMs * Math.pow(2, attempt);
  const cappedDelay = Math.min(exponentialDelay, options.maxDelayMs);
  const jitter = cappedDelay * options.jitterFactor * Math.random();
  return Math.floor(cappedDelay + jitter);
}

/** Rethrows the caller's own abort reason instead of inventing a new Error. */
function throwIfAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  const reason = signal.reason;
  throw reason instanceof Error ? reason : new Error('Operation aborted');
}

/**
 * Resolves/rejects with `work`, or rejects with the abort reason as soon as
 * `signal` aborts. The listener is removed on every path so repeated attempts do
 * not accumulate handlers on a long-lived signal.
 */
function raceAbort<T>(work: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return work;
  if (signal.aborted) return Promise.reject(signal.reason ?? new Error('Operation aborted'));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      cleanup();
      reject(signal.reason ?? new Error('Operation aborted'));
    };
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    signal.addEventListener('abort', onAbort, { once: true });
    work.then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error) => {
        cleanup();
        reject(error);
      },
    );
  });
}

/**
 * Executes a function with retry logic.
 */
export async function withRetry<T>(
  fn: (signal?: AbortSignal) => Promise<T>,
  options: RetryOptions<T> = {}
): Promise<T> {
  const opts = { ...DEFAULT_OPTIONS, ...options } as Required<RetryOptions<T>>;
  let lastError: unknown;

  for (let attempt = 0; attempt < opts.maxAttempts; attempt++) {
    // Check for cancellation
    throwIfAborted(opts.signal);

    // Per-attempt cancellation.
    //
    // A bare Promise.race left the losing promise running: after a timeout the
    // work continued in the background, and if it later rejected that rejection
    // was unhandled - which now terminates the worker. A child controller is
    // aborted on timeout, on the caller's signal, and again when the attempt
    // settles, so the work is actually asked to stop and no promise is orphaned.
    const attemptController = new AbortController();
    const onCallerAbort = () => attemptController.abort(opts.signal?.reason);
    opts.signal?.addEventListener('abort', onCallerAbort, { once: true });
    let attemptTimeoutId: ReturnType<typeof setTimeout> | undefined;
    if (opts.attemptTimeoutMs) {
      attemptTimeoutId = setTimeout(
        () => attemptController.abort(new Error(`Attempt timeout after ${opts.attemptTimeoutMs}ms`)),
        opts.attemptTimeoutMs,
      );
      attemptTimeoutId.unref?.();
    }

    try {
      // Race the work against the caller's abort so a cancellation that arrives
      // while `fn` is in flight ends the retry immediately. Without this the
      // abort only took effect at the next attempt boundary, so a call that read
      // `signal` only between retries could hang forever after a shutdown - a
      // real risk now that the worker exits on unhandled rejections.
      const result = await raceAbort(fn(attemptController.signal), attemptController.signal);
      return result;
    } catch (error) {
      lastError = error;

      // Don't retry on last attempt
      if (attempt === opts.maxAttempts - 1) break;

      // Check if error is retryable
      if (!opts.isRetryable(error)) {
        throw error;
      }

      // Check for cancellation before retrying
      throwIfAborted(opts.signal);

      const delayMs = calculateDelay(attempt, opts);
      opts.onRetry(attempt + 1, error, delayMs);

      await new Promise((resolve) => setTimeout(resolve, delayMs));
    } finally {
      // Always release this attempt's timer and listener. Without the cleanup a
      // long-lived retry (many attempts) accumulates one listener per attempt on
      // the caller's signal until Node warns and leaks.
      if (attemptTimeoutId) clearTimeout(attemptTimeoutId);
      opts.signal?.removeEventListener('abort', onCallerAbort);
    }
  }

  throw lastError;
}

/**
 * Retries a single database statement.
 *
 * IMPORTANT: only safe on an autocommit connection (a pool). A statement
 * timeout aborts the enclosing transaction, so retrying on a checked-out client
 * that is mid-transaction returns `25P02` ("current transaction is aborted") on
 * every subsequent attempt. Callers inside a transaction must use
 * `withStatementTimeoutRetry` in versionIndex.ts, which wraps each attempt in a
 * SAVEPOINT.
 */
export async function withDbRetry<T>(
  db: Db,
  query: string,
  values: unknown[] = [],
  options: RetryOptions<unknown> = {},
): Promise<unknown> {
  if (typeof (db as { release?: unknown }).release === 'function')
    throw new Error('withDbRetry requires a pool; use withStatementTimeoutRetry inside a transaction');
  return withRetry(
    async () => db.query(query, values),
    {
      ...options,
      isRetryable: (error: unknown) => {
        const code = (error as { code?: string }).code;
        // Always retry on statement timeout, lock timeout, deadlock
        if (code === '57014' || code === '55P03' || code === '40P01') return true;
        return DEFAULT_OPTIONS.isRetryable!(error);
      },
    },
  );
}

/**
 * Creates a retry wrapper with custom default options.
 */
export function createRetryWrapper<T>(defaultOptions: RetryOptions<T>) {
  return (fn: (signal?: AbortSignal) => Promise<T>, options?: RetryOptions<T>) =>
    withRetry(fn, { ...defaultOptions, ...options });
}

/**
 * Pre-configured retry wrappers for common scenarios.
 */
export const retryWrappers = {
  /** Quick retries for idempotent reads */
  fastRead: createRetryWrapper({
    maxAttempts: 3,
    baseDelayMs: 100,
    maxDelayMs: 1000,
    attemptTimeoutMs: 5000,
  }),

  /** Standard retries for writes */
  standardWrite: createRetryWrapper({
    maxAttempts: 5,
    baseDelayMs: 500,
    maxDelayMs: 10000,
    attemptTimeoutMs: 30000,
  }),

  /** Aggressive retries for critical operations */
  criticalOperation: createRetryWrapper({
    maxAttempts: 10,
    baseDelayMs: 1000,
    maxDelayMs: 60000,
    attemptTimeoutMs: 120000,
  }),

  /** Retries for external API calls */
  externalApi: createRetryWrapper({
    maxAttempts: 5,
    baseDelayMs: 2000,
    maxDelayMs: 60000,
    isRetryable: (error) => {
      if (!error) return false;
      const code = (error as { code?: string }).code;
      if (code === '57014' || code === '55P03' || code === '40P01') return true;
      if (error instanceof Error) {
        const status = (error as { status?: number }).status;
        if (typeof status === 'number' && status >= 500) return true;
        if (status === 408 || status === 429) return true;
      }
      return DEFAULT_OPTIONS.isRetryable!(error);
    },
    attemptTimeoutMs: 60000,
  }),
};