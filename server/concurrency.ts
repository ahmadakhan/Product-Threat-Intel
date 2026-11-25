/**
 * Runs `fn` over `items` with bounded concurrency, dispatching at most one
 * new call every `intervalMs`. This preserves the exact request *rate* of a
 * strictly serial `for (...) { await sleep(interval); await fn(item) }` loop,
 * but lets up to `concurrency` requests be in flight at once so each item's
 * network latency is overlapped rather than added on top of every wait —
 * the dominant cost in a large per-CVE detail-fetch loop.
 *
 * Fails closed: once any call throws, no further work is dispatched and the
 * first error is rethrown after in-flight work settles, matching the
 * all-or-nothing semantics of the serial loop it replaces.
 *
 * Partial results are therefore intentionally DISCARDED: workers that finished
 * before the failure did write their output into `results`, but the function
 * throws instead of returning it, so no caller can mistake a partially fetched
 * batch for a complete one. A caller that needs per-item outcomes must catch the
 * error from `fn` itself and return a value for that item.
 *
 * Results are written back by index, so the returned array preserves the
 * same order as `items` regardless of completion order.
 *
 * Dispatch pacing is measured with a monotonic clock (`hrtime.bigint()`), not
 * wall-clock `Date.now()`: a backward NTP step would otherwise stall dispatch
 * for the length of the skew and a forward step would release every worker at
 * once.
 */
export async function paceConcurrent<T, R>(
  items: T[],
  intervalMs: number,
  concurrency: number,
  sleep: (ms: number) => Promise<unknown>,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;
  // Pacing uses a MONOTONIC clock. `Date.now()` follows wall time, so an NTP
  // correction that steps the clock backwards makes `nextAllowedDispatch` look
  // far in the future (the loop sleeps for the whole skew: throughput collapse),
  // and a forward step makes it look long past (every worker dispatches at once:
  // a burst that can trip a provider's rate limit). `hrtime.bigint()` cannot
  // move backwards, so the rate the caller asked for is the rate it gets.
  // `sleep()` still takes milliseconds, so the monotonic delta is converted at
  // each use rather than once, keeping the comparison in the clock's own units.
  const monotonicMs = () => Number(process.hrtime.bigint() / 1_000_000n);
  let nextAllowedDispatch = 0;
  let failure: { error: unknown } | undefined;
  const worker = async () => {
    while (nextIndex < items.length) {
      if (failure) return;
      const i = nextIndex++;
      try {
        // Recheck after sleeping: timers can wake late or bunch together when
        // the event loop is busy. Reserve synchronously immediately before the
        // request so a delayed wakeup cannot dispatch a burst.
        while (true) {
          const wait = nextAllowedDispatch - monotonicMs();
          if (wait > 0) {
            await sleep(wait);
            if (failure) return;
            continue;
          }
          nextAllowedDispatch = monotonicMs() + intervalMs;
          break;
        }
        if (failure) return;
        results[i] = await fn(items[i], i);
      } catch (error) {
        if (!failure) failure = { error };
        return;
      }
    }
  };
  // Await every worker after cancellation/deadline errors too. Returning on the
  // first rejected worker would let already sleeping workers dispatch requests
  // after the caller has considered this batch failed.
  await Promise.allSettled(Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, worker));
  if (failure) throw failure.error;
  return results;
}
