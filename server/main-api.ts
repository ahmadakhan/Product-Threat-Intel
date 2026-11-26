import { createServer, type Server } from 'node:http';
import { createApp } from './app';
import { initShared } from './bootstrap';

const { pool, config, request, sendMail, correlation, mlRuntime, writeEvent, describeError } =
  await initShared();

const report = (event: string) => (error: unknown) => {
  const detail = describeError(error);
  void writeEvent(pool, {
    category: 'ISSUE',
    level: 'ERROR',
    code: 'api.failed',
    message: 'API process failed',
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

const app = createApp(pool, config, request, { correlation, mlRuntime,
  // The liveness probe only performs the stall check where the probe timeout is
  // comfortably above the block threshold; see the option's documentation.
  hangDetection: config.HANG_DETECTION_ENABLED === 'true',
});

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

let stopping = false;
async function shutdown() {
  if (stopping) return;
  stopping = true;
  const deadline = setTimeout(() => process.exit(1), 30000);
  deadline.unref();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await correlation.stop();
  await pool.end();
  clearTimeout(deadline);
}

process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
// Node terminates the process immediately on an uncaught exception
// with no listener registered. That would skip shutdown() entirely, leaving the
// HTTP server and any in-flight work to die mid-transaction.
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

// Session cleanup for API replicas. DELETE is idempotent and safe to run on
// every API instance; expired sessions and login attempts are security
// invariants, not retained business data.
setInterval(() => {
  void (async () => {
    await pool.query('DELETE FROM sessions WHERE expires_at<now()');
    await pool.query("DELETE FROM login_attempts WHERE window_start<now()-interval '1 day'");
    await pool.query('DELETE FROM password_reset_tokens WHERE expires_at<now()');
  })().catch(report('session-cleanup'));
}, 60000).unref();
