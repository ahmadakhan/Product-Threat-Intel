import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type pg from 'pg';
import type { Config } from './config';
import { loadConfig } from './config';
import { createPool } from './db';
import type { Db } from './db';
import { migrate, transaction, get, put, REQUIRED_SCHEMA_VERSION } from './db';
import { backfillCorrelationInventory } from './correlation/inventory.ts';
import { CorrelationRuntime } from './correlation/runtime.ts';
import { describeError, writeEvent } from './events';
import { createRequester } from './network';
import type { Requester } from './network';
import { createMailSender } from './delivery';
import { initMlRuntime } from './ml/integration.ts';
import type { MlRuntime } from './ml/factory.ts';
import { encryptionKeys } from './secrets';

export interface SharedContext {
  pool: pg.Pool;
  config: Config;
  request: Requester;
  sendMail: ReturnType<typeof createMailSender>;
  correlation: CorrelationRuntime;
  mlRuntime: MlRuntime | undefined;
  writeEvent: typeof writeEvent;
  describeError: typeof describeError;
}

/**
 * Shared initialization used by both the API and worker entry points.
 *
 * Everything here is safe to run in every process: config parsing, connection
 * pool creation, schema verification, native-inventory bootstrapping, ML
 * runtime setup, and correlation runtime construction. Nothing here starts
 * background workers or an HTTP server — those are the entry point's job.
 */
export async function initShared(): Promise<SharedContext> {
  const config = loadConfig();
  const pool = createPool(config.DATABASE_URL);

  // `npm start` does not pass --env-file, so keep the historical convenience of
  // reading ./.env when the process was started without a DATABASE_URL.
  const _envPath = join(process.cwd(), '.env');
  if (existsSync(_envPath) && !process.env.DATABASE_URL) {
    process.loadEnvFile(_envPath);
  }

  if (config.NODE_ENV === 'production') {
    const initialized = await pool.query("SELECT to_regclass('schema_migrations') AS name");
    if (!initialized.rows[0]?.name)
      throw new Error('Database schema is not initialized; run migrations before starting');
    const result = await pool.query('SELECT COALESCE(MAX(version), 0)::int AS version FROM schema_migrations');
    const version = Number(result.rows[0]?.version || 0);
    if (version < REQUIRED_SCHEMA_VERSION)
      throw new Error(
        `Database schema version ${version} is older than required version ${REQUIRED_SCHEMA_VERSION}; run migrations before starting`,
      );
  } else {
    await migrate(pool);
  }

  await transaction(
    pool,
    async (db) => {
      if (await get(db, 'systemState', 'native-inventory-v1')) return;
      await backfillCorrelationInventory(db);
      await put(db, 'systemState', 'native-inventory-v1', { completedAt: new Date().toISOString() });
    },
    undefined,
    { locks: ['native-inventory-bootstrap'] },
  );

  await writeEvent(pool, {
    category: 'SYSTEM',
    code: 'system.started',
    message: 'Application initialized',
    context: { workerEnabled: config.WORKER_ENABLED === 'true' },
  });

  const request = createRequester(config);
  const sendMail = createMailSender(config, pool, request);

  const mlStorageOptions = {
    directory: config.ML_DIRECTORY,
    signingKey: config.ML_SIGNING_KEY,
    ...(config.ML_STORAGE_MODE === 'database' ? { database: pool } : {}),
  };

  const correlation = new CorrelationRuntime(
    pool,
    encryptionKeys(config),
    config.CORRELATION_DLQ_DIRECTORY,
    {
      url: config.HEARTBEAT_URL,
      intervalSeconds: config.HEARTBEAT_INTERVAL_SECONDS,
      logLevel: config.LOG_LEVEL === 'verbose' ? 'verbose' : 'standard',
      scheduledStateRefreshIntervalSeconds: 60,
      deadLetterStorageMode: config.CORRELATION_DLQ_STORAGE_MODE,
    },
  );
  if (config.CORRELATION_DLQ_STORAGE_MODE === 'database') await correlation.flushLegacyDeadLetters();

  const mlRuntime = await initMlRuntime(pool, mlStorageOptions)
    .catch((error) => {
      console.error('ML runtime init failed:', error);
      void writeEvent(pool, {
        category: 'ML',
        level: 'ERROR',
        code: 'ml.runtime_init_failed',
        message:
          'ML runtime failed to initialize; all ML features degrade to rule-based fallbacks (confidence calibration, review ranking, delivery optimisation and threshold recommendations are inactive)',
        context: { error: (error as Error).message },
      }).catch(() => undefined);
      return undefined;
    });

  return {
    pool,
    config,
    request,
    sendMail,
    correlation,
    mlRuntime,
    writeEvent,
    describeError,
  };
}
