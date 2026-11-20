import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import supertest from 'supertest';
import { loadConfig } from '../server/config.ts';
import { createApp } from '../server/app.ts';
import { createPool, migrate } from '../server/db.ts';

const database = process.env.TEST_DATABASE_URL;

const baseEnv = () => ({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'https://vulnstream.internal',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  WORKER_ENABLED: 'false',
});

test('APP_ORIGINS_EXTRA normalises entries and rejects a path', () => {
  const config = loadConfig({
    ...baseEnv(),
    APP_ORIGINS_EXTRA: ' https://vulnstream.lan , http://127.0.0.1:3000 , https://vulnstream.lan ',
  });
  assert.equal(
    config.APP_ORIGINS_EXTRA,
    'https://vulnstream.lan,http://127.0.0.1:3000',
    'entries are trimmed, de-duplicated and kept in order',
  );
  assert.equal(
    loadConfig(baseEnv()).APP_ORIGINS_EXTRA,
    '',
    'no extra origins means only APP_ORIGIN is allowed',
  );
  assert.throws(
    () => loadConfig({ ...baseEnv(), APP_ORIGINS_EXTRA: 'https://vulnstream.lan/app' }),
    /must be an origin without a path/,
    'a path could never match an Origin header and must fail loudly',
  );
  assert.throws(
    () => loadConfig({ ...baseEnv(), APP_ORIGINS_EXTRA: 'not-a-url' }),
    /not a valid URL/,
  );
});

test(
  'mutations require an Origin header and still refuse origin-less requests',
  { skip: !database },
  async () => {
    const extra = 'https://vulnstream.lan';
    const config = loadConfig({
      ...baseEnv(),
      DATABASE_URL: database!,
      APP_ORIGINS_EXTRA: extra,
    });
    const pool = createPool(database!);
    await migrate(pool);
    const app = createApp(pool, config);
    // No session is needed to observe the origin gate: it runs before
    // authentication, so a request with any Origin header advances to 401 while
    // an origin-less mutation stops at 403. The gate intentionally accepts any
    // present origin so threat-feed clients on arbitrary origins can write; the
    // JSON content-type and session/CSRF checks remain the CSRF boundary.
    const status = async (origin?: string) => {
      const request = supertest(app).post('/api/commands').send({});
      if (origin) request.set('Origin', origin);
      return (await request).status;
    };
    assert.equal(await status(config.APP_ORIGIN), 401, 'APP_ORIGIN passes the gate');
    assert.equal(await status(extra), 401, 'a listed extra origin passes the gate');
    assert.equal(await status(), 403, 'an origin-less mutation is refused');
    assert.equal(
      await status('https://evil.test'),
      401,
      'any present origin passes the CSRF gate and reaches authentication',
    );
    assert.equal(
      await status('https://vulnstream.internal.evil.test'),
      401,
      'the gate no longer compares against an origin allowlist',
    );
    assert.equal(
      await status('http://vulnstream.internal'),
      401,
      'the gate no longer compares scheme against an allowlist',
    );
    await pool.end();
  },
);
