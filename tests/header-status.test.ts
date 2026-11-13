import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import supertest from 'supertest';
import { createApp } from '../server/app.ts';
import { loadConfig } from '../server/config.ts';
import { getSystemUptime } from '../src/utils/systemUptime.ts';

// Audit M-1: /api/system-uptime now requires a session like every other /api
// read. This harness resolves the session lookup without a real database.
const authedPool = () =>
  ({
    query: async (sql: string, values: unknown[]) =>
      String(sql).includes('FROM sessions')
        ? { rows: [{ id: 'op-1', username: 'admin', email: 'a@b.c', role: 'ADMIN', csrf: 'c', expires_at: new Date(Date.now() + 60000) }] }
        : { rows: [] },
  }) as never;

test('uptime requires a session like every other /api read', async () => {
  const config = loadConfig({
    NODE_ENV: 'test', DATABASE_URL: 'postgres://localhost/unused',
    APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  });
  const app = createApp(authedPool(), config);
  const token = 'a'.repeat(43);
  const anonymous = await supertest(app).get('/api/system-uptime');
  assert.equal(anonymous.status, 401, 'unauthenticated request must be rejected');
  const response = await supertest(app)
    .get('/api/system-uptime')
    .set('Cookie', `vulnstream=${token}`)
    .expect(200);
  assert.ok(typeof response.body.uptimeSeconds === 'number');
});

test('uptime reports the API process duration, not host uptime, and resets after restart', async (t) => {
  const config = loadConfig({
    NODE_ENV: 'test', DATABASE_URL: 'postgres://localhost/unused',
    APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  });
  let seconds = 90061;
  t.mock.method(process, 'uptime', () => seconds);
  const app = createApp(authedPool(), config);
  const cookie = `vulnstream=${'a'.repeat(43)}`;
  const response = await supertest(app).get('/api/system-uptime').set('Cookie', cookie).expect(200);
  assert.equal(response.body.systemUptime, '1d 1h 1m 1s');
  assert.equal(response.body.uptimeSeconds, seconds);
  assert.ok(Math.abs(Date.now() - Date.parse(response.body.startedAt) - seconds * 1000) < 2000);
  seconds = 5;
  const restarted = await supertest(app).get('/api/system-uptime').set('Cookie', cookie).expect(200);
  assert.equal(restarted.body.systemUptime, '0h 0m 5s');
  assert.equal(restarted.body.uptimeSeconds, 5);
});

test('uptime client keeps the start timestamp separate from elapsed duration and surfaces errors', async (t) => {
  let response = new Response(JSON.stringify({
    systemUptime: '0h 2m 5s', startedAt: '2026-11-04T22:00:00Z',
  }));
  t.mock.method(globalThis, 'fetch', async () => response);
  const uptime = await getSystemUptime();
  assert.deepEqual(uptime, { uptime: '0h 2m 5s' });
  response = new Response('{}', { status: 503 });
  await assert.rejects(getSystemUptime(), /HTTP 503/);
  response = new Response(JSON.stringify({ systemUptime: '' }));
  await assert.rejects(getSystemUptime(), /Invalid application uptime/);
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('Network unavailable'); });
  await assert.rejects(getSystemUptime(), /Network unavailable/);
});
