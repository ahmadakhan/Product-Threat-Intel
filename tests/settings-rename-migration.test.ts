import test from 'node:test';
import assert from 'node:assert/strict';
import { createPool, migrate } from '../server/db.ts';

const database = process.env.TEST_DATABASE_URL;
test(
  'migration 042 removes deprecated autoDispatchConfidenceThreshold key',
  { skip: !database },
  async () => {
    const pool = createPool(database!);
    // Bring the schema up to the version BELOW the rename first, so the seeded
    // row is written the way a pre-upgrade deployment would have left it, and
    // migration 042 is then the change under test.
    await migrate(pool);
    // The rename (042), the strip of removed keys (045) and the strip of settings
    // this suite no longer reads (047) are all under test, so each is rolled back
    // in the ledger before the second migrate().
    await pool.query(`DELETE FROM schema_migrations WHERE version IN (42, 45, 47)`);
    await pool.query(
      `INSERT INTO records(kind,id,data) VALUES('settings','main',$1::jsonb)
       ON CONFLICT (kind,id) DO UPDATE SET data = EXCLUDED.data`,
      [JSON.stringify({ autoDispatchEnabled: true, autoDispatchConfidenceThreshold: 75, timezone: 'UTC' })],
    );
    await migrate(pool);
    const row = (await pool.query(`SELECT data FROM records WHERE kind='settings' AND id='main'`)).rows[0];
    // Deprecated keys are stripped; timezone is preserved.
    assert.equal(row.data.autoDispatchEnabled, undefined, 'the removed autoDispatchEnabled key is stripped');
    assert.equal(row.data.autoDispatchConfidenceThreshold, undefined, 'the old key is gone');
    assert.equal(row.data.confirmedFindingThreshold, undefined, 'the removed confirmedFindingThreshold key is stripped');
    assert.equal(row.data.timezone, 'UTC', 'unrelated keys are preserved');
    // Idempotent: run again, no error, no duplication.
    await migrate(pool);
    const row2 = (await pool.query(`SELECT data FROM records WHERE kind='settings' AND id='main'`)).rows[0];
    assert.equal(row2.data.autoDispatchConfidenceThreshold, undefined);
    await pool.end();
  },
);

test(
  'migration 047 strips settings the application never reads and keeps tuned values',
  { skip: !database },
  async () => {
    const pool = createPool(database!);
    await migrate(pool);
    // Re-run the strip against a row shaped like a pre-upgrade deployment: every
    // removed key present, and security values an operator had tuned.
    await pool.query(`DELETE FROM schema_migrations WHERE version IN (47)`);
    await pool.query(
      `INSERT INTO records(kind,id,data) VALUES('settings','main',$1::jsonb)
       ON CONFLICT (kind,id) DO UPDATE SET data = EXCLUDED.data`,
      [
        JSON.stringify({
          timezone: 'Europe/Berlin',
          scopeHours: 48,
          ntpConfig: { enabled: true, server: 'time.cloudflare.com', driftToleranceMs: 50 },
          authorityPrecedence: ['VENDOR_PSIRT'],
          enrichmentMessageTemplate: 'custom {cveId}',
          ssrfProtection: { blockPrivateIps: true, blockLoopback: true, allowRedirects: true },
          webhookSigningSecret: 'whsec_legacy',
          securityPolicy: {
            csrfProtection: true,
            sessionTimeoutMins: 45,
            minPasswordLen: 18,
            maxLoginAttempts: 8,
            lockoutMins: 20,
            autoAliasTtlDays: 7,
          },
        }),
      ],
    );
    await migrate(pool);
    const row = (await pool.query(`SELECT data FROM records WHERE kind='settings' AND id='main'`)).rows[0];
    assert.deepEqual(
      row.data.securityPolicy,
      {
        sessionTimeoutMins: 45,
        minPasswordLen: 18,
        maxLoginAttempts: 8,
        lockoutMins: 20,
        autoAliasTtlDays: 7,
      },
      'security policy is rebuilt without csrfProtection and keeps every tuned value',
    );
    for (const key of [
      'ntpConfig',
      'authorityPrecedence',
      'enrichmentMessageTemplate',
      'ssrfProtection',
      'webhookSigningSecret',
    ])
      assert.equal(row.data[key], undefined, `${key} is stripped`);
    assert.equal(row.data.timezone, 'Europe/Berlin', 'unrelated values are preserved');
    assert.equal(row.data.scopeHours, 48, 'unrelated values are preserved');
    await pool.end();
  },
);
