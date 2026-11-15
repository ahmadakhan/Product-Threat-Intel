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
    // Both the rename (042) and the later strip of removed keys (045) are under
    // test, so both are rolled back in the ledger before the second migrate().
    await pool.query(`DELETE FROM schema_migrations WHERE version IN (42, 45)`);
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
