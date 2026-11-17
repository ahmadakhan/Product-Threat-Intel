import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { WatchListItem } from '../src/types/index.ts';
import {
  planBulkRegistration,
  planBulkRegistrationRows,
  type BulkRegistrationRow,
} from '../src/utils/bulkRegistrationPlan.ts';
import { watchlistConfirmationToken, watchlistIdentity } from '../shared/watchlistIdentity.ts';

const widgetCpe = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
const gadgetCpe = 'cpe:2.3:a:example:gadget:1.0:*:*:*:*:*:*:*';

function stored(overrides: Partial<WatchListItem> = {}): WatchListItem {
  return {
    id: 'stored-1',
    vendor: 'example',
    product: 'widget',
    version: '1.0',
    cpes: [widgetCpe],
    assetTag: 'ASSET-1',
    ownerGroup: 'SOC',
    notes: 'Bulk imported product asset',
    active: true,
    createdAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

function incoming(overrides: Partial<BulkRegistrationRow> = {}): BulkRegistrationRow {
  return {
    vendor: 'example',
    product: 'widget',
    version: '1.0',
    cpes: [widgetCpe],
    assetTag: 'ASSET-1',
    ownerGroup: 'SOC',
    notes: 'Bulk imported product asset',
    active: true,
    ...overrides,
  };
}

test('a new active row is a create that turns monitoring on', () => {
  const plan = planBulkRegistrationRows([incoming()]);
  assert.equal(plan.rows, 1);
  assert.equal(plan.activeRows, 1);
  assert.equal(plan.disabledRows, 0);
  assert.equal(plan.enableRows, 1);
  assert.equal(plan.reactivatedRows, 0);
  assert.equal(plan.changedRecords.length, 1);
  assert.equal(plan.changedRecords[0].action, 'create');
  assert.match(plan.changedRecords[0].token || '', /ASSET-1/);
});

test('an identical active row is left untouched', () => {
  const plan = planBulkRegistrationRows([incoming()], [stored()]);
  assert.equal(plan.unchangedActiveRows, 1);
  assert.equal(plan.enableRows, 0);
  assert.equal(plan.changedRecords.length, 0);
  assert.equal(plan.identities[0].active.length, 0);
});

test('an identical disabled stored row is reported as a re-enable', () => {
  const plan = planBulkRegistrationRows([incoming()], [stored({ active: false })]);
  assert.equal(plan.reactivatedRows, 1);
  assert.equal(plan.enableRows, 1);
  assert.equal(plan.changedRecords.length, 1);
  assert.equal(plan.changedRecords[0].action, 'enable');
});

test('a changed field on an enabled row is an overwrite with a reason', () => {
  const plan = planBulkRegistrationRows([incoming({ ownerGroup: 'Platform' })], [stored()]);
  assert.equal(plan.unchangedActiveRows, 0);
  assert.equal(plan.enableRows, 0);
  assert.equal(plan.changedRecords.length, 1);
  assert.equal(plan.changedRecords[0].action, 'update');
  assert.match(plan.changedRecords[0].overwriteReason || '', /owner group "SOC" -> "Platform"/);
});

test('an inactive row disables the stored identity', () => {
  const plan = planBulkRegistrationRows([incoming({ active: false })], [stored()]);
  assert.equal(plan.disabledRows, 1);
  assert.equal(plan.changedRecords.length, 1);
  assert.equal(plan.changedRecords[0].action, 'disable');
  assert.equal(plan.changedRecords[0].matchable, false);
  assert.equal(plan.identities[0].disabled.length, 1);
});

test('a rejected record is counted and reported without a token', () => {
  const plan = planBulkRegistration([
    { vendor: 'example', product: 'widget', cpes: ['not-a-cpe'], assetTag: 'BAD-1' },
  ]);
  assert.equal(plan.rows, 1);
  assert.equal(plan.invalidRows, 1);
  assert.equal(plan.disabledRows, 1);
  assert.equal(plan.changedRecords[0].action, 'invalid');
  assert.equal(plan.changedRecords[0].token, null);
  assert.match(plan.changedRecords[0].invalidReason || '', /Invalid CPE 2.3/);
});

test('duplicate keys collapse to the last record and report the split', () => {
  const plan = planBulkRegistrationRows(
    [incoming({ ownerGroup: 'First' }), incoming({ ownerGroup: 'Second' })],
    [],
  );
  assert.equal(plan.rows, 2);
  assert.equal(plan.activeRows, 2);
  assert.equal(plan.enableRows, 1);
  assert.equal(plan.changedRecords.length, 1);
  assert.equal(plan.changedRecords[0].action, 'create');
  assert.equal(plan.identities.length, 1);
  assert.equal(plan.identities[0].splits, true);
  assert.equal(plan.identities[0].records[0].ownerGroup, 'Second');
});

test('one record with two product CPEs plans two rows', () => {
  const plan = planBulkRegistration([
    {
      vendor: 'example',
      product: 'widget',
      assetTag: 'ASSET-9',
      cpes: [widgetCpe, gadgetCpe],
      ownerGroup: 'SOC',
    },
  ]);
  assert.equal(plan.rows, 2);
  assert.equal(plan.identities.length, 2);
  assert.deepEqual(plan.changedRecords.map((change) => change.assetTag).sort(), ['ASSET-9-1', 'ASSET-9-2']);
});

test('stored rows sharing a tag but not a key are reported as overlapping', () => {
  const other = stored({
    id: 'stored-2',
    product: 'gadget',
    cpes: [gadgetCpe],
    assetTag: 'ASSET-1',
  });
  const plan = planBulkRegistrationRows([incoming()], [stored(), other]);
  assert.equal(plan.overlappingRows, 1);
  // The addressed row is updated/created normally; the sibling is not touched.
  assert.equal(plan.changedRecords.length, 0);
  assert.equal(plan.unchangedActiveRows, 1);
});

test('the confirmation token combines the asset tag and exact identity', () => {
  assert.equal(
    watchlistConfirmationToken(incoming()),
    JSON.stringify(['ASSET-1', watchlistIdentity(incoming())]),
  );
  assert.equal(watchlistConfirmationToken({ ...incoming(), vendor: '', assetTag: 'ASSET-1' }), null);
});

test('the plan keys rows exactly as the command layer does', () => {
  const plan = planBulkRegistration([
    {
      vendor: 'example',
      product: 'widget',
      assetTag: 'ASSET-1',
      cpes: [widgetCpe],
      ownerGroup: 'SOC',
    },
  ]);
  const expected = JSON.stringify(['ASSET-1', watchlistIdentity(incoming())]);
  assert.equal(plan.identities[0].identity, expected);
});
