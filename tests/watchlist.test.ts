import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { WatchListItem } from '../src/types/index.ts';
import {
  editedWatchlistCpe,
  orderWatchlist,
  registrationAssetsFromCpes,
  verifyRegistrationCpes,
  verifyRegistrationAssets,
  dictionaryCpesForCandidate,
  bulkRegistrationAssets,
} from '../src/utils/watchlist.ts';
import { watchlistImportSchema, assetImportSchema } from '../server/validation.ts';

const item = (id: string, createdAt: string, product = 'widget'): WatchListItem => ({
  id,
  vendor: 'example',
  product,
  cpes: [`cpe:2.3:a:example:${product}:1.0:*:*:*:*:*:*:*`],
  assetTag: id,
  ownerGroup: 'test',
  active: true,
  createdAt,
});

test('editing inventory data does not change its created-time order', () => {
  const older = item('older', '2026-01-01T00:00:00.000Z');
  const newer = item('newer', '2026-02-01T00:00:00.000Z');
  const edited = { ...older, product: 'renamed', createdAt: older.createdAt };

  assert.deepEqual(
    orderWatchlist([edited, newer]).map((asset) => asset.id),
    ['newer', 'older'],
  );
});

test('editing the product field generates and saves a matching CPE', () => {
  const asset = item('asset', '2026-01-01T00:00:00.000Z');
  const cpe = editedWatchlistCpe(asset, {
    cpeExpression: asset.cpes[0],
    vendor: 'example',
    product: 'widget-enterprise',
    part: 'a',
    version: '1.0',
    targetHw: '*',
  });

  assert.equal(cpe, 'cpe:2.3:a:example:widget-enterprise:1.0:*:*:*:*:*:*:*');
});

test('editing the CPE expression directly preserves that expression', () => {
  const asset = item('asset', '2026-01-01T00:00:00.000Z');
  const cpe = 'cpe:2.3:o:example:widget:2.0:*:*:*:*:*:*:*';

  assert.equal(
    editedWatchlistCpe(asset, {
      cpeExpression: cpe,
      vendor: 'example',
      product: 'widget',
      part: 'a',
      version: '1.0',
      targetHw: '*',
    }),
    cpe,
  );
});

test('dictionary registration uses the selected identity and version without a fallback CPE', () => {
  const cpe = 'cpe:2.3:o:microsoft:windows_server_2022:20348:*:*:*:*:*:x64:*';
  const rows = registrationAssetsFromCpes([cpe, cpe], {
    assetTag: 'WIN-01',
    ownerGroup: 'SOC',
    notes: '',
    purls: [],
  });
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].cpes, [cpe]);
  assert.equal(rows[0].vendor, 'microsoft');
  assert.equal(rows[0].product, 'windows_server_2022');
  assert.equal(rows[0].version, '20348');
  assert.equal(rows[0].targetHw, 'x64');
  assert.equal(rows[0].assetTag, 'WIN-01');
});

test('registration separates different products and retains versions under the correct product', () => {
  const first = 'cpe:2.3:a:apache:http_server:2.4.61:*:*:*:*:*:*:*';
  const second = 'cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*';
  const other = 'cpe:2.3:o:fortinet:fortios:7.2.1:*:*:*:*:*:*:*';
  const rows = registrationAssetsFromCpes([first, other, second], {
    assetTag: 'EDGE',
    ownerGroup: 'SOC',
    notes: '',
    purls: [],
  });
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0].cpes, [first, second]);
  assert.equal(rows[0].version, '*');
  assert.equal(rows[1].vendor, 'fortinet');
  assert.equal(rows[1].version, '7.2.1');
  assert.deepEqual(
    rows.map((row) => row.assetTag),
    ['EDGE-1', 'EDGE-2'],
  );
});

test('registration refuses empty identifiers and malformed CPEs instead of generating software assets', () => {
  const details = { assetTag: 'APP-01', ownerGroup: 'SOC', notes: '', purls: [] };
  assert.throws(() => registrationAssetsFromCpes([], details), /verified NVD/);
  assert.throws(() => registrationAssetsFromCpes(['invalid'], details), /valid product CPE/);
});

test('registration checks exact dictionary identity and rejects a related but different version', async () => {
  const cpe = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  await assert.rejects(
    verifyRegistrationCpes([cpe], async () => ({ results: [{ cpeName: cpe.replace(':1.0:', ':2.0:') }] })),
    /not an active NVD dictionary entry/,
  );
  await assert.rejects(
    verifyRegistrationCpes([cpe], async () => ({ results: [] })),
    /not an active NVD/,
  );
  assert.deepEqual(
    await verifyRegistrationCpes([cpe, cpe], async (candidate) => ({ results: [{ cpeName: candidate }] })),
    [cpe],
  );
});

test('registration accepts vendor-agnostic match from NVD dictionary', async () => {
  const userCpe = 'cpe:2.3:a:notepad-plus-plus:notepadplus:*:*:*:*:*:*:*:*';
  const nvdCpe = 'cpe:2.3:a:don_ho:notepadplus:*:*:*:*:*:*:*:*';
  const verified = await verifyRegistrationCpes([userCpe], async () => ({
    results: [{ cpeName: nvdCpe }],
  }));
  assert.deepEqual(verified, [nvdCpe]);
});

test('registration propagates upstream failures and does not silently accept a CPE', async () => {
  const cpe = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  await assert.rejects(
    verifyRegistrationCpes([cpe], async () => {
      throw new Error('NVD rate limit reached');
    }),
    /NVD rate limit/,
  );
  await assert.rejects(
    verifyRegistrationCpes([], async () => {
      throw new Error('must not query');
    }),
    /verified NVD/,
  );
});

test('a dictionary selection replaces generated suggestions only for the same product', () => {
  const generated = 'cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*';
  const verified = 'cpe:2.3:o:microsoft:windows_server_2022:20348:*:*:*:*:*:x64:*';
  const unrelated = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  assert.deepEqual(dictionaryCpesForCandidate(generated, [unrelated, verified]), [verified]);
  assert.deepEqual(dictionaryCpesForCandidate(generated, [unrelated]), [generated]);
});

test('strict vendor matching prevents substitution from unrelated vendors', () => {
  // Operator entered "notepad_plus_plus" as the vendor, but the NVD registry
  // uses the vendor "don_ho". Strict matching requires the vendor to match
  // exactly, so the generated CPE is NOT replaced by the NVD entry. The
  // operator must manually select the verified dictionary CPE from search
  // results rather than relying on an automatic substitution.
  const generated = 'cpe:2.3:a:notepad_plus_plus:notepad\\+\\+:*:*:*:*:*:*:*:*';
  const verified = 'cpe:2.3:a:don_ho:notepad\\+\\+:5.5:*:*:*:*:*:*:*';
  const unrelated = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  assert.deepEqual(dictionaryCpesForCandidate(generated, [unrelated, verified]), [generated]);
  assert.deepEqual(dictionaryCpesForCandidate(generated, [unrelated]), [generated]);
});

test('registration allows operator-entered custom CPEs without an NVD dictionary match', async () => {
  const custom = 'cpe:2.3:a:internal:gateway:1.0.0:*:*:*:*:*:*:*';
  const verified = await verifyRegistrationCpes(
    [custom],
    async () => {
      throw new Error('must not query NVD for a custom CPE');
    },
    [custom],
  );
  assert.deepEqual(verified, [custom]);
});

test('registration still rejects a non-custom CPE missing from the NVD dictionary', async () => {
  const cpe = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  await assert.rejects(
    verifyRegistrationCpes([cpe], async () => ({ results: [] })),
    /not an active NVD/,
  );
});

test('bulk import accepts records without a published CPE and disables them by default', () => {
  for (const absent of [undefined, null, '', 'NA', 'n/a', 'none', '-', [], ['NA'], ['', 'N/A'], [null, undefined]]) {
    const result = bulkRegistrationAssets(
      { vendor: ' Example ', product: ' Internal Agent ', cpes: absent },
      'BULK-1',
    );
    assert.ok('rows' in result);
    assert.equal(result.rows.length, 1);
    assert.deepEqual(result.rows[0].cpes, []);
    assert.equal(result.rows[0].vendor, 'Example');
    assert.equal(result.rows[0].product, 'Internal Agent');
    assert.equal(result.rows[0].version, '*');
    assert.equal(result.rows[0].active, false);
    assert.equal(result.rows[0].assetTag, 'BULK-1');
    assert.equal(result.rows[0].ownerGroup, 'Imported-Inventory');
  }
});

test('a CPE-less bulk record can be enabled explicitly when it has a PURL', () => {
  const result = bulkRegistrationAssets(
    {
      vendor: 'acme',
      product: 'agent',
      cpes: 'NA',
      purls: ['pkg:generic/agent@1.0.0'],
      active: true,
    },
    'BULK-2',
  );
  assert.ok('rows' in result);
  assert.equal(result.rows[0].active, true);
});

test('an active bulk record without any structured identifier is rejected', () => {
  const result = bulkRegistrationAssets(
    { vendor: 'acme', product: 'agent', cpes: 'NA', active: true },
    'BULK-2B',
  );
  assert.ok('error' in result && /active product requires a CPE or PURL/.test(result.error));
});

test('bulk import verifies every supplied CPE and keeps singular cpe values', () => {
  const cpe = 'cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*';
  for (const input of [
    { cpe },
    { cpes: cpe },
    { cpes: ['NA', cpe] },
    { cpes: ['', cpe] },
  ]) {
    const result = bulkRegistrationAssets({ vendor: 'acme', product: 'widget', ...input }, 'BULK-3');
    assert.ok('rows' in result);
    assert.deepEqual(result.rows[0].cpes, [cpe]);
    assert.equal(result.rows[0].active, true);
  }
});

test('bulk import rejects malformed or non-string CPEs instead of dropping them', () => {
  for (const cpes of [['NA', 'not-a-cpe'], ['cpe:2.3:a:acme'], [42], [{ cpe: 'cpe' }]]) {
    const result = bulkRegistrationAssets({ vendor: 'acme', product: 'widget', cpes }, 'BULK-4');
    assert.ok('error' in result);
  }
  const invalid = bulkRegistrationAssets(
    { vendor: 'acme', product: 'widget', cpes: ['not-a-cpe'] },
    'BULK-5',
  );
  assert.ok('error' in invalid && /Invalid CPE 2\.3/.test(invalid.error));
});

test('bulk import still requires vendor and product when no CPE is supplied', () => {
  for (const record of [
    { vendor: '', product: 'widget', cpes: 'NA' },
    { vendor: 'acme', product: '   ', cpes: [] },
    { vendor: 42, product: 'widget', cpes: 'NA' },
  ]) {
    assert.ok('error' in bulkRegistrationAssets(record, 'BULK-6'));
  }
});

test('verification leaves CPE-less rows untouched without querying NVD', async () => {
  let calls = 0;
  const [verified] = await verifyRegistrationAssets(
    [{ vendor: 'acme', product: 'agent', cpes: [], assetTag: 'A-1', ownerGroup: 'SOC', active: false }],
    async () => {
      calls++;
      return { results: [] };
    },
  );
  assert.equal(calls, 0);
  assert.deepEqual(verified.cpes, []);
  assert.equal(verified.active, false);
  assert.equal(verified.assetTag, 'A-1');
});

test('the import contract accepts inventory rows without CPE identifiers', () => {
  const parsed = watchlistImportSchema.element.parse({
    id: 'no-cpe-row',
    vendor: 'acme',
    product: 'agent',
    cpes: [],
    assetTag: 'A-1',
    ownerGroup: 'SOC',
    active: false,
  });
  assert.deepEqual(parsed.cpes, []);
  assert.equal(parsed.active, false);
});

test('the bulk import contract accepts inactive rows without identifiers only', () => {
  const row = {
    vendor: 'example_vendor',
    product: 'internal_agent',
    cpes: [],
    assetTag: 'A-1',
    ownerGroup: 'SOC',
    active: false,
  };
  assert.deepEqual(assetImportSchema.parse(row).cpes, []);
  assert.throws(
    () => assetImportSchema.parse({ ...row, active: true }),
    /active asset requires at least one CPE or PURL/,
  );
  assert.deepEqual(
    assetImportSchema.parse({ ...row, active: true, cpes: ['cpe:2.3:a:acme:agent:1.0:*:*:*:*:*:*:*'] }).cpes,
    ['cpe:2.3:a:acme:agent:1.0:*:*:*:*:*:*:*'],
  );
});

test('bulk import reports a wildcard identity against its row instead of aborting the batch', () => {
  const result = bulkRegistrationAssets(
    {
      vendor: 'acme',
      product: 'widget',
      cpes: ['cpe:2.3:a:*:widget:*:*:*:*:*:*:*:*'],
    },
    'BULK-7',
  );
  assert.ok('error' in result && /valid product CPE/.test(result.error));
});

test('a CPE-less bulk record keeps PURLs and rejects malformed PURL fields', () => {
  const purl = 'pkg:npm/internal-agent@1.0.0';
  const kept = bulkRegistrationAssets(
    { vendor: 'acme', product: 'agent', cpes: [], purls: [' ', purl], active: false },
    'BULK-8',
  );
  assert.ok('rows' in kept);
  assert.deepEqual(kept.rows[0].purls, [purl]);
  assert.equal(kept.rows[0].active, false);

  for (const purls of ['pkg:npm/internal-agent@1.0.0', [42], [null]]) {
    const result = bulkRegistrationAssets({ vendor: 'acme', product: 'agent', cpes: [], purls }, 'BULK-9');
    assert.ok('error' in result && /purls must be an array of strings/.test(result.error));
  }
});
