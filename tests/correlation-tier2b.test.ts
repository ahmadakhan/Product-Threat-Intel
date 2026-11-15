import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TextCorrelationEngine } from '../server/correlation/engine.ts';
import type { ExtractedText } from '../server/correlation/validation.ts';

/**
 * Tier 2b is the weakest correlation tier: the prose names an inventoried
 * vendor and product, but no thesaurus alias resolved and no version bound
 * applies. It produces review evidence.
 *
 * These tests exist because that evidence is now *delivered* without a human
 * review step. The original implementation matched vendor and product as two
 * independent set members over every token in the document, so any article that
 * merely mentioned both words anywhere — in unrelated sentences — matched an
 * installed product and, with low-confidence alerts on, emailed the security
 * team about a vulnerability the article never claimed. A false alert in an
 * autonomous system reaches a human as noise and erodes trust in every real one,
 * so the tier must require the vendor and product to be named together.
 */

const ASSET = {
  id: '00000000-0000-0000-0000-00000000000a',
  vendor: 'microsoft',
  product: 'exchange_server',
  version: '2019',
  revision: 'r1',
};

/**
 * No alias resolves, so the engine falls through to Tier 2b. The inventory stub
 * evaluates the phrase array the engine binds, so it fails the same way the real
 * query would if the adjacency rule regressed.
 */
const query = (async (statement: string, params?: unknown[]) => {
  if (statement.includes('FROM vendor_product_aliases')) return { rows: [], rowCount: 0 };
  if (statement.includes('FROM correlation_asset_inventory i')) {
    const phrases = (params?.[0] ?? []) as string[];
    // A non-array binding is exactly the bug that made this tier dead code.
    if (!Array.isArray(phrases)) throw new Error('cannot cast type json to text[]');
    const named = phrases.includes(`${ASSET.vendor} ${ASSET.product}`);
    return { rows: named ? [ASSET] : [], rowCount: named ? 1 : 0 };
  }
  return { rows: [], rowCount: 0 };
}) as never;

const extracted = (text: string): ExtractedText => ({
  text,
  cleanContent: text,
  ranges: [],
  cveIds: [],
  zeroDay: false,
  securitySignal: true,
  negated: false,
  zeroDayDensity: 0,
});

const correlate = (text: string) =>
  new TextCorrelationEngine().correlate(
    { title: 't', content: 'c', url: 'https://example.org/a', cpes: [], purls: [], entities: [] } as never,
    extracted(text),
    query,
  );

test('a vendor and product mentioned in unrelated sentences do not match', async () => {
  const matches = await correlate(
    ' microsoft announced quarterly results today exchange_server popularity grew among admins ',
  );
  assert.deepEqual(matches, [], 'co-occurrence alone is not evidence that this advisory concerns the product');
});

test('an adjective between the vendor and product does not synthesise adjacency', async () => {
  const matches = await correlate(' microsoft new exchange_server release notes published ');
  assert.deepEqual(matches, []);
});

test('the vendor and product named together do match, as review evidence', async () => {
  const matches = await correlate(' an advisory affects microsoft exchange_server installations ');
  assert.equal(matches.length, 1);
  assert.equal(matches[0].confidence, 'LOW');
  assert.equal(matches[0].assetId, ASSET.id);
  assert.match(matches[0].reason, /named together/);
});

test('a bare product name alone is not enough for this weakest tier', async () => {
  // Prose about a vendor's roadmap or pricing names its products constantly
  // without describing an exposure. Tier 2b has no version bound to tie the
  // mention to the article, so it must not invent one.
  const matches = await correlate(' exchange_server licensing costs rose this quarter ');
  assert.deepEqual(matches, []);
});

test('a trailing period does not break an otherwise adjacent name', async () => {
  // Tokenisation drops sentence punctuation, so "microsoft. exchange_server" is
  // the same adjacent phrase. This is the intended tolerance, not a loophole:
  // requiring raw-string adjacency would miss real prose for no safety gain.
  const matches = await correlate(' microsoft. exchange_server was later discussed ');
  assert.equal(matches.length, 1);
  assert.equal(matches[0].confidence, 'LOW');
});

test('a vendor clause separated from the product by other words does not match', async () => {
  const matches = await correlate(
    ' microsoft reported earnings exchange_server was later discussed by analysts ',
  );
  assert.deepEqual(matches, []);
});

test('a product-only mention still matches at MEDIUM when a thesaurus alias resolves it', async () => {
  // Tier 2 is unaffected by the Tier 2b tightening: the alias resolves the
  // vendor/product identity, the entity walks the inventory, and with no bound
  // to confirm the version the result is MEDIUM (not LOW review evidence).
  const aliased = (async (statement: string) => {
    if (statement.includes('FROM vendor_product_aliases'))
      return { rows: [{ alias: 'exchange', vendor: 'microsoft', product: 'exchange_server' }], rowCount: 1 };
    if (statement.includes('FROM correlation_asset_inventory i')) return { rows: [ASSET], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  }) as never;
  const matches = await new TextCorrelationEngine().correlate(
    { title: 't', content: 'c', url: 'https://example.org/a', cpes: [], purls: [], entities: [] } as never,
    extracted(' the exchange builds need attention '),
    aliased,
  );
  assert.equal(matches.length, 1);
  assert.equal(matches[0].confidence, 'MEDIUM');
  assert.equal(matches[0].assetId, ASSET.id);
});
/**
 * The unit tests above use a hand-written query stub. That stub previously hid a
 * real defect: the phrase array was bound as `JSON.stringify([...])`, which
 * PostgreSQL rejects as `malformed array literal`, and the enclosing region
 * wrapper swallowed the error — so Tier 2b silently matched nothing in every
 * deployment. A stub cannot catch that class of bug, so this test exercises the
 * actual statement against a real server.
 */
test(
  'Tier 2b phrase binding works against PostgreSQL, for both matching and non-matching prose',
  { skip: !process.env.TEST_DATABASE_URL, timeout: 30000 },
  async () => {
    const { createPool, migrate, transaction } = await import('../server/db.ts');
    const { randomBytes } = await import('node:crypto');
    const control = createPool(process.env.TEST_DATABASE_URL!);
    const schema = `tier2b_${randomBytes(6).toString('hex')}`;
    await control.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(process.env.TEST_DATABASE_URL!);
    url.searchParams.set('options', `-c search_path=${schema}`);
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      const nativeId = '00000000-0000-0000-0000-0000000000b1';
      await pool.query(
        `INSERT INTO correlation_managed_assets(record_id,native_id,vendor,product,version,active)
         VALUES('managed-1',$1::uuid,'microsoft','exchange_server','2019',true)`,
        [nativeId],
      );

      const engine = new TextCorrelationEngine();
      const run = (text: string) =>
        transaction(pool, (db) =>
          engine.correlate(
            { title: 't', content: 'c', url: 'https://example.org/tier2b', cpes: [], purls: [], entities: [] } as never,
            {
              text,
              cleanContent: text,
              ranges: [],
              cveIds: [],
              zeroDay: false,
              securitySignal: true,
              negated: false,
              zeroDayDensity: 0,
            },
            // A bound wrapper: the engine calls this as a function, while a
            // pg client exposes `query` as a method that needs its receiver.
            ((sql: string, values?: unknown[]) => db.query(sql, values)) as never,
          ),
        );

      // Named together: the real query must find the inventory row.
      const matched = await run(' an advisory affects microsoft exchange_server installations ');
      assert.equal(matched.length, 1, 'the phrase array must reach unnest() as a real array');
      assert.equal(matched[0].assetId, nativeId);
      assert.equal(matched[0].confidence, 'LOW');

      // Named separately: the same real query must find nothing.
      const unrelated = await run(
        ' microsoft announced quarterly results today exchange_server popularity grew ',
      );
      assert.deepEqual(unrelated, [], 'co-occurrence in unrelated sentences is not a match');
    } finally {
      await pool.end();
      await control.query(`DROP SCHEMA ${schema} CASCADE`);
      await control.end();
    }
  },
);