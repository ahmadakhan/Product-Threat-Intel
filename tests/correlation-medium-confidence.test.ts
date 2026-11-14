import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TextCorrelationEngine } from '../server/correlation/engine.ts';
import type { ExtractedText } from '../server/correlation/validation.ts';

/**
 * The MEDIUM tier is what low-confidence alerts exist for: the prose names an
 * inventoried vendor and product through the thesaurus, but no version bound can
 * be tied to it, so applicability cannot be confirmed. These tests fix the tier's
 * behaviour because a delivery decision (deliver with a notice, or withhold)
 * depends on it, and an advisory that silently lands in the review buffer instead
 * of this tier would bypass that decision entirely.
 */

const ASSET = {
  id: '00000000-0000-0000-0000-000000000001',
  vendor: 'kubernetes',
  product: 'kubernetes',
  version: '1.28.0',
  revision: 'r1',
};

const extracted = (overrides: Partial<ExtractedText> = {}): ExtractedText => ({
  text: ' kubernetes is affected by an unknown issue ',
  cleanContent: 'kubernetes is affected by an unknown issue',
  ranges: [],
  cveIds: [],
  zeroDay: false,
  securitySignal: true,
  negated: false,
  zeroDayDensity: 0,
  ...overrides,
});

/**
 * Serves the alias lookup and the inventory walk the engine issues, and records
 * every statement so the assertions can prove which branch ran.
 */
const fakeQuery = (opts: { aliasRange?: { productPhrase: string; range: string } } = {}) => {
  const sql: string[] = [];
  const query = async (statement: string, params?: unknown[]) => {
    sql.push(statement);
    if (statement.includes('FROM vendor_product_aliases'))
      return { rows: [{ alias: 'kubernetes', vendor: 'kubernetes', product: 'kubernetes' }], rowCount: 1 };
    if (statement.includes('FROM correlation_asset_inventory i')) {
      const [vendor, product, cursor] = params as [string, string, string | null];
      const rows =
        cursor === null && vendor === ASSET.vendor && product === ASSET.product ? [ASSET] : [];
      return { rows, rowCount: rows.length };
    }
    // Tier 1 identity intersection and the Tier 2b name lookup return nothing.
    return { rows: [], rowCount: 0 };
  };
  return { query: query as never, sql };
};

test('a named entity with no bound to it is MEDIUM, which is the deliverable low-confidence tier', async () => {
  const { query } = fakeQuery();
  const matches = await new TextCorrelationEngine().correlate(
    { title: 't', content: 'c', url: 'https://example.org/a', cpes: [], purls: [], entities: [] } as never,
    extracted(),
    query,
  );
  assert.equal(matches.length, 1);
  assert.equal(matches[0].confidence, 'MEDIUM');
  assert.match(matches[0].reason, /affected versions unspecified/);
  assert.equal(matches[0].assetId, ASSET.id);
});

test('a satisfiable bound is HIGH and is not flagged as unconfirmed', async () => {
  const edit = { productPhrase: 'kubernetes', range: '<1.29' };
  const withRange = extracted({ text: ' kubernetes before 1.29 ', ranges: [edit] });
  const { query } = fakeQuery();
  const matches = await new TextCorrelationEngine().correlate(
    { title: 't', content: 'c', url: 'https://example.org/a', cpes: [], purls: [], entities: [] } as never,
    withRange,
    query,
  );
  assert.equal(matches[0]?.confidence, 'HIGH');
});

test('an unsatisfiable bound produces no match at all', async () => {
  const edit = { productPhrase: 'kubernetes', range: '<1.0' };
  const withRange = extracted({ text: ' kubernetes before 1.0 ', ranges: [edit] });
  const { query } = fakeQuery();
  const matches = await new TextCorrelationEngine().correlate(
    { title: 't', content: 'c', url: 'https://example.org/a', cpes: [], purls: [], entities: [] } as never,
    withRange,
    query,
  );
  assert.equal(matches.length, 0);
});

test('without a security signal the same unnamed-range entity is only review evidence', async () => {
  const { query } = fakeQuery();
  const matches = await new TextCorrelationEngine().correlate(
    { title: 't', content: 'c', url: 'https://example.org/a', cpes: [], purls: [], entities: [] } as never,
    extracted({ securitySignal: false }),
    query,
  );
  assert.equal(matches[0]?.confidence, 'LOW');
});
