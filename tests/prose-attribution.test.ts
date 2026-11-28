import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesWatchlistItem } from '../src/utils/cpeMatcher.ts';
import { exposureRoleOf, proseAttributesExposure } from '../src/utils/textEvidenceRefinements.ts';

/**
 * The prose fallback used to decide "is this identity too generic?" from an
 * enumerated list of platform, language and delivery words. A list is an
 * open-ended enumeration: it catches the names present when it was written and
 * misses every framework released afterwards, so the false positive it fixed
 * (an inventory item `PHP / PHP` matched by "written in PHP") returns under a
 * new product name. These tests pin the vocabulary-independent replacement:
 * attribution is decided from the grammar of the sentence, not from a list of
 * words.
 */

const cpe = (vendor: string, product: string, version = '*') =>
  `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

const HIDDEN_FRAMEWORK_TITLE = 'Checkout export endpoint disclosure';
const HIDDEN_FRAMEWORK_DESCRIPTION =
  'A vulnerability in the Acme Storefront checkout module allows an unauthenticated attacker to read order records via the export endpoint.';

test('an unlisted framework named only as an environment does not match that product', () => {
  // "Acme Storefront" is deliberately absent from every stop-list: the rule is
  // structural, so it needs no entry here.
  for (const [vendor, product] of [
    ['Acme Storefront', 'Acme Storefront'],
    ['Quicksilver', 'Quicksilver'],
    ['Nimbus Edge', 'Nimbus Edge'],
  ]) {
    const result = matchesWatchlistItem(
      [],
      vendor,
      product,
      [cpe('other', 'unrelated')],
      HIDDEN_FRAMEWORK_TITLE,
      HIDDEN_FRAMEWORK_DESCRIPTION,
    );
    assert.equal(result.matched, false, `${vendor}/${product} must not match on an environment mention`);
    assert.notEqual(result.method, 'VENDOR_PRODUCT_FALLBACK');
  }
});

test('the same advisory still matches the product that is actually described', () => {
  // The advisory is about Storefront; the module is part of it, not a separate
  // product, so a claim stated about Storefront itself is matched normally.
  const result = matchesWatchlistItem(
    [],
    'Acme',
    'Storefront',
    [cpe('other', 'unrelated')],
    'Acme export endpoint flaw',
    'A vulnerability in Acme Storefront allows an unauthenticated attacker to read order records via the export endpoint.',
  );
  assert.equal(result.matched, true);
  assert.equal(result.method, 'VENDOR_PRODUCT_FALLBACK');
  assert.equal(result.confidence, 70);
});

test('a self-referential generic identity still matches its own advisory', () => {
  // The earlier fix must not turn into over-suppression: strict identity still
  // matches when the advisory genuinely states the exposure about the product.
  for (const [vendor, product, title, description] of [
    ['PHP', 'PHP', 'PHP remote code execution', 'A flaw in PHP allows remote code execution.'],
    ['Django', 'Django', 'Django path traversal', 'Django is vulnerable to a path traversal.'],
    ['Go', 'Go', 'Go standard library denial of service', 'A flaw in Go allows a remote denial of service.'],
  ]) {
    const result = matchesWatchlistItem([], vendor, product, [], title, description);
    assert.equal(result.matched, true, `${vendor}/${product} must still match its own advisory`);
    assert.equal(result.method, 'VENDOR_PRODUCT_FALLBACK');
  }
});

test('a self-referential generic identity does not match an unrelated advisory naming it', () => {
  const result = matchesWatchlistItem(
    [],
    'PHP',
    'PHP',
    [cpe('sourcecodester', 'basic_hotel_online_reservation_system')],
    'SourceCodester Basic Hotel Online Reservation System SQL injection',
    'A SQL injection vulnerability in SourceCodester Basic Hotel Online Reservation System allows remote attackers to execute arbitrary SQL commands via the id parameter in PHP.',
  );
  assert.equal(result.matched, false);
});

test('attribution needs the product in subject position, not merely named', () => {
  const cases: Array<[string, boolean]> = [
    // Subject position: the claim is about the product.
    ['A flaw in Acme Storefront allows XSS.', true],
    ['Acme Storefront is affected by a remote code execution flaw.', true],
    ['Acme Storefront vulnerability Versions before 2.0 are affected.', true],
    ['A flaw was found in the Acme Storefront product family.', true],
    // Environment, dependency, modifier or remediation: no claim about it.
    ['An application written in Acme Storefront allows XSS.', false],
    ['The Acme Storefront plugin that ships with WordPress allows XSS.', false],
    ['Acme Storefront 2.0 fixes the issue.', false],
    ['Attackers reached the portal running on Acme Storefront.', false],
    ['Acme Storefront is not affected by this flaw.', false],
  ];
  for (const [description, expected] of cases) {
    const text = `Acme Storefront security notice. ${description}`;
    assert.equal(proseAttributesExposure(text, 'acme', 'storefront', false).stated, expected, description);
  }
});

test('exposure roles distinguish absent, mentioned and stated', () => {
  assert.equal(exposureRoleOf('Acme Widget is affected.', 'acme widget'), 'subject');
  assert.equal(exposureRoleOf('An app written in Acme Widget allows XSS.', 'acme widget'), 'mention');
  assert.equal(exposureRoleOf('Nothing relevant here.', 'acme widget'), 'absent');
});

test('generic identities are exempt from the two-name requirement but not from attribution', () => {
  // A same-word identity cannot supply two independent names; it is judged on
  // the identity alone, and an environment mention still fails.
  assert.equal(proseAttributesExposure('Written in PHP.', 'php', 'php', true).stated, false);
  assert.equal(proseAttributesExposure('A flaw in PHP allows XSS.', 'php', 'php', true).stated, true);
});

test('the vendor may sit in a distinct clause from the exposure-stating product', () => {
  // The design the fallback is built on: the *product phrase* carries the exposure,
  // the *vendor* supplies the identity, and the two may be in different clauses.
  // This is the ordinary advisory shape (a vendor headline plus a body sentence).
  const paired = 'Acme publishes a bulletin. A flaw in Storefront allows uploads.';
  assert.equal(proseAttributesExposure(paired, 'Acme', 'Storefront').stated, true);

  // The same clause, with the vendor as a modifier of the subject.
  assert.equal(
    proseAttributesExposure('A flaw in Acme Storefront allows uploads.', 'Acme', 'Storefront').stated,
    true,
  );

  // What the vendor clause cannot do is be absent: the product alone is not
  // vendor-plus-product evidence.
  assert.equal(
    proseAttributesExposure('A flaw in Storefront allows uploads.', 'Acme', 'Storefront').stated,
    false,
  );
});

test('a product nested inside another product name is not attributed to it', () => {
  // The reported failure mode of an enumerated stop-list: a new product name whose
  // first word is the identity. No list needs extending for this.
  const text = 'A SQL injection in the Acme PHP Builder plugin allows file uploads.';
  assert.equal(proseAttributesExposure(text, 'Acme', 'PHP').stated, false);
  assert.equal(proseAttributesExposure(text, 'Acme Storefront', 'Storefront').stated, false);
  // The same shape as a real subject keeps the first word inside the name.
  assert.equal(
    proseAttributesExposure(
      'Atlassian Confluence Data Center is vulnerable to RCE.',
      'Atlassian',
      'Confluence',
    ).stated,
    true,
  );
});

test('a bare name that only begins another product name is not that product', () => {
  // "Ferrum" appears only as the first word of "Ferrum Builder plugin". The head
  // noun (`plugin`) is what the predicate is about, so the fallback must not
  // attribute the advisory to Ferrum. This used to be an accepted limitation; the
  // structural rule now separates it from a longer *subject* name such as
  // "Atlassian Confluence Data Center is vulnerable".
  const result = matchesWatchlistItem(
    [],
    'Acme',
    'Ferrum',
    [cpe('other', 'unrelated')],
    'Acme Corp Ferrum Builder plugin file upload',
    'A SQL injection in the Acme Corp Ferrum Builder plugin allows file uploads.',
  );
  assert.equal(result.matched, false);
  assert.notEqual(result.method, 'VENDOR_PRODUCT_FALLBACK');
});

test('a longer subject name keeps the first word as part of the affected product', () => {
  // The converse shape must not be swept up by the rule above: here the compound
  // noun is the clause subject, so its first word is inside the affected name.
  const result = matchesWatchlistItem(
    [],
    'Acme',
    'Ferrum',
    [cpe('other', 'unrelated')],
    'Ferrum Builder security notice',
    'Acme Corp Ferrum Builder is vulnerable to a SQL injection.',
  );
  assert.equal(result.matched, true);
  assert.equal(result.method, 'VENDOR_PRODUCT_FALLBACK');
});
