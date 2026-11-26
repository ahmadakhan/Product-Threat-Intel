import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isRenderableReferenceUrl, referenceUrlValue } from '../server/validation.ts';

/**
 * Ingest-time reference URL salvage.
 *
 * `referenceUrlValue` backs the schema's `referenceUrl` rule at ingestion. It
 * exists so a single malformed feed-controlled link (embedded credentials, a
 * non-http scheme, a non-URL) nulls that one field instead of rejecting the
 * whole CVE. These cases pin the exact accept/reject contract.
 */
test('referenceUrlValue preserves well-formed http(s) links', () => {
  assert.equal(referenceUrlValue('https://vendor.example/advisory'), 'https://vendor.example/advisory');
  assert.equal(referenceUrlValue('http://vendor.example/advisory'), 'http://vendor.example/advisory');
  // Query strings and fragments are part of the URL and are preserved verbatim.
  assert.equal(
    referenceUrlValue('https://vendor.example/a?b=c&d=e#frag'),
    'https://vendor.example/a?b=c&d=e#frag',
  );
});

test('referenceUrlValue drops links with embedded credentials', () => {
  assert.equal(referenceUrlValue('https://user:secret@vendor.example/advisory'), '');
  assert.equal(referenceUrlValue('https://user@vendor.example/advisory'), '');
});

test('referenceUrlValue drops non-http(s) schemes and non-URLs', () => {
  assert.equal(referenceUrlValue('javascript:alert(1)'), '');
  assert.equal(referenceUrlValue('data:text/html,<script>alert(1)</script>'), '');
  assert.equal(referenceUrlValue('ftp://vendor.example/advisory'), '');
  assert.equal(referenceUrlValue('not a url'), '');
  assert.equal(referenceUrlValue('/relative/path'), '');
});

test('referenceUrlValue handles empty and non-string input', () => {
  assert.equal(referenceUrlValue(''), '');
  assert.equal(referenceUrlValue(undefined), '');
  assert.equal(referenceUrlValue(null), '');
  assert.equal(referenceUrlValue(42), '');
  assert.equal(referenceUrlValue({ url: 'https://vendor.example' }), '');
});

test('referenceUrlValue enforces the 2048-character ceiling', () => {
  const base = 'https://vendor.example/';
  const ok = base + 'a'.repeat(2048 - base.length);
  assert.equal(ok.length, 2048);
  assert.equal(referenceUrlValue(ok), ok);
  assert.equal(referenceUrlValue(`${ok}a`), '');
});

test('isRenderableReferenceUrl agrees with referenceUrlValue on accept/reject', () => {
  for (const value of [
    'https://vendor.example/advisory',
    'http://vendor.example/advisory',
    'https://user:secret@vendor.example/advisory',
    'javascript:alert(1)',
    'not a url',
    '',
  ]) {
    assert.equal(
      isRenderableReferenceUrl(value),
      referenceUrlValue(value) === value && value !== '',
      `disagreement for ${JSON.stringify(value)}`,
    );
  }
});
