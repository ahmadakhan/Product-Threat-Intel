import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderAdvisory } from '../server/advisoryRender.ts';
import { MAX_TEMPLATE_BLOCK_DEPTH, renderEmailTemplate } from '../src/utils/emailTemplate.ts';
import type { Advisory, Finding } from '../src/types/index.ts';

/**
 * Regression suite for the shared email-template engine and the advisory
 * renderer that wraps it.
 *
 * Each test pins a defect that shipped in the previous renderer:
 *
 *  - `server/advisoryRender.ts` kept a second, hand-rolled block engine beside
 *    the shared one. It started a block body one character after the opening
 *    tag (swallowing a literal `<` as "partial block" syntax) and its close-tag
 *    regex did not accept `{{else}}`, so a three-level severity chain collapsed
 *    to its LOW branch and every template with a nested `if` shipped the wrong
 *    content while the Studio preview showed the right one.
 *  - The tokeniser made the closing `}}` optional, so a body of stray braces
 *    caused quadratic regex backtracking (~25s for 50k braces) on the request
 *    thread.
 *  - Nesting was unbounded, so a deeply nested template escaped as a raw
 *    `RangeError: Maximum call stack size exceeded` from the dispatch path.
 *  - Lookup used `in`, so `{{constructor}}` / `{{__proto__}}` resolved engine
 *    internals instead of being treated as unknown placeholders.
 */

const finding = (n: number, severity: string): Finding =>
  ({
    id: `f${n}`,
    cveId: `CVE-2026-100${n}`,
    cve: {
      cveId: `CVE-2026-100${n}`,
      title: 't',
      description: 'A vendor description.',
      cvss: { score: 7, severity, vector: '', version: '3.1' },
      cpeMatches: [],
      cwe: [],
      sourceFeeds: [],
      publishedDate: '2026-11-19T00:00:00Z',
      modifiedDate: '2026-11-19T00:00:00Z',
      // No listed actions: the per-CVE guidance falls back to its built sentence.
      remediation: { immediateActions: [], patchUrl: '', vendorAdvisoryRef: '' },
    },
    matchedAssetId: `a${n}`,
    matchedAssetName: `host-0${n}`,
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'widget',
    matchedCpe: '',
    matchingMethod: 'CPE',
    matchingEvidence: 'e',
    confidence: 90,
    exposure: 'INTERNAL',
    exploitRisk: 'STANDARD',
    dispatchDeferred: false,
    notificationStatus: 'QUEUED_FOR_DISPATCH',
    status: 'MONITORED',
    autoDispatchedAt: null,
    advisoryId: null,
    reviewNotifiedAt: null,
    timeline: [],
  }) as unknown as Finding;

const advisory = (findings: Finding[]): Advisory =>
  ({
    id: 'ADV-1',
    title: 'T',
    severity: 'CRITICAL',
    cveIds: findings.map((f) => f.cveId),
    findingIds: findings.map((f) => f.id),
    createdDate: '2026-11-19T00:00:00Z',
    deliveryStatus: 'PENDING',
    recipientCount: 1,
    executiveSummary: 'Summary.',
    remediationInstructions: 'Remediate.',
    affectedSystems: ['host'],
  }) as unknown as Advisory;

// Findings are passed as the third argument so the ``cves`` scope exists; the
// advisory's cveIds also drive the remediation field. Default: same list.
const render = (template: string, findings: Finding[]) =>
  renderAdvisory(template, advisory(findings), findings, { generatedAt: new Date('2026-11-19T11:12:00Z') });

test('the live advisory renderer keeps literal "<" after a block tag', () => {
  // "Partial block" syntax is `{{#> name}}`; a block body starts right after
  // `}}`, so `<` here is markup and must survive.
  const out = render('{{#each cves}}<b>{{id}}</b>{{/each}}', [finding(1, 'CRITICAL')]);
  assert.ok(out.startsWith('<b>CVE-2026-1001</b>'), `body preserved, got ${JSON.stringify(out)}`);
});

test('a top-level nested if/else chain resolves per item in the live renderer', () => {
  const tpl =
    '{{#each cves}}{{#if is_critical}}C{{else}}{{#if is_high}}H{{else}}{{#if is_medium}}M{{else}}L{{/if}}{{/if}}{{/if}};{{/each}}';
  const out = render(tpl, [
    finding(1, 'CRITICAL'),
    finding(2, 'HIGH'),
    finding(3, 'MEDIUM'),
    finding(4, 'LOW'),
  ]);
  // The old regex start-tag matcher could not see `{{else}}` as a block token,
  // so it paired the inner closes with the outer opens and returned L,L,L,L.
  assert.equal(out, 'C;H;M;L;');
});

test('every close tag consumes no content and leaves no brace behind', () => {
  const out = render('{{#if is_top_critical}}x{{/if}}', [finding(1, 'CRITICAL')]);
  assert.equal(out, 'x');
});

test('block keywords are case-insensitive, matching the openers', () => {
  // Openers were already matched with the `i` flag; mismatched close/else tags
  // previously leaked as literal `{{/IF}}` text into the delivered body.
  const out = renderEmailTemplate('{{#IF a}}A{{ELSE}}B{{/IF}}', { a: false });
  assert.equal(out, 'B');
  assert.equal(renderEmailTemplate('{{#Each xs}}{{This}}{{/EACH}}', { xs: [1, 2] }), '12');
});

test('nested block depth beyond the cap is rejected with an actionable error', () => {
  const deep = '{{#if is_top_critical}}'.repeat(MAX_TEMPLATE_BLOCK_DEPTH + 5) + 'x' + '{{/if}}'.repeat(MAX_TEMPLATE_BLOCK_DEPTH + 5);
  assert.throws(
    () => render(deep, [finding(1, 'CRITICAL')]),
    /nest deeper than 100 levels/,
    'a stack overflow must not escape as a RangeError',
  );
  // At the cap the template still renders.
  const atCap = '{{#if is_top_critical}}'.repeat(MAX_TEMPLATE_BLOCK_DEPTH) + 'x' + '{{/if}}'.repeat(MAX_TEMPLATE_BLOCK_DEPTH);
  assert.equal(render(atCap, [finding(1, 'CRITICAL')]), 'x');
});

test('stray braces are scanned in linear time instead of backtracking', () => {
  const template = '{{'.repeat(50_000);
  const started = process.hrtime.bigint();
  const out = renderEmailTemplate(template, {});
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.equal(out, template, 'unmatched braces are text, not a partial render');
  // The previous pattern took ~25 seconds here; a generous ceiling still catches
  // a return to quadratic behaviour without being flaky on a loaded runner.
  assert.ok(elapsedMs < 2_000, `stray-brace scan took ${elapsedMs.toFixed(0)}ms`);
});

test('inherited object members are not template values', () => {
  assert.equal(renderEmailTemplate('[{{constructor}}]', {}), '[]');
  assert.equal(renderEmailTemplate('[{{__proto__}}]', {}), '[]');
  assert.equal(renderEmailTemplate('[{{toString}}]', {}), '[]');
  // An own property with the same name still resolves.
  assert.equal(renderEmailTemplate('[{{constructor}}]', { constructor: 'mine' }), '[mine]');
});

test('a no-steps template still renders the vendor-availability sentence', () => {
  // The sentence is chosen by `patchHref || vendorHref ? ... : ...`; WITHOUT a
  // patch it must state that no fix is assumed, and WITH one it must point at
  // the vendor. The ternary is what this pins, not the wording.
  const bare = finding(1, 'CRITICAL');
  const patched = finding(2, 'CRITICAL');
  (patched.cve.remediation as { patchUrl: string }).patchUrl = 'https://vendor.example/patch';
  // `remediation_steps` is a registered raw-HTML token carrying the per-CVE
  // guidance block; it is the field this sentence is built into.
  const out = render('{{{remediation_steps}}}', [bare, patched]);
  assert.ok(out.includes('No vendor patch or fix guidance is supplied'), 'no-patch sentence present');
  assert.ok(out.includes('Follow only remediation steps documented by the vendor'), 'patch sentence present');
});
