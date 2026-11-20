import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { renderAdvisory } from '../server/advisoryRender.ts';
import type { Advisory, Finding } from '../src/types/index.ts';

/**
 * Template engine correctness for the enterprise notification template.
 *
 * The engine previously substituted with three chained regexes: `{{#if}}` was
 * matched non-greedily (so a three-level nested chain closed at the wrong tag),
 * `{{else}}` did not exist, and an item's array field could not be iterated.
 * The shipped template uses all three, so it rendered as static chrome with no
 * content. These tests pin the constructs it actually depends on.
 */

const finding = (n: number, severity: string, score: number): Finding =>
  ({
    id: `f${n}`,
    cveId: `CVE-2026-000${n}`,
    cve: {
      cveId: `CVE-2026-000${n}`,
      title: 't',
      description: 'A vendor description.',
      cvss: { score, severity, vector: '', version: '3.1' },
      cpeMatches: [],
      cwe: [],
      sourceFeeds: ['nvd'],
      publishedDate: '2026-11-19T00:00:00Z',
      modifiedDate: '2026-11-19T00:00:00Z',
      remediation: { immediateActions: ['Patch immediately.', 'Restrict access.'] },
    },
    matchedAssetId: `a${n}`,
    matchedAssetName: `host-0${n} (acme widget)`,
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

const render = (template: string, findings: Finding[]) =>
  renderAdvisory(template, advisory(findings), findings, { generatedAt: new Date('2026-11-19T11:12:00Z') });

test('nested if/else chains resolve the correct branch per item', () => {
  const tpl = '{{#each cves}}[{{id}}:{{#if is_critical}}C{{else}}{{#if is_high}}H{{else}}{{#if is_medium}}M{{else}}L{{/if}}{{/if}}{{/if}}]{{/each}}';
  const out = render(tpl, [
    finding(1, 'CRITICAL', 9.8),
    finding(2, 'HIGH', 7.5),
    finding(3, 'MEDIUM', 5.0),
    finding(4, 'LOW', 2.0),
  ]);
  assert.equal(out, '[CVE-2026-0001:C][CVE-2026-0002:H][CVE-2026-0003:M][CVE-2026-0004:L]');
});

test('an each over a string array renders every entry via {{this}}', () => {
  const out = render('{{#each cves}}{{#each mitigations}}<{{this}}>{{/each}}{{/each}}', [
    finding(1, 'CRITICAL', 9.8),
  ]);
  assert.ok(out.includes('<Patch immediately.>'), 'first mitigation renders');
  assert.ok(out.includes('<Restrict access.>'), 'second mitigation renders');
});

test('top-level values are escaped exactly once', () => {
  const tpl = '{{top_severity_label}}';
  const out = render(tpl, [finding(1, 'CRITICAL', 9.8), finding(2, 'HIGH', 7.5)]);
  assert.equal(out, 'CRITICAL &amp; HIGH', 'no double encoding');
});

test('the shipped enterprise template renders with no unresolved placeholders', () => {
  const template = readFileSync('./enterprise-vulnerability-notification-handlebars.html', 'utf8');
  const findings = [finding(1, 'CRITICAL', 9.8), finding(2, 'HIGH', 7.5)];
  const out = renderAdvisory(template, advisory(findings), findings, { generatedAt: new Date('2026-11-19T11:12:00Z') });
  const leftover = out.match(/\{\{[^}]+\}\}/g) ?? [];
  assert.deepEqual(leftover, [], 'every placeholder resolves');

  // Content, not just structure: the summary matrix and both detail cards.
  assert.ok(out.includes('Vulnerability Summary Matrix'));
  assert.ok(out.includes('CVE-2026-0001'));
  assert.ok(out.includes('CVE-2026-0002'));
  assert.ok(out.includes('CRITICAL (9.8)'), 'critical badge in the matrix');
  assert.ok(out.includes('HIGH (7.5)'), 'high badge in the matrix');
  assert.ok(out.includes('acme'), 'vendor column populated');
  assert.ok(out.includes('widget'), 'product column populated');
  assert.ok(out.includes('Patch immediately.'), 'per-CVE mitigation populated');
});

test('an unclosed block throws instead of emitting a partial document', () => {
  assert.throws(() => render('{{#if is_top_critical}}x', [finding(1, 'CRITICAL', 9.8)]), /Unclosed/);
});
