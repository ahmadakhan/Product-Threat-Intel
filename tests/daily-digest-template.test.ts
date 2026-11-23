import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_DAILY_DIGEST_TEMPLATE,
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  compileDailyDigestTemplate,
  renderDailyDigest,
  digestBadgeSeverity,
  type DailyDigestParts,
} from '../src/utils/templateCompiler.ts';

/**
 * The Daily Digest Studio, the preview canvas and the delivered email must all
 * use one document. These tests pin that contract:
 *
 *  - the shipped default compiles to itself (the studio never silently rewrites
 *    the canonical markup);
 *  - every placeholder the template references is supplied by the renderer;
 *  - a digest with no findings still renders a valid badge instead of a blank
 *    header cell.
 */

const parts = (overrides: Partial<DailyDigestParts> = {}): DailyDigestParts => ({
  advisory_id: 'ADV-DAILY_20261123',
  advisory_title: 'Daily Vulnerability Notification - 23 Nov 2026',
  dispatch_date: '23 Nov 2026',
  severity: 'HIGH',
  finding_count: 3,
  severity_counts: 'Critical 1 | High 2',
  findings_summary: '<ul><li>CVE-2026-0001</li></ul>',
  health_report: '<span>Database connected</span>',
  recipient_name: 'Security Team',
  critical_count: 1,
  high_count: 2,
  medium_count: 0,
  low_count: 0,
  asset_count: 2,
  executive_summary: '<p>One critical finding requires action.</p>',
  report_generated: '23 Nov 2026, 09:00 UTC',
  critical_summary: '<span>1</span>',
  high_summary: '<span>2</span>',
  medium_summary: '',
  low_summary: '',
  critical_kpi: '<td>1</td>',
  high_kpi: '<td>2</td>',
  medium_kpi: '',
  low_kpi: '',
  held_for_review: '',
  ...overrides,
});

const placeholdersIn = (html: string) =>
  [...new Set(html.match(/\{\{\{?\s*[a-zA-Z0-9_]+\s*\}?\}\}/g) ?? [])].map((token) =>
    token.replace(/[{}]/g, '').trim(),
  );

test('the shipped digest customization compiles to the canonical template unchanged', () => {
  assert.equal(compileDailyDigestTemplate(DEFAULT_DAILY_DIGEST_CUSTOMIZATION), DEFAULT_DAILY_DIGEST_TEMPLATE);
});

test('the canonical template is the BA Security Advisory digest document', () => {
  assert.match(DEFAULT_DAILY_DIGEST_TEMPLATE, /<title>\{\{advisory_id\}\} \| Daily Vulnerability Notification<\/title>/);
  assert.match(DEFAULT_DAILY_DIGEST_TEMPLATE, /BA Security Advisory/);
  assert.match(DEFAULT_DAILY_DIGEST_TEMPLATE, /24-HOUR EXPOSURE &amp; ASSET SNAPSHOT/);
  assert.match(DEFAULT_DAILY_DIGEST_TEMPLATE, /DIGEST DETAILS &amp; PLATFORM TELEMETRY/);
  assert.match(DEFAULT_DAILY_DIGEST_TEMPLATE, /BA Security Operations/);
  assert.match(
    DEFAULT_DAILY_DIGEST_TEMPLATE,
    /mailto:DL-HBS-Cyber-Operations@HoneywellProd\.onmicrosoft\.com/,
  );
});

test('every placeholder in the template is rendered with a value', () => {
  const output = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, parts());
  assert.deepEqual(placeholdersIn(output), [], 'no template token may survive rendering');
  assert.match(output, /<meta name="dispatch-date" content="23 Nov 2026">/);
  assert.match(output, /<meta name="digest-severity" content="HIGH">/);
  // The TOTAL FINDINGS KPI figure must carry the real count. Anchored to its
  // own label rather than a bare `>3<`, which would match any integer on the
  // page. Whitespace-tolerant: the canonical document may place the value and
  // its label on the same line or on separate lines.
  assert.match(
    output,
    />\s*3<\/div>\s*<div\s+style="[^"]*">\s*TOTAL FINDINGS<\/div>/,
    'the TOTAL FINDINGS KPI must render the real finding count',
  );
});

test('a digest with no findings still renders a valid severity badge', () => {
  const output = renderDailyDigest(
    DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
    parts({ severity: 'UNKNOWN', finding_count: 0, critical_count: 0, high_count: 0 }),
  );
  const cell = output.match(/<td valign="top" align="right" style="white-space: nowrap;">\s*([\s\S]*?)<\/td>/);
  assert.ok(cell, 'the header badge cell must exist');
  assert.match(cell[1], /NO NEW FINDINGS/, 'an empty digest must not render a blank badge');
  assert.match(output, /<meta name="digest-severity" content="UNKNOWN">/);
});

test('digestBadgeSeverity normalises unknown or empty input', () => {
  assert.equal(digestBadgeSeverity('critical'), 'CRITICAL');
  assert.equal(digestBadgeSeverity(' HIGH '), 'HIGH');
  assert.equal(digestBadgeSeverity(''), 'UNKNOWN');
  assert.equal(digestBadgeSeverity(null), 'UNKNOWN');
  assert.equal(digestBadgeSeverity(undefined), 'UNKNOWN');
  assert.equal(digestBadgeSeverity('weird'), 'UNKNOWN');
});

test('customization changes colours without breaking the document', () => {
  const output = renderDailyDigest(
    { ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION, accentColor: '#ff0000', canvasBg: '#eeeeee' },
    parts(),
  );
  assert.match(output, /#ff0000/, 'the chosen accent must reach the document');
  assert.match(output, /#eeeeee/, 'the chosen canvas colour must reach the document');
  assert.deepEqual(placeholdersIn(output), []);
});
