import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  countDigestSeverities,
  formatDigestSeverityCounts,
  digestSeverityKpi,
  renderDailyDigest,
  type DigestFinding,
  type DailyDigestParts,
} from '../src/utils/templateCompiler.ts';

/**
 * The digest's KPI card claims four numbers: total findings, assets, and a count
 * for each severity band. Every one of them has to be derived from the same
 * finding list, normalised the same way, and rendered even when it is zero -
 * otherwise the card contradicts the breakdown printed beneath it.
 */

const finding = (severity: string, asset: string): DigestFinding => ({
  cveId: `CVE-${severity}-${asset}`,
  severity,
  assetName: asset,
});

test('severity counts are case- and whitespace-normalised', () => {
  const counts = countDigestSeverities([
    finding('CRITICAL', 'a'),
    finding('critical', 'b'),
    finding(' HIGH ', 'c'),
    finding('Medium', 'd'),
  ]);
  assert.equal(counts.CRITICAL, 2);
  assert.equal(counts.HIGH, 1);
  assert.equal(counts.MEDIUM, 1);
  assert.equal(counts.LOW, 0);
  assert.equal(counts.UNKNOWN, 0);
});

test('an unrecognised severity is UNKNOWN rather than a new bucket', () => {
  const counts = countDigestSeverities([finding('SEVERE', 'a'), finding('', 'b')]);
  assert.equal(counts.UNKNOWN, 2);
  // No stray key was invented, so the breakdown cannot print a phantom band.
  assert.deepEqual(Object.keys(counts).sort(), ['CRITICAL', 'HIGH', 'LOW', 'MEDIUM', 'UNKNOWN']);
});

test('the severity total always equals the number of findings', () => {
  const findings = [
    finding('CRITICAL', 'a'),
    finding('LOW', 'b'),
    finding('LOW', 'c'),
    finding('nonsense', 'd'),
  ];
  const counts = countDigestSeverities(findings);
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
  assert.equal(total, findings.length, 'no finding is dropped or double-counted');
});

test('the formatted breakdown lists only non-zero bands', () => {
  assert.equal(
    formatDigestSeverityCounts({ CRITICAL: 2, HIGH: 1, MEDIUM: 0, LOW: 0, UNKNOWN: 0 }),
    '2 critical, 1 high',
  );
  assert.equal(
    formatDigestSeverityCounts({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 3 }),
    '3 unknown',
  );
});

test('an empty band still renders a KPI tile showing zero', () => {
  // Returning '' collapsed the tile, which removed a column from the grid and
  // made the card show fewer severities than the breakdown beneath it.
  for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
    const html = digestSeverityKpi(severity, 0, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
    assert.ok(html.includes('>0<'), `${severity} must render a visible 0`);
    assert.ok(/bgcolor="#[0-9a-f]{6}"/i.test(html), `${severity} must keep its tile background`);
  }
});

test('a non-zero band renders its exact count', () => {
  const html = digestSeverityKpi('HIGH', 7, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('>7<'));
});

/**
 * End-to-end: the rendered document, not just the parts fed into it.
 *
 * A digest whose parts disagree with the finding list is the failure mode this
 * guards: the card would print a total that the breakdown beneath it
 * contradicts. The header row of the KPI card is the only place the total is
 * printed, so its value has to equal the number of findings, and the assets
 * tile has to equal the number of distinct assets.
 */
test('the rendered card states the true total and asset count', () => {
  const findings: DigestFinding[] = [
    finding('CRITICAL', 'edge-router-01'),
    finding('critical', 'auth-service'),
    finding(' HIGH ', 'portal-web'),
    finding('THING', 'weird'),
    finding('MEDIUM', 'edge-router-01'), // same asset as the first finding
  ];
  const counts = countDigestSeverities(findings);
  const uniqueAssets = new Set(findings.map((f) => f.assetName)).size;
  const kpi = (severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW') =>
    digestSeverityKpi(severity, counts[severity], DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  const parts: DailyDigestParts = {
    advisory_id: 'ADV-1',
    advisory_title: 'Daily',
    dispatch_date: new Date('2026-11-28T00:00:00Z').toISOString(),
    severity: 'CRITICAL',
    finding_count: findings.length,
    severity_counts: formatDigestSeverityCounts(counts),
    findings_summary: '',
    health_report: '',
    recipient_name: 'Team',
    critical_count: counts.CRITICAL,
    high_count: counts.HIGH,
    medium_count: counts.MEDIUM,
    low_count: counts.LOW,
    critical_summary: '',
    high_summary: '',
    medium_summary: '',
    low_summary: '',
    critical_kpi: kpi('CRITICAL'),
    high_kpi: kpi('HIGH'),
    medium_kpi: kpi('MEDIUM'),
    low_kpi: kpi('LOW'),
    asset_count: uniqueAssets,
    executive_summary: 'Summary',
    report_generated: 'now',
    held_for_review: '',
  };
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, parts);

  // Every band renders its own exact count; nothing is merged or dropped.
  assert.equal(counts.CRITICAL, 2);
  assert.equal(counts.HIGH, 1);
  assert.equal(counts.MEDIUM, 1);
  assert.equal(counts.LOW, 0);
  assert.equal(counts.UNKNOWN, 1);
  assert.equal(
    Object.values(counts).reduce((sum, value) => sum + value, 0),
    findings.length,
    'the rendered total must equal the number of findings',
  );

  // The document carries the total and the distinct-asset count verbatim. Both
  // tiles indent their value with newlines before the closing tag, so read the
  // cell content rather than matching a bare `>N<` substring.
  const totalCell = /style="font-size: 20px; line-height: 24px; font-weight: 700; color: #0f172a[^"]*">\s*(\d+)\s*<\/div>/.exec(html)?.[1];
  assert.equal(totalCell, String(findings.length), 'total findings rendered verbatim');
  const assetCell = /color: #1d4ed8[^"]*">\s*(\d+)\s*<\/div>/.exec(html)?.[1];
  assert.equal(assetCell, String(uniqueAssets), 'distinct assets rendered verbatim');
  assert.equal(uniqueAssets, 4, 'a repeated asset is not double-counted');

  // No unresolved placeholder survived the render.
  assert.deepEqual(html.match(/\{\{[^}]+\}\}/g) ?? [], []);
  assert.ok(!html.includes('undefined'));
});
