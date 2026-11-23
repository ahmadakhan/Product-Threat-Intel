import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { emptyState } from '../shared/state.ts';
import { advisoryEmail } from '../server/advisoryEmail.ts';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  DEFAULT_DAILY_DIGEST_TEMPLATE,
  compileDailyDigestTemplate,
  digestSeverityKpi,
  digestSeveritySummary,
  formatExecutiveSummary,
  renderDailyDigest,
  renderDailyFindingSummary,
  renderDailyHealthReport,
  renderHeldForReview,
  type DailyDigestParts,
  type DigestFinding,
  type DigestHealth,
} from '../src/utils/templateCompiler.ts';
import type { Advisory } from '../src/types/index.ts';

/**
 * The Daily Digest Studio shows one document in four surfaces:
 *
 *   - "HTML template"   the studio source pane (`dailyDigestTemplate`)
 *   - "Visual Canvas"   the iframe rendering the live customization
 *   - "Rendered"        preview values substituted into the same template
 *   - the delivered email body sent to recipients
 *
 * This suite pins the exact document those four surfaces must describe. The
 * fixture is the checked-in canonical HTML, not a second copy synthesized from
 * the constant, so an edit to `DEFAULT_DAILY_DIGEST_TEMPLATE` (a stray attribute,
 * a reordered table cell, a changed width) fails here instead of silently
 * shipping a different email from the one the studio shows.
 */
const CANONICAL = readFileSync('./tests/fixtures/canonical-daily-digest-template.html', 'utf8')
  .replace(/\r\n/g, '\n')
  .replace(/\n$/, '');

/** Every placeholder the canonical document declares. */
const EXPECTED_PLACEHOLDERS = [
  'advisory_id',
  'advisory_title',
  'asset_count',
  'critical_kpi',
  'critical_summary',
  'dispatch_date',
  'executive_summary',
  'finding_count',
  'findings_summary',
  'health_report',
  'held_for_review',
  'high_kpi',
  'high_summary',
  'low_kpi',
  'low_summary',
  'medium_kpi',
  'medium_summary',
  'report_generated',
  'severity',
  'severity_counts',
  'severity_header_badge',
];

const TOKEN = /\{\{\{?\s*([a-z_][a-z0-9_]*)\s*\}?\}\}/gi;

/** Placeholder names in document order. */
const tokens = (html: string): string[] => [...html.matchAll(TOKEN)].map((match) => match[1]);

/** Literal runs between placeholders; their concatenation is the document. */
const literals = (html: string): string[] => {
  const result: string[] = [];
  let cursor = 0;
  for (const match of html.matchAll(TOKEN)) {
    result.push(html.slice(cursor, match.index));
    cursor = (match.index ?? 0) + match[0].length;
  }
  result.push(html.slice(cursor));
  return result;
};

const FINDINGS: DigestFinding[] = [
  {
    cveId: 'CVE-2026-0001',
    severity: 'CRITICAL',
    assetName: 'edge-router-01',
    vendor: 'VendorX',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001',
    cvssScore: 9.8,
  },
  {
    cveId: 'CVE-2026-0002',
    severity: 'CRITICAL',
    assetName: 'auth-service',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0002',
    cvssScore: 9.1,
  },
  {
    cveId: 'CVE-2026-0003',
    severity: 'HIGH',
    assetName: 'portal-web',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0003',
    cvssScore: 8.5,
  },
  { cveId: 'CVE-2026-0004', severity: 'MEDIUM', assetName: 'internal-api' },
  { cveId: 'CVE-2026-0005', severity: 'LOW', assetName: 'monitoring-agent' },
];

const HEALTH: DigestHealth = {
  database: 'connected',
  databaseLatencyMs: 12,
  workerStatus: 'HEALTHY',
  workerHeartbeatAgeSeconds: 4,
  nextScheduledAttempt: '2026-10-30T09:00:00.000Z',
  nextDailyDigestAt: '2026-10-31T05:00:00.000Z',
  backlog: [
    { status: 'QUEUED', count: 0 },
    { status: 'ACCEPTED', count: 12 },
  ],
  checkedAt: '2026-10-29T08:00:00.000Z',
  systemUptime: '187 Days 14 Hours',
  systemUptimePercentage: null,
  pipelineJobs: { total: 0, succeeded: 0, failed: 0 },
};

const counts = { CRITICAL: 2, HIGH: 1, MEDIUM: 1, LOW: 1 };

const parts = (): DailyDigestParts => ({
  advisory_id: 'BA-DAILY_20261029',
  advisory_title: 'Daily Vulnerability Notification — 29Oct2026',
  dispatch_date: '2026-10-29T10:00:00.000Z',
  severity: 'HIGH',
  finding_count: FINDINGS.length,
  severity_counts: '2 critical, 1 high, 1 medium, 0 low',
  findings_summary: renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  health_report: renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  recipient_name: 'Team',
  critical_count: counts.CRITICAL,
  high_count: counts.HIGH,
  medium_count: counts.MEDIUM,
  low_count: counts.LOW,
  asset_count: 5,
  executive_summary: formatExecutiveSummary(FINDINGS.length, counts),
  report_generated: '29 October 2026 | 22:48 GMT+4',
  critical_summary: digestSeveritySummary('CRITICAL', counts.CRITICAL, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  high_summary: digestSeveritySummary('HIGH', counts.HIGH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  medium_summary: digestSeveritySummary('MEDIUM', counts.MEDIUM, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  low_summary: digestSeveritySummary('LOW', counts.LOW, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  critical_kpi: digestSeverityKpi('CRITICAL', counts.CRITICAL, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  high_kpi: digestSeverityKpi('HIGH', counts.HIGH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  medium_kpi: digestSeverityKpi('MEDIUM', counts.MEDIUM, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  low_kpi: digestSeverityKpi('LOW', counts.LOW, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  held_for_review: renderHeldForReview(0, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
});

/** Tag names in document order, with the closing forms marked. */
const tagNames = (html: string): string[] => [
  ...html.matchAll(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>/g),
].map((match) => (match[0].startsWith('</') ? `/${match[1]}` : match[1].toLowerCase()));

test('the studio template pane is the canonical document, byte for byte', () => {
  // The source pane (`getTemplateSource`), the template the AppContext exposes,
  // and the stock compile all resolve to this one document when the workspace has
  // not customized it.
  assert.equal(DEFAULT_DAILY_DIGEST_TEMPLATE, CANONICAL);
  assert.equal(
    compileDailyDigestTemplate(DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
    CANONICAL,
    'the stock customization must compile to the canonical document',
  );
  assert.equal(
    emptyState().dailyDigestTemplate,
    CANONICAL,
    'an untouched workspace must open the studio on the canonical document',
  );
});

test('the canonical document declares exactly the placeholders the studio fills', () => {
  assert.deepEqual([...new Set(tokens(CANONICAL))].sort(), EXPECTED_PLACEHOLDERS);
});

/**
 * The "Rendered" preview surface: preview values substituted into the same
 * document. It must keep the canonical structure and resolve every placeholder.
 */
test('rendering the canonical document resolves every placeholder and keeps its structure', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, parts());
  assert.equal(/\{\{\{?\s*[a-z_][a-z0-9_]*\s*\}?\}\}/i.test(html), false, 'no unresolved placeholders');
  // Every literal run of the canonical document survives, in order.
  let cursor = 0;
  for (const literal of literals(CANONICAL)) {
    if (!literal) continue;
    const at = html.indexOf(literal, cursor);
    assert.notEqual(at, -1, `canonical literal missing from rendered output: ${JSON.stringify(literal.slice(0, 60))}`);
    cursor = at + literal.length;
  }
});

/** The delivered email body must be the same document, wrapped by the mailer. */
test('the delivered digest email body carries the canonical document', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, parts());
  const advisory = {
    id: 'BA-DAILY_20261029',
    title: 'Daily Vulnerability Notification — 29Oct2026',
    severity: 'HIGH',
    cveIds: [],
    findingIds: [],
    createdDate: '2026-10-29T10:00:00.000Z',
    deliveryStatus: 'PENDING',
    recipientCount: 1,
    executiveSummary: 'Summary',
    remediationInstructions: '',
    affectedSystems: [],
  } as unknown as Advisory;
  const email = advisoryEmail(advisory, html);
  // The mailer may add its own chrome; the document itself must be present intact.
  assert.ok(email.html, 'the delivered email must carry an HTML body');
  assert.notEqual(email.html.indexOf(html), -1, 'the digest document must be embedded verbatim');
  assert.equal(tagNames(html).length > 0, true, 'the rendered document declares tags');
});
