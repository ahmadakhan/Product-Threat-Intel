import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { advisoryEmail } from '../server/advisoryEmail.ts';
import { emptyState } from '../shared/state.ts';
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

const FINDINGS: DigestFinding[] = [
  {
    cveId: 'CVE-2026-0001',
    severity: 'CRITICAL',
    assetName: 'edge-router-01',
    vendor: 'VendorX',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001',
  },
  {
    cveId: 'CVE-2026-0002',
    severity: 'CRITICAL',
    assetName: 'auth-service',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0002',
  },
  {
    cveId: 'CVE-2026-0003',
    severity: 'HIGH',
    assetName: 'portal-web',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0003',
  },
  {
    cveId: 'CVE-2026-0004',
    severity: 'MEDIUM',
    assetName: 'internal-api',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0004',
  },
  {
    cveId: 'CVE-2026-0005',
    severity: 'LOW',
    assetName: 'monitoring-agent',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0005',
  },
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

const parts = (): DailyDigestParts => ({
  advisory_id: 'DAILY-2026-10-29',
  advisory_title: 'Daily Vulnerability Notification',
  dispatch_date: '2026-10-29T10:00:00.000Z',
  severity: 'HIGH',
  finding_count: FINDINGS.length,
  severity_counts: '2 critical, 1 high, 1 medium, 1 low',
  findings_summary: renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  health_report: renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  recipient_name: 'Team',
  critical_count: 2,
  high_count: 1,
  medium_count: 1,
  low_count: 1,
  asset_count: 5,
  executive_summary: formatExecutiveSummary(5, { CRITICAL: 2, HIGH: 1, MEDIUM: 1, LOW: 1 }),
  report_generated: '29 October 2026 | 22:48 GMT+4',
  critical_summary: digestSeveritySummary('CRITICAL', 2, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  high_summary: digestSeveritySummary('HIGH', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  medium_summary: digestSeveritySummary('MEDIUM', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  low_summary: digestSeveritySummary('LOW', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  critical_kpi: digestSeverityKpi('CRITICAL', 2, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  high_kpi: digestSeverityKpi('HIGH', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  medium_kpi: digestSeverityKpi('MEDIUM', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  low_kpi: digestSeverityKpi('LOW', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  held_for_review: renderHeldForReview(0, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
});

/**
 * The Daily Digest Studio labels its panes "HTML template", "Visual Canvas",
 * "Rendered (preview values)" and "Send Test Email". Those are four views of one
 * document; this suite pins the identities that make that true.
 */
test('the stock digest document is the studio default, not a stored copy', () => {
  const state = emptyState();
  assert.equal(state.dailyDigestTemplate, DEFAULT_DAILY_DIGEST_TEMPLATE);
  assert.equal(state.dailyDigestCustomTemplate, null, 'an untouched workspace sends the stock document');
  assert.deepEqual(state.dailyDigestCustomization, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.equal(
    compileDailyDigestTemplate(DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
    DEFAULT_DAILY_DIGEST_TEMPLATE,
    'the studio compile of the stock customization is the stock document itself',
  );
});

test('the canvas render is the stock template with its values substituted', () => {
  const source = new JSDOM(DEFAULT_DAILY_DIGEST_TEMPLATE).window.document;
  const rendered = new JSDOM(renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, parts())).window.document;

  // The stylesheet is carried through literally: a mail client is the only
  // thing allowed to interpret it, and a preview must not restyle it.
  assert.equal(
    rendered.querySelector('style')?.textContent,
    source.querySelector('style')?.textContent,
    'the canvas keeps the shipped stylesheet byte for byte',
  );
  // Machine-readable identity carried by the document, not by a wrapper.
  assert.equal(
    rendered.querySelector('meta[name="dispatch-date"]')?.getAttribute('content'),
    '2026-10-29T10:00:00.000Z',
  );
  assert.equal(rendered.querySelector('meta[name="digest-severity"]')?.getAttribute('content'), 'HIGH');
  assert.equal(rendered.title, 'DAILY-2026-10-29 | Daily Vulnerability Notification');

  // The three numbered sections and the footer survive the substitution: the
  // canvas is the shipped document, not a hand-built approximation of it.
  const body = rendered.body.textContent ?? '';
  for (const marker of [
    'DAILY VULNERABILITY DIGEST',
    'BA Security Advisory',
    '01',
    'EXECUTIVE SUMMARY',
    '02',
    '24-HOUR EXPOSURE & ASSET SNAPSHOT',
    '03',
    'DIGEST DETAILS & PLATFORM TELEMETRY',
    'Severity Breakdown',
    'Findings (24h)',
    'Confidence Follow-Up',
    'Platform Health',
    'BA Security Operations',
  ]) {
    assert.ok(body.includes(marker), `the rendered digest is missing "${marker}"`);
  }
  assert.ok(!rendered.documentElement.outerHTML.includes('{{'), 'no placeholder survives the render');
  assert.ok(!rendered.documentElement.outerHTML.includes('undefined'), 'no missing value renders literally');
});

test('the delivered email is the canvas document, byte for byte', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, parts());
  const advisory: Advisory = {
    id: 'DAILY-2026-10-29',
    title: 'Daily Vulnerability Notification',
    severity: 'HIGH',
    cveIds: ['CVE-2026-0001', 'CVE-2026-0002'],
    findingIds: [],
    createdDate: '2026-10-29T10:00:00.000Z',
    deliveryStatus: 'PENDING',
    recipientCount: 1,
    executiveSummary: 'Preview of the daily digest template.',
    affectedSystems: ['Example inventory asset'],
    remediationInstructions: 'Preview only; no remediation action is required.',
  };

  const mail = advisoryEmail(advisory, html);

  // advisoryEmail normally injects an "Advisory ID" paragraph for bodies that
  // do not identify themselves. The digest already does, so the transport body
  // must be exactly the document the studio rendered -- not a reskinned copy.
  assert.equal(mail.html, html);
  assert.match(mail.subject, /^\[DAILY-2026-10-29\] \[HIGH\] Daily Vulnerability Notification$/);
});
