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

/**
 * The canonical document, resolved relative to this file.
 *
 * A cwd-relative path breaks whenever the runner is invoked from anywhere but
 * the repository root, which turns a real assertion failure into an unrelated
 * ENOENT. `import.meta.url` anchors the path to the test file itself.
 */
const CANONICAL = readFileSync(
  new URL('./fixtures/canonical-daily-digest-template.html', import.meta.url),
  'utf8',
)
  // Line endings and the trailing newline are checkout artifacts, not document
  // content: Git may restore the fixture with CRLF on Windows. Normalising here
  // keeps the byte comparison about the document itself.
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

/** Matches a `{{name}}` or `{{{name}}}` placeholder. */
const PLACEHOLDER = /\{\{\{?\s*([a-z_][a-z0-9_]*)\s*\}?\}\}/gi;

/** Placeholder names in document order. */
const tokens = (html: string): string[] => [...html.matchAll(PLACEHOLDER)].map((match) => match[1]);

/** Literal runs between placeholders; their concatenation is the document. */
const literals = (html: string): string[] => {
  const result: string[] = [];
  let cursor = 0;
  for (const match of html.matchAll(PLACEHOLDER)) {
    result.push(html.slice(cursor, match.index));
    cursor = (match.index ?? 0) + match[0].length;
  }
  result.push(html.slice(cursor));
  return result;
};

/** Tag names in document order, with the closing forms marked. */
const tagNames = (html: string): string[] => [
  ...html.matchAll(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>/g),
].map((match) => (match[0].startsWith('</') ? `/${match[1]}` : match[1].toLowerCase()));

/**
 * Asserts that `actual` contains every non-empty literal run of `canonical`, in
 * order. Injected fragments (a severity badge, KPI cells, finding cards) sit
 * inside placeholder positions, so the rendered document legitimately has more
 * markup than the template; what must never change is the template's own text
 * appearing in the template's own order.
 *
 * Skipping empty literals is deliberate: adjacent placeholders produce empty
 * runs, and `indexOf('')` always matches at the cursor, which would silently
 * turn this check into a no-op.
 */
const assertPreservesLiterals = (canonical: string, actual: string, label: string): void => {
  let cursor = 0;
  for (const literal of literals(canonical)) {
    if (!literal) continue;
    const at = actual.indexOf(literal, cursor);
    assert.notEqual(
      at,
      -1,
      `${label}: canonical literal missing or out of order: ${JSON.stringify(literal.slice(0, 80))}`,
    );
    cursor = at + literal.length;
  }
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

/** Studio preview values for the canonical document. */
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

/**
 * A fully typed Advisory fixture. Casting through `unknown` would hide a missing
 * required field if the interface changed, so every property is supplied
 * explicitly and the compiler checks it.
 */
const advisory = (overrides: Partial<Advisory> = {}): Advisory => ({
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
  ...overrides,
});

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
  // A placeholder the studio never fills would render as an empty string and
  // disappear from the recipient's email without any error; a placeholder the
  // studio fills but the document does not declare is dead configuration.
  assert.deepEqual(
    [...new Set(tokens(CANONICAL))].filter((name) => !EXPECTED_PLACEHOLDERS.includes(name)),
    [],
    'the document must not declare a placeholder outside the documented set',
  );
});

test('the canonical document keeps its structural shape', () => {
  // Guard the skeleton independently of the byte comparison: if the fixture is
  // ever regenerated from the constant, this still fails when the document's
  // table structure changes, because a flattened or reordered layout produces a
  // different tag sequence.
  const tags = tagNames(CANONICAL);
  assert.deepEqual(
    tags.slice(0, 6),
    ['html', 'head', 'meta', 'meta', 'meta', 'meta'],
    'the document must open with a head of meta tags',
  );
  assert.ok(tags.filter((tag) => tag === 'table').length >= 8, 'the document keeps its table layout');
  // A tag-balance check would be wrong here: the MSO conditional block wraps
  // `<xml>` / `<o:OfficeDocumentSettings>` in downlevel-hidden comments, which a
  // tag scanner sees as unclosed elements. Assert on both MSO branches by name
  // instead, since those are what make the Outlook layout correct.
  assert.ok(CANONICAL.includes('<!--[if gte mso 9]>'), 'the MSO downlevel settings block must be present');
  assert.ok(CANONICAL.includes('<![endif]-->'), 'the MSO block must be terminated');
  assert.ok(CANONICAL.includes('<!--[if mso]>'), 'the Outlook 680px wrapper must be present');
});

/**
 * The "Rendered" preview surface: preview values substituted into the same
 * document. It must keep the canonical structure and resolve every placeholder.
 */
test('rendering the canonical document resolves every placeholder and keeps its structure', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, parts());
  assert.equal(
    /\{\{\{?\s*[a-z_][a-z0-9_]*\s*\}?\}\}/i.test(html),
    false,
    'no unresolved placeholders may reach a recipient',
  );
  assertPreservesLiterals(CANONICAL, html, 'rendered preview');

  // The preview must actually carry the substituted values, not merely the
  // document shell: an empty parts map would otherwise pass every check above.
  const fixture = parts();
  for (const value of [fixture.advisory_id, fixture.report_generated, String(fixture.finding_count)]) {
    assert.ok(html.includes(value), `rendered output must contain the substituted value ${JSON.stringify(value)}`);
  }
  // The title is rendered by the document's own header, so it must appear after
  // the header kicker. The kicker text also occurs in the hidden preheader at the
  // very top of the body, so the comparison is anchored to the *last* kicker,
  // which is the visible header one.
  const kickerAt = html.lastIndexOf('DAILY VULNERABILITY DIGEST');
  const titleAt = html.indexOf(fixture.advisory_title, kickerAt);
  assert.notEqual(kickerAt, -1, 'the header kicker must be present');
  assert.notEqual(titleAt, -1, 'the advisory title must be rendered by the header');
  assert.ok(titleAt > kickerAt, 'the title must follow the header kicker');
});

/** The delivered email body must be the same document, wrapped by the mailer. */
test('the delivered digest email body carries the canonical document unchanged', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, parts());
  const email = advisoryEmail(advisory(), html);

  assert.ok(email.html, 'the delivered email must carry an HTML body');
  // `advisoryEmail` prepends an "Advisory ID" banner when the body does not
  // already name the advisory. The canonical document does name it, so the body
  // must arrive byte-identical; a wrapper appearing here means the template lost
  // the identity it declares.
  assert.equal(email.html, html, 'the digest document must be embedded unchanged');
  assert.ok(email.subject.includes('BA-DAILY_20261029'), 'the subject must identify the digest');
});

test('a digest missing the advisory identity is still identified by the mailer', () => {
  // The contract the previous test relies on: when the body lacks the id, the
  // mailer injects it. Pinning both sides proves the "unchanged" assertion above
  // is a real property of this document, not an untested assumption.
  const withoutIdentity = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, {
    ...parts(),
    advisory_id: '',
  });
  assert.equal(withoutIdentity.includes('Adv' + 'isory ID:</strong> BA-DAILY_20261029'), false);
  const email = advisoryEmail(advisory(), withoutIdentity);
  assert.ok(email.html, 'the delivered email must carry an HTML body');
  assert.notEqual(email.html, withoutIdentity, 'the mailer must repair a body without the identity');
  assert.ok(
    email.html.includes('<body') && email.html.indexOf('Advisory ID') > email.html.indexOf('<body'),
    'the injected identity must land inside the body',
  );
});
