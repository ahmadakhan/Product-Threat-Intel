import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { DEFAULT_ADVISORY_EMAIL_TEMPLATE } from '../src/utils/defaultAdvisoryEmailTemplate.ts';

/**
 * Pins the shipped advisory template byte-for-byte to the canonical document.
 *
 * The template is the contract between three consumers that must never
 * disagree: the server renderer (what the recipient receives), the Template
 * Studio preview (what the operator sees while editing), and the copy served
 * from disk. A stray edit to one of them silently ships a different email, so
 * the expected text is stored beside the test rather than reconstructed.
 */
const CANONICAL = readFileSync('./tests/fixtures/canonical-advisory-template.html', 'utf8').replace(/\n$/, '');

test('the shipped advisory template is byte-identical to the canonical document', () => {
  assert.equal(DEFAULT_ADVISORY_EMAIL_TEMPLATE.replace(/\n$/, ''), CANONICAL);
});

test('the Studio-served copy is byte-identical to the canonical document', () => {
  const onDisk = readFileSync('./server/default-advisory-email-template.html', 'utf8').replace(/\n$/, '');
  assert.equal(onDisk, CANONICAL);
});

test('the canonical document declares exactly the expected placeholder set', () => {
  const tokens = [...new Set(CANONICAL.match(/\{\{\{?\s*[^{}]+?\s*\}?\}\}/g) ?? [])].sort();
  assert.deepEqual(tokens, [
    '{{#each cves}}',
    '{{#each honeywell_actions}}',
    '{{#each mitigations}}',
    // These two live in the explanatory HTML comment, not as template logic.
    '{{#if}}',
    '{{/each}}',
    '{{advisory_id}}',
    '{{advisory_title}}',
    '{{affected_versions}}',
    '{{badge_bg}}',
    '{{contact_email}}',
    '{{contact_team}}',
    '{{cve_count}}',
    '{{cve_id}}',
    '{{cvss_score}}',
    '{{else}}',
    '{{inventory_status}}',
    '{{pill_bg}}',
    '{{pill_border}}',
    '{{pill_text}}',
    '{{product}}',
    '{{published_date}}',
    '{{severity}}',
    '{{source_url}}',
    '{{title}}',
    '{{tlp_classification}}',
    '{{top_severity_color}}',
    '{{top_severity_label}}',
    '{{updated_date}}',
    '{{vendor}}',
    '{{{description}}}',
    '{{{detail}}}',
    '{{{executive_summary}}}',
    '{{{this}}}',
  ]);
});

/**
 * Byte-identical markup is not sufficient: a placeholder must also *resolve*.
 * The server blanks an unknown token, so a missing key silently ships an empty
 * cell (`bgcolor=""`, `<a href="mailto:"></a>`) rather than a visible error.
 * This renders the real document with real data and asserts that none of that
 * happens.
 */
test('every placeholder resolves against real advisory data', async () => {
  const { renderAdvisory } = await import('../server/advisoryRender.ts');
  const finding = (n: number, severity: string, score: number, vendor: string, product: string) =>
    ({
      id: `f${n}`,
      cveId: `CVE-2026-2000${n}`,
      cve: {
        cveId: `CVE-2026-2000${n}`,
        title: 't',
        description: 'A vendor description.',
        cvss: { score, severity, vector: '', version: '3.1' },
        cpeMatches: [],
        cwe: [],
        sourceFeeds: [],
        publishedDate: '2026-11-19T00:00:00Z',
        modifiedDate: '2026-11-20T00:00:00Z',
        remediation: { immediateActions: ['Apply the vendor update.'], patchUrl: '', vendorAdvisoryRef: '' },
      },
      matchedAssetId: `a${n}`,
      matchedAssetName: `host-0${n}`,
      matchedAssetVendor: vendor,
      matchedAssetProduct: product,
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
    }) as never;
  const findings = [
    finding(1, 'CRITICAL', 9.8, 'fortinet', 'fortimanager'),
    finding(2, 'HIGH', 7.2, 'cisco', 'ios_xe'),
    finding(3, 'MEDIUM', 5.0, 'acme', 'widget'),
    finding(4, 'LOW', 3.1, 'acme', 'gizmo'),
  ];
  const advisory = {
    id: 'ADV-0001',
    title: 'Vulnerability notice',
    severity: 'CRITICAL',
    cveIds: findings.map((f) => (f as { cveId: string }).cveId),
    findingIds: findings.map((f) => (f as { id: string }).id),
    createdDate: '2026-11-19T00:00:00Z',
    deliveryStatus: 'PENDING',
    recipientCount: 1,
    executiveSummary: 'A summary.',
    remediationInstructions: 'Remediate.',
    affectedSystems: ['host'],
  };
  const cveIds = advisory.cveIds;

  for (const options of [{}, { contactTeam: 'SOC', contactEmail: 'soc@example.com', tlpClassification: 'TLP:RED' }]) {
    const html = renderAdvisory(CANONICAL, advisory as never, findings, options);
    assert.deepEqual([...new Set(html.match(/\{\{[^}]+\}\}/g) ?? [])], [], 'no token survives');
    for (const blank of ['bgcolor=""', 'href=""', 'href="mailto:"', 'background-color: ;', 'color: ;', 'border: 1px solid ;'])
      assert.ok(!html.includes(blank), `no unresolved attribute: ${blank}`);
    for (const sev of ['CRITICAL (9.8)', 'HIGH (7.2)', 'MEDIUM (5.0)', 'LOW (3.1)']) assert.ok(html.includes(sev), sev);
    for (const cve of cveIds) assert.ok(html.includes(cve), cve);
    // The footer address must always be a real mailbox, never an empty link.
    assert.match(html, /href="mailto:[^"@]+@[^"]+"/);
    if (options.contactEmail) assert.ok(html.includes('mailto:soc@example.com'), 'override is honoured');
  }
});
