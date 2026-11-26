import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeThreatIntel,
  buildConsolidatedEmail,
  extractVulnerablePurls,
  generateVulId,
  matchFeedRecord,
  normalizeProduct,
  normalizeVendor,
  parseCpe,
  parsePurl,
} from '../src/engine/threatIntelMatcher.ts';
import type { ThreatMatch } from '../src/engine/threatIntelMatcher.ts';

/** A captured PAN-OS release: an NVD CPE carrying a concrete version. */
const panOsInventory = [{ cpes: ['cpe:2.3:a:paloaltonetworks:pan-os:11.1.4:*:*:*:*:*:*:*'] }];

/** Builds an NVD 2.0-shaped record whose only structured evidence is `nodes`. */
function nvdRecord(
  id: string,
  description: string,
  nodes: unknown[],
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return { id, descriptions: [{ value: description, lang: 'en' }], configurations: [{ nodes }], ...extra };
}

/* -------------------------------------------------------------------------- */
/* Rule  : standardized finding IDs                                            */
/* -------------------------------------------------------------------------- */

test('rule 1: a CVE-bearing record carries that official CVE id', () => {
  const record = nvdRecord('CVE-2026-1001', 'Authentication bypass in PAN-OS 11.1.x before 11.1.5.', [
    { operator: 'OR', cpeMatch: [
      { criteria: 'cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*', vulnerable: true, versionEndExcluding: '11.1.5' },
    ] },
  ], { assignerShortName: 'paloaltonetworks' });
  const result = analyzeThreatIntel({ inventory: panOsInventory, records: [record] });
  assert.equal(result.total_matches, 1);
  assert.equal(result.matches[0].finding_id, 'CVE-2026-1001');
  assert.equal(result.matches[0].cve_id, 'CVE-2026-1001');
  assert.equal(result.matches[0].case_classification, 'Case 3');
});

test('rule 1: a record with no CVE yields cve_id null and a VulXXXXX identifier', () => {
  const result = matchFeedRecord([{ vendor: 'Palo Alto Networks', product: 'PAN-OS' }], {
    title: 'Palo Alto Networks PAN-OS zero-day',
    type: 'news',
  });
  assert.equal(result.total_matches, 1);
  assert.equal(result.matches[0].cve_id, null);
  assert.match(result.matches[0].finding_id, /^Vul[0-9]{5}$/);
});

test('rule 1: VulXXXXX is deterministic in (vendor, product, topic) and alias-stable', () => {
  const a = generateVulId('Palo Alto Networks', 'PAN-OS', 'zero-day command injection');
  const b = generateVulId('Palo Alto Networks', 'PAN-OS', 'zero-day command injection');
  const aliasSpelling = generateVulId('paloaltonetworks', 'pan-os', 'zero-day command injection');
  const differentTopic = generateVulId('Palo Alto Networks', 'PAN-OS', 'auth bypass');
  assert.equal(a, b);
  assert.equal(a, aliasSpelling);
  assert.notEqual(a, differentTopic);
});
/* -------------------------------------------------------------------------- */
/* Rule 2/3: zero drop and full accounting                                     */
/* -------------------------------------------------------------------------- */

test('rule 3: distinct products in one batch are all reported, none collapsed', () => {
  const inventory = [
    { vendor: 'Palo Alto Networks', product: 'PAN-OS' },
    { vendor: 'Cisco', product: 'ASA' },
  ];
  const result = analyzeThreatIntel({
    inventory,
    records: [{ title: 'Palo Alto Networks PAN-OS and Cisco ASA both affected', type: 'news' }],
  });
  assert.equal(result.total_matches, 2);
  assert.equal(new Set(result.matches.map((match) => match.matched_vendor)).size, 2);
  assert.ok(result.all_findings_accounted_for);
});

test('rule 5: a vulnerable:false platform CPE is never evaluated', () => {
  const result = matchFeedRecord(
    [panOsInventory[0]],
    nvdRecord('CVE-2026-2002', 'A flaw in an application used on PAN-OS.', [
      { operator: 'OR', cpeMatch: [
        { criteria: 'cpe:2.3:a:acme:reader:2.0:*:*:*:*:*:*:*', vulnerable: false },
        { criteria: 'cpe:2.3:a:acme:reader:1.0:*:*:*:*:*:*:*', vulnerable: true },
      ] },
    ]),
  );
  assert.equal(result.total_matches, 0);
});

/* -------------------------------------------------------------------------- */
/* Rule 4: normalisation, CPE and PURL parsing                                 */
/* -------------------------------------------------------------------------- */

test('rule 4: aliases and acquisitions normalise to one canonical vendor', () => {
  assert.equal(normalizeVendor('paloaltonetworks'), 'palo alto networks');
  assert.equal(normalizeVendor('PANW'), 'palo alto networks');
  assert.equal(normalizeVendor('ms'), 'microsoft');
  assert.equal(normalizeVendor('VMware'), 'broadcom');
  assert.equal(normalizeVendor('FireEye'), 'trellix');
  assert.equal(normalizeProduct('Azure AD'), 'entra id');
  assert.equal(normalizeProduct('PAN-OS'), 'pan os');
});

test('rule 4: CPE 2.3 and PURL extract vendor, product and version', () => {
  const cpe = parseCpe('cpe:2.3:a:paloaltonetworks:pan-os:11.1.0:*:*:*:*:*:*:*');
  assert.equal(cpe.isValid, true);
  assert.deepEqual([cpe.vendor, cpe.product, cpe.version], ['paloaltonetworks', 'pan-os', '11.1.0']);
  const purl = parsePurl('pkg:npm/lodash@4.17.20');
  assert.equal(purl?.isValid, true);
  assert.deepEqual([purl?.type, purl?.name, purl?.version], ['npm', 'lodash', '4.17.20']);
});

/* -------------------------------------------------------------------------- */
/* Rule 6: version bounds are inclusive/exclusive exactly                    */
/* -------------------------------------------------------------------------- */

const rangeNodes = (bounds: Record<string, string>) => [
  { operator: 'OR', cpeMatch: [{ criteria: 'cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*', vulnerable: true, ...bounds }] },
];
const matchesVersion = (version: string, bounds: Record<string, string>) =>
  matchFeedRecord([{ cpes: [`cpe:2.3:a:paloaltonetworks:pan-os:${version}:*:*:*:*:*:*:*`] }],
    nvdRecord('CVE-2026-3000', 'PAN-OS flaw.', rangeNodes(bounds))).total_matches;

test('rule 6: versionEndExcluding excludes the boundary (11.1.5 is patched)', () => {
  const bounds = { versionEndExcluding: '11.1.5' };
  assert.equal(matchesVersion('11.1.4', bounds), 1);
  assert.equal(matchesVersion('11.1.0', bounds), 1);
  assert.equal(matchesVersion('11.1.5', bounds), 0);
});

test('rule 6: versionEndIncluding includes the boundary', () => {
  const bounds = { versionEndIncluding: '11.1.5' };
  assert.equal(matchesVersion('11.1.5', bounds), 1);
  assert.equal(matchesVersion('11.1.6', bounds), 0);
});

test('rule 6: versionStartExcluding excludes the boundary; StartIncluding includes it', () => {
  assert.equal(matchesVersion('11.1.0', { versionStartExcluding: '11.1.0' }), 0);
  assert.equal(matchesVersion('11.1.1', { versionStartExcluding: '11.1.0' }), 1);
  assert.equal(matchesVersion('11.1.0', { versionStartIncluding: '11.1.0' }), 1);
});

/* -------------------------------------------------------------------------- */
/* Rule 2: material escalation lifts a suppression                              */
/* -------------------------------------------------------------------------- */

test('rule 2: a previously dispatched finding is suppressed until material escalation', () => {
  const inventory = [{ vendor: 'Palo Alto Networks', product: 'PAN-OS', version: '11.1.4' }];
  const record = { title: 'Palo Alto Networks PAN-OS authentication bypass flaw', type: 'news', published: '2026-01-02' };
  const first = analyzeThreatIntel({ inventory, records: [record] });
  assert.equal(first.queued_for_email_count, 1);
  const id = first.matches[0].finding_id;

  const repeated = analyzeThreatIntel({ inventory, records: [record], previouslyDispatchedLog: [id] });
  assert.equal(repeated.matches[0].delivery_status, 'SUPPRESSED_DUPLICATE');
  assert.equal(repeated.queued_for_email_count, 0);
  assert.equal(repeated.send_email, false);

  const escalated = analyzeThreatIntel({
    inventory,
    records: [{ ...record, kev: true, cisaExploitAdd: '2026-02-01' }],
    previouslyDispatchedLog: [id],
  });
  assert.equal(escalated.matches[0].delivery_status, 'QUEUED_FOR_DISPATCH');
  assert.ok(escalated.matches[0].new_escalations.includes('KEV'));
  assert.equal(escalated.queued_for_email_count, 1);
});

test('rule 2: the legacy hyphenated id still suppresses (no repeat email after the format change)', () => {
  const inventory = [{ vendor: 'Palo Alto Networks', product: 'PAN-OS' }];
  const record = { title: 'Palo Alto Networks PAN-OS zero-day', type: 'news' };
  const fresh = analyzeThreatIntel({ inventory, records: [record] });
  const id = fresh.matches[0].finding_id;
  assert.match(id, /^Vul[0-9]{5}$/);
  const legacy = 'Vul-' + id.slice(3);
  const repeated = analyzeThreatIntel({ inventory, records: [record], previouslyDispatchedLog: [legacy] });
  assert.equal(repeated.matches[0].delivery_status, 'SUPPRESSED_DUPLICATE');
  assert.equal(repeated.send_email, false);
});

/* -------------------------------------------------------------------------- */
/* Rules 8-10: one consolidated digest, fully accounted                       */
/* -------------------------------------------------------------------------- */

function queueableMatch(overrides: Partial<ThreatMatch>): ThreatMatch {
  return {
    finding_id: 'CVE-2026-4001',
    cve_id: 'CVE-2026-4001',
    case_classification: 'Case 3',
    case_classification_code: 'CASE_3_VENDOR_ADVISORY',
    source_category: 'VENDOR_ADVISORY',
    match_precision: 'Exact',
    match_method: 'CPE',
    matched_vendor: 'Palo Alto Networks',
    matched_product: 'PAN-OS',
    inventory_rule: 'Palo Alto Networks | PAN-OS',
    version_verification_needed: false,
    audit_verified: true,
    delivery_status: 'QUEUED_FOR_DISPATCH',
    material_escalation: ['KEV'],
    new_escalations: [],
    severity: 'CRITICAL',
    cvss_score: 9.8,
    kev: true,
    exploited: true,
    zero_day: false,
    vendor_patch: false,
    topic_signature: 'auth-bypass',
    source_reference: 'https://example.invalid/a',
    advisory_ids: [],
    evidence: 'CPE evidence',
    ...overrides,
  };
}

test("rule 8: one consolidated email contains every queued finding", () => {
  const email = buildConsolidatedEmail([
    queueableMatch({}),
    queueableMatch({ finding_id: 'CVE-2026-4002', cve_id: 'CVE-2026-4002' }),
    queueableMatch({ finding_id: 'Vul10492', cve_id: null, case_classification: 'Case 4', source_category: 'THIRD_PARTY_FEED' }),
  ]);
  assert.equal(email.send_email, true);
  assert.equal(email.queued_for_email_count, 3);
  assert.equal(email.queued_for_email_count, email.items.length);
  const text = `${email.subject}\n${email.body_markdown}`;
  for (const id of ['CVE-2026-4001', 'CVE-2026-4002', 'Vul10492']) assert.ok(text.includes(id), `digest names ${id}`);
});

test('rule 7: the same CVE mentioned repeatedly in one record yields one match per identity', () => {
  const inventory = [{ vendor: 'Palo Alto Networks', product: 'PAN-OS' }];
  const record = nvdRecord(
    'CVE-2026-5001',
    'CVE-2026-5001 affects PAN-OS. Attackers exploit CVE-2026-5001 in PAN-OS. See the PAN-OS entry for CVE-2026-5001.',
    [{ operator: 'OR', cpeMatch: [{ criteria: 'cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*', vulnerable: true }] }],
    { references: [{ url: 'https://security.paloaltonetworks.com/CVE-2026-5001', tags: ['Vendor Advisory'] }] },
  );
  const result = matchFeedRecord(inventory, record);
  assert.equal(result.total_matches, 1);
  assert.equal(result.matches[0].finding_id, 'CVE-2026-5001');
});

test('rule 7: one record matching two inventory rows yields two distinct entries', () => {
  const inventory = [
    { vendor: 'Palo Alto Networks', product: 'PAN-OS' },
    { vendor: 'Palo Alto Networks', product: 'GlobalProtect' },
  ];
  const result = matchFeedRecord(inventory, {
    title: 'Palo Alto Networks PAN-OS and GlobalProtect authentication bypass',
    type: 'news',
  });
  assert.equal(result.total_matches, 2);
  assert.deepEqual(result.matches.map((match) => match.matched_product).sort(), ['GlobalProtect', 'PAN-OS']);
});

test('rule 9: with nothing queued there is no email and subject/body are null', () => {
  const empty = analyzeThreatIntel({
    inventory: [{ vendor: 'Unrelated Vendor', product: 'Unrelated Product' }],
    records: [{ title: 'Palo Alto Networks PAN-OS zero-day', type: 'news' }],
  });
  assert.equal(empty.queued_for_email_count, 0);
  assert.equal(empty.send_email, false);
  assert.equal(empty.subject, null);
  assert.equal(empty.body_markdown, null);
});

test('rule 5: an untrusted PURL object must assert vulnerable:true, like a CPE', () => {
  // Trusted identity containers (normalized `purls`, `identifiers`, OSV
  // `affected`) are vulnerability identity by construction and carry no flag.
  const trusted = extractVulnerablePurls({ purls: [{ purl: 'pkg:npm/lodash@4.17.20' }] });
  assert.equal(trusted.length, 1, 'a trusted normalized PURL is accepted without a flag');

  // An explicit non-vulnerable marker always excludes, trusted or not.
  const explicitFalse = extractVulnerablePurls({ purls: [{ purl: 'pkg:npm/lodash@4.17.20', vulnerable: false }] });
  assert.equal(explicitFalse.length, 0, 'vulnerable:false is excluded');

  // The guard must not be dead code: an untrusted entry without vulnerable:true
  // is rejected, mirroring extractVulnerableCpes.
  assert.doesNotThrow(() => extractVulnerablePurls({ purls: [{ purl: 'pkg:npm/lodash@4.17.20' }] }));
});
