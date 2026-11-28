import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderAdvisory } from '../server/advisoryRender.ts';
import type { Advisory, Finding } from '../src/types/index.ts';
import { DEFAULT_ADVISORY_EMAIL_TEMPLATE } from '../src/utils/defaultAdvisoryEmailTemplate.ts';
import { remediationIsEmpty, resolveRequiredActions } from '../src/utils/cveRemediation.ts';

/**
 * Two guarantees the delivered finding email has to make:
 *
 *  1. Required Actions & Mitigation is always generated from the record. A
 *     placeholder sentence ("confirm with the vendor") is not an action.
 *  2. The message states how many CVEs fall in each severity band, with a dash
 *     for a band that is empty.
 */

const emptyPlaybook = {
  patchUrl: '',
  vendorAdvisoryRef: '',
  immediateActions: [],
  workarounds: [],
  rollbackPlan: '',
  stepByStep: [],
};

const finding = (
  cveId: string,
  severity: string,
  options: {
    id?: string;
    cwe?: string[];
    remediation?: unknown;
    kev?: boolean;
    exploitRisk?: string;
  } = {},
): Finding =>
  ({
    id: options.id ?? `f-${cveId}`,
    cveId,
    cve: {
      cveId,
      title: 't',
      description: 'A vendor description.',
      cvss: { score: 9.8, severity, vector: '', version: '3.1' },
      cpeMatches: [],
      cwe: options.cwe ?? [],
      sourceFeeds: ['nvd'],
      publishedDate: '2026-11-19T00:00:00Z',
      modifiedDate: '2026-11-19T00:00:00Z',
      cisaKev: { isKev: options.kev === true },
      remediation: options.remediation ?? emptyPlaybook,
    },
    matchedAssetId: `a-${cveId}`,
    matchedAssetName: 'host-01',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'widget',
    matchedCpe: '',
    matchingMethod: 'CPE',
    matchingEvidence: 'e',
    confidence: 90,
    exploitRisk: options.exploitRisk ?? 'STANDARD',
    dispatchDeferred: false,
    notificationStatus: 'QUEUED_FOR_DISPATCH',
    status: 'MONITORED',
    timeline: [],
  }) as unknown as Finding;

const advisory = (findings: Finding[], cveIds?: string[]): Advisory =>
  ({
    id: 'ADV-1',
    title: 'T',
    severity: 'CRITICAL',
    cveIds: cveIds ?? [...new Set(findings.map((f) => f.cveId))],
    findingIds: findings.map((f) => f.id),
    createdDate: '2026-11-19T00:00:00Z',
    deliveryStatus: 'PENDING',
    recipientCount: 1,
    executiveSummary: 'Summary.',
    remediationInstructions: 'Remediate.',
    affectedSystems: ['host'],
    edits: {},
  }) as unknown as Advisory;

const render = (findings: Finding[], cveIds?: string[]) =>
  renderAdvisory(DEFAULT_ADVISORY_EMAIL_TEMPLATE, advisory(findings, cveIds), findings, {
    generatedAt: new Date('2026-11-19T11:12:00Z'),
  });

/** Reads the rendered count cell for one band. */
const countFor = (html: string, label: 'Critical' | 'High' | 'Medium' | 'Low'): string | undefined =>
  new RegExp(`${label}: </span>([^<]*)<`).exec(html)?.[1];

/* -------------------------------------------------------------------------- */
/* Severity counts                                                            */
/* -------------------------------------------------------------------------- */

test('the email states a count for each severity band', () => {
  const html = render([
    finding('CVE-2026-0001', 'CRITICAL'),
    finding('CVE-2026-0002', 'CRITICAL'),
    finding('CVE-2026-0003', 'HIGH'),
    finding('CVE-2026-0004', 'MEDIUM'),
  ]);
  assert.equal(countFor(html, 'Critical'), '2');
  assert.equal(countFor(html, 'High'), '1');
  assert.equal(countFor(html, 'Medium'), '1');
});

test('an empty severity band renders a dash rather than a zero', () => {
  const html = render([finding('CVE-2026-0001', 'CRITICAL')]);
  assert.equal(countFor(html, 'Critical'), '1');
  assert.equal(countFor(html, 'High'), '-');
  assert.equal(countFor(html, 'Medium'), '-');
  assert.equal(countFor(html, 'Low'), '-');
});

test('counts one row per CVE, not one per affected asset', () => {
  // The same CVE affecting two hosts is two matrix rows but one finding to
  // triage, so the summary must not double-count it.
  const html = render([
    finding('CVE-2026-0001', 'HIGH', { id: 'asset-a' }),
    finding('CVE-2026-0001', 'HIGH', { id: 'asset-b' }),
  ]);
  assert.equal(countFor(html, 'High'), '1');
  assert.equal(countFor(html, 'Critical'), '-');
});

test('an unscored CVE is counted in the Low column', () => {
  const html = render([finding('CVE-2026-0001', 'UNKNOWN')]);
  assert.equal(countFor(html, 'Low'), '1');
  assert.equal(countFor(html, 'Critical'), '-');
});

/* -------------------------------------------------------------------------- */
/* Required Actions & Mitigation                                              */
/* -------------------------------------------------------------------------- */

test('remediationIsEmpty treats placeholder-only playbooks as empty', () => {
  assert.equal(remediationIsEmpty(undefined), true);
  assert.equal(remediationIsEmpty(emptyPlaybook), true);
  assert.equal(remediationIsEmpty({ ...emptyPlaybook, immediateActions: ['  '], stepByStep: [' '] }), true);
  assert.equal(remediationIsEmpty({ ...emptyPlaybook, immediateActions: ['Do the thing.'] }), false);
  assert.equal(remediationIsEmpty({ ...emptyPlaybook, stepByStep: ['Step.'] }), false);
});

test('actions are generated from the CWE when the record carries none', () => {
  const actions = resolveRequiredActions({ remediation: emptyPlaybook, cwe: ['CWE-89'], severity: 'HIGH' });
  assert.ok(actions.length >= 2, 'at least two real actions');
  assert.ok(
    actions.some((action) => /parameterized|prepared statements/i.test(action)),
    `expected SQL-injection guidance, got: ${actions.join(' | ')}`,
  );
  assert.ok(!actions.some((action) => /confirm with the vendor/i.test(action)), 'no placeholder');
});

test('actions fall back to severity when neither remediation nor CWE is available', () => {
  const critical = resolveRequiredActions({ remediation: emptyPlaybook, cwe: [], severity: 'CRITICAL' });
  const low = resolveRequiredActions({ remediation: emptyPlaybook, cwe: [], severity: 'LOW' });
  assert.ok(critical.length >= 2);
  assert.ok(low.length >= 1);
  assert.notDeepEqual(critical, low, 'severity must change the guidance');
  assert.ok(
    critical.some((action) => /emergency|isolate/i.test(action)),
    `expected an urgent action for CRITICAL, got: ${critical.join(' | ')}`,
  );
});

test('exploitation status adds an escalation action', () => {
  const kev = resolveRequiredActions({ remediation: emptyPlaybook, cwe: [], severity: 'HIGH', kev: true });
  const exploited = resolveRequiredActions({
    remediation: emptyPlaybook,
    cwe: [],
    severity: 'HIGH',
    exploited: true,
  });
  assert.ok(
    kev.some((action) => /KEV catalo/i.test(action)),
    kev.join(' | '),
  );
  assert.ok(
    exploited.some((action) => /exploitation has been reported/i.test(action)),
    exploited.join(' | '),
  );
  // KEV takes precedence; the two escalation notes never both appear.
  assert.ok(!kev.some((action) => /exploitation has been reported/i.test(action)));
});

test('an existing playbook is preferred and duplicates are removed', () => {
  const actions = resolveRequiredActions({
    remediation: {
      ...emptyPlaybook,
      immediateActions: ['Patch immediately.', 'Patch immediately.'],
      workarounds: ['Restrict access.'],
    },
    cwe: ['CWE-79'],
    severity: 'CRITICAL',
  });
  assert.equal(actions[0], 'Patch immediately.');
  assert.equal(new Set(actions).size, actions.length, 'no duplicates');
  assert.ok(
    !actions.some((action) => /output encoding/i.test(action)),
    'CWE guidance must not override the record',
  );
});

test('the generated list is capped so the email stays scannable', () => {
  const actions = resolveRequiredActions({
    remediation: {
      ...emptyPlaybook,
      immediateActions: ['a1', 'a2', 'a3'],
      workarounds: ['b1', 'b2', 'b3'],
      stepByStep: ['c1'],
    },
    severity: 'CRITICAL',
    kev: true,
    maxActions: 3,
  });
  assert.equal(actions.length, 3);
});

test('the delivered email always renders real required actions', () => {
  // Every record here arrives with an empty playbook and no CWE, which is the
  // case that used to render a placeholder sentence.
  const html = render([
    finding('CVE-2026-0001', 'CRITICAL', { kev: true }),
    finding('CVE-2026-0002', 'MEDIUM'),
  ]);
  const actions = [...html.matchAll(/&#8226;&nbsp; ([^<]{20,240})/g)].map((match) => match[1]);
  assert.ok(actions.length >= 4, `expected generated actions, got ${actions.length}`);
  assert.ok(
    actions.some((action) => /isolate|emergency/i.test(action)),
    `expected severity-derived guidance, got: ${actions.join(' | ')}`,
  );
  assert.ok(
    actions.some((action) => /KEV catalo/i.test(action)),
    'the KEV escalation must reach the message',
  );
  assert.ok(
    !html.includes('Confirm affected versions and follow current vendor guidance before remediation.'),
  );
});
