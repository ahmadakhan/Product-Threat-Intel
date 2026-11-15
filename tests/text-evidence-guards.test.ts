import test from 'node:test';
import assert from 'node:assert/strict';
import {
  evidenceSentences,
  isNegatedSentence,
  isPassivePlatformMention,
  rejectionReason,
  sentenceSupportsExposure,
  textSupportsExposure,
} from '../src/utils/textEvidenceGuards.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { NormalizedCVE, WatchListItem } from '../src/types/index.ts';

/**
 * These guards exist because a text match on a vendor and product name is the
 * weakest evidence the engine can produce. Two constructions defeat naive token
 * matching, and both are common in real feeds:
 *
 *   "Windows Server 2022 is not affected by this flaw"
 *   "a flaw in Tomcat running on Windows Server 2022"
 *
 * The first names every identity an affected advisory would. The second names the
 * asset only as the substrate for something else. Neither is evidence of exposure,
 * and on a fleet where one OS is ubiquitous the second is the single largest
 * source of false alerts an autonomous system can emit.
 */

const now = new Date('2026-11-15T00:00:00Z');

const asset = (vendor: string, product: string, version = '1.0'): WatchListItem => ({
  id: 'asset',
  assetTag: 'asset',
  vendor,
  product,
  version,
  cpes: [`cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`],
  purls: [],
  active: true,
  ownerGroup: 'SOC',
  createdAt: now.toISOString(),
});

const advisory = (overrides: Partial<NormalizedCVE>): NormalizedCVE =>
  ({
    cveId: 'CVE-2026-55555',
    title: '',
    description: '',
    publishedDate: now.toISOString(),
    modifiedDate: now.toISOString(),
    cvss: { version: '3.1', score: 9.8, severity: 'CRITICAL', vector: '' },
    cpeMatches: [],
    sourceFeeds: [],
    cwe: [],
    remediation: {
      immediateActions: [],
      vendorAdvisoryRef: '',
      patchUrl: '',
      workarounds: [],
      rollbackPlan: '',
      stepByStep: [],
    },
    cisaKev: { isKev: false },
    epss: { score: 0, percentile: 0 },
    exploitStatus: 'None',
    ...overrides,
  }) as NormalizedCVE;

/** Text-only match: no CPE, so the fallback heuristic is the only path. */
const textOnlyFindings = (vendor: string, product: string, text: string) =>
  runVulnerabilityPipeline(
    [],
    [advisory({ title: text, description: text })],
    [asset(vendor, product)],
    [],
    [],
    { ...DEFAULT_SETTINGS, scopeHours: 0 },
  ).newFindings;

/* -------------------------------------------------------------------------- */
/* Negation                                                                   */
/* -------------------------------------------------------------------------- */

test('a negated sentence is recognised regardless of the verb used', () => {
  for (const sentence of [
    'Windows Server 2022 is not affected by this flaw',
    'Acme Gateway unaffected',
    'Acme Gateway is not vulnerable',
    'this flaw does not affect Acme Gateway',
    'there is no impact on Acme Gateway',
    'Acme Gateway is not exposed',
  ])
    assert.equal(isNegatedSentence(sentence), true, sentence);
});

test('negation is whole-word, so unrelated words cannot trigger it', () => {
  // The obvious `includes('unaffected')` is fine, but a substring check on
  // shorter phrases matches inside other words. "Norton" contains "no".
  assert.equal(isNegatedSentence('Norton antivirus was bypassed'), false);
  assert.equal(isNegatedSentence('the affected Acme Gateway was patched'), false);
  assert.equal(isNegatedSentence('Acme Gateway is affected'), false);
});

test('a negated advisory produces no finding', () => {
  const findings = textOnlyFindings(
    'microsoft',
    'windows_server_2022',
    'Microsoft Windows Server 2022 is not affected by this flaw.',
  );
  assert.equal(findings.length, 0);
});

test('negation is scoped to a sentence, so a later positive claim still matches', () => {
  const findings = textOnlyFindings(
    'microsoft',
    'windows_server_2022',
    'Microsoft Windows Server 2022 is not affected. Microsoft Windows Server 2022 21H2 builds are affected.',
  );
  assert.equal(findings.length, 1, 'a positive sentence in the same document must not be suppressed');
});

/* -------------------------------------------------------------------------- */
/* Passive platform                                                          */
/* -------------------------------------------------------------------------- */

test('passive platform constructions are recognised', () => {
  for (const sentence of [
    'a flaw in Apache Tomcat running on Windows Server 2022',
    'Tomcat installed on Windows Server 2022',
    'the service hosted on Windows Server 2022',
    'the agent deployed on Windows Server 2022',
    'an attack via Windows Server 2022 jump hosts',
    'when integrated with Windows Server 2022',
  ])
    assert.equal(isPassivePlatformMention(sentence, 'windows_server_2022'), true, sentence);
});

test('a passive mention of a different product does not reject this one', () => {
  const sentence = 'a flaw in Tomcat running on Windows Server 2022';
  assert.equal(isPassivePlatformMention(sentence, 'windows_server_2022'), true);
  assert.equal(isPassivePlatformMention(sentence, 'tomcat'), false);
});

test('calling a product vulnerable outright is not a passive mention', () => {
  assert.equal(isPassivePlatformMention('Windows Server 2022 is affected', 'windows_server_2022'), false);
});

test('a flaw described as running on another host does not flag the host asset', () => {
  const findings = textOnlyFindings(
    'microsoft',
    'windows_server_2022',
    'Attackers exploited a flaw in Apache Tomcat running on Microsoft Windows Server 2022.',
  );
  assert.equal(findings.length, 0, 'the host is not the vulnerable product');
});

/* -------------------------------------------------------------------------- */
/* Sentence scoping and API contract                                          */
/* -------------------------------------------------------------------------- */

test('evidence is evaluated per sentence', () => {
  assert.deepEqual(evidenceSentences('One flaw. Two flaws! Three?\nFour'), [
    'one flaw',
    'two flaws',
    'three',
    'four',
  ]);
});

test('rejection reasons are reported rather than swallowed', () => {
  assert.equal(rejectionReason('Acme is not affected', 'acme'), 'NEGATED');
  assert.equal(rejectionReason('Tomcat running on Acme', 'acme'), 'PASSIVE_PLATFORM');
  assert.equal(rejectionReason('Acme is affected', 'acme'), undefined);
});

test('textSupportsExposure scans every relevant sentence before rejecting', () => {
  const text = 'Acme Gateway is not affected by CVE-1. Acme Gateway remains affected by CVE-2.';
  assert.equal(textSupportsExposure(text, 'acme', 'gateway'), undefined);
  assert.equal(textSupportsExposure('Acme Gateway is not affected.', 'acme', 'gateway'), 'NEGATED');
  assert.equal(textSupportsExposure('Tomcat running on Acme Gateway.', 'acme', 'gateway'), 'PASSIVE_PLATFORM');
});

test('an identity split by punctuation is not lost to sentence scoping', () => {
  // "Acme." ends a sentence, so no single sentence holds both identities. The
  // guard must not reject on that basis: the caller already proved both present.
  assert.equal(textSupportsExposure('Acme. Gateway shipped today.', 'acme', 'gateway'), undefined);
});

test('sentenceSupportsExposure agrees with the reason API', () => {
  assert.equal(sentenceSupportsExposure('Acme Gateway is affected', 'gateway'), true);
  assert.equal(sentenceSupportsExposure('Acme Gateway is not affected', 'gateway'), false);
  assert.equal(sentenceSupportsExposure('Tomcat running on Acme Gateway', 'gateway'), false);
});

test('product names containing regex metacharacters are matched literally', () => {
  // C++ and C# are not regex operators here. `+` is escaped, and the trailing
  // boundary excludes it, so `c++` cannot match inside `c+++`.
  assert.equal(isPassivePlatformMention('the runtime hosted on Visual C++', 'visual_c++'), true);
  assert.equal(isPassivePlatformMention('the runtime hosted on Visual C+++', 'visual_c++'), false);
  assert.equal(isPassivePlatformMention('the runtime hosted on Visual C#', 'visual_c++'), false);
  // The product being the *subject* is not a passive mention of itself.
  assert.equal(isPassivePlatformMention('Visual C++ running on Windows', 'visual_c++'), false);
});
