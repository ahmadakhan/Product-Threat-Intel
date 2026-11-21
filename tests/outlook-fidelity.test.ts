import assert from 'node:assert/strict';
import test from 'node:test';
import { renderFindingsDocument } from '../server/deliveryDocument.ts';
import type { Advisory, Finding } from '../src/types/index.ts';

/**
 * Outlook desktop renders HTML with the Word engine, which honours a small
 * subset of CSS and *silently drops* anything it does not understand. Two
 * failure modes matter for this template:
 *
 *  - markup stripped before it reaches the wire (a sanitizer or a DOM
 *    round-trip removes `<style>`, `<v:rect>` or the mso conditional comments);
 *  - layout collapsed because the Word engine ignores `max-width`, so a
 *    `width:100%` table inside an auto-width cell shrinks.
 *
 * This renders the real delivery document and asserts both.
 */

const finding = (n: number, vendor: string, product: string): Finding =>
  ({
    id: `f${n}`,
    cveId: `CVE-2026-7000${n}`,
    cve: {
      cveId: `CVE-2026-7000${n}`,
      title: 't',
      description: 'A vendor description that is long enough to wrap across several lines in a narrow column, which is where exact line-height clips descenders.',
      cvss: { score: 9.8, severity: 'CRITICAL', vector: '', version: '3.1' },
      cpeMatches: [],
      cwe: [],
      sourceFeeds: [],
      publishedDate: '2026-11-19T00:00:00Z',
      modifiedDate: '2026-11-20T00:00:00Z',
      remediation: {
        immediateActions: [
          'Apply the vendor update immediately.',
          'Restrict network access to the management interface until patched.',
        ],
        patchUrl: '',
        vendorAdvisoryRef: '',
      },
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
  }) as unknown as Finding;

const advisory = (findings: Finding[]): Advisory =>
  ({
    id: 'ADV-OUTLOOK1',
    title: 'Vulnerability notice',
    severity: 'CRITICAL',
    cveIds: findings.map((f) => f.cveId),
    findingIds: findings.map((f) => f.id),
    createdDate: '2026-11-19T00:00:00Z',
    deliveryStatus: 'PENDING',
    recipientCount: 1,
    executiveSummary: 'A summary long enough to wrap onto a second line in the 680px container used by this document.',
    remediationInstructions: 'Remediate.',
    affectedSystems: ['host'],
  }) as unknown as Advisory;

const render = () => {
  const findings = [finding(1, 'fortinet', 'fortimanager'), finding(2, 'cisco', 'ios_xe')];
  return renderFindingsDocument({ advisory: advisory(findings), findings, generatedAt: new Date('2026-11-19T12:00:00Z') }).html;
};

test('nothing Outlook needs is stripped from the delivered HTML', () => {
  const html = render();
  // The <style> block carries the font stack and text-size adjustments.
  assert.ok(html.includes('<style'), 'style block survives');
  assert.ok(html.includes('-ms-text-size-adjust'), 'Word-engine text-size rule survives');
  // VML gradient: the only way Outlook desktop shows the header background.
  assert.ok(html.includes('<!--[if gte mso 9]>'), 'mso conditional survives');
  assert.ok(html.includes('<v:rect'), 'VML rect survives');
  assert.ok(html.includes('<v:fill type="gradient"'), 'VML gradient fill survives');
  assert.ok(html.includes('</v:rect>'), 'VML rect closed');
  // Conditional wrapper table that pins the 680px column for Outlook.
  assert.ok(html.includes('<!--[if mso]>'), 'mso wrapper conditional survives');
});

test('the layout carries widths the Word engine can honour', () => {
  const html = render();
  // Word ignores max-width; the width attribute and inline width are what it
  // reads. The conditional wrapper cell must not be auto-width.
  assert.ok(html.includes('<td width="680"'), 'wrapper cell has an explicit width');
  assert.ok(html.includes('width: 680px; max-width: 680px'), 'container pins its width');
  assert.ok(html.includes('width="680"'), 'container carries the width attribute');
});

test('wrapping prose does not use exact line-height (descender clipping)', () => {
  const html = render();
  // The summary, description, affected-version and mitigation cells wrap to an
  // unknown number of lines; `exactly` clips the g/y/p descenders in Outlook.
  const wrapping = /style="[^"]*mso-line-height-rule: exactly[^"]*"[^>]*>\s*\{\{\{/;
  assert.ok(!wrapping.test(html), 'no wrapping placeholder cell uses exact line-height');
  assert.ok(html.includes('mso-line-height-rule: at-least'), 'wrapping cells use at-least');
});

test('vendor and product render as proper display names', () => {
  const html = render();
  assert.ok(html.includes('Fortinet'), 'vendor capitalised');
  assert.ok(html.includes('FortiManager'), 'product capitalised');
  assert.ok(html.includes('Cisco'), 'second vendor capitalised');
  assert.ok(html.includes('IOS XE'), 'underscored product rendered with a space');
  // The raw CPE pair must never reach the recipient.
  assert.ok(!html.includes('fortinet / fortimanager'), 'no raw lowercase pair');
  assert.ok(!html.includes('cisco / ios_xe'), 'no raw CPE pair');
});
