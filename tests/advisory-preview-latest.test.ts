import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { JSDOM } from 'jsdom';
import React, { act } from 'react';
import { DEFAULT_ADVISORY_EMAIL_TEMPLATE } from '../src/utils/defaultAdvisoryEmailTemplate.ts';
import { DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';

/**
 * The Template Studio must preview the current template, not a stale copy.
 *
 * Three things have to agree, and each has broken before:
 *
 *  1. the shipped `.ts` template is the canonical document (see
 *     advisory-template-canonical.test.ts);
 *  2. the Studio falls back to the same template, not a legacy one, when no
 *     operator template is saved;
 *  3. that fallback renderer supplies every placeholder the canonical document
 *     addresses. A missing key is blanked, not reported, so a drifted fallback
 *     silently previews an unpainted/unlabelled document while the delivered
 *     email is correct.
 *
 * This mounts the real view with no saved template and with the server preview
 * deliberately unavailable, then asserts the rendered document has no blank
 * placeholders and carries the current template's markup.
 */
test('the Studio preview renders the current canonical template', async () => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost' });
  const globals = globalThis as any;
  globals.window = dom.window;
  globals.document = dom.window.document;
  globals.HTMLElement = dom.window.HTMLElement;
  globals.IS_REACT_ACT_ENVIRONMENT = true;

  const cveId = 'CVE-2026-10001';
  const advisory = {
    id: 'ADV-0000000001',
    title: 'Preview advisory',
    severity: 'CRITICAL',
    cveIds: [cveId],
    findingIds: ['f1'],
    createdDate: '2026-11-19T00:00:00Z',
    deliveryStatus: 'PENDING',
    recipientCount: 1,
    executiveSummary: 'Summary.',
    remediationInstructions: 'Remediate.',
    affectedSystems: ['host'],
  };
  const finding = {
    id: 'f1',
    cveId,
    advisoryId: advisory.id,
    cve: {
      cveId,
      title: 't',
      description: 'A vendor description.',
      cvss: { score: 9.8, severity: 'CRITICAL', vector: '', version: '3.1' },
      cpeMatches: [],
      cwe: [],
      sourceFeeds: [],
      publishedDate: '2026-11-19T00:00:00Z',
      modifiedDate: '2026-11-19T00:00:00Z',
      remediation: { immediateActions: ['Patch.'], patchUrl: '', vendorAdvisoryRef: '' },
    },
    matchedAssetId: 'a1',
    matchedAssetName: 'host',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'widget',
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
    reviewNotifiedAt: null,
    timeline: [],
  };
  const context = {
    advisories: [advisory],
    findings: [finding],
    advisoryTemplate: DEFAULT_ADVISORY_EMAIL_TEMPLATE,
    customAdvisoryTemplate: null as string | null,
    settings: { advisoryPrefix: 'ADV-' },
    templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION,
    updateTemplateCustomization() {},
    error: null as string | null,
    clearError() {},
    saveTemplate: async () => true,
    // Never resolves: force the preview onto its own renderer.
    renderAdvisoryTemplate: () => new Promise(() => {}),
  };
  globals.__studioPreviewContext = context;

  const directory = await mkdtemp(join(process.cwd(), '.studio-latest-test-'));
  const output = join(directory, 'view.mjs');
  await build({
    entryPoints: ['src/components/AdvisoryTemplateView.tsx'],
    outfile: output,
    bundle: true,
    platform: 'node',
    format: 'esm',
    packages: 'external',
    plugins: [
      {
        name: 'test-context',
        setup(builder) {
          builder.onResolve({ filter: /\/context\/AppContext$/ }, () => ({ path: 'context', namespace: 'test' }));
          builder.onLoad(
            { filter: /.*/, namespace: 'test' },
            () => ({ contents: 'export const useApp = () => globalThis.__studioPreviewContext;' }),
          );
        },
      },
    ],
  });
  const { AdvisoryTemplateView } = await import(pathToFileURL(output).href);
  const { createRoot } = await import('react-dom/client');
  const root = createRoot(document.getElementById('root')!);

  try {
    await act(async () => root.render(React.createElement(AdvisoryTemplateView)));
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    // The preview renders into a sandboxed iframe document.
    const docs = Array.from(document.querySelectorAll('iframe')).map((frame) => frame.contentDocument?.body?.innerHTML ?? '');
    const rendered = [document.body.innerHTML, ...docs].join('\n');

    // Current template, not a legacy one: these structures only exist in the
    // canonical document.
    for (const marker of ['Executive Summary', 'CVE Identifier', 'ENTERPRISE VULNERABILITY NOTIFICATION'])
      assert.ok(rendered.includes(marker), `current template section present: ${marker}`);
    assert.ok(!rendered.includes('NEXT STEPS'), 'no legacy section from an older template');

    // Match only real template tokens: `{{name}}` / `{{{name}}}` with no braces
    // inside, so CSS rule bodies in the <style> block are not mistaken for them.
    const left = [...new Set(rendered.match(/\{\{\{?\s*[^{}]+?\s*\}?\}\}/g) ?? [])];
    assert.deepEqual(left, [], 'no placeholders left');
    assert.ok(!rendered.includes('bgcolor=""'), 'no unresolved bgcolor');
    assert.ok(!rendered.includes('href="mailto:"'), 'footer address resolved');
    assert.ok(rendered.includes(cveId), 'CVE id rendered');
    // CRITICAL palette from the canonical Outlook-safe header.
    assert.ok(rendered.includes('#ffb4ad'), 'severity accent colour painted');

    await act(async () => root.unmount());
  } finally {
    await act(async () => root.unmount());
    dom.window.close();
    delete globals.__studioPreviewContext;
    await rm(directory, { recursive: true, force: true });
  }
});
