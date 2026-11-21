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
 * Every placeholder the shipped template can address must resolve in the
 * Template Studio's client-side preview.
 *
 * The preview prefers the server render, but falls back to its own
 * `renderEmailTemplate` pass while the server response is in flight, when the
 * server rejects a template mid-edit, or for local edits. That fallback had
 * drifted from the server's register twice over:
 *
 *  1. Keys were missing: `cves` items lacked `source_url`, and the per-CVE
 *     `vulnerabilities` list did not exist, so `{{source_url}}` and `{{cve_id}}`
 *     (inside their loops) showed verbatim.
 *  2. It ran with `preserveUnknown`, so ANY token the register did not resolve
 *     was printed literally, while the server blanks it. A bare `{{cve_id}}`
 *     outside `{{#each vulnerabilities}}` therefore appeared in the preview and
 *     blocked send-test-email, even though the delivered email never contained
 *     it. The preview now renders exactly like the server.
 */
test('the Studio preview leaves no unrendered placeholders', async () => {
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
    severity: 'HIGH',
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
      cvss: { score: 7.2, severity: 'HIGH', vector: '', version: '3.1' },
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
    updateTemplateCustomization() { },
    error: null as string | null,
    clearError() { },
    saveTemplate: async () => true,
    // Never resolves: the preview pane must fall back to its own renderer.
    renderAdvisoryTemplate: () => new Promise(() => { }),
  };
  globals.__studioPreviewContext = context;

  const directory = await mkdtemp(join(process.cwd(), '.studio-preview-test-'));
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
  const root = (await import('react-dom/client')).createRoot(document.getElementById('root')!);

  try {
    await act(async () => root.render(React.createElement(AdvisoryTemplateView)));
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    // The preview is written into an iframe document plus the page itself; read
    // everything on screen and require that no placeholder survived.
    const iframeDocs = Array.from(document.querySelectorAll('iframe')).map(
      (frame) => frame.contentDocument?.body?.innerHTML ?? '',
    );
    const visible = [document.body.innerHTML, ...iframeDocs].join('\n');
    assert.ok(visible.includes('Preview advisory'), 'the preview actually rendered the document');
    const leftovers = [...new Set(visible.match(/\{\{\{?\s*[^}]+?\s*\}?\}\}/g) ?? [])];
    assert.deepEqual(leftovers, [], 'the Studio preview shows literal placeholders');
    // Spell out the two tokens that regressed: `source_url` lives on each `cves`
    // item and `cve_id` on each `vulnerabilities` item (server/advisoryRender.ts).
    assert.ok(!visible.includes('{{source_url}}'), 'cves items carry source_url');
    assert.ok(!visible.includes('{{cve_id}}'), 'vulnerabilities items carry cve_id');
    assert.ok(visible.includes(cveId), 'the per-CVE content actually rendered');

    await act(async () => root.unmount());
  } finally {
    await act(async () => root.unmount());
    dom.window.close();
    delete globals.__studioPreviewContext;
    await rm(directory, { recursive: true, force: true });
  }
});

/**
 * The send-test-email path renders the SAVED template through
 * `getRenderedHtml()` and refuses to send if it finds a leftover token. That
 * check is only meaningful if the preview produces the same document the
 * server will: an unknown token must resolve to the empty string in both, not
 * to its own literal text in the preview only.
 *
 * A bare `{{cve_id}}` (valid only inside `{{#each vulnerabilities}}`) was the
 * reported case: the server blanked it, while the preview's `preserveUnknown`
 * kept it and blocked the send with "Template has unrendered tokens".
 */
test('the preview resolves unknown tokens the same way the server does', async () => {
  const { renderEmailTemplate } = await import('../src/utils/emailTemplate.ts');
  const { renderAdvisory } = await import('../server/advisoryRender.ts');
  const template = '<h1>ID: {{cve_id}}</h1>{{#each vulnerabilities}}<li>{{cve_id}}</li>{{/each}}';
  const advisory = {
    id: 'ADV-TEST',
    title: 'Template test',
    severity: 'UNKNOWN',
    cveIds: [],
    findingIds: [],
    createdDate: '2026-11-19T00:00:00Z',
    deliveryStatus: 'PENDING',
    recipientCount: 1,
    executiveSummary: 'Template test.',
    affectedSystems: ['Example asset'],
    remediationInstructions: 'Preview only.',
  } as never;

  const server = renderAdvisory(template, advisory);
  // The register the preview builds for a test email (no advisory, no findings).
  const preview = renderEmailTemplate(template, { severity: 'UNKNOWN', vulnerabilities: [], cves: [] });

  assert.equal(server, '<h1>ID: </h1>', 'the server blanks the out-of-scope token');
  assert.equal(preview, server, 'the preview must not show a token the recipient never receives');
  assert.deepEqual(preview.match(/\{\{[^}]+\}\}/g) ?? [], [], 'no token survives either render');
});
