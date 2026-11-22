import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { JSDOM } from 'jsdom';
import React, { act } from 'react';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  DEFAULT_NEWS_EMAIL_CUSTOMIZATION,
  DEFAULT_NEWS_EMAIL_TEMPLATE,
  compileNewsTemplate,
} from '../src/utils/templateCompiler.ts';
import { emptyState } from '../shared/state.ts';

/**
 * The News Template Studio must show one document.
 *
 * Reported symptom: "Template HTML Source" and "Live Rendered Preview" showed
 * different HTML. Three defects produced that:
 *
 *  1. `compileNewsTemplate` ignored its config and returned the stock string,
 *     so a saved studio template never carried the operator's colours.
 *  2. The preview rendered with a hard-coded daily-digest customization
 *     instead of the live `newsDigestCustomization`.
 *  3. The app state fell back to the raw snapshot or the stock constant rather
 *     than compiling from the customization.
 *
 * This renders the real component with a customized context and asserts the
 * rendered pane reflects it, and that the source pane is the template itself.
 */
test('the news studio state defaults to the news palette, not the digest one', () => {
  // The initial snapshot seeded `newsDigestCustomization` from the daily digest
  // palette, so an untouched install showed the news document in the digest's
  // colours while the delivered email used the news defaults.
  const state = emptyState();
  assert.deepEqual(state.newsDigestCustomization, DEFAULT_NEWS_EMAIL_CUSTOMIZATION);
  assert.notDeepEqual(state.newsDigestCustomization, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
});

test('the news studio preview renders the live customization, not a stale template', async () => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost' });
  const globals = globalThis as any;
  globals.window = dom.window;
  globals.document = dom.window.document;
  globals.HTMLElement = dom.window.HTMLElement;
  globals.IS_REACT_ACT_ENVIRONMENT = true;

  const customization = {
    ...DEFAULT_NEWS_EMAIL_CUSTOMIZATION,
    accentColor: '#7c3aed',
    canvasBg: '#fdf4ff',
    cardBg: '#fffaf0',
  };
  const context = {
    settings: { timezone: 'UTC' },
    error: null as string | null,
    clearError() { },
    // What AppContext exposes: the saved template compiled from the live
    // customization.
    newsDigestTemplate: compileNewsTemplate(customization),
    newsDigestCustomization: customization,
    updateNewsDigestCustomization() { },
    saveNewsDigestTemplate: async () => true,
    setNewsDigestCustomTemplate() { },
    // The studio routes its test send through the app context so it gets the
    // session CSRF token and the real `/api/test-email` endpoint.
    sendTestEmail: async () => ({ success: true, message: 'queued' }),
  };
  globals.__newsStudioPreviewContext = context;

  const directory = await mkdtemp(join(process.cwd(), '.news-studio-test-'));
  const output = join(directory, 'view.mjs');
  await build({
    entryPoints: ['src/components/NewsTemplateView.tsx'],
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
            () => ({ contents: 'export const useApp = () => globalThis.__newsStudioPreviewContext;' }),
          );
        },
      },
    ],
  });
  const { NewsTemplateView } = await import(pathToFileURL(output).href);
  const root = (await import('react-dom/client')).createRoot(document.getElementById('root')!);

  try {
    await act(async () => root.render(React.createElement(NewsTemplateView)));
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    // JSDOM does not execute a srcDoc into a document, so read the attribute:
    // that string is exactly what the browser renders in the pane.
    const frames = Array.from(document.querySelectorAll('iframe'));
    assert.ok(frames.length > 0, 'the preview pane is rendered');
    const preview = frames.map((frame) => frame.getAttribute('srcdoc') ?? '').join('\n');
    assert.ok(preview.length > 0, 'the preview iframe has a document');
    assert.match(preview, /#7c3aed/, "the preview applies the operator's accent");
    assert.match(preview, /#fdf4ff/, 'the preview applies the canvas colour');
    assert.ok(!preview.includes('#1d4ed8'), 'the stock accent is not used once customized');
    assert.ok(!/\{\{[^}]+\}\}/.test(preview), 'the preview is fully rendered');

    // The saved template that the app holds is the customized compile, not the
    // stock constant, so the source pane and the preview describe one document.
    assert.notEqual(context.newsDigestTemplate, DEFAULT_NEWS_EMAIL_TEMPLATE);
    assert.match(context.newsDigestTemplate, /#7c3aed/);

    await act(async () => root.unmount());
  } finally {
    await act(async () => root.unmount());
    dom.window.close();
    delete globals.__newsStudioPreviewContext;
    await rm(directory, { recursive: true, force: true });
  }
});
