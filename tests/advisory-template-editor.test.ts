import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { JSDOM } from 'jsdom';
import React, { act } from 'react';
import { DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';

test('HTML edits survive preview/editor switching, save, and reopening the studio', async () => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost' });
  const globals = globalThis as any;
  globals.window = dom.window;
  globals.document = dom.window.document;
  globals.HTMLElement = dom.window.HTMLElement;
  globals.IS_REACT_ACT_ENVIRONMENT = true;
  const directory = await mkdtemp(join(process.cwd(), '.template-editor-test-'));
  let saved: string | undefined;
  const context = {
    advisoryTemplate: '<html><body>Original template</body></html>',
    customAdvisoryTemplate: null as string | null,
    settings: { advisoryPrefix: 'TEST-' },
    templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION,
    updateTemplateCustomization() {},
    error: null as string | null,
    clearError() {},
    saveTemplate: async (html?: string) => {
      saved = html;
      if (html !== undefined) {
        context.customAdvisoryTemplate = html;
        context.advisoryTemplate = html;
      }
      return true;
    },
  };
  globals.__templateEditorContext = context;
  const output = join(directory, 'view.mjs');
  await build({
    entryPoints: ['src/components/AdvisoryTemplateView.tsx'],
    outfile: output, bundle: true, platform: 'node', format: 'esm', packages: 'external',
    plugins: [{
      name: 'test-context',
      setup(builder) {
        builder.onResolve({ filter: /\/context\/AppContext$/ }, () => ({ path: 'context', namespace: 'test' }));
        builder.onLoad({ filter: /.*/, namespace: 'test' }, () => ({ contents: 'export const useApp = () => globalThis.__templateEditorContext;' }));
      },
    }],
  });
  const { AdvisoryTemplateView } = await import(pathToFileURL(output).href);
  const { createRoot } = await import('react-dom/client');
  let root = createRoot(document.getElementById('root')!);
  const click = async (label: string) => {
    const button = [...document.querySelectorAll('button')].find((item) => item.textContent?.trim() === label);
    assert.ok(button, `Button ${label} exists`);
    await act(async () => button.click());
  };
  const edit = async (html: string) => {
    const textarea = document.querySelector('textarea')!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(dom.window.HTMLTextAreaElement.prototype, 'value')!.set!.call(textarea, html);
      textarea.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
    });
  };
  try {
    await act(async () => root.render(React.createElement(AdvisoryTemplateView)));
    await click('Template Editor');
    const edited = '<html><body>Changed heading {{advisory_title}}</body></html>';
    await edit(edited);
    await click('Apply to Preview');
    await click('Template Editor');
    assert.equal(document.querySelector('textarea')!.value, edited, 'reopening must preserve the draft');
    await click('Save & Apply to Notifications');
    await click('Save & Apply');
    assert.equal(saved, edited, 'save submits edited HTML rather than the old saved source');
    await act(async () => root.unmount());
    root = createRoot(document.getElementById('root')!);
    await act(async () => root.render(React.createElement(AdvisoryTemplateView)));
    await click('Template Editor');
    assert.equal(document.querySelector('textarea')!.value, edited, 'a fresh studio loads the saved HTML');

    // An unsaved edit must survive leaving and re-entering the editor through
    // any other view. Re-seeding the draft from the saved template on every
    // entry (the pre-fix behaviour) silently discarded exactly this edit.
    await edit('<html><body>Unsaved second pass</body></html>');
    const unsaved = document.querySelector('textarea')!.value;
    assert.notEqual(unsaved, edited, 'the second edit is a real change');
    await click('HTML Code');
    await click('Template Editor');
    assert.equal(document.querySelector('textarea')!.value, unsaved, 'an unsaved edit survives re-entry');

    // "Discard Changes" is the explicit way to drop it, and it must still work.
    await click('Discard Changes');
    await click('Template Editor');
    assert.equal(document.querySelector('textarea')!.value, edited, 'discard restores the saved template');
  } finally {
    await act(async () => root.unmount());
    dom.window.close();
    delete globals.__templateEditorContext;
    await rm(directory, { recursive: true, force: true });
  }
});