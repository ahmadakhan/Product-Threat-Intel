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
  DEFAULT_DAILY_DIGEST_TEMPLATE,
  compileDailyDigestTemplate,
} from '../src/utils/templateCompiler.ts';

/**
 * The Daily Digest Studio must show one document.
 *
 * Reported symptom: "Template HTML Source" and "Live Rendered Preview" showed
 * different HTML. The news studio had the same three defects, fixed earlier:
 *
 *  1. The preview fell back to `DEFAULT_DAILY_DIGEST_TEMPLATE`, so a saved
 *     studio template never carried the operator's colours.
 *  2. It rendered through a hand-rolled `.replace()` chain that drifted from
 *     the real renderer (it blanked `held_for_review`, hard-coded the severity
 *     badge, and skipped `{{#if}}` branches).
 *  3. `dailyDigestTemplate` was not compiled from the customization.
 *
 * This renders the real component and asserts the preview pane reflects the
 * live customization and is produced by the delivery renderer.
 */
test('the digest studio preview renders the live customization, not a stale template', async () => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost' });
  const globals = globalThis as any;
  globals.window = dom.window;
  globals.document = dom.window.document;
  globals.HTMLElement = dom.window.HTMLElement;
  globals.IS_REACT_ACT_ENVIRONMENT = true;

  const customization = {
    ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
    accentColor: '#7c3aed',
    canvasBg: '#fdf4ff',
    cardBg: '#fffaf0',
  };
  const sent: { email: string; html?: string }[] = [];
  const context = {
    settings: { timezone: 'UTC', advisoryPrefix: 'BA-' },
    error: null as string | null,
    clearError() {},
    // What AppContext exposes: the saved template compiled from the live
    // customization.
    dailyDigestTemplate: compileDailyDigestTemplate(customization),
    dailyDigestCustomization: customization,
    updateDailyDigestCustomization() {},
    saveDailyDigestTemplate: async () => true,
    setDailyDigestCustomTemplate() {},
    sendTestDailyDigestEmail: async (email: string, html?: string) => {
      sent.push({ email, html });
      return { success: true, message: 'queued' };
    },
  };
  globals.__digestStudioPreviewContext = context;

  const directory = await mkdtemp(join(process.cwd(), '.digest-studio-test-'));
  const output = join(directory, 'view.mjs');
  await build({
    entryPoints: ['src/components/DailyDigestView.tsx'],
    outfile: output,
    bundle: true,
    platform: 'node',
    format: 'esm',
    packages: 'external',
    plugins: [
      {
        name: 'test-context',
        setup(builder) {
          builder.onResolve({ filter: /\/context\/AppContext$/ }, () => ({
            path: 'context',
            namespace: 'test',
          }));
          builder.onLoad({ filter: /.*/, namespace: 'test' }, () => ({
            contents: 'export const useApp = () => globalThis.__digestStudioPreviewContext;',
          }));
        },
      },
    ],
  });
  const { DailyDigestView } = await import(pathToFileURL(output).href);
  const root = (await import('react-dom/client')).createRoot(document.getElementById('root')!);

  try {
    await act(async () => root.render(React.createElement(DailyDigestView)));
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
    // Produced by the real renderer: the Confidence Follow-Up row is populated
    // rather than blanked, which the old replace() chain got wrong.
    assert.match(preview, /No outstanding confidence follow-ups/);

    // The saved template the app holds is the customized compile, not the
    // stock constant, so the source pane and the preview describe one document.
    assert.notEqual(context.dailyDigestTemplate, DEFAULT_DAILY_DIGEST_TEMPLATE);
    assert.match(context.dailyDigestTemplate, /#7c3aed/);

    // The email surface is the same document: "Send Test Email" submits what the
    // canvas iframe is showing, not a second server render of the saved state.
    const canvasHtml = frames[0].getAttribute('srcdoc') ?? '';
    const sendTestEmail = Array.from(document.querySelectorAll('button')).find(
      (button) => button.textContent?.trim() === 'Send Test Email',
    );
    assert.ok(sendTestEmail, 'the Send Test Email action is rendered');
    await act(async () => sendTestEmail.click());

    const recipient = document.querySelector('input[type="email"]') as HTMLInputElement | null;
    assert.ok(recipient, 'the test recipient field is rendered');
    await act(async () => {
      Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, 'value')!.set!.call(
        recipient,
        'soc@example.com',
      );
      recipient.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
    });

    const send = Array.from(document.querySelectorAll('button')).find(
      (button) => button.textContent?.trim() === 'Send Test',
    );
    assert.ok(send, 'the Send Test action is rendered');
    await act(async () => send.click());
    const confirm = Array.from(document.querySelectorAll('button')).find(
      (button) => button.textContent?.trim() === 'Confirm send',
    );
    assert.ok(confirm, 'the confirmation action is rendered');
    await act(async () => confirm.click());
    assert.equal(sent.length, 1, 'the studio queued exactly one test email');
    assert.equal(sent[0].email, 'soc@example.com');
    assert.equal(sent[0].html, canvasHtml, 'the email body is the canvas document, byte for byte');

    await act(async () => root.unmount());
  } finally {
    await act(async () => root.unmount());
    dom.window.close();
    delete globals.__digestStudioPreviewContext;
    await rm(directory, { recursive: true, force: true });
  }
});
