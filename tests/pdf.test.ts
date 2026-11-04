import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { resolveChromeExecutablePath, renderAdvisoryPdf, closePdfRenderer, securePdfPage } from '../server/pdf.ts';
import type { Page, HTTPRequest } from 'puppeteer-core';
import { renderAdvisory } from '../server/advisoryRender.ts';
import { advisoryFilename, unverifiableMatchFilename } from '../server/pdf.ts';
import { compileCustomizedTemplate, DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';
import { DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import { sendProviderEmail } from '../server/emailProviders.ts';
import type { Advisory, EmailConfiguration } from '../src/types/index.ts';
import { applyJobEdits, type Job } from '../server/delivery.ts';

const chrome = resolveChromeExecutablePath();

test('PDF pages disable script execution and block every external resource scheme', async () => {
  const settings: Record<string, boolean> = {};
  let handler: ((request: HTTPRequest) => void) | undefined;
  const page = {
    async setJavaScriptEnabled(value: boolean) { settings.javascript = value; },
    async setBypassServiceWorker(value: boolean) { settings.bypassServiceWorker = value; },
    async setRequestInterception(value: boolean) { settings.interception = value; },
    on(_event: string, listener: (request: HTTPRequest) => void) { handler = listener; },
  } as unknown as Page;
  await securePdfPage(page);
  assert.deepEqual(settings, { javascript: false, bypassServiceWorker: true, interception: true });
  for (const url of [
    'https://api.sendgrid.com/private', 'http://127.0.0.1/',
    'http://169.254.169.254/latest/meta-data/', 'file:///etc/passwd',
    'ftp://example.com/image', 'blob:https://example.com/id',
    'data:image/png;base64,AA==', 'about:blank',
  ]) {
    let outcome = '';
    handler!({
      isInterceptResolutionHandled: () => false,
      url: () => url,
      async continue() { outcome = 'allowed'; },
      async abort() { outcome = 'blocked'; },
    } as unknown as HTTPRequest);
    assert.equal(outcome, url.startsWith('data:') || url === 'about:blank' ? 'allowed' : 'blocked', url);
  }
});

test('advisoryFilename is a ddMMMyyyyHHMM timestamp in the workspace timezone', () => {
  const at = new Date('2026-10-05T13:42:00Z');
  assert.match(advisoryFilename('ADV-05Oct2026-A1B2C3D4', at, 'UTC'), /^05Oct2026\d{4}\.pdf$/);
  assert.equal(advisoryFilename('ADV-05Oct2026-A1B2C3D4', at, 'UTC'), '05Oct20261342.pdf');
  // A timezone shift moves the local hour, not the shape of the name.
  assert.equal(advisoryFilename('ADV-05Oct2026-A1B2C3D4', at, 'Europe/Berlin'), '05Oct20261542.pdf');
});

test('unverifiableMatchFilename shares the advisory attachment shape', () => {
  assert.equal(
    unverifiableMatchFilename(new Date('2026-03-09T08:05:00Z'), 'UTC'),
    '09Mar20260805.pdf',
  );
});

const advisory = {
  id: 'ADV-05Oct2026-A1B2C3D4',
  title: 'Test vulnerability advisory',
  severity: 'CRITICAL',
  cveIds: ['CVE-2026-12345', 'CVE-2026-67890'],
  affectedSystems: ['web-01', 'db-02'],
  executiveSummary: 'A critical test vulnerability affects monitored systems.',
  remediationInstructions: 'Apply the vendor patch and verify inventory coverage.',
  vendorLink: 'https://example.com/advisory/2026-0001',
} as unknown as Advisory;

test('renderAdvisoryPdf renders the compiled advisory HTML to a PDF', { skip: !chrome }, async () => {
  const template = compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION);
  const html = renderAdvisory(template, advisory);
  assert.ok(html.includes('CVE-2026-12345'));
  assert.ok(!html.includes('{{advisory_id}}'));

  const pdf = await renderAdvisoryPdf(html);
  try {
    assert.equal(Buffer.from(pdf).slice(0, 5).toString(), '%PDF-');
    assert.ok(pdf.length > 2000, 'PDF should contain rendered content');
  } finally {
    await closePdfRenderer();
  }
});

test('real PDF rendering cannot fetch remote images, styles or script resources', { skip: !chrome }, async () => {
  let requests = 0;
  const server = createServer((_request, response) => {
    requests++;
    response.end('external content');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  const remote = `http://127.0.0.1:${port}`;
  try {
    const pdf = await renderAdvisoryPdf(`<html><head><link rel="stylesheet" href="${remote}/style.css"></head>
      <body><h1>Isolated advisory</h1><img src="${remote}/image.png">
      <script src="${remote}/script.js"></script><iframe src="file:///etc/passwd"></iframe></body></html>`);
    assert.equal(Buffer.from(pdf).subarray(0, 5).toString(), '%PDF-');
    assert.equal(requests, 0);
  } finally {
    await closePdfRenderer();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('rendered advisory PDF is attached to provider messages', { skip: !chrome }, async () => {
  const template = compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION);
  const html = renderAdvisory(template, advisory);
  const pdf = await renderAdvisoryPdf(html);
  const attachment = {
    filename: advisoryFilename('ADV-05Oct2026-A1B2C3D4'),
    content: Buffer.from(pdf),
    contentType: 'application/pdf' as const,
  };
  const base64 = attachment.content.toString('base64');
  const config: EmailConfiguration = { ...DEFAULT_EMAIL_CONFIG, provider: 'SENDGRID', fromEmail: 'security@example.invalid' };
  const job = {
    id: 'test-job',
    dedupe_key: 'test',
    channel: 'email',
    target_id: 'recipient',
    advisory_id: 'ADV-05Oct2026-A1B2C3D4',
    attempts: 1,
    lock_token: 'test',
    payload: { subject: 'Security notice', text: 'see html', html, recipientEmail: 'recipient@example.invalid', cveIds: ['CVE-2026-12345'] },
  };
  let capturedBody: string | undefined;
  await sendProviderEmail(
    config,
    'token',
    job as any,
    async (_url, options) => {
      capturedBody = options?.body;
      return { status: 202, headers: { 'x-message-id': 'id' }, body: '' };
    },
    false,
    attachment,
  );
  await closePdfRenderer();

  assert.ok(capturedBody);
  const payload = JSON.parse(capturedBody!);
  assert.equal(payload.attachments[0].type, 'application/pdf');
  // Timestamped attachment name: ddMMMyyyyHHMM.pdf.
  assert.match(payload.attachments[0].filename, /^\d{2}[A-Z][a-z]{2}\d{4}\d{4}\.pdf$/);
  assert.equal(payload.attachments[0].disposition, 'attachment');
  assert.equal(payload.attachments[0].content, base64);
  assert.ok(base64.length > 1000);
});

/**
 * The PDF attachment must be built from the *edited* body.
 *
 * `buildPdfAttachment` used to render `job.payload.html` directly. An operator
 * editing an email in the Action Center (notice, reviewer comment, or a full
 * body override) therefore shipped a corrected email whose attachment still
 * showed the original text. The sender normalises through `applyJobEdits`, so
 * this asserts the helper the attachment renderer relies on stays lossless and
 * idempotent — the same contract the transport path depends on.
 */
test('PDF input is derived from the edited email body, not the queued template', () => {
  const original = '<html><body><p>Original advisory body</p></body></html>';
  const edits = {
    audienceNotice: 'Patched on the DMZ cluster already.',
    reviewerComment: 'Validated by the on-call engineer.',
    reviewerName: 'Ops',
    customBodyOverride: '<html><body><p>Corrected advisory body</p></body></html>',
  };

  const edited = applyJobEdits({
    id: 'job-1',
    dedupe_key: 'dedupe-1',
    channel: 'email',
    target_id: 'recipient-1',
    advisory_id: 'ADV-TEST',
    payload: { recipientEmail: 'sec@example.com', subject: 'Subject', text: 'text', cveIds: [], html: original },
    attempts: 0,
    lock_token: 'token',
    edits,
  } as Job);

  assert.match(edited.payload.html ?? '', /Corrected advisory body/);
  // The attachment renderer receives `applyJobEdits(job).payload.html`; the
  // unedited template must not be what reaches it.
  assert.notEqual(edited.payload.html, original);

  // Idempotent: re-applying the same edits must not duplicate the notice/comment
  // blocks, which would otherwise appear twice in the rendered PDF.
  const again = applyJobEdits(edited);
  assert.equal(again.payload.html, edited.payload.html);
});
