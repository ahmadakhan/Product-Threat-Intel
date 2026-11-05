import { test } from 'node:test';
import assert from 'node:assert/strict';
import { advisoryHtmlToPdfBlocks, advisoryHtmlToText, renderAdvisoryPdf, closePdfRenderer } from '../server/pdf.ts';
import { renderAdvisory } from '../server/advisoryRender.ts';
import { advisoryFilename, unverifiableMatchFilename } from '../server/pdf.ts';
import { compileCustomizedTemplate, DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';
import { DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import { sendProviderEmail } from '../server/emailProviders.ts';
import type { Advisory, EmailConfiguration } from '../src/types/index.ts';
import { applyJobEdits, type Job } from '../server/delivery.ts';

test('advisory HTML conversion preserves readable content and skips executable/resource markup', () => {
  const text = advisoryHtmlToText(`<html><head><title>Ignored title</title><style>.secret{display:none}</style></head>
    <body><h1>CVE-2026-12345 advisory</h1><p>Patch the affected application.</p>
    <a href="https://vendor.example/advisory">Vendor guidance</a>
    <script>EXECUTABLE_SENTINEL</script><img src="https://tracker.example/pixel" alt="tracking pixel">
    <svg><text>SVG_SENTINEL</text></svg></body></html>`);
  assert.match(text, /CVE-2026-12345 advisory/i);
  assert.match(text, /Patch the affected application/);
  assert.match(text, /Vendor guidance/);
  assert.doesNotMatch(text, /Ignored title|secret|EXECUTABLE_SENTINEL|tracker\.example|SVG_SENTINEL/);
});

test('PDF blocks preserve each email CVE card and its severity accent', () => {
  const blocks = advisoryHtmlToPdfBlocks(
    '<html><body><p>Security advisory</p>' +
      '<div class="vulnstream-pdf-card" data-pdf-accent="#f59e0b" style="border-left:4px solid #f59e0b"><h2>CVE-2026-12345</h2><p>High description</p></div>' +
      '<div class="vulnstream-pdf-card" data-pdf-accent="#10b981" style="border-left:4px solid #10b981"><h2>CVE-2026-67890</h2><p>Low description</p></div>' +
      '</body></html>',
  );
  const cards = blocks.filter((block) => block.kind === 'cve-card');
  assert.deepEqual(cards.map((card) => card.kind === 'cve-card' && card.accent), ['#f59e0b', '#10b981']);
  assert.ok(cards[0].text.includes('CVE-2026-12345'));
  assert.ok(cards[1].text.includes('CVE-2026-67890'));
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

test('renderAdvisoryPdf renders the compiled advisory HTML to a PDF without a browser', async () => {
  const template = compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION);
  const html = renderAdvisory(template, advisory);
  assert.ok(html.includes('CVE-2026-12345'));
  assert.ok(!html.includes('{{advisory_id}}'));
  const cveCards = advisoryHtmlToPdfBlocks(html).filter((block) => block.kind === 'cve-card');
  assert.equal(cveCards.length, advisory.cveIds.length);
  assert.deepEqual(cveCards.map((block) => block.kind === 'cve-card' && block.accent), ['#ef4444', '#ef4444']);
  assert.ok(cveCards[0].text.includes('CVE-2026-12345'));
  assert.ok(cveCards[1].text.includes('CVE-2026-67890'));

  const pdf = await renderAdvisoryPdf(html);
  try {
    assert.equal(Buffer.from(pdf).slice(0, 5).toString(), '%PDF-');
    assert.ok(pdf.length > 2000, 'PDF should contain rendered content');
  } finally {
    await closePdfRenderer();
  }
});

test('rendered advisory PDF is attached to provider messages', async () => {
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
