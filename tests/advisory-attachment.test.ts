import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findingHtmlAttachment, withUtf8Charset } from '../server/delivery.ts';
import type { Job } from '../server/delivery.ts';

/**
 * The HTML attachment must be the exact body the recipient receives.
 *
 * The template is operator-facing and the saved file is what people forward to
 * auditors, so any byte-level divergence (escape, charset, timer staleness)
 * makes the attachment evidence of something that was never sent.
 */

const html = '<!DOCTYPE html><html><head><title>A</title></head><body><p>x &amp; y</p></body></html>';

const job = (overrides: Partial<Job> = {}): Job =>
  ({
    id: 'job-1',
    dedupe_key: 'k',
    channel: 'email',
    target_id: 'r1',
    advisory_id: 'FINDINGS:abc',
    payload: { subject: 'Subject', html, text: 't', recipientEmail: 'a@b.c' },
    status: 'QUEUED',
    attempts: 1,
    priority: 0,
    next_attempt: new Date().toISOString(),
    error: null,
    edits: {},
    ...overrides,
  }) as unknown as Job;

test('the attachment body is byte-identical to the emailed HTML', () => {
  const attachment = findingHtmlAttachment(job())!;
  assert.ok(attachment, 'a finding email carries the HTML attachment');
  assert.equal(attachment.contentType, 'text/html; charset=utf-8');
  // withUtf8Charset only adds a charset when the document lacks one; this
  // document does not, so the attachment is the body plus one <meta> tag and
  // nothing else.
  assert.equal(attachment.content.toString('utf8'), withUtf8Charset(html));
});

test('the attachment never diverges from the body by re-rendering', () => {
  // Two calls must produce identical bytes: nothing time-dependent (a "now"
  // timestamp) may leak into the attachment path.
  const first = findingHtmlAttachment(job())!;
  const second = findingHtmlAttachment(job())!;
  assert.ok(first.content.equals(second.content), 'rendering is deterministic');
});

test('a documents own charset declaration is preserved, not rewritten', () => {
  const declared = '<html><head><meta charset="utf-8"></head><body>ok</body></html>';
  assert.equal(withUtf8Charset(declared), declared);
});

test('a non-finding email carries no HTML attachment', () => {
  // NEWS/SELFHEAL/... bundles are explicitly excluded from the finding path.
  assert.equal(findingHtmlAttachment(job({ advisory_id: 'NEWS:abc' })), undefined);
});

test('an explicit attachHtml=false is honoured', () => {
  assert.equal(findingHtmlAttachment(job({ edits: { attachHtml: false } })), undefined);
});
