import { createHash } from 'node:crypto';
import PDFDocument from 'pdfkit';
import { convert, type HtmlToTextOptions } from 'html-to-text';
import { resolveTimezone } from '../src/utils/dateTime.ts';

const PDF_CACHE_TTL_MS = 5 * 60_000;
const PDF_CACHE_MAX = 64;
const pdfCache = new Map<string, { content: Uint8Array; expires: number }>();
let cacheAccess = 0;
const HTML_TO_TEXT_OPTIONS: HtmlToTextOptions = {
  baseElements: { selectors: ['body'], returnDomByDefault: false },
  wordwrap: 92,
  limits: { maxInputLength: 2_000_000 },
  selectors: [
    { selector: 'script', format: 'skip' },
    { selector: 'style', format: 'skip' },
    { selector: 'img', format: 'skip' },
    { selector: 'svg', format: 'skip' },
    { selector: 'a', options: { hideLinkHrefIfSameAsText: true, linkBrackets: [' (', ')'] } },
  ],
};

export interface PdfAttachment {
  filename: string;
  content: Uint8Array;
  contentType: 'application/pdf';
}

/**
 * Attachment filename: `ddMMMyyyyHHMM.pdf`, e.g. `03Nov20261435.pdf`.
 *
 * Derived from the dispatch instant in the workspace timezone rather than the
 * server's local zone, so the filename matches the `Generated` timestamp on the
 * advisory the recipient is reading, and a file saved by two operators in
 * different offices still tells them when it was produced.
 */
export function advisoryFilename(advisoryId: string, at: Date = new Date(), timezone?: string): string {
  // Kept for signature compatibility and to make a malformed id obvious.
  const safeId = /^[A-Za-z0-9._-]+$/.test(advisoryId) ? advisoryId : 'advisory';
  const tz = resolveTimezone(timezone);
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: tz,
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(at);
  const pick = (type: string) => parts.find((part) => part.type === type)?.value || '';
  const month = pick('month');
  if (!month) return `${safeId}.pdf`;
  return `${pick('day')}${month}${pick('year')}${pick('hour')}${pick('minute')}.pdf`;
}

export function unverifiableMatchFilename(at: Date = new Date(), timezone?: string): string {
  // Same shape as an advisory attachment so a mailbox sorted by filename keeps
  // every report from this platform together.
  return advisoryFilename('unverifiable', at, timezone);
}

export function advisoryHtmlToText(html: string): string {
  if (Buffer.byteLength(html, 'utf8') > 2_000_000) throw new Error('Advisory HTML exceeds the PDF size limit');
  return convert(html, HTML_TO_TEXT_OPTIONS).trim();
}

export async function renderAdvisoryPdf(html: string): Promise<Uint8Array> {
  const key = createHash('sha256').update(html).digest('hex');
  const cached = pdfCache.get(key);
  if (cached && cached.expires > Date.now()) return cached.content;

  const text = advisoryHtmlToText(html);
  if (!text) throw new Error('Advisory HTML contains no printable content');

  const content = await new Promise<Uint8Array>((resolve, reject) => {
    const document = new PDFDocument({
      size: 'A4',
      margin: 48,
      bufferPages: true,
      info: { Title: 'Security advisory', Author: 'BA Threat Intel', Creator: 'VulnStream' },
    });
    const chunks: Buffer[] = [];
    document.on('data', (chunk: Buffer) => chunks.push(chunk));
    document.once('error', reject);
    document.once('end', () => resolve(new Uint8Array(Buffer.concat(chunks))));

    document.font('Helvetica-Bold').fontSize(18).fillColor('#122033').text('Security Advisory');
    document.moveDown(0.35);
    document.moveTo(48, document.y).lineTo(document.page.width - 48, document.y).strokeColor('#ccd4df').stroke();
    document.moveDown(0.8);
    document.font('Helvetica').fontSize(10).fillColor('#202a38').text(text, {
      lineGap: 3,
      paragraphGap: 5,
    });

    const pages = document.bufferedPageRange();
    for (let pageIndex = pages.start; pageIndex < pages.start + pages.count; pageIndex++) {
      document.switchToPage(pageIndex);
      const footerY = document.page.height - 32;
      document.font('Helvetica').fontSize(8).fillColor('#667085')
        .text('BA Threat Intel | Security advisory', 48, footerY, { lineBreak: false });
      document.text(`Page ${pageIndex - pages.start + 1} of ${pages.count}`, 48, footerY, {
        width: document.page.width - 96,
        align: 'right',
        lineBreak: false,
      });
    }
    document.end();
  });
  pdfCache.set(key, { content, expires: Date.now() + PDF_CACHE_TTL_MS });
  if (++cacheAccess > PDF_CACHE_MAX * 2) evictPdfCache();
  return content;
}

function evictPdfCache(): void {
  const now = Date.now();
  cacheAccess = 0;
  for (const [k, v] of pdfCache) if (v.expires < now) pdfCache.delete(k);
  while (pdfCache.size > PDF_CACHE_MAX) {
    const first = pdfCache.keys().next().value;
    if (first === undefined) break;
    pdfCache.delete(first);
  }
}

export async function closePdfRenderer(): Promise<void> {
  pdfCache.clear();
}
