import { createHash, randomUUID } from 'node:crypto';
import PDFDocument from 'pdfkit';
import { convert, type FormatCallback, type HtmlToTextOptions } from 'html-to-text';
import { resolveTimezone } from '../src/utils/dateTime.ts';

const PDF_CACHE_TTL_MS = 5 * 60_000;
const PDF_CACHE_MAX = 64;
const pdfCache = new Map<string, { content: Uint8Array; expires: number }>();
let pdfQueue: Promise<void> = Promise.resolve();
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

export type AdvisoryPdfBlock =
  | { kind: 'text'; text: string }
  | { kind: 'cve-card'; text: string; accent: string };

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

export function advisoryHtmlToPdfBlocks(html: string): AdvisoryPdfBlock[] {
  if (Buffer.byteLength(html, 'utf8') > 2_000_000) throw new Error('Advisory HTML exceeds the PDF size limit');
  const marker = `VULNSTREAMPDF${randomUUID().replaceAll('-', '')}`;
  const accents: string[] = [];
  const pdfCveCard: FormatCallback = (element, walk, builder) => {
    const index = accents.length;
    const candidate = String(element.attribs?.['data-pdf-accent'] || '');
    accents.push(/^#[0-9a-f]{6}$/i.test(candidate) ? candidate.toLowerCase() : '#64748b');
    builder.openBlock({ leadingLineBreaks: 1 });
    builder.addInline(`[[[${marker}_${index}_START]]]`, { noWordTransform: true });
    builder.addLineBreak();
    walk(element.children, builder);
    builder.addLineBreak();
    builder.addInline(`[[[${marker}_${index}_END]]]`, { noWordTransform: true });
    builder.closeBlock({ trailingLineBreaks: 1 });
  };
  const text = convert(html, {
    ...HTML_TO_TEXT_OPTIONS,
    formatters: { pdfCveCard },
    selectors: [
      ...(HTML_TO_TEXT_OPTIONS.selectors ?? []),
      { selector: 'div.vulnstream-pdf-card', format: 'pdfCveCard' },
      { selector: 'tr.vulnstream-pdf-card', format: 'pdfCveCard' },
    ],
  });
  const blocks: AdvisoryPdfBlock[] = [];
  const startPattern = new RegExp(`\\[\\[\\[${marker}_(\\d+)_START\\]\\]\\]`, 'g');
  let cursor = 0;
  for (let match = startPattern.exec(text); match; match = startPattern.exec(text)) {
    const index = Number(match[1]);
    const endMarker = `[[[${marker}_${index}_END]]]`;
    const end = text.indexOf(endMarker, startPattern.lastIndex);
    if (end < 0) continue;
    const before = text.slice(cursor, match.index).trim();
    const cardText = text.slice(startPattern.lastIndex, end).trim();
    if (before) blocks.push({ kind: 'text', text: before });
    if (cardText) blocks.push({ kind: 'cve-card', text: cardText, accent: accents[index] || '#64748b' });
    cursor = end + endMarker.length;
    startPattern.lastIndex = cursor;
  }
  const remaining = text.slice(cursor).trim();
  if (remaining) blocks.push({ kind: 'text', text: remaining });
  return blocks;
}

async function renderPdfBlocks(blocks: AdvisoryPdfBlock[]): Promise<Uint8Array> {
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

    const left = document.page.margins.left;
    const width = document.page.width - left - document.page.margins.right;
    const contentBottom = document.page.height - document.page.margins.bottom - 28;
    for (const block of blocks) {
      if (block.kind === 'text') {
        document.font('Helvetica').fontSize(9).fillColor('#202a38').text(block.text, {
          width,
          lineGap: 3,
          paragraphGap: 5,
        });
        document.moveDown(0.3);
        continue;
      }

      document.font('Helvetica').fontSize(9).fillColor('#202a38');
      const innerWidth = width - 28;
      const cardHeight = Math.max(54, document.heightOfString(block.text, {
        width: innerWidth,
        lineGap: 3,
        paragraphGap: 4,
      }) + 22);
      if (cardHeight > document.page.height - document.page.margins.top - document.page.margins.bottom - 28) {
        document.moveTo(left + 3, document.y).lineTo(left + 3, document.y + 12).lineWidth(4).strokeColor(block.accent).stroke();
        document.font('Helvetica').fontSize(9).fillColor('#202a38').text(block.text, { width: innerWidth, indent: 12, lineGap: 3, paragraphGap: 4 });
        document.moveDown(0.4);
        continue;
      }
      if (document.y + cardHeight > contentBottom) document.addPage();
      const top = document.y;
      document.save();
      document.roundedRect(left, top, width, cardHeight, 4).fillAndStroke('#ffffff', '#dfe4e8');
      document.moveTo(left + 2, top + 5).lineTo(left + 2, top + cardHeight - 5)
        .lineWidth(4).strokeColor(block.accent).stroke();
      document.restore();
      document.font('Helvetica').fontSize(9).fillColor('#202a38').text(block.text, left + 14, top + 11, {
        width: innerWidth,
        lineGap: 3,
        paragraphGap: 4,
      });
      document.y = Math.max(document.y, top + cardHeight) + 10;
    }

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
  return content;
}

function serializePdf<T>(operation: () => Promise<T>): Promise<T> {
  const result = pdfQueue.then(operation);
  pdfQueue = result.then(() => undefined, () => undefined);
  return result;
}

export async function renderAdvisoryPdf(html: string): Promise<Uint8Array> {
  if (Buffer.byteLength(html, 'utf8') > 2_000_000) throw new Error('Advisory HTML exceeds the PDF size limit');
  const key = createHash('sha256').update(html).digest('hex');
  const content = await serializePdf(async () => {
    const cached = pdfCache.get(key);
    if (cached && cached.expires > Date.now()) return cached.content;
    const blocks = advisoryHtmlToPdfBlocks(html);
    if (!blocks.length) throw new Error('Advisory HTML contains no printable content');
    const rendered = await renderPdfBlocks(blocks);
    pdfCache.set(key, { content: rendered, expires: Date.now() + PDF_CACHE_TTL_MS });
    return rendered;
  });
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
