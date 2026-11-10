import type { IntelligenceArticle, IntelligenceMatch } from '../src/types/index.ts';

/**
 * Consolidated security-news rendering.
 *
 * Every `IntelligenceMatch` is a piece of evidence tied to one monitored asset.
 * The matcher keys a match on `hash(cveId || articleId)`, so re-correlating the
 * same coverage produces new match rows for evidence the team has already been
 * given — which is how the news path previously emailed the same article more
 * than once. This module makes the *article*, not the match, the unit of
 * delivery:
 *
 *  - one email per recipient per pipeline run, containing every new article;
 *  - an article that is already present in an accepted or queued news email for
 *    that recipient is never included again (`selectUnnotifiedArticles`).
 *
 * The HTML format is preserved: the same card layout, palette and typography
 * used by the original per-match news alert, extended so a consolidated email
 * lists every article and every matched asset.
 */

type NewsArticle = Pick<
  IntelligenceArticle,
  'id' | 'title' | 'url' | 'sourceFeeds' | 'publishedDate' | 'modifiedDate' | 'cveIds'
>;

export interface ConsolidatedNewsItem {
  article: NewsArticle;
  /** Assets this article was correlated with in this run. */
  assets: string[];
  /** CVEs reference by the article (or by the match), de-duplicated. */
  cveIds: string[];
  /** Per-match evidence lines, de-duplicated. */
  evidence: string[];
  /** True when at least one match describes an unassigned vulnerability. */
  zeroDay: boolean;
  /** Highest credibility score observed across the matches for this run. */
  credibilityScore?: number;
  /** IntelligenceMatch ids consolidated into this item, for audit. */
  matchIds: string[];
  /** Why this item survived consolidation (audit trail for dedup decisions). */
  consolidationReason: 'new_article' | 'cve_dedup_kept' | 'cve_dedup_suppressed';
  /** CVE IDs this item suppresses (same CVE reported by other articles). */
  suppressesCveIds: string[];
  /** True when this item was removed because a higher-scoring article covers the same CVE. */
  suppressedByCve?: string;
}

/** Collapses feed-controlled text into a single safe line. */
export const newsSafeLine = (value: string | undefined) =>
  (value || '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '')
    .trim();

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (character) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!,
  );

/** Only absolute http(s) URLs without credentials may be hyperlinked. */
const safeHref = (value: string): string => {
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return '';
    return url.href;
  } catch {
    return '';
  }
};

/**
 * Builds one consolidated item per article from a set of matches and their
 * articles. Items are ordered by publication date (newest first) then id, which
 * keeps the rendered document deterministic across runs.
 */
export function consolidateNewsMatches(
  matches: readonly IntelligenceMatch[],
  articles: ReadonlyMap<string, NewsArticle>,
  assetNameFor: (assetId: string) => string | undefined,
): ConsolidatedNewsItem[] {
  const byArticle = new Map<string, ConsolidatedNewsItem>();
  for (const match of matches) {
    const assetName = assetNameFor(match.assetId) || match.assetName || 'unknown asset';
    for (const articleId of match.articleIds) {
      const article = articles.get(articleId);
      if (!article) continue;
      const identity = newsArticleIdentity(article);
      const item = byArticle.get(identity) ?? {
        article,
        assets: [],
        cveIds: [],
        evidence: [],
        zeroDay: false,
        credibilityScore: undefined,
        matchIds: [],
        consolidationReason: 'new_article',
        suppressesCveIds: [],
      };
      if (!item.assets.includes(assetName)) item.assets.push(assetName);
      if (!item.matchIds.includes(match.id)) item.matchIds.push(match.id);
      for (const cveId of [...(article.cveIds || []), ...(match.cveId ? [match.cveId] : [])])
        if (cveId && !item.cveIds.includes(cveId)) item.cveIds.push(cveId);
      const evidence = newsSafeLine(match.evidence);
      if (evidence && !item.evidence.includes(evidence)) item.evidence.push(evidence);
      item.zeroDay ||= match.zeroDay === true;
      if (
        typeof match.credibilityScore === 'number' &&
        Number.isFinite(match.credibilityScore) &&
        (item.credibilityScore === undefined || match.credibilityScore > item.credibilityScore)
      )
        item.credibilityScore = match.credibilityScore;
      byArticle.set(identity, item);
    }
  }
  const items = [...byArticle.values()];
  /** After per-article consolidation, collapse articles that report the same CVE
   *  from different sources so a vulnerability is never emailed twice in one run.
   *
   *  For each CVE ID shared by multiple items, the item with the highest
   *  credibility score wins (ties broken by most recent publication date, then
   *  article id). Suppressed items record which CVE kept them out.
   */
  const byCve = new Map<string, number[]>();
  items.forEach((item, index) => {
    for (const cveId of item.cveIds) {
      const set = byCve.get(cveId) ?? [];
      set.push(index);
      byCve.set(cveId, set);
    }
  });
  const keptIndices = new Set<number>();
  const cveOwners = new Map<string, number>();
  for (const [cveId, indices] of byCve) {
    if (indices.length <= 1) {
      indices.forEach((i) => keptIndices.add(i));
      continue;
    }
    // Pick the winner: highest credibility, then newest, then first id.
    let winner = indices[0];
    for (let i = 1; i < indices.length; i++) {
      const challenger = indices[i];
      const wScore = items[winner].credibilityScore ?? 0;
      const cScore = items[challenger].credibilityScore ?? 0;
      if (cScore > wScore ||
          (cScore === wScore && Date.parse(items[challenger].article.modifiedDate || items[challenger].article.publishedDate || '') >
           Date.parse(items[winner].article.modifiedDate || items[winner].article.publishedDate || '')) ||
          (cScore === wScore && items[challenger].article.id < items[winner].article.id))
        winner = challenger;
    }
    cveOwners.set(cveId, winner);
    keptIndices.add(winner);
    // Suppressed items record which CVE kept them out; they may still be kept
    // if they carry other CVEs this winner does not cover.
    for (const i of indices) {
      if (i !== winner) {
        items[i].suppressedByCve = cveId;
      }
    }
  }
  // An item is kept only if it owns at least one CVE (is the winner for that
  // CVE) or has no CVE IDs at all. Items that own no CVEs are fully suppressed.
  items.forEach((item, index) => {
    const ownsCve = item.cveIds.some((cveId) => cveOwners.get(cveId) === index);
    if (ownsCve || item.cveIds.length === 0) {
      keptIndices.add(index);
      // Filter the item's CVEs down to only those it owns; CVEs owned by
      // another (higher-scoring) article are dropped from this item.
      const allCveIds = item.cveIds;
      item.cveIds = allCveIds.filter((cveId) => cveOwners.get(cveId) === index);
      item.consolidationReason = ownsCve ? 'cve_dedup_kept' : 'new_article';
      // CVEs this item is the authoritative source for that other articles
      // also reported — i.e., CVEs this item's presence suppresses elsewhere.
      item.suppressesCveIds = [...new Set(allCveIds.filter((cveId) => cveOwners.get(cveId) === index && items.some((other, oi) => oi !== index && other.cveIds.includes(cveId))))];
    } else {
      item.consolidationReason = 'cve_dedup_suppressed';
    }
  });

  return items.filter((_, i) => keptIndices.has(i))
    .map((item) => ({
      ...item,
      assets: [...item.assets].sort(),
      cveIds: [...item.cveIds].sort(),
      matchIds: [...item.matchIds].sort(),
    }))
    .sort(
      (left, right) =>
        Date.parse(right.article.publishedDate || '') - Date.parse(left.article.publishedDate || '') ||
        left.article.id.localeCompare(right.article.id),
    );
}

/** Stable identity for "this evidence was already sent to this recipient". */
export const newsNotifiedKey = (recipientId: string, articleId: string) => `${recipientId}\u0000${articleId}`;

/**
 * Query parameters that never identify an article.
 *
 * These are campaign/click tracking, session and referrer markers. They are
 * stripped so the same story syndicated through two feeds is recognised as one
 * article. Everything else is KEPT: many sites identify an article by a query
 * parameter (`?id=100` and `?id=200` are different stories), and discarding the
 * whole query string suppressed genuinely distinct articles (AUD-003).
 */
const TRACKING_PARAMETERS = new Set([
  'fbclid',
  'gclid',
  'dclid',
  'gbraid',
  'wbraid',
  'msclkid',
  'yclid',
  'twclid',
  'igshid',
  'mc_cid',
  'mc_eid',
  '_hsenc',
  '_hsmi',
  'mkt_tok',
  'ref',
  'referrer',
  'source',
  'spm',
  'cmpid',
  'campaign',
  'sessionid',
  'phpsessid',
  'jsessionid',
]);

const isTrackingParameter = (name: string): boolean => {
  const key = name.toLowerCase();
  return key.startsWith('utm_') || TRACKING_PARAMETERS.has(key);
};

/**
 * Canonical query string: tracking parameters removed, the rest kept in a
 * stable order so two spellings of the same URL compare equal.
 */
const canonicalQuery = (parsed: URL): string => {
  const kept = [...parsed.searchParams.entries()]
    .filter(([name]) => !isTrackingParameter(name))
    .sort(([leftName, leftValue], [rightName, rightValue]) =>
      leftName.localeCompare(rightName) || leftValue.localeCompare(rightValue),
    );
  if (!kept.length) return '';
  return `?${kept
    .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`)
    .join('&')}`;
};

/**
 * URL identity is stable across tracking parameters and article-id changes,
 * while still distinguishing articles that differ only by a meaningful query
 * parameter.
 */
export function newsArticleIdentity(article: Pick<IntelligenceArticle, 'id' | 'url'>): string {
  const url = (article.url || '').trim();
  if (url) {
    try {
      const parsed = new URL(url);
      if (!['https:', 'http:'].includes(parsed.protocol)) return `id:${article.id}`;
      const path = parsed.pathname.replace(/\/+$/, '') || '/';
      return `url:${parsed.hostname.toLowerCase()}${path}${canonicalQuery(parsed)}`;
    } catch { /* malformed article URL falls back to id */ }
  }
  return `id:${article.id}`;
}

/**
 * Removes articles the recipient has already received.
 *
 * `alreadyNotified` is derived from queued/accepted news deliveries and from the
 * per-article delivery ledger, so an article is sent at most once per recipient
 * no matter how many matches, runs or retries reference it.
 */
export function selectUnnotifiedArticles(
  items: readonly ConsolidatedNewsItem[],
  recipientId: string,
  alreadyNotified: ReadonlySet<string>,
): ConsolidatedNewsItem[] {
  // A syndication feed may assign a different article id to the same URL.
  return items.filter((item) =>
    !alreadyNotified.has(newsNotifiedKey(recipientId, item.article.id)) &&
    !alreadyNotified.has(newsNotifiedKey(recipientId, newsArticleIdentity(item.article)))
  );
}

export interface ConsolidatedNewsDocument {
  subject: string;
  text: string;
  html: string;
  /**
   * Articles that did not fit the HTML size budget and are listed in the
   * overflow summary instead of as full cards. They are still named in the
   * email, so nothing is silently dropped.
   */
  overflow: ConsolidatedNewsItem[];
}

/**
 * HTML size budget for a consolidated news email.
 *
 * The body must stay valid, styled HTML: substituting the plain-text document
 * when the render is too large dropped every colour, card and link (AUD-004).
 * Instead the renderer keeps the full card layout for as many articles as fit
 * and lists the remainder in a styled summary table. The budget is well below
 * common provider limits so HTML can be used unchanged across clients.
 */
export const NEWS_HTML_MAX_BYTES = 1_500_000;

/**
 * Renders the consolidated news email within `maxBytes` of HTML.
 *
 * Articles are added in order until the next card would exceed the budget; the
 * rest are rendered as a compact, styled overflow summary (title, source, link)
 * so every article still appears in the same email. The plain-text alternative
 * always lists every article.
 */
export function renderConsolidatedNewsEmailWithin(
  items: readonly ConsolidatedNewsItem[],
  maxBytes: number = NEWS_HTML_MAX_BYTES,
): ConsolidatedNewsDocument {
  const full = renderConsolidatedNewsEmail(items);
  if (Buffer.byteLength(full.html, 'utf8') <= maxBytes) return full;
  // Binary search the largest prefix whose full render fits. The render is
  // monotonic in the number of cards, so this is exact and costs O(log n)
  // renders rather than one per article.
  let low = 0;
  let high = items.length - 1;
  let best = renderConsolidatedNewsEmail(items.slice(0, 0), items.slice(0));
  if (Buffer.byteLength(best.html, 'utf8') > maxBytes)
    throw new Error('Consolidated news HTML exceeds the allowed size even in compact summary form');
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = renderConsolidatedNewsEmail(items.slice(0, middle), items.slice(middle));
    if (Buffer.byteLength(candidate.html, 'utf8') <= maxBytes) {
      best = candidate;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return best;
}

/**
 * Renders the consolidated news email.
 *
 * All article titles, URLs, feed names and evidence strings are feed-controlled
 * and are escaped everywhere they appear. The document is intentionally
 * self-contained (inline styles, single column) for HTML email clients.
 */
export function renderConsolidatedNewsEmail(
  items: readonly ConsolidatedNewsItem[],
  /** Articles listed in the overflow summary instead of as full cards. */
  overflow: readonly ConsolidatedNewsItem[] = [],
): ConsolidatedNewsDocument {
  const count = items.length + overflow.length;
  const countLabel = `${count} article${count === 1 ? '' : 's'}`;
  const leadTitle = newsSafeLine(items[0]?.article.title ?? overflow[0]?.article.title) || 'Security news';
  const subject =
    count === 1
      ? `[Threat intelligence] [NEWS] ${leadTitle}`
      : `[Threat intelligence] [NEWS] ${countLabel}: ${leadTitle}`;
  const footer =
    'This is applicability evidence, not a confirmed advisory. Confirm source authenticity and consult the vendor before remediation.';

  const chip = (label: string, background: string, color: string) =>
    `<span style="display:inline-block;padding:2px 8px;margin:0 6px 6px 0;border-radius:10px;background:${background};color:${color};font-size:10px;line-height:14px;font-weight:700;letter-spacing:0.4px;white-space:nowrap;">${escapeHtml(label)}</span>`;

  const assetBadges = (assets: string[]) =>
    assets
      .map((asset) => chip(asset, '#f1f5f9', '#475569'))
      .join('');

  const cveChips = (cveIds: string[]) =>
    cveIds
      .map(
        (cveId) =>
          `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}" style="color:#1e40af;text-decoration:none;border:1px solid #bfdbfe;background:#eff6ff;border-radius:6px;padding:2px 8px;margin:0 6px 6px 0;font-size:12px;line-height:16px;font-weight:600;white-space:nowrap;">${escapeHtml(cveId)}</a>`,
      )
      .join(' ');

  const credibilityBadge = (score: number) => {
    const rounded = Math.round(score);
    const [background, color] =
      rounded < 50 ? ['#fde68a', '#92400e']
        : rounded < 75 ? ['#dbeafe', '#1e40af']
        : ['#dcfce7', '#15803d'];
    return chip(`${rounded}/100 credibility`, background, color);
  };

  const text = [
    'VulnStream Enterprise | Threat Intelligence',
    `Security news (${countLabel})`,
    ...items.map((item, index) => {
      const source = item.article.sourceFeeds.length
        ? item.article.sourceFeeds.map(newsSafeLine).join(', ')
        : 'security news';
      return [
        `${index + 1}. ${newsSafeLine(item.article.title)}`,
        `Source: ${newsSafeLine(item.article.url)}`,
        `Published: ${newsSafeLine(item.article.modifiedDate || item.article.publishedDate)}`,
        `Source feed: ${source}`,
        `Matched asset(s): ${item.assets.map(newsSafeLine).join(', ') || 'unknown asset'}`,
        ...(item.cveIds.length ? [`CVE reference(s): ${item.cveIds.join(', ')}`] : []),
        ...(item.evidence.length ? [`Evidence: ${item.evidence.join(' | ')}`] : []),
        ...(typeof item.credibilityScore === 'number' ? [`Credibility: ${Math.round(item.credibilityScore)}/100`] : []),
        ...(item.zeroDay ? ['Potential zero-day: no assigned CVE'] : []),
      ].join('\n');
    }),
    ...(overflow.length
      ? [
          `Additional articles (${overflow.length}) listed in summary form because the email reached its size limit:`,
          ...overflow.map(
            (item, index) =>
              `${items.length + index + 1}. ${newsSafeLine(item.article.title)}\nSource: ${newsSafeLine(item.article.url)}`,
          ),
        ]
      : []),
    footer,
  ].join('\n\n');

  const cards = items
    .map((item, index) => {
      const href = safeHref(item.article.url);
      const source = item.article.sourceFeeds.length
        ? item.article.sourceFeeds.map(newsSafeLine).join(', ')
        : 'security news';
      const published = newsSafeLine(item.article.modifiedDate || item.article.publishedDate);
      const title = newsSafeLine(item.article.title);
      const titleHtml = href
        ? `<a href="${escapeHtml(href)}" style="color:#1e40af;text-decoration:underline;font-weight:700;">${escapeHtml(title)}</a>`
        : escapeHtml(title);
      const evidence = item.evidence.map(escapeHtml).join('<br>');
      const chips = [
        item.assets.length ? assetBadges(item.assets) : '',
        item.cveIds.length ? cveChips(item.cveIds) : '',
        typeof item.credibilityScore === 'number' ? credibilityBadge(item.credibilityScore) : '',
      ].filter(Boolean).join('');
      const evidenceBox = evidence
        ? `<p style="margin:10px 0 0;padding:12px 16px;border-radius:8px;background:#f8fafc;border:1px solid #e2e8f0;border-left:4px solid #1e40af;font-size:12.5px;line-height:20px;color:#334155;">${evidence}</p>`
        : '';
      const zeroDayBanner = item.zeroDay
        ? '<p style="margin:12px 0 0;padding:10px 14px;border-radius:8px;background:#fef3c7;border:1px solid #fcd34d;font-size:12.5px;line-height:19px;font-weight:700;color:#92400e;">Potential zero-day: no assigned CVE</p>'
        : '';
      const viewSource = href
        ? `<p style="margin:16px 0 0;"><a href="${escapeHtml(href)}" style="display:inline-block;background:#1e40af;color:#ffffff;text-decoration:none;border-radius:6px;padding:10px 18px;font-size:13px;font-weight:700;">View source article &rarr;</a></p>`
        : '';
      return `<tr><td style="padding:22px 26px;border-top:1px solid #e2e8f0;border-left:4px solid #1e40af;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;table-layout:fixed;">
          <tr><td style="padding:0 0 10px;">
            <p style="margin:0 0 6px;font-size:11px;line-height:16px;color:#64748b;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;">ARTICLE ${index + 1} OF ${count}</p>
            <h2 style="margin:0 0 10px;font-size:20px;line-height:28px;font-weight:800;color:#0f172a;">${titleHtml}</h2>
          </td></tr>
          ${chips ? `<tr><td style="padding:0 0 10px;">${chips}</td></tr>` : ''}
          <tr><td style="padding:0 0 12px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;table-layout:fixed;border-collapse:collapse;">
              <tr>
                <td style="padding:4px 0;font-size:12.5px;line-height:18px;color:#475569;width:50%;vertical-align:top;"><strong style="color:#94a3b8;">Source:</strong> ${escapeHtml(newsSafeLine(item.article.url))}</td>
                <td style="padding:4px 0;font-size:12.5px;line-height:18px;color:#475569;width:50%;text-align:right;vertical-align:top;"><strong style="color:#94a3b8;">Published:</strong> ${escapeHtml(published)}</td>
              </tr>
              <tr>
                <td style="padding:4px 0 0;font-size:12.5px;line-height:18px;color:#475569;width:50%;vertical-align:top;"><strong style="color:#94a3b8;">Source feed:</strong> ${escapeHtml(source)}</td>
                <td style="padding:4px 0 0;font-size:12.5px;line-height:18px;color:#475569;width:50%;text-align:right;vertical-align:top;"><strong style="color:#94a3b8;">Matched asset(s):</strong> ${escapeHtml(item.assets.join(', ') || 'unknown asset')}</td>
              </tr>
            </table>
          </td></tr>
          ${evidenceBox ? `<tr><td style="padding:0 0 12px;">${evidenceBox}</td></tr>` : ''}
          ${zeroDayBanner ? `<tr><td style="padding:0 0 12px;">${zeroDayBanner}</td></tr>` : ''}
          ${viewSource ? `<tr><td style="padding:0;">${viewSource}</td></tr>` : ''}
        </table>
      </td></tr>`;
    })
    .join('');

  // Overflow summary: the articles that did not fit the size budget are still
  // named, linked and styled like the rest of the email. The body therefore
  // stays valid, styled HTML instead of degrading to the plain-text document.
  const overflowRows = overflow
    .map((item, index) => {
      const href = safeHref(item.article.url);
      const title = escapeHtml(newsSafeLine(item.article.title));
      const titleHtml = href
        ? `<a href="${escapeHtml(href)}" style="color:#1e40af;text-decoration:underline;font-weight:700;">${title}</a>`
        : title;
      const source = item.article.sourceFeeds.length
        ? item.article.sourceFeeds.map(newsSafeLine).join(', ')
        : 'security news';
      return `<tr><td style="padding:10px 24px;border-top:1px solid #e2e8f0;font-size:13px;line-height:19px;color:#475569;">
        <span style="color:#64748b;font-weight:700;">${items.length + index + 1}.</span> ${titleHtml}
        <br><span style="color:#94a3b8;">${escapeHtml(source)}</span>
      </td></tr>`;
    })
    .join('');
  const overflowSection = overflow.length
    ? '<tr><td style="padding:20px 24px 8px;border-top:1px solid #e2e8f0;border-left:4px solid #b7791f;background:#fffbeb;">' +
      `<p style="margin:0 0 4px;font-size:11px;line-height:16px;color:#92400e;font-weight:600;letter-spacing:0.5px;">ADDITIONAL ARTICLES (${overflow.length})</p>` +
      '<p style="margin:0;font-size:13px;line-height:19px;color:#475569;">These articles matched your monitored inventory but are shown in summary form because the email reached its size limit.</p></td></tr>' +
      overflowRows
    : '';

  const html =
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
    `<title>${escapeHtml(subject)}</title></head>` +
    '<body style="margin:0;padding:0;background:#f1f5f9;color:#0f172a;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,\'Helvetica Neue\',Arial,sans-serif;">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f1f5f9;border-collapse:collapse;"><tr><td align="center" style="padding:24px 8px;">' +
    '<!--[if mso]><table role="presentation" width="640" align="center"><tr><td><![endif]-->' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:640px;table-layout:fixed;background:#ffffff;border:1px solid #e2e8f0;border-top:4px solid #1e3a8a;border-collapse:collapse;">' +
    '<tr><td style="padding:20px 24px;border-bottom:1px solid #e2e8f0;">' +
    '<p style="margin:0;font-size:15px;line-height:22px;font-weight:800;color:#0f172a;letter-spacing:0.2px;">BA Threat intelligence | Security news</p></td></tr>' +
    '<tr><td style="padding:26px 24px 22px;">' +
    '<p style="margin:0 0 12px;display:inline-block;padding:4px 10px;border-radius:10px;background:#dbeafe;color:#1e40af;font-size:11px;line-height:15px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;">news</p>' +
    `<h1 style="margin:0 0 14px;font-size:26px;line-height:34px;font-weight:800;color:#0f172a;">Security news</h1>` +
    `<p style="margin:0;font-size:14px;line-height:23px;color:#475569;">${escapeHtml(countLabel)} matched your monitored inventory in this intelligence run.</p></td></tr>` +
    cards +
    overflowSection +
    `<tr><td style="padding:22px 24px;border-top:1px solid #e2e8f0;background:#f8fafc;"><p style="margin:0 0 8px;font-size:12.5px;line-height:20px;color:#64748b;">${escapeHtml(footer)}</p><p style="margin:0;font-size:11px;line-height:17px;color:#94a3b8;">VulnStream Enterprise &middot; Automated threat intelligence. Confirm source authenticity and consult the vendor before remediation.</p></td></tr>` +
    '</table><!--[if mso]></td></tr></table><![endif]--></td></tr></table></body></html>';

  return { subject: newsSafeLine(subject), text, html, overflow: [...overflow] };
}
