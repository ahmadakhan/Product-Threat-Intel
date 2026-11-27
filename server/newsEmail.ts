import type { IntelligenceArticle, IntelligenceMatch, TemplateCustomization } from '../src/types/index.ts';
import {
  DEFAULT_NEWS_EMAIL_CUSTOMIZATION,
  compileNewsTemplate,
  renderNewsTemplate,
} from '../src/utils/templateCompiler.ts';

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

/** Generated timestamp for the studio document, in the operator's timezone. */
function formatNewsDate(timezone: string | undefined): string {
  try {
    return new Intl.DateTimeFormat('en-GB', {
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZone: timezone || 'UTC',
    }).format(new Date());
  } catch {
    return new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  }
}

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
  //
  // Each check reads the ORIGINAL CVE list. Deriving `suppressesCveIds` after
  // `cveIds` had been filtered against `cveOwners` could never match anything, and
  // filtering an item's list before a later item was classified made the retained
  // and suppressed sets disagree about the same CVE.
  const originalCveIds = items.map((item) => item.cveIds);
  items.forEach((item, index) => {
    const allCveIds = originalCveIds[index];
    const ownsCve = allCveIds.some((cveId) => cveOwners.get(cveId) === index);
    if (ownsCve || allCveIds.length === 0) {
      keptIndices.add(index);
      item.consolidationReason = ownsCve ? 'cve_dedup_kept' : 'new_article';
      item.suppressesCveIds = [
        ...new Set(
          allCveIds.filter(
            (cveId) =>
              cveOwners.get(cveId) === index &&
              originalCveIds.some((other, oi) => oi !== index && other.includes(cveId)),
          ),
        ),
      ];
    } else {
      item.consolidationReason = 'cve_dedup_suppressed';
    }
  });
  // The per-article lists are left intact for the items that are kept, so an
  // article that reports several CVEs still lists them all. De-duplication is
  // already expressed by the winning item and `suppressedByCve`; trimming the
  // winner's list was what dropped a CVE from the delivered email entirely.

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

/**
 * The News Template Studio document the delivered email is built from.
 *
 * Both values come from `template.main` (server/commands.ts `newsTemplate.save`):
 * `customTemplate` is the hand-authored HTML when an operator saved one, and
 * `customization` is the visual configuration used to compile the studio's own
 * template otherwise. They are optional so callers that have no saved studio
 * document (unit tests, one-off renders) fall back to the default studio HTML.
 */
export interface NewsEmailTemplateInput {
  customization?: TemplateCustomization;
  customTemplate?: string | null;
  /** Display timezone for the generated timestamp. */
  timezone?: string;
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
  studio?: NewsEmailTemplateInput,
): ConsolidatedNewsDocument {
  const full = renderConsolidatedNewsEmail(items, [], studio);
  if (Buffer.byteLength(full.html, 'utf8') <= maxBytes) return full;
  // Binary search the largest prefix whose full render fits. The render is
  // monotonic in the number of cards, so this is exact and costs O(log n)
  // renders rather than one per article.
  let low = 0;
  let high = items.length - 1;
  let best = renderConsolidatedNewsEmail(items.slice(0, 0), items.slice(0), studio);
  if (Buffer.byteLength(best.html, 'utf8') > maxBytes)
    throw new Error('Consolidated news HTML exceeds the allowed size even in compact summary form');
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = renderConsolidatedNewsEmail(items.slice(0, middle), items.slice(middle), studio);
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
  /**
   * The News Template Studio document. When omitted the default studio HTML is
   * compiled from the default customization, so the delivered email always has
   * the same layout the studio previews (there is no separate hard-coded body).
   */
  studio: NewsEmailTemplateInput = {},
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
      const position = `ARTICLE ${index + 1} OF ${count}`;
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
        ? `<p style="margin:10px 0 0;padding:12px 16px;border-radius:8px;background:#f8fafc;border:1px solid #e2e8f0;font-size:12.5px;line-height:20px;color:#334155;">${evidence}</p>`
        : '';
      const zeroDayBanner = item.zeroDay
        ? '<p style="margin:12px 0 0;padding:10px 14px;border-radius:8px;background:#fef3c7;border:1px solid #fcd34d;font-size:12.5px;line-height:19px;font-weight:700;color:#92400e;">Potential zero-day: no assigned CVE</p>'
        : '';
      const viewSource = href
        ? `<p style="margin:16px 0 0;"><a href="${escapeHtml(href)}" style="display:inline-block;background:#1e40af;color:#ffffff;text-decoration:none;border-radius:6px;padding:10px 18px;font-size:13px;font-weight:700;">View source article &rarr;</a></p>`
        : '';
      return `<tr><td style="padding:22px 26px;border-top:1px solid #e2e8f0;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;table-layout:fixed;">
          <tr><td style="padding:0 0 10px;">
            <p style="margin:0 0 6px;font-size:11px;line-height:16px;color:#64748b;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;">${position}</p>
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
  // named and linked inside the studio's card section, so the body stays the
  // styled studio document instead of degrading to the plain-text version.
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
      return `<div style="padding:10px 0;border-top:1px solid #e2e8f0;font-size:13px;line-height:19px;color:#475569;">
        <span style="color:#64748b;font-weight:700;">${items.length + index + 1}.</span> ${titleHtml}
        <br><span style="color:#94a3b8;">${escapeHtml(source)}</span>
      </div>`;
    })
    .join('');
  const overflowSection = overflow.length
    ? '<div style="margin:0 0 16px;padding:16px;border-radius:8px;background:#fffbeb;border:1px solid #fcd34d;">' +
      `<div style="font-size:11px;line-height:16px;color:#92400e;font-weight:700;letter-spacing:0.5px;padding-bottom:4px;">ADDITIONAL ARTICLES (${overflow.length})</div>` +
      '<div style="font-size:13px;line-height:19px;color:#475569;padding-bottom:4px;">These articles matched your monitored inventory but are shown in summary form because the email reached its size limit.</div>' +
      overflowRows +
      '</div>'
    : '';

  // The delivered body is the News Template Studio document. An operator's
  // custom HTML wins; otherwise the studio's own markup is compiled from their
  // saved customization, so the email matches what the studio previews.
  const customization = studio.customization ?? DEFAULT_NEWS_EMAIL_CUSTOMIZATION;
  const template = studio.customTemplate || compileNewsTemplate(customization);
  const summary =
    `${countLabel} matched your monitored inventory in this intelligence run.` +
    (overflow.length
      ? ` ${overflow.length} additional article${overflow.length === 1 ? '' : 's'} ${overflow.length === 1 ? 'is' : 'are'} listed in summary form.`
      : '');

  // One source card per consolidated article, rendered by the {{#each news_sources}}
  // loop in the studio template. Feed-controlled fields are escaped by the
  // renderer; excerpt is delivered raw ({{{excerpt}}}) so feed HTML survives.
  const newsSources = items.map((item) => {
    const href = safeHref(item.article.url);
    return {
      title: newsSafeLine(item.article.title),
      url: href,
      source_name: item.article.sourceFeeds.length
        ? item.article.sourceFeeds.map(newsSafeLine).join(', ')
        : 'Security news',
      published_at: newsSafeLine(item.article.modifiedDate || item.article.publishedDate),
      excerpt: escapeHtml(item.evidence.length ? item.evidence.join(' | ') : newsSafeLine(item.article.title)),
    };
  });
  const html = renderNewsTemplate(
    customization,
    {
      news_title: 'Security news',
      news_subject_badge_text: 'THREAT BRIEFING',
      news_subject: subject,
      news_date: formatNewsDate(studio.timezone),
      news_count: count,
      news_summary: summary,
      news_sources: newsSources,
      news_articles: overflowSection + cards,
      sources_hub_url: 'https://www.cisa.gov/news-events/cybersecurity-advisories',
      news_footer: footer,
    },
    template,
  );

  return { subject: newsSafeLine(subject), text, html, overflow: [...overflow] };
}
