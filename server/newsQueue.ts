import { createHash } from 'node:crypto';
import type {
  EmailRecipient,
  IntelligenceArticle,
  IntelligenceMatch,
} from '../src/types/index.ts';
import type { Db } from './db.ts';
import { get, list, put } from './db.ts';
import { writeEvent } from './events.ts';
import { stableJson } from '../src/utils/deduplicator.ts';
import {
  consolidateNewsMatches,
  newsNotifiedKey,
  renderConsolidatedNewsEmail,
  selectUnnotifiedArticles,
  type ConsolidatedNewsItem,
} from './newsEmail.ts';
import { deliveryHtmlIsAttachable } from './deliveryDocument.ts';

/**
 * Per-article news delivery ledger.
 *
 * The article is the unit of delivery, not the match. One record per
 * `(recipient, article)` is written when an email carrying that article is
 * queued, which is what makes "never send the same news twice" survive:
 *
 *  - re-correlation (the matcher re-keys matches on `hash(cveId || articleId)`,
 *    so the same article yields new match rows over time);
 *  - an article arriving through a second feed (same URL, new article id);
 *  - a pipeline run whose outbox row has since been cleaned up.
 *
 * The record is keyed by the content identity of the article — the normalised
 * URL when one is available, otherwise the article id — so the same story is
 * recognised across feeds. It is not a delivery receipt: `outbox` still owns
 * transport state. It answers exactly one question, "has this recipient already
 * been told about this article?".
 */
const NEWS_LEDGER_KIND = 'newsNotifications';

/** Canonical content identity for an article: URL first, then the id. */
export function newsArticleIdentity(article: Pick<IntelligenceArticle, 'id' | 'url'>): string {
  const url = (article.url || '').trim();
  if (url) {
    try {
      const parsed = new URL(url);
      parsed.hash = '';
      // Query strings differ per tracking parameter on syndicated feeds; the
      // path is the story identity.
      return `url:${parsed.hostname.toLowerCase()}${parsed.pathname.replace(/\/+$/, '')}`;
    } catch {
      // Fall through to the id for a malformed feed URL.
    }
  }
  return `id:${article.id}`;
}

export function newsLedgerRecordId(recipientId: string, article: Pick<IntelligenceArticle, 'id' | 'url'>): string {
  return createHash('sha256')
    .update(newsNotifiedKey(recipientId, newsArticleIdentity(article)))
    .digest('hex');
}

interface NewsLedgerEntry {
  id: string;
  recipientId: string;
  articleId: string;
  identity: string;
  firstNotifiedAt: string;
  lastNotifiedAt: string;
  /** Number of consolidated emails that carried this article. */
  deliveries: number;
  /** Most recent delivery that carried it. */
  advisoryId: string;
}

export interface NewsQueueResult {
  /** Consolidated emails queued (one per recipient). */
  emailsQueued: number;
  /** Articles included in at least one email. */
  articlesIncluded: number;
  /** Articles skipped because the recipient already received them. */
  articlesSuppressed: number;
}

export interface NewsQueueDeps {
  /** Enqueue one consolidated email; injectable so the pipeline owns delivery. */
  enqueue: (input: {
    db: Db;
    recipient: EmailRecipient;
    articles: ConsolidatedNewsItem[];
    subject: string;
    text: string;
    html: string;
    cveIds: string[];
    contentRevision: string;
    identity: string;
    advisoryId: string;
  }) => Promise<string | null>;
}

const MAX_ARTICLES_PER_EMAIL = 100;

/**
 * Reads the articles already delivered to a recipient.
 *
 * Two sources are consulted because either alone is insufficient: the ledger
 * survives outbox retention, and the outbox catches emails queued before the
 * ledger existed (or by a build that predates it).
 */
async function alreadyNotified(
  db: Db,
  recipientIds: readonly string[],
  articles: ReadonlyMap<string, Pick<IntelligenceArticle, 'id' | 'url'>>,
): Promise<Map<string, Set<string>>> {
  const notified = new Map<string, Set<string>>(recipientIds.map((id) => [id, new Set<string>()]));
  if (!recipientIds.length || !articles.size) return notified;
  const articleIds = [...articles.keys()];
  const ledger = await db.query<{ recipient_id: string; article_id: string }>(
    "SELECT data->>'recipientId' AS recipient_id, data->>'articleId' AS article_id FROM records WHERE kind=$1 AND data->>'recipientId'=ANY($2::text[]) AND data->>'articleId'=ANY($3::text[])",
    [NEWS_LEDGER_KIND, [...recipientIds], articleIds],
  );
  for (const row of ledger.rows) notified.get(row.recipient_id)?.add(row.article_id);
  const queued = await db.query<{ target_id: string; article_id: string }>(
    `SELECT o.target_id, entry->>'id' AS article_id
       FROM outbox o
       CROSS JOIN LATERAL jsonb_array_elements(CASE
         WHEN jsonb_typeof(o.payload->'newsEvidence'->'articles')='array'
         THEN o.payload->'newsEvidence'->'articles' ELSE '[]'::jsonb END) entry
      WHERE o.channel='email' AND o.status=ANY($1::text[])
        AND o.target_id=ANY($2::text[]) AND entry->>'id'=ANY($3::text[])`,
    [['QUEUED', 'SENDING', 'ACCEPTED'], [...recipientIds], articleIds],
  );
  for (const row of queued.rows) notified.get(row.target_id)?.add(row.article_id);
  return notified;
}

/**
 * Writes the per-article ledger rows for one consolidated email.
 *
 * Idempotent: a replayed queue pass updates the delivery count instead of
 * creating a second record, so the ledger cannot grow on retries.
 */
export async function recordNewsDeliveries(
  db: Db,
  recipientId: string,
  advisoryId: string,
  articles: ReadonlyArray<Pick<IntelligenceArticle, 'id' | 'url'>>,
  /** Shared across the batch so one delivery cannot look like several. */
  deliveredAt: string = new Date().toISOString(),
): Promise<void> {
  if (!articles.length) return;
  const now = deliveredAt;
  for (const article of articles) {
    const id = newsLedgerRecordId(recipientId, article);
    const existing = await get<NewsLedgerEntry>(db, NEWS_LEDGER_KIND, id);
    await put(db, NEWS_LEDGER_KIND, id, {
      id,
      recipientId,
      articleId: article.id,
      identity: newsArticleIdentity(article),
      firstNotifiedAt: existing?.firstNotifiedAt || now,
      lastNotifiedAt: now,
      deliveries: existing?.lastNotifiedAt === now ? existing.deliveries : (existing?.deliveries || 0) + 1,
      advisoryId,
    } satisfies NewsLedgerEntry);
  }
}

/**
 * Queues ONE consolidated news email per eligible Security-team recipient for
 * every article that is (a) new to that recipient and (b) still new in this run.
 *
 * Consolidation and de-duplication are per recipient. Content revision is
 * derived from the *article set*, not the match ids, so:
 *  - the same articles re-derived on a later run produce the same dedupe key
 *    and cannot be queued twice;
 *  - a changed article set (a genuinely new story) is a different email.
 */
export async function queueConsolidatedNews(
  db: Db,
  matches: readonly IntelligenceMatch[],
  articles: ReadonlyMap<string, IntelligenceArticle>,
  recipients: readonly EmailRecipient[],
  deps: NewsQueueDeps,
): Promise<NewsQueueResult> {
  const result: NewsQueueResult = { emailsQueued: 0, articlesIncluded: 0, articlesSuppressed: 0 };
  const selected = recipients.filter(
    (recipient) =>
      recipient.enabled && (recipient.deliveryGroup === 'SECURITY_TEAM' || recipient.deliveryGroup === undefined),
  );
  if (!selected.length || !matches.length) return result;
  const assetNameFor = (assetId: string) =>
    matches.find((match) => match.assetId === assetId)?.assetName || assetId;
  const items = consolidateNewsMatches(matches, articles, assetNameFor).filter(
    // A news email must reference at least one asset the recipient monitors and
    // carry a real article; empty items would produce a meaningless email.
    (item) => item.assets.length > 0 && item.article.url,
  );
  if (!items.length) return result;
  const articleRecord = new Map(items.map((item) => [item.article.id, item.article] as const));
  const notified = await alreadyNotified(db, selected.map((recipient) => recipient.id), articleRecord);
  // One instant for every recipient of this run, so each ledger row records the
  // delivery it actually belongs to.
  const deliveredAt = new Date().toISOString();
  for (const recipient of selected) {
    const own = selectUnnotifiedArticles(items, recipient.id, notified.get(recipient.id) || new Set());
    if (!own.length) {
      result.articlesSuppressed += items.length;
      continue;
    }
    const batch = own.slice(0, MAX_ARTICLES_PER_EMAIL);
    const overflow = own.slice(MAX_ARTICLES_PER_EMAIL);
    const document = renderConsolidatedNewsEmail(batch);
    const cveIds = [...new Set(batch.flatMap((item) => item.cveIds))].sort();
    const articleIds = batch.map((item) => item.article.id).sort();
    const contentRevision = createHash('sha256')
      .update(stableJson({ recipientId: recipient.id, articleIds, articleIdentities: batch.map((item) => newsArticleIdentity(item.article)).sort() }))
      .digest('hex')
      .slice(0, 20);
    const advisoryId = `NEWS:${articleIds.join(',')}`.slice(0, 512);
    const queuedId = await deps.enqueue({
      db,
      recipient,
      articles: batch,
      subject: document.subject,
      text: document.text,
      html: deliveryHtmlIsAttachable(document.html) ? document.html : document.text,
      cveIds,
      contentRevision,
      identity: `news:${recipient.id}:${articleSetFingerprint(articleIds)}`,
      advisoryId,
    });
    if (!queuedId) {
      // An identical message is already queued (dedupe key matched). Treat it
      // as already told so the next run does not retry the same content.
      result.articlesSuppressed += batch.length;
      continue;
    }
    result.emailsQueued++;
    result.articlesIncluded += batch.length;
    result.articlesSuppressed += overflow.length;
    await recordNewsDeliveries(
      db,
      recipient.id,
      advisoryId,
      batch.map((item) => item.article),
      deliveredAt,
    );
    await writeEvent(db, {
      category: 'MATCHING',
      level: 'INFO',
      code: 'matching.news_email_queued',
      message: 'Consolidated security-news email queued for the Security team',
      context: {
        recipientId: recipient.id,
        articles: batch.length,
        matches: [...new Set(batch.flatMap((item) => item.matchIds))].length,
        advisoryId,
        suppressAlreadySent: own.length - batch.length,
      },
    });
  }
  return result;
}

/** Short, stable article-set fingerprint for the dedupe identity. */
const articleSetFingerprint = (articleIds: readonly string[]) =>
  createHash('sha256').update(articleIds.join(',')).digest('hex').slice(0, 24);

/**
 * Recipients eligible for consolidated news. Kept here so the pipeline and any
 * caller share one definition of "the Security team".
 */
export const newsRecipients = (recipients: readonly EmailRecipient[]) =>
  recipients.filter(
    (recipient) =>
      recipient.enabled && (recipient.deliveryGroup === 'SECURITY_TEAM' || recipient.deliveryGroup === undefined),
  );

/** Loads enabled recipients once; small table, single query. */
export const loadNewsRecipients = async (db: Db) => newsRecipients(await list<EmailRecipient>(db, 'recipients'));
