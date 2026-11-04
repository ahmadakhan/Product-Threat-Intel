import type { PoolClient } from './db.ts';
import { list, put } from './db.ts';
import type { ThreatFeed } from '../src/types/index.ts';
import { RECOMMENDED_FEEDS, RECOMMENDED_FEED_URLS } from './recommendedFeeds.ts';

export async function reconcileRecommendedFeeds(db: PoolClient, bootstrap = false): Promise<void> {
  const existing = await list<ThreatFeed>(db, 'feeds');
  const ids = new Set(existing.map((feed) => feed.id));
  if (bootstrap)
    for (const feed of RECOMMENDED_FEEDS) {
      if (ids.has(feed.id)) continue;
      await put(db, 'feeds', feed.id, {
        ...feed,
        healthStatus: 'UNTESTED',
        lastSync: null,
        latencyMs: 0,
        itemCountLastRun: 0,
        ssrfValidated: false,
      });
    }
  for (const feed of existing) {
    const url = RECOMMENDED_FEED_URLS.get(feed.id);
    if (!url || !feed.url || feed.url === url) continue;
    await put(db, 'feeds', feed.id, {
      ...feed,
      url,
      ssrfValidated: false,
      etag: undefined,
      lastSync: null,
      healthStatus: 'UNTESTED',
      errorLog: undefined,
      consecutiveFailures: 0,
      circuitOpenUntil: null,
    });
  }
}
