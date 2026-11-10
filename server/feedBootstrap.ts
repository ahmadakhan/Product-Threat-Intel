import type { PoolClient } from './db.ts';
import { get, list, put, remove } from './db.ts';
import type { ThreatFeed } from '../src/types/index.ts';
import { RECOMMENDED_FEEDS, RECOMMENDED_FEED_URLS } from './recommendedFeeds.ts';
import { findDuplicateFeedSource } from './feedIdentity.ts';

const RETIRED_DUPLICATE_FEEDS = [{ duplicateId: 'feed-darkreading-full', canonicalId: 'feed-darkreading' }];

export async function reconcileRecommendedFeeds(db: PoolClient, bootstrap = false): Promise<void> {
  const existing = await list<ThreatFeed>(db, 'feeds');
  const ids = new Set(existing.map((feed) => feed.id));
  // Catalog insertion is opt-in; repairs below still preserve existing feeds.
  if (bootstrap) for (const feed of RECOMMENDED_FEEDS) {
    if (ids.has(feed.id) || findDuplicateFeedSource(feed, existing)) continue;
    await put(db, 'feeds', feed.id, {
      ...feed,
      healthStatus: 'healthStatus' in feed ? feed.healthStatus : 'UNTESTED',
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
  for (const source of RECOMMENDED_FEEDS) {
    if (source.enabled || !('healthStatus' in source) || source.healthStatus !== 'DOWN') continue;
    const feed = await get<ThreatFeed>(db, 'feeds', source.id);
    if (!feed?.vendorSeed || feed.url !== source.url) continue;
    await put(db, 'feeds', feed.id, {
      ...feed,
      enabled: false,
      healthStatus: source.healthStatus,
      errorLog: source.errorLog,
    });
  }
  // Retire any legacy MITRE/OpenCVE feeds that may persist in existing
  // databases. VulnCheck NVD++ is the recommended authoritative CVE source;
  // NIST NVD 2.0 remains available as a free community service (NVD_API type)
  // and is not retired.
  const RETIRED_FEED_TYPES = new Set(['MITRE_CVE', 'OPENCVE_API']);
  for (const feed of existing) {
    if (!RETIRED_FEED_TYPES.has(feed.type)) continue;
    await put(db, 'feeds', feed.id, {
      ...feed,
      enabled: false,
      healthStatus: 'DOWN' as const,
      errorLog: 'Retired: VulnCheck NVD++ is the sole authoritative CVE source. NIST NVD, MITRE CVE, and OpenCVE feeds are disabled.',
    });
  }
  // Disable any VulnCheck feeds (NVD++ or KEV) that lack a configured Bearer
  // token, or that have previously failed with HTTP 401 (invalid token),
  // preventing repeated authentication failures on every run.
  // Re-fetch all feeds after seeding so newly seeded feeds are also checked.
  const allFeeds = await list<ThreatFeed>(db, 'feeds');
  for (const feed of allFeeds) {
    if (feed.type !== 'VULNCHECK_KEV' && feed.type !== 'VULNCHECK_NVD') continue;
    if (!feed.enabled) continue;
    const hasAuthError = /401|unauthorized|invalid.*token/i.test(feed.errorLog ?? '');
    if (!feed.authSecretKey || feed.authType !== 'BEARER' || hasAuthError) {
      await put(db, 'feeds', feed.id, {
        ...feed,
        enabled: false,
        healthStatus: 'DOWN' as const,
        errorLog: hasAuthError
          ? `Disabled: VulnCheck ${feed.type === 'VULNCHECK_NVD' ? 'NVD++' : 'KEV'} authentication failed (HTTP 401); configure a valid Bearer API token.`
          : feed.type === 'VULNCHECK_NVD'
            ? 'Disabled: VulnCheck NVD++ requires a configured Bearer API token.'
            : 'Disabled: VulnCheck KEV requires a configured Bearer API token.',
      });
    }
  }
  for (const { duplicateId, canonicalId } of RETIRED_DUPLICATE_FEEDS) {
    const [duplicate, canonical] = await Promise.all([
      get<ThreatFeed>(db, 'feeds', duplicateId),
      get<ThreatFeed>(db, 'feeds', canonicalId),
    ]);

    if (
      !duplicate?.vendorSeed ||
      !canonical?.vendorSeed ||
      duplicate.url !== 'https://www.darkreading.com/rss.xml' ||
      canonical.url !== duplicate.url
    )
      continue;
    if (duplicate.enabled && !canonical.enabled) {
      await put(db, 'feeds', canonicalId, { ...canonical, enabled: true });
    }
    await remove(db, 'feeds', duplicateId);
  }
}
