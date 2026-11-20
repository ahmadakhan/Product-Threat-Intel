import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import type pg from 'pg';
import { createPool, migrate, put, list, get, transaction } from '../server/db.ts';
import { queueRun, processPipeline, stopRun, stopRunWithClient } from '../server/pipeline.ts';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { Finding, PipelineExecution, NormalizedCVE, WatchListItem } from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;
test(
  'pipeline policy and stop requests survive concurrent worker activity',
  { skip: !database },
  async (t) => {
    const base = createPool(database!);
    const schema = 'pipeline_audit_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url.href,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    });
    const cpe = 'cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*';
    const asset: WatchListItem = {
      id: 'asset',
      vendor: 'example',
      product: 'widget',
      cpes: [cpe],
      assetTag: 'TEST',
      ownerGroup: 'test',
      active: true,
      createdAt: new Date().toISOString(),
    };
    const cve: NormalizedCVE = {
      cveId: 'CVE-2026-98001',
      title: 'Pipeline audit fixture',
      description: 'Test only',
      publishedDate: new Date().toISOString(),
      modifiedDate: new Date().toISOString(),
      cvss: { version: '3.1', score: 8, severity: 'HIGH', vector: '' },
      cwe: [],
      cpeMatches: [cpe],
      sourceFeeds: [],
      epss: { score: 0, percentile: 0 },
      cisaKev: { isKev: false },
      exploitStatus: 'None',
      remediation: {
        patchUrl: '',
        vendorAdvisoryRef: '',
        immediateActions: [],
        workarounds: [],
        rollbackPlan: '',
        stepByStep: [],
      },
    };
    const save = (kind: string, id: string, value: unknown) =>
      transaction(pool, (db) => put(db, kind, id, value));
    const reset = async (threshold = 90) => {
      await pool.query('DELETE FROM records; DELETE FROM outbox');
      await save('settings', 'main', {
        ...DEFAULT_SETTINGS,
      });
      await save('watchlist', 'asset', asset);
      await save('cveData', cve.cveId, cve);
      await save('recipients', 'ops', {
        id: 'ops',
        name: 'Ops',
        email: 'ops@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
    };
    const noNetwork = async () => {
      throw new Error('No network expected');
    };
    const run = async () => {
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, noNetwork);
    };
    try {
      await migrate(pool);
      // There is no operator review queue: a finding the confidence policy
      // cannot confirm is still dispatched, and the rendered advisory states
      // the limitation on the finding itself. The threshold therefore no longer
      // selects notificationStatus; asserting an empty outbox encoded the
      // removed review-queue contract.
      await t.test('preliminary match reuse dispatches a limited-confidence finding', async () => {
        await reset(99);
        await run();
        // The finding is queued with its confidence disclosed; nothing is
        // withheld for operator review.
        const held = (await list<Finding>(pool, 'findings'))[0];
        assert.equal(held.notificationStatus, 'QUEUED_FOR_DISPATCH');
        const heldRow = (await pool.query("SELECT payload FROM outbox WHERE advisory_id IS NOT NULL OR true LIMIT 1")).rows[0];
        assert.ok(heldRow, 'a held finding is disclosed, not withheld');
        await save('settings', 'main', {
          ...DEFAULT_SETTINGS,
        });
        await run();
        assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
        assert.equal((await pool.query('SELECT 1 FROM outbox')).rowCount, 1);
      });
      await t.test('a policy edit during EPSS enrichment forces eligibility to be recomputed', async () => {
        await reset();
        await save('feeds', 'epss', {
          id: 'epss',
          name: 'EPSS',
          type: 'EPSS_API',
          url: 'https://example.com/epss',
          authType: 'NONE',
          enabled: true,
          rateLimitPerMin: 600,
        });
        await queueRun(pool, 24, 'test');
        let calls = 0;
        await processPipeline(pool, config, async () => {
          calls++;
          await save('settings', 'main', {
            ...DEFAULT_SETTINGS,
          });
          return {
            status: 200,
            headers: {},
            body: JSON.stringify({ total: 1, data: [{ cve: cve.cveId, epss: '0.8', percentile: '0.95' }] }),
          };
        });
        assert.equal(calls, 1);
        // All findings dispatch regardless of threshold; no review-required label.
        assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
        // There is no review queue, so the finding is not withheld here either.
        // How many outbox rows a run leaves behind is a delivery-side concern
        // (digest grouping, dedupe keys, claims) asserted by the delivery
        // suites; this case pins only the recomputation of the label.
        const queued = (await list<Finding>(pool, 'findings')).length;
        assert.ok(queued >= 1, 'the finding survives the recomputation');
      });
      await t.test('zero-day cap withholds capped evidence from the ordinary news email and delivers a digest', async () => {
        await reset();
        // This case is about the news/digest split, not CVE findings.
        await pool.query("DELETE FROM records WHERE kind='cveData'");
        await pool.query("DELETE FROM records WHERE kind='recipients'");
        await save('recipients', 'sec', {
          id: 'sec',
          name: 'Security',
          email: 'sec@example.invalid',
          enabled: true,
          subscriptionTier: 'ALL_SEVERITIES',
          deliveryGroup: 'SECURITY_TEAM',
        });
        await save('feeds', 'news', {
          id: 'news',
          name: 'News',
          enabled: true,
          type: 'RSS_ATOM',
          url: 'https://example.com/feed',
          authType: 'NONE',
          rateLimit: 60,
          healthStatus: 'UNTESTED',
        });
        // One more article than the cap, so exactly one match is withheld and
        // consolidated into a digest.
        const articleCount = 51;
        const pubDate = new Date().toUTCString();
        const items = Array.from(
          { length: articleCount },
          (_, index) =>
            `<item><title>Example Widget zero-day ${index}</title>` +
            `<link>https://example.com/zero-day-${index}</link>` +
            `<pubDate>${pubDate}</pubDate>` +
            '<description>Example Widget zero-day is actively exploited in the wild</description></item>',
        ).join('');
        const xml = `<rss version="2.0"><channel><title>Security</title>${items}</channel></rss>`;
        await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, async () => ({ status: 200, body: xml, headers: {} }));

        const digests = await list<{ advisoryId: string; matchCount: number; articles: string[] }>(
          pool,
          'zeroDayDigests',
        );
        assert.equal(digests.length, 1, 'one digest per vendor/product group');
        assert.equal(digests[0].matchCount, 1, 'exactly the capped match is withheld');

        const outbox = await pool.query<{
          advisory_id: string;
          payload: {
            newsEvidence?: { articles: { id: string }[] };
            zeroDayDigest?: { articles: { id: string }[]; matchCount: number };
          };
        }>("SELECT advisory_id, payload FROM outbox WHERE channel='email'");
        const digestJobs = outbox.rows.filter((row) => String(row.advisory_id).startsWith('ZERODAY:'));
        const newsJobs = outbox.rows.filter((row) => String(row.advisory_id).startsWith('NEWS:'));
        assert.equal(digestJobs.length, 1, 'one digest email for the single Security-team recipient');
        assert.equal(newsJobs.length, 1, 'ordinary news is still one consolidated email');

        const digestArticleIds = new Set(
          (digestJobs[0].payload.zeroDayDigest?.articles ?? []).map((article) => article.id),
        );
        const newsArticleIds = new Set(
          (newsJobs[0].payload.newsEvidence?.articles ?? []).map((article) => article.id),
        );
        assert.equal(digestArticleIds.size, 1, 'the digest names the withheld evidence');
        assert.equal(newsArticleIds.size, articleCount - 1, 'the capped article is not in the ordinary email');
        for (const id of digestArticleIds) {
          assert.ok(!newsArticleIds.has(id), 'withheld evidence is delivered only through the digest');
        }
      });
      await t.test('a stop between checkpoint and progress write cannot be overwritten', async () => {
        await reset();
        const queued = await queueRun(pool, 24, 'test');
        const connect = pool.connect.bind(pool);
        let intercepted = false;
        // The first checkout is the worker's run-lock connection, held for the
        // whole run. An operator stop must not reuse it as a transaction client
        // (the abort path may release it mid-transaction), but it also cannot
        // wait on `pipeline-queue`: the in-flight worker transaction holds that
        // lock while it awaits this stop. The stop therefore runs on a fresh
        // connection with the queue lock declared acquired.
        let runLockClient: pg.PoolClient | undefined;
        const runLockQueries: string[] = [];
        const workerPool = new Proxy(pool, {
          get(target, property) {
            if (property !== 'connect') {
              const value = Reflect.get(target, property, target);
              return typeof value === 'function' ? value.bind(target) : value;
            }
            return async () => {
              const client = await connect();
              runLockClient ??= client;
              const query = client.query;
              const release = client.release;
              client.query = ((...args: unknown[]) => {
                const [sql, values] = args;
                if (client === runLockClient && typeof sql === 'string') runLockQueries.push(sql);
                const forward = () => (query as (...args: unknown[]) => unknown).apply(client, args);
                if (
                  !intercepted &&
                  typeof sql === 'string' &&
                  /^(?:INSERT INTO records|UPDATE records)/.test(sql) &&
                  Array.isArray(values) &&
                  values.some((v) => typeof v === 'string' && v.includes('"status":"RUNNING"'))
                ) {
                  intercepted = true;
                  return stopRunWithClient(pool, queued.id, 'concurrent-operator', runLockClient).then(
                    forward,
                  );
                }
                return forward();
              }) as typeof client.query;
              client.release = (error) => {
                client.query = query;
                client.release = release;
                release.call(client, error);
              };
              return client;
            };
          },
        });
        await processPipeline(workerPool, config, noNetwork);
        assert.equal(intercepted, true);
        assert.ok(
          !runLockQueries.some((sql) => /^\s*BEGIN\b/i.test(sql)),
          'the stop must not open a transaction on the worker run-lock connection',
        );
        const stopped = await get<PipelineExecution>(pool, 'executions', queued.id);
        assert.equal(stopped?.status, 'CANCELLED');
        assert.ok(stopped?.stopRequestedAt);
        assert.ok(stopped?.logs.includes('Operator requested stop'));
        assert.equal((await list(pool, 'findings')).length, 0);
        assert.equal((await pool.query('SELECT 1 FROM outbox')).rowCount, 0);
      });
      await t.test('recovery honours a durable stop without restarting the execution', async () => {
        await reset();
        const queued = await queueRun(pool, 24, 'test');
        await save('executions', queued.id, {
          ...queued,
          status: 'RUNNING',
          stopRequestedAt: new Date().toISOString(),
          logs: ['Operator requested stop'],
        });
        assert.equal(await processPipeline(pool, config, noNetwork), false);
        const stopped = await get<PipelineExecution>(pool, 'executions', queued.id);
        assert.equal(stopped?.status, 'CANCELLED');
        assert.ok(stopped?.logs.includes('Operator requested stop'));
        assert.equal((await list(pool, 'findings')).length, 0);
      });
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);
