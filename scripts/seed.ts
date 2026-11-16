import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { ZodError } from 'zod';
import { loadConfig } from '../server/config.ts';
import { createPool, transaction } from '../server/db.ts';
import { applyCommand } from '../server/commands.ts';
import { seedRecommendedFeeds } from '../server/feedBootstrap.ts';
import { RECOMMENDED_FEEDS } from '../server/recommendedFeeds.ts';

// Load .env file if environment variables are not already set, so the seed
// script works from a plain `npm run seed` invocation without manual export.
const envPath = join(process.cwd(), '.env');
if (existsSync(envPath)) {
  const envContent = readFileSync(envPath, 'utf8');
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const value = trimmed
      .slice(eqIdx + 1)
      .trim()
      .replace(/^['"]|['"]$/g, '');
    if (!(key in process.env)) process.env[key] = value;
  }
}

const config = loadConfig();
const pool = createPool(config.DATABASE_URL);

// Seeding is manual only: the server never inserts seed data at startup. This
// script is the single entry point and applies the feed catalog when invoked
// (`npm run seed`); pass --dry-run to only report current contents. It never
// writes product inventory: see SEEDED_WATCHLIST below.
const shouldSeed = !process.argv.includes('--dry-run');

// The seed registers no monitored products. Inventory is operator-owned, and a
// seeded CPE pattern that names a product but no version would match every
// advisory for that product the moment an operator enabled it, creating
// findings nobody confirmed. Register products through the Monitored Products
// page (or its bulk import).
const SEEDED_WATCHLIST: [] = [];

if (!shouldSeed) {
  // --dry-run: report current database contents and exit without writing.
  const feedRows = (await pool.query('SELECT id FROM records WHERE kind=$1', ['feeds'])).rows;
  const watchlistRows = (await pool.query('SELECT id FROM records WHERE kind=$1', ['watchlist'])).rows;
  console.log(`Database has ${feedRows.length} feeds and ${watchlistRows.length} monitored products.`);
  console.log('Re-run `npm run seed` without --dry-run to register the feed catalog (all disabled).');
  console.log('Monitored products are operator-owned and are never seeded; manage them on the Monitored Products page.');
  process.exit(0);
}

try {
  await transaction(pool, async (db) => {
    // Every catalog feed is registered disabled. The operator enables a source
    // from the Threat Feeds page after its credentials (VulnCheck Bearer token,
    // OTX API key) and its egress allowlist entry are configured, and after its
    // connectivity test passes. A feed that started enabled would fail its
    // first run here and report a configuration gap as a platform fault.
    await seedRecommendedFeeds(db);
    // Feeds go through the same validated command path as the API, so a
    // misconfigured feed fails the seed loudly instead of landing in the DB.
    // The payload re-applies the full catalog so the rows exist on a database
    // that had removed some of them.
    await applyCommand(db, config, {
      action: 'feed.import',
      data: RECOMMENDED_FEEDS.map((feed) => ({ ...feed, enabled: false })),
      actor: 'seed-script',
    });
    if (SEEDED_WATCHLIST.length) {
      await applyCommand(db, config, {
        action: 'watchlist.import',
        data: SEEDED_WATCHLIST,
        actor: 'seed-script',
      });
    }
  });

  console.log('Seed data applied: Threat Feed Sources (all disabled by default), no monitored products.');
} catch (e) {
  if (e instanceof ZodError) {
    console.error('Seed failed: feed configuration is invalid.');
    for (const issue of e.issues) console.error(`  - ${issue.path.join('.') || '(root)'}: ${issue.message}`);
    process.exitCode = 1;
  } else {
    console.error('Seed failed:', e);
    process.exitCode = 1;
  }
} finally {
  await pool.end();
}
