import { describeError, writeEvent } from './events';
import { mergeArticles, matchIntelligence } from '../src/utils/intelligenceMatcher';
import { formatExecutionName, formatAdvisoryId } from '../src/utils/executionName';
import type pg from 'pg';
import { randomUUID, createHash } from 'node:crypto';
import {
  acquireSessionClassLock,
  get,
  getForUpdate,
  getMany,
  list,
  put,
  putMany,
  removeMany,
  transaction,
  appendAudit,
  pipelineState,
  schemaLockKey,
} from './db';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type {
  AppSettings,
  PipelineExecution,
  ThreatFeed,
  Advisory,
  Finding,
  NormalizedCVE,
  WatchListItem,
  AliasEntry,
  EmailDeliveryLog,
  WebhookDeliveryLog,
  EmailRecipient,
  IntelligenceMatch,
  IntelligenceArticle,
} from '../src/types/index.ts';
import { buildAliasMap, parseCPE23 } from '../src/utils/cpeMatcher';
import {
  deriveCorrelationAliases,
  deriveInventoryAliases,
  reconcileAutoAliases,
} from '../src/utils/aliasLifecycle';
import { mergeCveRecords, normalizeCveId, stableJson } from '../src/utils/deduplicator';
import { countNewFindings, findingIdentity, reconcileFindings } from '../src/engine/reconcileFindings';
import {
  applyVexSuppression,
  determineExploitRisk,
  MAX_ZERO_DAYS_PER_RUN,
  rankAndRateLimitZeroDays,
  runVulnerabilityPipeline,
} from '../src/engine/pipelineEngine';
import { ingestFeed, type IngestContext, type CVERejection, FeedDeferred } from './ingestion';
import { assessFindings } from './ml/assessment.ts';
import {
  predictCredibilityWeights,
  computeFeedRecoveryDelay,
  shouldAutoDispatch,
  rankReviewFindings,
  predictMatchConfidence,
  predictSeverityTier,
  predictAliasConfidence,
  classifyDeliveryError,
  mlOrderFindingsByImportance,
  predictExploitRisk,
  calibrateCredibilityScore,
  getZeroDayCap,
} from './ml/integration.ts';
import { bindClusterToCve, clusterSuppressedAssets } from './correlation/clusters.ts';
import { refreshCandidatePairs } from './versionIndex';
import { recoveryDue, recoveryAt, isPermanentFeedFailure, shouldStartAutomaticRun } from './feedRecovery';
import { queueOperatorAlert } from './selfHealing';
import { ingestionWindow, type FeedCursor } from './ingestionState';
import { persistIngestionRejections, rejectionOccurrences } from './ingestionRejections';
import type { Requester } from './network';
import { withAbortSignal } from './network';
import { feedEgressHosts, type Config } from './config';
import {
  enqueue,
  deliveryRevisionEvidence,
  findingRevision,
  queueAdvisory,
  queueConsolidatedFindingNotifications,
  queueZeroDayDigestNotification,
  recipientAllows,
  revision,
  consolidatedFindingsDocument,
  type Job,
} from './delivery';
import { attachClaimsToJob, claimItems, claimsForJob } from './deliveryClaims';
import { loadNewsRecipients, queueConsolidatedNews, newsArticleIdentity } from './newsQueue';
import { renderAdvisory } from './advisoryRender';
import { HttpError } from './validation';
import { advisoryEmail } from './advisoryEmail';
import { currentAdvisoryView, currentAdvisoryBody } from './advisoryRebuild';
export { renderAdvisory } from './advisoryRender';

/**
 * Input captured inside the commit transaction so delivery queueing can run
 * post-commit without holding the pipeline-queue advisory lock. All fields are
 * snapshotted inside the transaction; the post-commit step reads them from the
 * per-attempt slot below.
 */
interface PostCommitDeliveryInput {
  rateLimitedMatches: IntelligenceMatch[];
  articles: IntelligenceArticle[];
  snapshot: Awaited<ReturnType<typeof pipelineState>>;
  settings: AppSettings;
  dispatchFindings: Finding[];
  zeroDayDigestNotificationsQueued: number;
  executionId: string;
  queueStarted: number;
}

/**
 * The attempt-scoped slot carrying a run's {@link PostCommitDeliveryInput} from
 * its commit transaction to its post-commit delivery block.
 *
 * This state used to be a module-level `let` written inside the commit
 * transaction and read by the post-commit block. Two attempts of the same
 * execution can run concurrently: the worker detaches an attempt whose
 * cancellation did not settle within its grace period and starts a replacement
 * while the old promise is still unwinding. When that happened, the replacement
 * overwrote the module-level value and the first attempt's delivery block then
 * queued the other run's findings under its own execution id. Scoping the slot
 * to the attempt removes the shared cell entirely: each call can only observe
 * the snapshot it published itself.
 */
type PostCommitDeliverySlot = { current?: PostCommitDeliveryInput };
/**
 * Rebuilds a queued job's stored payload from current intelligence.
 *
 * Jobs queued before content-revision evidence existed (or whose payload was
 * queued under an older revision scheme) carry no `cveRevisions`, so the
 * delivery worker cannot prove the advisory text still describes the current
 * CVE corpus. Rather than failing such a job permanently, the payload is
 * regenerated from the advisory and the findings it currently references, with
 * fresh `cveRevisions` / `findingRevisions` computed from the current cache. A
 * job whose findings no longer match the stored CVE revisions keeps its stale
 * evidence, so the worker's normal applicability check still rejects it and
 * rebuilds the bundle instead of delivering outdated content.
 *
 * Returns true when the payload was rewritten; false when the job no longer
 * exists, belongs to a native correlation (which has its own evidence hash), or
 * already carries revision evidence.
 */
export async function rebuildLegacyDeliveryPayload(db: pg.Pool | pg.PoolClient, job: Job): Promise<boolean> {
  if (job.payload.nativeCorrelation) return false;
  const advisory = await get<Advisory>(db, 'advisories', job.advisory_id);
  if (!advisory && typeof job.advisory_id === 'string' && job.advisory_id.startsWith('FINDINGS:')) {
    // A consolidated finding batch has no advisory row by design: the batch
    // identity is its content. A legacy copy of it (queued without revision
    // evidence) is rebuilt in place from its declared finding rows — the same
    // rows the delivery worker treats as the batch's validated evidence at
    // transport time. Only the revision maps are regenerated; the body already
    // describes those exact finding rows.
    const declaredCves = job.payload.cveIds ?? [];
    const existingEvidence = job.payload.cveRevisions ?? {};
    if (!declaredCves.length || declaredCves.every((cveId) => existingEvidence[cveId])) return false;
    const findingIds = job.payload.includedFindingIds ?? [];
    const findingMap = await getMany<Finding>(db, 'findings', findingIds);
    if (!findingIds.length || findingMap.size !== new Set(findingIds).size) return false;
    const current: Finding[] = [];
    for (const finding of findingMap.values()) {
      // Serial: `db` is a single client inside this transaction.
      const asset = await get<WatchListItem>(db, 'watchlist', finding.matchedAssetId);
      const cve = await get<NormalizedCVE>(db, 'cveData', finding.cveId);
      const withdrawal = await get<{ modifiedDate: string }>(db, 'cveWithdrawals', finding.cveId);
      if (
        !asset ||
        asset.active === false ||
        !cve ||
        ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status) ||
        (withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate))
      )
        return false;
      current.push(finding);
    }
    const payload = {
      ...job.payload,
      // Recipient-specific per-recipient evidence preserved by the spread: the
      // canonical builder is the same one every enqueue site uses (audit L-6).
      ...deliveryRevisionEvidence(current),
    };
    const updated = await db.query(
      "UPDATE outbox SET payload=$2::jsonb, review_approved=false, updated_at=now() WHERE id=$1 AND (status='QUEUED' OR (status='SENDING' AND lock_token=$3))",
      [job.id, JSON.stringify(payload), job.lock_token],
    );
    if (!updated.rowCount) return false;
    job.payload = payload;
    job.review_approved = false;
    return true;
  }
  if (!advisory) return false;
  const declaredCves = job.payload.cveIds ?? advisory.cveIds;
  const evidence = job.payload.cveRevisions ?? {};
  if (declaredCves.every((cveId) => evidence[cveId])) return false;
  const findingIds = job.payload.includedFindingIds ?? advisory.findingIds;
  const findingMap = await getMany<Finding>(db, 'findings', findingIds);
  if (!findingIds.length || findingMap.size !== new Set(findingIds).size) return false;
  const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
  const aliases = await list<AliasEntry>(db, 'aliases');
  const current: Finding[] = [];
  for (const finding of findingMap.values()) {
    // Serial: `db` is a single client inside this transaction, and issuing
    // queries concurrently on one pg connection races the protocol queue.
    const asset = await get<WatchListItem>(db, 'watchlist', finding.matchedAssetId);
    const cve = await get<NormalizedCVE>(db, 'cveData', finding.cveId);
    const withdrawal = await get<{ modifiedDate: string }>(db, 'cveWithdrawals', finding.cveId);
    if (
      !asset ||
      asset.active === false ||
      !cve ||
      ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status) ||
      (withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate))
    )
      return false;
    const match = runVulnerabilityPipeline(
      [],
      [cve],
      [asset],
      [],
      [],
      { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
      'Server worker',
      false,
      buildAliasMap(aliases, 'VENDOR'),
      buildAliasMap(aliases, 'PRODUCT'),
      undefined,
      aliases,
    ).newFindings[0];
    if (match?.notificationStatus !== 'QUEUED_FOR_DISPATCH') return false;
    current.push({ ...finding, ...match, id: finding.id });
  }
  const view = currentAdvisoryView(advisory, current);
  if (
    view.cveIds.length !== new Set(declaredCves).size ||
    declaredCves.some((id) => !view.cveIds.includes(id))
  )
    return false;
  const payload = {
    ...job.payload,
    ...(await currentAdvisoryBody(db, view, current)),
    cveIds: view.cveIds,
    includedFindingIds: view.findingIds,
    // Single canonical evidence-builder (audit L-6): the same revision maps are
    // produced by `deliveryRevisionEvidence` (delivery.ts) everywhere else.
    ...deliveryRevisionEvidence(current),
  };
  const updated = await db.query(
    "UPDATE outbox SET payload=$2::jsonb, review_approved=false, updated_at=now() WHERE id=$1 AND (status='QUEUED' OR (status='SENDING' AND lock_token=$3))",
    [job.id, JSON.stringify(payload), job.lock_token],
  );
  if (!updated.rowCount) return false;
  job.payload = payload;
  job.review_approved = false;
  return true;
}

type KevSnapshot = {
  fingerprint: string;
  etag?: string;
  kev: NonNullable<Awaited<ReturnType<typeof ingestFeed>>['kev']>;
};
const sourceFingerprint = (feed: ThreatFeed) =>
  createHash('sha256')
    .update(JSON.stringify([feed.type, feed.url, feed.authType, feed.authSecretKey || '']))
    .digest('hex');
/**
 * Shallow content view of a stored CVE, used to decide whether this run changed
 * it.
 *
 * Audit H-3: change detection compared `stableJson(wholeRecord)` for every CVE
 * in the corpus on every run, which required keeping a second full copy of the
 * corpus in memory and serialising several hundred thousand objects per run.
 * Only applicability-affecting fields can change correlation output; the
 * remaining fields (EPSS, KEV, exploit status) are updated in place below and do
 * not need to invalidate the candidate index.
 */
function cveContentView(cve: NormalizedCVE): string {
  return stableJson({
    cveId: cve.cveId,
    title: cve.title,
    description: cve.description,
    publishedDate: cve.publishedDate,
    modifiedDate: cve.modifiedDate,
    cvss: cve.cvss,
    cpeMatches: cve.cpeMatches,
    cpeMatchDetails: cve.cpeMatchDetails,
    versionRange: cve.versionRange,
    purls: cve.purls,
    sourceApplicability: cve.sourceApplicability,
    applicabilityRequiresReview: cve.applicabilityRequiresReview,
    applicabilityPolicy: cve.applicabilityPolicy,
    // Risk metadata is written by the enrichment pass below, so it must be part
    // of the change comparison or a KEV/EPSS update is never persisted.
    cisaKev: cve.cisaKev,
    epss: cve.epss,
    exploitStatus: cve.exploitStatus,
    exploitationSources: cve.exploitationSources,
  });
}

/**
 * Applicability-only projection of a CVE.
 *
 * This is the set of fields that decides which assets a CVE affects. It
 * deliberately excludes metadata and enrichment (title, description, CVSS,
 * publication/modification timestamps, EPSS, KEV, exploit sources): providers
 * rewrite those when they re-analyse a CVE, and that history-only churn must not
 * re-run correlation or notify recipients. CPE criteria (including the
 * configurations / `vcVulnerableCPEs` equivalent), per-criterion ranges, the
 * product-level range, package URLs and the applicability review flags are all
 * included.
 */
function cveApplicabilityView(cve: NormalizedCVE): string {
  return stableJson({
    cpeMatches: cve.cpeMatches ?? [],
    cpeMatchDetails: cve.cpeMatchDetails ?? [],
    versionRange: cve.versionRange,
    purls: cve.purls ?? [],
    applicabilityRequiresReview: cve.applicabilityRequiresReview ?? false,
    applicabilityPolicy: cve.applicabilityPolicy,
  });
}

/** Compact fingerprint of {@link cveApplicabilityView} for whole-corpus snapshots. */
function cveApplicabilitySignature(cve: NormalizedCVE): string {
  return createHash('sha256').update(cveApplicabilityView(cve)).digest('hex');
}

/** One pending CPE-applicability re-evaluation. */
type CpeRematchEntry = { cveId: string; firstSeen: string; runs: number };

/** Durable shape of the `cpe-changed-cves` system state (newest format). */
export type CpeRematchState = {
  cveIds?: string[];
  entries?: CpeRematchEntry[];
  updatedAt?: string;
};

/**
 * How long a CPE applicability change stays eligible for an out-of-window
 * re-match, and how many runs it may occupy before it is considered settled.
 *
 * Both bounds exist because the backlog is otherwise a per-run cost that grows
 * with deployment age: every entry makes a run re-evaluate that CVE against the
 * full inventory regardless of scope. Five scheduled runs (or a week, whichever
 * ends first) gives a provider's delayed CPE publication ample opportunity to
 * reach an asset while keeping the set proportional to recent changes rather
 * than to history.
 */
export const CPE_REMATCH_MAX_RUNS = 5;
export const CPE_REMATCH_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Lock-wait budget for the candidate-index refresh transactions.
 *
 * The index refresh deliberately raises `statement_timeout` (minutes on a large
 * installation). Without a separate lock budget, a refresh that merely collided
 * with a concurrent writer would wait on the index's row locks for that entire
 * statement budget while holding a pool connection and the `match-index`
 * advisory lock. Five seconds is far above the observed contention window and
 * far below the stall watchdog, so a collision surfaces as a fast, retryable
 * `55P03` instead of a run that appears wedged.
 */
export const MATCH_INDEX_LOCK_TIMEOUT_MS = 5_000;

/**
 * Merges this run's CPE changes into the persisted re-match backlog and drops
 * entries that have been re-evaluated often enough or are too old to keep.
 *
 * Only CVEs still present in the corpus and still unmatched after a bounded
 * number of re-evaluations are dropped; a genuinely new applicability change is
 * always re-added by the caller, so pruning never loses detection.
 */
export function carryCpeRematchBacklog(
  previous: CpeRematchState | undefined,
  changedThisRun: ReadonlySet<string>,
  nowIso: string,
  nowMs: number,
): { entries: CpeRematchEntry[]; dropped: number } {
  const previousEntries = new Map<string, CpeRematchEntry>();
  for (const entry of previous?.entries ?? []) if (entry?.cveId) previousEntries.set(entry.cveId, entry);
  // Legacy shape: a bare id list with no per-entry counter. Treat each id as
  // first seen now so the bound applies from this run onward instead of
  // stranding it in the backlog forever.
  for (const cveId of previous?.cveIds ?? [])
    if (cveId && !previousEntries.has(cveId))
      previousEntries.set(cveId, { cveId, firstSeen: nowIso, runs: 0 });
  const entries: CpeRematchEntry[] = [];
  let dropped = 0;
  const ids = new Set([...previousEntries.keys(), ...changedThisRun]);
  for (const cveId of ids) {
    // A change detected in this run restarts the budget: this is new evidence,
    // not a stale carry-over.
    if (changedThisRun.has(cveId)) {
      entries.push({ cveId, firstSeen: nowIso, runs: 1 });
      continue;
    }
    const previousEntry = previousEntries.get(cveId)!;
    const runs = (Number.isFinite(previousEntry.runs) ? previousEntry.runs : 0) + 1;
    const firstSeenMs = Date.parse(previousEntry.firstSeen);
    const expired = Number.isFinite(firstSeenMs) && nowMs - firstSeenMs > CPE_REMATCH_MAX_AGE_MS;
    if (runs > CPE_REMATCH_MAX_RUNS || expired) {
      dropped++;
      continue;
    }
    entries.push({ cveId, firstSeen: previousEntry.firstSeen, runs });
  }
  return { entries, dropped };
}

/**
 * (vendor, product) identities a CVE asserts, used to join pre-CVE clusters.
 * Derived only from non-wildcard CPE criteria; a CVE with no parseable
 * structured identity cannot bind a cluster (binding on prose would let a
 * poisoned CVE claim another vulnerability's rulings).
 */
function cveClusterIdentities(cve: NormalizedCVE): { vendor: string; product: string }[] {
  // `cpeMatches` may list criteria that `cpeMatchDetails` does not. Both are
  // applicability claims, and a cluster that resolved to such a criterion must
  // still bind to the CVE, so the union is the correct identity set.
  const criteria = cve.cpeMatchDetails?.length
    ? [...new Set([...cve.cpeMatchDetails.map((detail) => detail.criteria), ...cve.cpeMatches])]
    : cve.cpeMatches;
  const identities = new Map<string, { vendor: string; product: string }>();
  for (const criterion of criteria) {
    const parsed = parseCPE23(criterion);
    if (!parsed.isValid || /[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) continue;
    const vendor = parsed.vendor.toLowerCase();
    const product = parsed.product.toLowerCase();
    identities.set(`${vendor}\u0000${product}`, { vendor, product });
  }
  return [...identities.values()];
}

/** Bounded retries for a pre-CVE disposition bind that lost its lock race. */
const DEFERRED_BIND_MAX_ATTEMPTS = 5;

/** Upper bound for {@link recoveryBackoffMs}. */
export const RECOVERY_BACKOFF_CAP_MS = 15 * 60_000;

/**
 * Backoff (ms) between pipeline lock-loss recovery requeues.
 *
 * The first recovery is immediate: a run that lost its lock connection has not
 * been shown to be flaky yet, and making the very first hand-back wait means a
 * single transient connection reset leaves the run QUEUED for half a minute with
 * nothing running — the scheduler tick that could recover it is gated by this
 * same value. Only a *repeated* loss is throttled, and that throttle is
 * exponential with full jitter (base 30s, capped at 15 minutes) so a worker that
 * keeps dropping its lock cannot make the installation retry in lockstep or
 * spin faster than it can make progress.
 *
 * `rng` is injectable so the schedule can be asserted deterministically.
 */
export const recoveryBackoffMs = (attempt: number, rng: () => number = Math.random): number => {
  const safeAttempt = Number.isFinite(attempt) ? Math.max(0, Math.floor(attempt)) : 0;
  // `attempt` is 1-based (the count including the recovery being scheduled).
  // attempt <= 1 is the first hand-back and must not be delayed.
  if (safeAttempt <= 1) return 0;
  const base = Math.min(RECOVERY_BACKOFF_CAP_MS, 30_000 * 2 ** (safeAttempt - 2));
  return Math.floor(rng() * (base + 1));
};

export async function queueRun(
  pool: pg.Pool,
  scope: number | undefined,
  actor: string,
  incrementalFeeds?: boolean,
  client?: pg.PoolClient,
): Promise<PipelineExecution> {
  // `incrementalFeeds === undefined` means "the caller expressed no preference"
  // and must never be coerced to `true` before the active-run check: doing so
  // turned a generic POST or a scheduler queue into an explicit "source
  // checkpoints on" that overwrote the operator's choice on the queued run.
  // A brand-new run still needs a concrete value, which is the `?? true` at the
  // construction site below.
  return transaction(
    pool,
    async (db) => {
      // Only the active execution matters here. `list('executions')` loaded
      // every run ever recorded and de-serialised it in JavaScript, which on a
      // long-lived installation grew past the 15 s pool statement timeout and
      // turned "queue a run" into a 500. The JSONB status is indexed.
      // The row is locked because this call may now rewrite the active run's
      // scope and checkpoint settings; an unlocked read-then-write could race a
      // worker that is promoting the same execution from QUEUED to RUNNING.
      const active = await db.query<{ data: PipelineExecution }>(
        "SELECT data FROM records WHERE kind='executions' AND data->>'status' IN ('QUEUED','RUNNING') ORDER BY updated_at DESC LIMIT 1 FOR UPDATE",
      );
      // Deduplication is about not running two pipelines at once, but the
      // operator's request still carries intent the active run may not have:
      // their explicit scope and their "use source checkpoints" choice. The
      // previous version returned the active row untouched, so unticking
      // "Use source checkpoints" while a run was queued/running silently did
      // nothing, and an operator who asked for a wider window got the active
      // run's window with no indication either value was ignored.
      const existing = active.rows[0]?.data;
      if (existing) {
        const requestedScope = scope === undefined ? existing.scopeHours : scope;
        const requestedIncremental = incrementalFeeds ?? existing.incrementalFeeds ?? true;
        if (
          existing.scopeHours === requestedScope &&
          (existing.incrementalFeeds ?? true) === requestedIncremental
        )
          return existing;
        // Only apply the request to a run that has not started ingesting. A
        // RUNNING execution's window is already in use by live feed cursors;
        // rewriting it mid-flight would make the recorded scope disagree with
        // the data the run actually collected.
        if (existing.status === 'RUNNING') {
          await writeEvent(db, {
            category: 'PIPELINE',
            level: 'WARNING',
            code: 'pipeline.request_ignored_while_running',
            message:
              'Requested scope/checkpoint settings were not applied because a run is already in progress',
            runId: existing.id,
            context: {
              requestedScopeHours: requestedScope,
              activeScopeHours: existing.scopeHours,
              requestedIncrementalFeeds: requestedIncremental,
              activeIncrementalFeeds: existing.incrementalFeeds ?? true,
            },
          });
          return existing;
        }
        const updated: PipelineExecution = structuredClone({
          ...existing,
          scopeHours: requestedScope,
          incrementalFeeds: requestedIncremental,
          logs: [
            ...(existing.logs ?? []),
            `Queued-run settings updated by ${actor}: ingestion window ${existing.scopeHours}h -> ${requestedScope}h; source checkpoints ${(existing.incrementalFeeds ?? true) ? 'on' : 'off'} -> ${requestedIncremental ? 'on' : 'off'}`,
          ],
          // Same reason as the worker path: the success path must not hand the
          // caller (or the shared active-row object) the mutable row by reference.
        });
        await put(db, 'executions', existing.id, updated);
        await appendAudit(
          db,
          'Queued pipeline settings updated',
          `Execution ${existing.id}; window ${existing.scopeHours}h -> ${requestedScope}h; checkpoints ${requestedIncremental ? 'on' : 'off'}`,
          actor,
          'PIPELINE',
        );
        return updated;
      }
      const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
      const id = randomUUID();
      const execution: PipelineExecution = {
        id,
        name: formatExecutionName(id),
        startTime: new Date().toISOString(),
        endTime: null,
        status: 'QUEUED',
        scopeHours: scope ?? settings.scopeHours,
        incrementalFeeds: incrementalFeeds ?? true,
        phases: [],
        stats: {
          rawIngested: 0,
          normalized: 0,
          deduplicated: 0,
          inRunDuplicatesDropped: 0,
          matchedWatchlist: 0,
          autoDispatchedNotifications: 0,
          advisoriesDispatched: 0,
          webhooksFired: 0,
          vexSuppressedCount: 0,
        },
        logs: [],
      };
      await put(db, 'executions', id, execution);
      await writeEvent(db, {
        category: 'PIPELINE',
        code: 'pipeline.queued',
        message: 'Pipeline queued',
        runId: id,
      });
      await appendAudit(db, 'Pipeline queued', `Execution ${id}`, actor, 'PIPELINE');
      return execution;
    },
    client,
    client ? { locks: [], lockAcquired: ['pipeline-queue'] } : { locks: ['pipeline-queue'] },
  );
}
/** Recover an unsent stale advisory after its failed attempt is committed.
 * Rebuild applicable subsets, invalidate remaining queued siblings, and leave
 * every in-flight delivery lease untouched. Policy holds do not start ingestion
 * loops; a wholly inapplicable bundle schedules one reconciliation run.
 */
export async function rebuildFromCurrentInventory(
  pool: pg.Pool,
  advisoryId: string,
  reason: string,
  options: { payloadRebuilt?: boolean } = {},
): Promise<void> {
  const rebuiltInPlace: string[] = [];
  if (!options.payloadRebuilt) {
    const legacy = await pool.query<Job>(
      "SELECT * FROM outbox WHERE advisory_id=$1 AND status='QUEUED' AND payload->'cveRevisions' IS NULL",
      [advisoryId],
    );
    for (const job of legacy.rows) {
      if (await rebuildLegacyDeliveryPayload(pool, job).catch(() => false)) rebuiltInPlace.push(job.id);
    }
  }
  // Regroup the still-deliverable jobs of this bundle before failing the rest,
  // so a single held finding cannot silently drop the deliverable findings.
  const { regrouped, holdGated } = await regroupStaleAdvisory(pool, advisoryId).catch(() => ({
    regrouped: false,
    holdGated: false,
  }));
  await transaction(pool, async (db) => {
    const invalidated = await db.query<{ id: string; channel: string; attempts: number }>(
      `UPDATE outbox
         SET status='FAILED', delivery_outcome='NOT_ATTEMPTED', error=$1, next_attempt=now(),
             locked_at=NULL, lock_token=NULL, updated_at=now()
       WHERE advisory_id=$2 AND status='QUEUED'
         AND id::text <> ALL($3::text[])
       RETURNING id,channel,attempts`,
      [reason, advisoryId, rebuiltInPlace],
    );
    if (invalidated.rows.length > 0) {
      await db.query(`DELETE FROM delivery_claims WHERE job_id = ANY($1::uuid[]) AND state='CLAIMED'`, [
        invalidated.rows.map((r) => r.id),
      ]);
    }
    for (const row of invalidated.rows) {
      if (row.channel === 'email') {
        const log = await getForUpdate<EmailDeliveryLog>(db, 'emailLogs', row.id);
        if (log)
          await put(db, 'emailLogs', row.id, {
            ...log,
            status: 'FAILED',
            attemptCount: row.attempts,
            nextRetryTime: null,
            errorMessage: reason,
          });
      } else {
        const log = await getForUpdate<WebhookDeliveryLog>(db, 'webhookLogs', row.id);
        if (log) await put(db, 'webhookLogs', row.id, { ...log, status: 'FAILED', errorMessage: reason });
      }
    }
  });
  // Fresh replacement jobs are already queued. Only a wholly inapplicable
  // bundle needs correlation to reconcile inventory; policy holds await review.
  if (!regrouped && !holdGated) {
    const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
    await queueRun(pool, settings.scopeHours, 'delivery-rebuild');
  }
}
/** Regenerate unsent delivery subsets from current inventory and policy.
 * Queued jobs move to a fresh advisory; failed pre-transport attempts retain
 * their history and receive an idempotent replacement. Accepted and sending
 * jobs are excluded. Only the retained findings bind to the new advisory.
 */
export async function regroupStaleAdvisory(
  pool: pg.Pool,
  advisoryId: string,
): Promise<{ regrouped: boolean; holdGated: boolean }> {
  return transaction(pool, async (db) => {
    let advisory = await get<Advisory>(db, 'advisories', advisoryId);
    const jobs = (
      await db.query<Job>(
        "SELECT * FROM outbox WHERE advisory_id=$1 AND (status='QUEUED' OR (status='FAILED' AND COALESCE(error,'') LIKE '%no longer applicable%')) AND payload->'nativeCorrelation' IS NULL ORDER BY id ASC FOR UPDATE",
        [advisoryId],
      )
    ).rows;
    if (!jobs.length) return { regrouped: false, holdGated: false };

    if (!advisory && typeof advisoryId === 'string' && advisoryId.startsWith('FINDINGS:')) {
      const findingIds = (jobs[0]?.payload?.includedFindingIds ?? []) as string[];
      const findingMap = await getMany<Finding>(db, 'findings', findingIds);
      const findings = findingIds.map((id) => findingMap.get(id)).filter((f): f is Finding => !!f);
      if (findings.length > 0) {
        const generatedAt = jobs[0]?.payload?.generatedAt
          ? new Date(jobs[0].payload.generatedAt)
          : new Date();
        advisory = consolidatedFindingsDocument(findings, generatedAt).advisory;
      }
    }
    if (!advisory) return { regrouped: false, holdGated: false };
    const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    const aliasEntries = await list<AliasEntry>(db, 'aliases');
    const vendorAliases = buildAliasMap(aliasEntries, 'VENDOR');
    const productAliases = buildAliasMap(aliasEntries, 'PRODUCT');
    const deliverability = new Map<string, boolean>();
    const evidence = new Map<
      string,
      { cveRevisions: Record<string, string>; findingRevisions: Record<string, string>; findings: Finding[] }
    >();
    let holdGated = false;
    for (const job of jobs) {
      const findingIds = job.payload.includedFindingIds ?? advisory.findingIds;
      const findings = [...(await getMany<Finding>(db, 'findings', findingIds)).values()];
      const cves = await getMany<NormalizedCVE>(db, 'cveData', [...new Set(findings.map((f) => f.cveId))]);
      const assets = await getMany<WatchListItem>(db, 'watchlist', [
        ...new Set(findings.map((f) => f.matchedAssetId)),
      ]);
      const cveRevisions: Record<string, string> = {};
      const findingRevisions: Record<string, string> = {};
      const current: Finding[] = [];
      for (const finding of findings) {
        const cve = cves.get(finding.cveId) || finding.cve;
        const asset = assets.get(finding.matchedAssetId);
        if (cve) cveRevisions[cve.cveId] = revision(cve);
        // Only findings the current policy and inventory still admit may move to
        // the new bundle; a review-held or unverifiable finding stays in place and
        // is finalized by the caller's FAILED update.
        const withdrawal = await get<{ modifiedDate: string }>(db, 'cveWithdrawals', finding.cveId);
        if (
          !asset ||
          asset.active === false ||
          !cve ||
          ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status) ||
          (withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate))
        ) {
          continue;
        }
        const match = runVulnerabilityPipeline(
          [],
          [cve],
          [asset],
          [],
          [],
          { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
          'Server worker',
          false,
          vendorAliases,
          productAliases,
          undefined,
          aliasEntries,
        ).newFindings[0];
        // Limited-confidence matches are dispatched too (the email states the
        // limitation), so they are admitted exactly like QUEUED_FOR_DISPATCH.
        if (
          match?.notificationStatus !== 'QUEUED_FOR_DISPATCH' &&
          match?.notificationStatus !== 'REVIEW_REQUIRED'
        ) {
          continue;
        }
        const fresh = { ...finding, ...match, id: finding.id };
        findingRevisions[finding.id] = findingRevision(fresh);
        current.push(fresh);
      }
      deliverability.set(job.id, current.length > 0);
      evidence.set(job.id, { cveRevisions, findingRevisions, findings: current });
    }
    const regroup = jobs.filter((job) => deliverability.get(job.id));
    if (!regroup.length) return { regrouped: false, holdGated };
    const isDigest =
      Boolean(jobs[0].payload.digestKey) &&
      jobs.every((job) => job.payload.digestKey === jobs[0].payload.digestKey);
    const replacement: Advisory = {
      ...currentAdvisoryView(advisory, [
        ...new Map(
          regroup.flatMap((job) => evidence.get(job.id)!.findings.map((f) => [f.id, f] as const)),
        ).values(),
      ]),
      id: formatAdvisoryId(settings.advisoryPrefix),
      createdDate: new Date().toISOString(),
      deliveryStatus: 'PENDING',
    };
    let regroupedJobs = 0;
    let emailJobs = 0;
    for (const job of regroup) {
      const { cveRevisions, findingRevisions, findings: groupedFindings } = evidence.get(job.id)!;
      const included = groupedFindings.map((f) => f.id);
      const body = await currentAdvisoryBody(
        db,
        currentAdvisoryView(replacement, groupedFindings),
        groupedFindings,
      );
      const payload = {
        ...job.payload,
        ...body,
        cveIds: Array.from(new Set(groupedFindings.map((f) => f.cveId))).sort(),
        includedFindingIds: included,
        // Canonical evidence-builder (audit L-6); `findingRevisions` from the
        // scan loop is keyed identically, so it is replaced wholesale.
        ...deliveryRevisionEvidence(groupedFindings),
        digestKey: isDigest ? `${job.payload.digestKey}:regrouped` : undefined,
      };
      // Preserve the failed attempt and its log. A deterministic rebuild key
      // coalesces equivalent failed jobs for the same recipient. Keying by the
      // source job id lets repeated stale-bundle recovery create one replacement
      // per retrying row and send the same content repeatedly.
      if ((job as Job & { status?: string }).status === 'FAILED') {
        const fingerprint = createHash('sha256')
          .update(
            stableJson({
              cveRevisions: payload.cveRevisions,
              findingRevisions,
              included,
            }),
          )
          .digest('hex');
        const inserted = await enqueue(
          db,
          job.channel,
          job.target_id,
          replacement.id,
          payload,
          `rebuild:${job.channel}:${job.target_id}:${fingerprint}`,
          'QUEUED',
          job.priority || 0,
        );
        if (!inserted) continue;
        if (job.channel === 'email') {
          // Take the claims the replacement needs BEFORE attaching them. The
          // replacement is built here, outside `queueDigestAdvisory`, so nothing
          // has claimed its findings; attaching claims that were never granted is
          // a no-op, which left the new job owning nothing. `activeClaims` then
          // reported every finding as unclaimed and the next pipeline run queued
          // a duplicate copy of the same bundle under a different advisory id.
          // Claiming first (and only attaching what was actually granted) makes
          // the replacement authoritative until it is delivered or terminally
          // refused.
          const granted = await claimItems(
            db,
            claimsForJob(job.target_id, 'finding', included),
            { jobId: inserted },
          );
          if (!granted.granted.length) {
            // Another live job already owns every finding: this replacement would
            // duplicate it. Retire it as a superseded no-op instead of leaving an
            // unclaimed live row behind.
            await db.query(
              `UPDATE outbox SET status='SUPERSEDED', delivery_outcome='NOT_ATTEMPTED', updated_at=now()
                WHERE id=$1 AND status='QUEUED'`,
              [inserted],
            );
            continue;
          }
        }
        // The source row is deliberately left FAILED. It is the durable record
        // that this bundle could not be delivered as written, and the operator
        // view (and the suite) relies on that status. Duplicate suppression does
        // not depend on it: the replacement claims the findings below, and
        // `activeClaims` will not hand a claim to a second job while a queued or
        // sending owner holds it.
      } else {
        await db.query(
          `UPDATE outbox
            SET advisory_id=$2, payload=$3::jsonb, review_approved=false, status='QUEUED', attempts=0,
                locked_at=NULL, lock_token=NULL, next_attempt=now(), error=NULL, updated_at=now()
          WHERE id=$1 AND (status='QUEUED' OR (status='FAILED' AND COALESCE(error,'') LIKE '%no longer applicable%'))`,
          [job.id, replacement.id, JSON.stringify(payload)],
        );
      }
      regroupedJobs++;
      if (job.channel === 'email') emailJobs++;
      for (const finding of groupedFindings) {
        await put(db, 'findings', finding.id, {
          ...finding,
          advisoryId: replacement.id,
          notificationStatus: 'QUEUED_FOR_DISPATCH',
        });
      }
    }
    if (!regroupedJobs) return { regrouped: true, holdGated };
    await put(db, 'advisories', replacement.id, { ...replacement, recipientCount: emailJobs });
    await writeEvent(db, {
      category: 'EMAIL',
      code: 'delivery.bundle_regrouped',
      message: `Regrouped ${regroupedJobs} deliverable job(s) from a stale advisory bundle`,
      context: { staleAdvisoryId: advisoryId, advisoryId: replacement.id, jobs: regroupedJobs },
    });
    return { regrouped: true, holdGated };
  });
}
class PipelineStopped extends Error {
  constructor() {
    // This sentinel means the worker observed a cancellation state. The database
    // stop marker is the source of truth for whether an operator requested it;
    // the exception itself must not claim an actor.
    super('Pipeline cancellation observed; uncommitted results discarded');
  }
}

/**
 * The pipeline could not take its advisory-lock connection because the pool was
 * saturated. This is a scheduling condition, not a failure of the run: the tick
 * retries on its next pass and the operator sees the pool state in the event.
 */
export class PipelinePoolStarved extends Error {
  readonly detail: { total: number; idle: number; waiting: number; error: string };
  constructor(detail: { total: number; idle: number; waiting: number; error: string }) {
    super(
      `Could not acquire the pipeline connection (pool total=${detail.total} idle=${detail.idle} waiting=${detail.waiting}); run deferred`,
    );
    this.name = 'PipelinePoolStarved';
    this.detail = detail;
  }
}
/** WHATWG name a timeout strategy assigns to its abort reason. */
const TIMEOUT_REASON_NAME = 'TimeoutError';

/** Sentinel stamped on external abort reasons so main.ts can recognize them. */
export const ABORT_REASON = Symbol('abort-reason');

/**
 * Marks an abort as an EXTERNAL cancel for the engine, distinct from the
 * operation's own deadlines (the corpus/commit budget, feed windows).
 *
 * `AbortSignal.timeout()` and `AbortSignal.any()` abort with a reason whose
 * `name` is "TimeoutError", and `throwIfAborted()` rethrows that reason object
 * unchanged. `reasonAborted()` in main.ts classifies on that name, so an
 * external cancel must be tagged through here.
 *
 * IMPORTANT: this only tags the controller's CURRENT reason; it never aborts.
 * Call sites are written as
 *
 *     setAbortReason(controller);
 *     controller.abort(new Error('Worker leadership lost'));
 *
 * and an earlier version of this helper aborted on the caller's behalf when the
 * signal was not yet aborted. That made the caller's own `abort(reason)` a
 * silent no-op (the signal was already aborted), so EVERY external cancel -
 * leadership loss, shutdown, and the stall watchdog - arrived at the engine as
 * a generic "Operation exceeded its deadline". Operators lost the actual cause
 * in the event log, and the watchdog's measured stall duration was discarded.
 * Returning without aborting leaves the caller's reason authoritative.
 */
export function setAbortReason(controller: AbortController): void {
  // Not aborted yet: there is no reason to tag, and aborting here would
  // overwrite the caller's own abort reason (see the note above).
  if (!controller.signal.aborted) return;
  const reason = controller.signal.reason;
  // A caller-supplied reason, and the browser-shaped `AbortError` that a
  // timeout strategy may still synthesise, are already distinguishable from a
  // bare cancel. Only an untyped or generic abort is ambiguous, and an
  // ambiguous cancel in this pipeline is always a deadline.
  if (reason !== undefined && !(reason instanceof Error && reason.name === 'Error')) return;
  // Built from the tagged name, without importing the class: some Node/type
  // combinations do not export `TimeoutError` from `node:util`, yet the tag it
  // appends is stable. Callers classify on `name`, never on the constructor.
  const deadlineReason = Object.assign(new Error('Operation exceeded its deadline'), {
    name: TIMEOUT_REASON_NAME,
    [ABORT_REASON]: true,
  });
  controller.abort(deadlineReason);
}
/**
 * A source that cannot finish within its configured window.
 *
 * Audit R-2: this used to be a plain `Error` that fell through the generic
 * failure branch, so a slow-but-healthy source was recorded as DOWN, consumed
 * one of its `consecutiveFailures`, and could open its circuit breaker. A
 * deadline is a capacity signal about *this run*, not evidence that the source
 * is unreachable, so it is classified separately and never fed to recoveryAt.
 */
class FeedDeadlineExceeded extends Error {
  constructor() {
    super('Feed ingestion exceeded its configured duration limit');
    this.name = 'FeedDeadlineExceeded';
  }
}

/** Bounds the in-memory execution log.
 *
 * Audit P-3: every feed worker appended to the execution's log array, and the
 * whole object was persisted on every source. With N feeds that is O(N^2)
 * JSON written per run, and the record grows without limit across a long
 * bootstrap. Recent entries are what an operator reads; older ones are already
 * in `operational_events`.
 *
 * Audit F-1: the cap must never touch the crash-recovery counter. Counting
 * restarts by scanning log lines meant one eviction of the marker silently
 * reset the poison-pill budget and a crashing worker restarted forever. The
 * count now lives in `stats.recoveryAttempts`, which the cap cannot reach;
 * `countRecoveries` still reads the historical marker so executions persisted
 * by older builds keep their budget across a deploy.
 */
const EXECUTION_LOG_LIMIT = 200;
/** Log fragment older builds used as the recovery counter. Read-only. */
const LEGACY_RECOVERY_MARKER = 'Recovered interrupted worker';
/**
 * Lines that are operational state, not narration. Audit F-1: the recovery
 * counter used to live in a log line, and audit P-1's regression test asserts
 * the stop marker survives a long feed run — eviction of either silently broke
 * the crash-recovery budget or erased the operator's stop decision. Both are
 * pinned to the tail on every bound.
 */
const PINNED_LOG_MARKERS = [LEGACY_RECOVERY_MARKER, 'Operator requested stop'] as const;
const isPinnedLogLine = (line: string) => PINNED_LOG_MARKERS.some((marker) => line.includes(marker));
function countRecoveries(execution: PipelineExecution): number {
  return Math.max(
    Number.isFinite(Number(execution.stats.recoveryAttempts)) ? Number(execution.stats.recoveryAttempts) : 0,
    0,
  );
}
/**
 * Counts lock-loss recoveries. A run from before the counter existed reports 0,
 * which matches the historical behaviour (it fell back to the crash counter, and
 * a run that had never crashed was at 0 there too).
 */
function countLockRecoveries(execution: PipelineExecution): number {
  return Math.max(
    Number.isFinite(Number(execution.stats.lockRecoveryAttempts))
      ? Number(execution.stats.lockRecoveryAttempts)
      : 0,
    0,
  );
}
function pushExecutionLog(execution: PipelineExecution, line: string) {
  execution.logs.push(line);
  boundExecutionLogs(execution.logs);
}
/** Applies the log bound in place, keeping pinned state lines, and returns it. */
function boundExecutionLogs(logs: string[]): string[] {
  if (logs.length <= EXECUTION_LOG_LIMIT) return logs;
  const pinned = logs.filter(isPinnedLogLine);
  const evictionPool = logs.filter((line) => !isPinnedLogLine(line));
  const evictCount = logs.length - EXECUTION_LOG_LIMIT;
  const evicted = new Set(evictionPool.slice(0, evictCount));
  const kept = logs.filter((line) => !evicted.has(line));
  logs.length = 0;
  logs.push(...kept);
  return logs;
}
/** Atomically reject a stale worker write after an operator has stopped a run.
 * A checkpoint read alone leaves a race before the following JSON upsert.
 *
 * The first write promotes the execution from QUEUED to RUNNING, so the guard
 * must accept both states: requiring RUNNING here made the very first save a
 * no-op and surfaced as a phantom cancellation. Later writes still only land
 * while the row is active and has no stop request. */
async function saveActiveExecution(db: pg.PoolClient, execution: PipelineExecution) {
  const saved = await db.query(
    `UPDATE records SET data=$2::jsonb,updated_at=now()
     WHERE kind='executions' AND id=$1 AND data->>'status' IN ('QUEUED','RUNNING')
       AND COALESCE(data->>'stopRequestedAt','')='' RETURNING id`,
    [execution.id, JSON.stringify(execution)],
  );
  if (saved.rowCount) return;
  if (!(await get(db, 'executions', execution.id))) throw new Error('Pipeline execution no longer exists');
  throw new PipelineStopped();
}
export async function stopRun(pool: pg.Pool, id: string, actor: string): Promise<PipelineExecution> {
  return stopRunWithClient(pool, id, actor);
}

/*
 * Run-lock namespace. `processPipeline` takes this session advisory lock on its
 * dedicated connection and holds it for the whole run, so "is this lock held?"
 * is an exact answer to "does a live worker own this execution right now?".
 */
const PIPELINE_RUN_LOCK_CLASS = 800003;
/** Canonical UUID, used where a `text` id is written to a `uuid` column. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Is the pipeline run lock currently held by any live session?
 *
 * Used by `stopRun` to distinguish a run a worker will stop at its next
 * checkpoint from an orphaned row no worker will ever look at again. The probe
 * must never wait: `pg_locks` is read instead of `pg_try_advisory_lock`, because
 * taking the lock to test it would (a) block-free require a release on every
 * path and (b) report "free" only after a real acquisition race. A plain read of
 * `pg_locks` observes the holder without touching the lock at all.
 *
 * `granted` is filtered because a waiter waiting on the lock is not a holder.
 * Advisory locks are two-part keys, so both halves are matched.
 */
async function isRunOwnedByLiveWorker(db: pg.PoolClient, runId: string): Promise<boolean> {
  // `schemaLockKey` is a SQL expression, not a bindable value (it is
  // `hashtext(COALESCE(current_schema(), current_database()))`), so it is
  // interpolated exactly as the acquisition site does. The class is a numeric
  // constant and is likewise safe to interpolate.
  const result = await db.query<{ held: boolean }>(
    `SELECT EXISTS (
       SELECT 1 FROM pg_locks
        WHERE locktype = 'advisory'
          AND granted
          AND classid = ${PIPELINE_RUN_LOCK_CLASS}
          AND objid = ${schemaLockKey}
     ) AS held`,
  );
  // `runId` is accepted for readability at the call site and future per-run
  // locking; the run lock is installation-scoped today, so the answer is the
  // same for every RUNNING execution in this schema.
  void runId;
  return Boolean(result.rows[0]?.held);
}

/**
 * Cancel RUNNING executions that no live worker owns.
 *
 * `queueRun()` refuses to start a new run while any execution is QUEUED or
 * RUNNING, on the assumption that a worker is servicing it. A worker that
 * crashed, was detached by the stall watchdog, or lost its lock connection can
 * leave that row behind, and nothing else rewrites it: the crash-recovery sweep
 * runs inside `processPipeline`, which the stuck row prevents from starting.
 * That is a circle - the row blocks the only code that would clear it.
 *
 * This is the escape. It only touches rows with no lock holder, so it can never
 * race a live worker: ownership is proven by `pg_locks`, not by age. Returns the
 * ids it cancelled so the caller can report them.
 */
export async function releaseOrphanedRunningExecutions(pool: pg.Pool, reason: string): Promise<string[]> {
  return transaction(pool, async (db) => {
    if (await isRunOwnedByLiveWorker(db, '')) return [];
    const stuck = await db.query<{ id: string }>(
      `SELECT id FROM records
        WHERE kind='executions' AND data->>'status'='RUNNING'
        ORDER BY id
        FOR UPDATE`,
    );
    const cancelled: string[] = [];
    for (const row of stuck.rows) {
      const current = await db.query<{ data: PipelineExecution }>(
        "SELECT data FROM records WHERE kind='executions' AND id=$1 AND data->>'status'='RUNNING'",
        [row.id],
      );
      const run = current.rows[0]?.data;
      if (!run) continue;
      const now = new Date().toISOString();
      await put(db, 'executions', row.id, {
        ...run,
        status: 'CANCELLED',
        endTime: now,
        stopRequestedAt: run.stopRequestedAt ?? now,
        phases: run.phases.map((phase) =>
          ['RUNNING', 'PENDING'].includes(phase.status) ? { ...phase, status: 'CANCELLED' as const } : phase,
        ),
        logs: boundExecutionLogs([...run.logs, `Cancelled ${now}: ${reason}`]),
      });
      await writeEvent(db, {
        category: 'PIPELINE',
        level: 'WARNING',
        code: 'pipeline.orphaned_run_cancelled',
        message: 'Cancelled a RUNNING execution that no worker owned',
        // `operational_events.run_id` is a uuid column, so a legacy or malformed
        // execution id would make the event INSERT fail and abort the whole sweep
        // transaction - leaving every orphan in place, which is exactly the state
        // this function exists to clear. The id is always in the context.
        ...(UUID.test(row.id) ? { runId: row.id } : {}),
        context: { reason, executionId: row.id },
      });
      cancelled.push(row.id);
    }
    return cancelled;
  });
}

/**
 * Record a stop in a queue-serialized transaction.
 *
 * `workerLockClient` is only a signal that the caller already owns the worker's
 * run lock. In that case the queue-admission lock is declared acquired so this
 * write does not wait on the in-flight worker transaction that holds it. The
 * client itself is never used as a transaction client: the abort path may
 * release it mid-transaction, and handing it to `transaction()` would
 * desynchronise the pool (see the lifetime note on `processPipeline`).
 * Network ingestion never holds the queue-admission lock.
 */
export async function stopRunWithClient(
  pool: pg.Pool,
  id: string,
  actor: string,
  workerLockClient?: pg.PoolClient,
): Promise<PipelineExecution> {
  return transaction(
    pool,
    async (db) => {
      const run = await getForUpdate<PipelineExecution>(db, 'executions', id);
      if (!run) throw new HttpError(404, 'Execution not found');
      /*
       * A stop must always end the run, even when no worker is left to notice it.
       *
       * Writing `stopRequestedAt` alone only works when a live worker reaches a
       * checkpoint. If the worker crashed, was detached by the stall watchdog, or
       * lost its advisory connection, nothing ever transitions the row: it stays
       * RUNNING forever, and because `queueRun()` treats any RUNNING row as the
       * active run, every later request and scheduled tick is deduplicated against
       * a run that no longer exists. The pipeline looks alive and stop "does
       * nothing".
       *
       * Ownership decides which of the two correct behaviours applies:
       *  - a live worker owns the run, so the stop is REQUESTED and that worker
       *    finalizes the row at its next checkpoint;
       *  - nobody owns it, so the stop is APPLIED here and the queue is released.
       *
       * Ownership evidence, strongest first: `workerLockClient` proves the caller
       * is the worker; otherwise the run's session advisory lock, still held in
       * `pg_locks`, proves a worker is alive. A QUEUED row a worker has already
       * locked is mid-promotion and belongs to that worker too.
       */
      if (!['QUEUED', 'RUNNING'].includes(run.status)) return run;
      const workerAlive = Boolean(workerLockClient) || (await isRunOwnedByLiveWorker(db, id));
      // A live worker already told to stop needs no second write.
      if (run.stopRequestedAt && workerAlive) return run;
      const alreadyRequested = Boolean(run.stopRequestedAt);
      run.stopRequestedAt ??= new Date().toISOString();
      if (!workerAlive) {
        run.status = 'CANCELLED';
        run.endTime = run.stopRequestedAt;
        run.phases = run.phases.map((phase) =>
          ['RUNNING', 'PENDING'].includes(phase.status) ? { ...phase, status: 'CANCELLED' as const } : phase,
        );
        run.logs.push(
          alreadyRequested
            ? 'Operator requested stop (the earlier request was still pending; no worker owned this execution, so it is now cancelled)'
            : 'Operator requested stop (no live worker owned this execution; cancelled immediately)',
        );
      } else {
        run.logs.push('Operator requested stop');
      }
      await put(db, 'executions', id, run);
      await writeEvent(db, {
        category: 'PIPELINE',
        code: 'pipeline.stop_requested',
        message: 'Operator requested pipeline stop',
        runId: id,
        context: {
          actor,
          stopRequestedAt: run.stopRequestedAt,
        },
      });
      await appendAudit(db, 'Pipeline stop requested', `Execution ${id}`, actor, 'PIPELINE');
      return run;
    },
    // The client is never handed to `transaction()`: the abort path may release
    // it mid-transaction and that would desynchronise the pool (see the note
    // above). A fresh connection is taken instead, and the lock decision below
    // is what keeps it safe.
    undefined,
    // `workerLockClient` means the caller already holds the run lock, so this
    // write must not wait on it. Without one, the lock MUST be taken: an earlier
    // version declared it acquired with no client at all, so an operator stop
    // wrote the execution row with no mutual exclusion - measured completing in
    // 13ms while another session held `pipeline-queue` exclusively - which let a
    // stop interleave with a live run and have its CANCELLED overwritten.
    workerLockClient ? { locks: [], lockAcquired: ['pipeline-queue'] } : { locks: ['pipeline-queue'] },
  );
}
/** How often a running pipeline proves it is still alive. */
export const PIPELINE_HEARTBEAT_MS = 15_000;

/**
 * How many feeds are ingested concurrently.
 *
 * Feeds are I/O-bound (one HTTP request at a time, each paced by its own
 * provider rate limit), so this is a network-concurrency bound, not a CPU one:
 * raising it does not contend for the event loop. Each adapter keeps its own
 * per-provider pacing, so the limit here cannot exceed a provider's rate limit.
 *
 * Configurable because the right value depends on the feed mix: a deployment
 * with 40 fast RSS feeds and one slow API gains most from a wider pool, while a
 * small one gains nothing above its feed count.
 */
/**
 * Body of the pipeline heartbeat timer.
 *
 * Reports LIVENESS only (the scheduler heartbeat row), never PROGRESS. See the
 * contract below: a timer cannot distinguish a wedged statement from a slow but
 * healthy one, so letting it feed the stall watchdog made an endless run
 * invisible. Exported so the contract can be tested without a database.
 */
/*
 * Progress vs. liveness - the two must not be conflated.
 *
 * Two independent clocks run against a pipeline attempt:
 *
 *  - PROGRESS: the run advanced. Only `checkpoint()` can attest to this: it
 *    re-reads the execution row and throws when the run must stop. It fires at
 *    every request boundary and between feed pages.
 *
 *  - LIVENESS: the process is still able to run timers and reach the database.
 *    The heartbeat attests to this, and to nothing more.
 *
 * `main.ts` cancels an attempt that produces no PROGRESS for STUCK_PROMISE_MS,
 * whose default is deliberately several times the longest legitimate silent
 * stretch (one slow source request). The bug was that the heartbeat called the
 * progress callback on every beat. `main.ts` reset `pipelineStartedAt` from that
 * callback, so the stall clock was cleared by the heartbeat itself, forever: a
 * run whose promise never settled (an aborted feed that ignored its signal, a
 * query parked on a dead socket) never reached STUCK_PROMISE_MS, was never
 * cancelled, and was never detached by PIPELINE_ABORT_GRACE_MS. The pipeline
 * looked like it was still running, indefinitely.
 *
 * The heartbeat therefore no longer reports progress. `checkpoint()` remains the
 * only progress signal, and STUCK_PROMISE_MS (documented at 5 minutes, against a
 * 120 s worst-case request) is what keeps a slow-but-healthy run from being
 * cancelled.
 */
export function pipelineHeartbeat(options: { onBeat: () => void }): () => void {
  return () => {
    options.onBeat();
  };
}

export async function processPipeline(
  pool: pg.Pool,
  config: Config,
  request: Requester,
  signal?: AbortSignal,
  onProgress?: () => void,
): Promise<boolean> {
  signal?.throwIfAborted();
  // The session advisory lock needs its own connection for the whole run.
  // `pool.connect()` rejects after `connectionTimeoutMs` when every slot is
  // busy. Nothing is wrong with the run in that case — it simply never started —
  // so the failure is reported as a scheduling condition with the pool's state
  // instead of an opaque timeout, and the next tick retries. Without this the
  // watchdog saw a bare "timeout exceeded when trying to connect" and the
  // operator could not tell pool exhaustion from a broken database.
  let lock: pg.PoolClient;
  try {
    lock = await pool.connect();
  } catch (error) {
    const detail = {
      total: pool.totalCount,
      idle: pool.idleCount,
      waiting: pool.waitingCount,
      error: error instanceof Error ? error.message : String(error),
    };
    await writeEvent(pool, {
      category: 'PIPELINE',
      level: 'WARNING',
      code: 'pipeline.pool_exhausted',
      message: 'Pipeline could not acquire its advisory-lock connection; run deferred to the next tick',
      context: detail,
    }).catch(() => undefined);
    throw new PipelinePoolStarved(detail);
  }
  let connectionLost = false;
  const onError = () => {
    connectionLost = true;
  };
  lock.on('error', onError);
  // `lock` must never be used as a transaction client. It carries the session
  // advisory lock, and `onAbort` may already have destroyed it, so
  // `transaction()` must not release it when a unit finishes or aborts.
  //
  // Handing it over was a lifetime bug. An abort could queue a `release` on
  // `lock` while the in-flight unit was still running; the pool then handed
  // that same client out again and another caller began its `BEGIN` on it. The
  // first unit's `readyForQuery` was answered by the wrong state machine (the
  // desync documented on `transaction()` in db.ts), so it saw no error and
  // returned as if it had committed even though the abort had rolled it back.
  // Only the handed-over unit's later release discovered the error.
  //
  // Passing no client instead makes `transaction()` own a temporary one, which
  // it always releases in its `finally`, on abort and on throw as well. `lock`
  // therefore has exactly one owner for its whole life (`processPipeline`), and
  // no unit can hand it out while it is mid-transaction.
  const lockedTransaction = <T>(fn: (db: pg.PoolClient) => Promise<T>) =>
    transaction(pool, fn, undefined, { locks: ['pipeline-queue'], signal });

  let locked = false,
    execution: PipelineExecution | undefined;
  // Per-attempt snapshot handed from the commit transaction to the post-commit
  // delivery block. See PostCommitDeliverySlot.
  const postCommitDelivery: PostCommitDeliverySlot = {};
  // Alerts for faults found inside this run's commit. They are dispatched only
  // AFTER the transaction succeeds: an alert sent from inside a transaction that
  // then rolls back would report a failure that never happened.
  const pendingOperatorAlerts: { incident: string; subject: string; text: string }[] = [];
  let heartbeat: ReturnType<typeof setInterval> | undefined;
  let released = false;
  // CVEs streamed from ingestFeed via onBatch are accumulated here so the
  // pipeline retains full access to every record even after ingestFeed's
  // internal batch buffer is flushed. Accessible from ingestSources via closure
  // and from the commit phase below.
  const streamedCves: NormalizedCVE[] = [];
  const onAbort = () => {
    connectionLost = true;
    if (heartbeat) clearInterval(heartbeat);
    if (!released) {
      released = true;
      lock.release(true);
    }
  };
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    if (signal?.aborted) {
      onAbort();
      signal.throwIfAborted();
    }
    locked = await acquireSessionClassLock(lock, PIPELINE_RUN_LOCK_CLASS, schemaLockKey);
    if (!locked) return false;
    // Only RUNNING executions can be recovered; the bounded query replaces a
    // load of every historical run on each tick.
    const running = await pool.query<{ data: PipelineExecution }>(
      "SELECT data FROM records WHERE kind='executions' AND data->>'status'='RUNNING' ORDER BY updated_at DESC",
    );
    const runs = running.rows.map((row) => row.data);
    // Owning the advisory lock proves no other live worker owns a run. Recovery
    // is safe because records, advisories and outbox are committed atomically.
    await lockedTransaction(async (db) => {
      for (const scanned of runs.filter((e) => e.status === 'RUNNING')) {
        const stale = await getForUpdate<PipelineExecution>(db, 'executions', scanned.id);
        if (!stale || stale.status !== 'RUNNING') continue;
        if (stale.stopRequestedAt) {
          await put(db, 'executions', stale.id, {
            ...stale,
            status: 'CANCELLED',
            endTime: new Date().toISOString(),
            phases: stale.phases.map((phase) =>
              ['RUNNING', 'PENDING'].includes(phase.status) ? { ...phase, status: 'CANCELLED' } : phase,
            ),
            logs: [...stale.logs, 'Recovered interrupted worker with an outstanding stop request; cancelled'],
          });
          await writeEvent(db, {
            category: 'PIPELINE',
            code: 'pipeline.cancelled',
            message: 'Recovered pipeline stop request',
            runId: stale.id,
          });
          continue;
        }
        const recoveryCount = countRecoveries(stale) + 1;
        if (recoveryCount > 3) {
          await put(db, 'executions', stale.id, {
            ...stale,
            status: 'FAILED',
            endTime: new Date().toISOString(),
            logs: [
              ...stale.logs,
              `Worker exceeded maximum recovery attempts (${recoveryCount - 1}); marked FAILED to prevent poison-pill crash loop`,
            ],
            phases: stale.phases.map((phase) =>
              phase.status === 'RUNNING' || phase.status === 'PENDING'
                ? { ...phase, status: 'FAILED' }
                : phase,
            ),
          });
          await writeEvent(db, {
            category: 'ISSUE',
            level: 'ERROR',
            code: 'pipeline.recovery_limit_exceeded',
            message: 'Pipeline execution repeatedly failed; marked FAILED',
            runId: stale.id,
          });
          await appendAudit(
            db,
            'Pipeline recovery limit exceeded',
            `Execution ${stale.id} marked FAILED after ${recoveryCount - 1} crashes`,
            'worker',
            'PIPELINE',
            'ERROR',
          );
        } else {
          await put(db, 'executions', stale.id, {
            ...stale,
            status: 'QUEUED',
            stats: { ...stale.stats, recoveryAttempts: recoveryCount },
            logs: [
              ...stale.logs,
              `Recovered interrupted worker (attempt ${recoveryCount}/3); restarting idempotently`,
            ],
          });
          await writeEvent(db, {
            category: 'PIPELINE',
            code: 'pipeline.recovered',
            message: 'Recovered interrupted worker',
            runId: stale.id,
          });
          await appendAudit(
            db,
            'Pipeline recovered',
            `Execution ${stale.id} recovered (attempt ${recoveryCount}/3)`,
            'worker',
            'PIPELINE',
          );
        }
      }
    });
    // Same bounded query as queueRun: only active executions matter. Loading
    // the whole executions table on every worker tick was both an unbounded
    // read and a statement-timeout risk.
    const queued = await pool.query<{ data: PipelineExecution }>(
      "SELECT data FROM records WHERE kind='executions' AND data->>'status'='QUEUED' ORDER BY updated_at DESC LIMIT 1",
    );
    execution = queued.rows[0]?.data;
    if (!execution) {
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      const last = (await pool.query('SELECT last_run FROM scheduler_state WHERE id=1')).rows[0];
      const schedulerNow = Date.now();
      const catchUpDue =
        settings.schedulerEnabled &&
        (await pool.query<{ data: FeedCursor }>(
          `SELECT data FROM records WHERE kind='feedCursors'
           AND (data->>'hasMore')::boolean = true
           AND (data->>'next_catchup_at' IS NULL OR (data->>'next_catchup_at')::timestamptz <= now())
           LIMIT 1`,
        )).rows.length > 0;
      const recoveryProbeDue =
        !settings.schedulerEnabled &&
        (await list<ThreatFeed>(pool, 'feeds', 500)).some((feed) => recoveryDue(feed, schedulerNow));
      if (
        shouldStartAutomaticRun(
          {
            schedulerEnabled: settings.schedulerEnabled,
            recoveryProbeDue,
            catchUpDue,
            lastRun: last?.last_run ? new Date(last.last_run).toISOString() : null,
            intervalMinutes: settings.schedulerIntervalMinutes,
          },
          schedulerNow,
        )
      )
        // `queueRun` must own a fresh connection: `lock` carries the run's
        // session advisory lock and must never be used as a transaction client
        // (an abort can destroy it mid-transaction). The `pipeline-queue` lock
        // `queueRun` acquires is a different namespace from the run lock, so
        // this cannot deadlock with the run already in progress.
        execution = await queueRun(pool, settings.scopeHours, 'scheduler');
    }
    await pool.query('UPDATE scheduler_state SET heartbeat=now() WHERE id=1');
    if (!execution) return false;
    if (execution.stats?.recoveryBackoffUntil && execution.stats.recoveryBackoffUntil > Date.now()) {
      // Lock-loss recovery backoff not yet expired. Leave it QUEUED; the next
      // scheduler tick will retry once the cooldown has elapsed.
      return false;
    }
    const checkpoint = async (db: pg.Pool | pg.PoolClient = pool) => {
      signal?.throwIfAborted();
      const current = await get<PipelineExecution>(db, 'executions', execution!.id);
      // A successful database read confirms the lock connection is alive again:
      // clear the flag so a transient error does not poison the entire run.
      connectionLost = false;
      if (!current) throw new Error('Pipeline execution no longer exists');
      if (current?.stopRequestedAt || current?.status === 'CANCELLED') throw new PipelineStopped();
      signal?.throwIfAborted();
      onProgress?.();
    };
    await checkpoint();
    execution.status = 'RUNNING';
    execution.phases = [
      'Feed ingestion',
      'Normalize & deduplicate',
      'Product matching',
      'Delivery queue',
    ].map((name, index) => ({
      name,
      status: index === 0 ? 'RUNNING' : 'PENDING',
      durationMs: 0,
      details: index === 0 ? 'Retrieving and enriching enabled sources' : 'Waiting for dependencies',
    }));
    execution.startTime = new Date().toISOString();
    let heartbeatPending = false;
    heartbeat = setInterval(
      pipelineHeartbeat({
        onBeat: () => {
          if (heartbeatPending) return;
          heartbeatPending = true;
          void pool
            .query('UPDATE scheduler_state SET heartbeat=now() WHERE id=1')
            .catch(() => console.error(JSON.stringify({ level: 'error', event: 'pipeline-heartbeat' })))
            .finally(() => {
              heartbeatPending = false;
            });
        },
      }),
      PIPELINE_HEARTBEAT_MS,
    );
    heartbeat.unref();
    await lockedTransaction(async (db) => {
      await checkpoint(db);
      await saveActiveExecution(db, execution!);
      await db.query('UPDATE scheduler_state SET last_run=now() WHERE id=1');
      await writeEvent(db, {
        category: 'PIPELINE',
        code: 'pipeline.started',
        message: 'Pipeline started',
        runId: execution!.id,
      });
    });
    const allFeeds = await list<ThreatFeed>(pool, 'feeds');
    // Feed adapter types that `ingestFeed` can actually handle. Anything else
    // (retired types such as MITRE_CVE / OPENCVE_API) is skipped instead of
    // failing every run with "Unsupported feed adapter".
    const SUPPORTED_FEED_ADAPTERS = new Set([
      'NVD_API',
      'MITRE_CVE',
      'OPENCVE_API',
      'VULNCHECK_NVD',
      'VULNCHECK_KEV',
      'RSS_ATOM',
      'OTX_API',
      'OSV_API',
      'GITHUB_ADVISORIES',
      'CISA_KEV',
      'EPSS_API',
      'JSON_SEARCH_API',
    ]);
    // VULNCHECK_NVD respects its enabled flag like all other feeds.
    // Operators configure a Bearer token and enable it via the Feeds UI;
    // without credentials the feed is auto-disabled by bootstrap.
    const feeds = allFeeds.filter((feed) => feed.enabled && SUPPORTED_FEED_ADAPTERS.has(feed.type));
    for (const skipped of allFeeds.filter((f) => f.enabled && !SUPPORTED_FEED_ADAPTERS.has(f.type))) {
      pushExecutionLog(
        execution!,
        `Feed ${skipped.id}: skipped — unsupported feed adapter (${skipped.type})`,
      );
    }
    const feedTypesById = new Map(allFeeds.map((feed) => [feed.id, feed.type]));
    const [cachedCves, cachedWithdrawals, inventory, aliasEntries] = await Promise.all([
      list<NormalizedCVE>(pool, 'cveData'),
      list<{ cveId: string; modifiedDate: string }>(pool, 'cveWithdrawals'),
      list<WatchListItem>(pool, 'watchlist'),
      list<AliasEntry>(pool, 'aliases'),
    ]);
    // Operator-managed additions to the built-in alias thesaurus (see cpeMatcher.ts
    // DEFAULT_VENDOR_ALIASES/DEFAULT_PRODUCT_ALIASES) plus the automatic rows
    // that were derived on previous runs. Inventory-derived aliases are merged
    // immediately so a newly added/renamed asset benefits from the current run;
    // the full add/remove reconciliation happens once correlation evidence for
    // this run is known.
    const inventoryAliases = deriveInventoryAliases(inventory, aliasEntries);
    const startedAliasEntries: AliasEntry[] = [...aliasEntries, ...inventoryAliases];
    const vendorAliases = buildAliasMap(startedAliasEntries, 'VENDOR');
    const productAliases = buildAliasMap(startedAliasEntries, 'PRODUCT');
    const canonicalCache = mergeCveRecords(cachedCves);
    const knownCveModifiedAt = new Map([...canonicalCache].map(([id, cve]) => [id, cve.modifiedDate]));
    const knownWithdrawalAt = new Map(cachedWithdrawals.map((entry) => [entry.cveId, entry.modifiedDate]));
    let succeeded = 0,
      rawCount = 0;
    /** Rejections from feeds whose run failed before returning a result. */
    const rejectedThisRun: CVERejection[] = [];
    const results: Awaited<ReturnType<typeof ingestFeed>>[] = [];
    const feedUpdates: ThreatFeed[] = [];
    // Bound cross-feed concurrency; each adapter also paces its own pages.
    const ingestSources = async (sources: ThreatFeed[], targets: string[] = []) => {
      // Longest-processing-time-first.
      //
      // The pool used to take feeds in database order. With 41 feeds where one
      // (VulnCheck NVD++, 48-114s per request) costs more than all the RSS feeds
      // combined (~80s total), the run's wall time was that one feed plus
      // whatever happened to start alongside it. Starting the expensive sources
      // first overlaps them with everything else instead of ending the run on a
      // single long tail. `latencyMs` is the provider's own reported latency
      // from the previous run, so the order is learned rather than hard-coded.
      const ordered = [...sources].sort((left, right) => (right.latencyMs ?? 0) - (left.latencyMs ?? 0));
      // The leadership and run-lock sessions are pinned for the whole run. Keep
      // at least one additional pool slot for progress/commit transactions and
      // another for unrelated worker/API work; otherwise high feed concurrency
      // can starve the very checkpoints needed to stop feeds cleanly.
      const poolBound = Math.max(1, config.POOL_MAX_CONNECTIONS - 4);
      const concurrency = Math.min(ordered.length, config.FEED_CONCURRENCY, poolBound);
      let nextIndex = 0;
      const worker = async () => {
        while (nextIndex < ordered.length) {
          const i = nextIndex++;
          const feed = ordered[i];
          // Audit R-1: this checkpoint is the only stop signal in the loop, and
          // the circuit-open branch below used to `continue` straight past it on
          // the next iteration. Every iteration now re-checks the operator's
          // stop request before the skip is evaluated.
          await checkpoint();
          if (feed.circuitOpenUntil && Date.parse(feed.circuitOpenUntil) > Date.now()) {
            pushExecutionLog(
              execution!,
              `Feed ${feed.id}: skipped (circuit open, ${feed.consecutiveFailures} consecutive failures)`,
            );
            continue;
          }
          const start = Date.now();
          // MITRE can return up to 5,000 delta records; at its documented feed
          // pacing that bootstrap needs over 40 minutes for detail retrieval.
          // Give that source enough time to finish atomically while preserving
          // the configured limit for all other feeds.
          const maxDurationSeconds = config.FEED_MAX_DURATION_SECONDS;
          const deadline = start + maxDurationSeconds * 1000;
          const configuredFeedHosts = config.EGRESS_ALLOWED_HOSTS.split(',')
            .map((host) => host.trim())
            .filter(Boolean);
          const additionalAllowedHosts = feedEgressHosts(feed.type, feed.url, configuredFeedHosts).filter(
            (host) => !configuredFeedHosts.includes(host),
          );
          const sourceCheckpoint = async () => {
            await checkpoint();
            if (Date.now() >= deadline) throw new FeedDeadlineExceeded();
          };
          try {
            const checkedRequest: Requester = async (url, options) => {
              await sourceCheckpoint();
              const remaining = Math.max(1, deadline - Date.now());
              const requestSignal =
                signal && options?.signal
                  ? AbortSignal.any([signal, options.signal])
                  : (signal ?? options?.signal);
              const response = await withAbortSignal(
                request(url, {
                  ...options,
                  additionalAllowedHosts,
                  // Publishers routinely move between the apex and www spelling;
                  // follow that hop when the target still passes the SSRF check.
                  sameSiteRedirects: true,
                  signal: requestSignal,
                  timeoutMs: Math.min(options?.timeoutMs ?? 20000, remaining),
                  socketTimeoutMs: Math.min(options?.socketTimeoutMs ?? 15000, remaining),
                }),
                requestSignal,
              );
              await sourceCheckpoint();
              return response;
            };
            const checkedSleep = async (ms: number, sleepSignal?: AbortSignal) => {
              const until = Date.now() + ms;
              while (Date.now() < until) {
                // `sourceCheckpoint` awaits a database read and a clock check, so
                // the remaining time can cross zero between the loop test and the
                // timer. A negative delay is clamped by Node only after warning,
                // which flooded the worker log with TimeoutNegativeWarning.
                const delay = until - Date.now();
                await sourceCheckpoint();
                if (delay <= 0) return;
                const activeSignal = sleepSignal ?? signal;
                if (activeSignal?.aborted) activeSignal.throwIfAborted();
                await new Promise<void>((resolve, reject) => {
                  let timer: ReturnType<typeof setTimeout> | undefined;
                  const onAbort = () => {
                    if (timer) clearTimeout(timer);
                    activeSignal?.removeEventListener('abort', onAbort);
                    reject(activeSignal?.reason ?? new Error('Operation aborted'));
                  };
                  timer = setTimeout(
                    () => {
                      activeSignal?.removeEventListener('abort', onAbort);
                      resolve();
                    },
                    Math.min(500, delay),
                  );
                  activeSignal?.addEventListener('abort', onAbort, { once: true });
                  if (activeSignal?.aborted) onAbort();
                });
              }
            };
            const savedCursor = await get<FeedCursor>(pool, 'feedCursors', feed.id);
            const cursor = savedCursor?.fingerprint === sourceFingerprint(feed) ? savedCursor : undefined;
            if (feed.type === 'VULNCHECK_KEV') {
              const maxWindow = 24;
              const window = ingestionWindow(execution!.scopeHours, cursor, undefined, maxWindow);
              execution!.logs.push(
                `Feed ${feed.id}: ${window.incremental ? 'incremental' : 'initial bounded'} sync ${window.start.toISOString()} to ${window.end.toISOString()}`,
              );
            }
            const savedKev =
              feed.type === 'CISA_KEV' ? await get<KevSnapshot>(pool, 'feedSnapshots', feed.id) : undefined;
            const cachedKev = savedKev?.fingerprint === sourceFingerprint(feed) ? savedKev : undefined;
            const context: IngestContext = {
              signal,
              ...(execution!.incrementalFeeds !== false && cursor ? cursor : {}),
              knownCveModifiedAt,
              knownWithdrawalAt,
              knownCveContent: canonicalCache,
              // Prior rejection counts let the adapter decide when an unparseable
              // record has been retried enough to quarantine. Without this the
              // window could never advance past a permanently broken record.
              rejectedOccurrences: await rejectionOccurrences(pool, feed.id),
              ...(feed.type === 'OSV_API'
                ? {
                    targetPurls: inventory.filter((item) => item.active).flatMap((item) => item.purls || []),
                  }
                : {}),
            };
            // A validator is usable only together with its complete source snapshot.
            let result = await ingestFeed(
              feed.type === 'CISA_KEV' ? { ...feed, etag: cachedKev?.etag } : feed,
              execution!.scopeHours,
              checkedRequest,
              config,
              checkedSleep,
              targets,
              undefined,
              context,
              // Stream CVEs to the pipeline-side accumulator as they are
              // normalized, keeping ingestFeed's in-memory buffer bounded even
              // for very large windows.
              async (batch) => {
                streamedCves.push(...batch);
              },
              500,
            );
            if (feed.type === 'CISA_KEV' && result.notModified) {
              if (!cachedKev) throw new Error('KEV conditional response has no source snapshot');
              result = { ...result, kev: cachedKev.kev };
            }
            results.push({ ...result, sourceId: feed.id });
            rawCount += result.notModified ? 0 : result.count;
            succeeded++;
            if (feed.type === 'EPSS_API' && targets.length === 0) {
              execution!.logs.push(`Feed ${feed.id}: no applicable CVEs; EPSS network retrieval skipped`);
              // No request was needed: clear expired recovery state without claiming
              // a successful connectivity check or changing lastSync.
              feedUpdates.push({
                ...feed,
                healthStatus: 'UNTESTED',
                errorLog: null,
                consecutiveFailures: 0,
                circuitOpenUntil: null,
              });
              continue;
            }
            feedUpdates.push({
              ...feed,
              healthStatus: result.warnings?.length ? 'DEGRADED' : 'HEALTHY',
              lastSync: new Date().toISOString(),
              latencyMs: Date.now() - start,
              itemCountLastRun: result.notModified ? feed.itemCountLastRun : result.count,
              errorLog: result.warnings?.join('; ') || null,
              ssrfValidated: true,
              // An NVD++ run that stopped at the page budget returns only part of
              // its window. Persisting the ETag it saw would make the next
              // (resumed or re-issued) window send If-None-Match, get a 304 for
              // the same state and end the run without reading the rest. Keep the
              // previously stored validator until the window completes; the
              // adapter then reports the window's own ETag.
              etag: result.syncState?.pageCursor ? feed.etag : result.etag,
              consecutiveFailures: 0,
              circuitOpenUntil: null,
              // A successful run proves the recovery probe worked. Leaving the
              // old probe timestamp behind let `recoveryDue` keep refusing the
              // next probe for up to its 30-40s minimum interval after a fresh
              // failure, during which the scheduler could decide no run was due
              // and leave the source unprobed. The write below reads
              // `lastRecoveryAttemptAt` forward from this update.
              lastRecoveryAttemptAt: null,
            });
            // Feed completeness verification: if the source reports items but
            // none of them actually survived into this feed's own result
            // (cves + articles), the feed may be silently dropping records.
            // Flag it for operator review.
            //
            // Bug fix: this used to search `results` for a *second* entry with
            // the same `sourceId` and a zero count. `ingestSources` runs each
            // feed id at most once per invocation (and the primary/EPSS
            // invocations touch disjoint feed sets), and the only entry ever
            // pushed for this feed id is the one added immediately above with
            // this exact `result.count` — which the surrounding guard already
            // requires to be greater than zero. No second, zero-count entry
            // for the same id can ever exist, so the check could never fire.
            // The actual signal is a mismatch between what the provider
            // reported and what this feed itself produced.
            const producedCount =
              result.cves.length +
              (result.articles?.length ?? 0) +
              (result.kev ? Object.keys(result.kev).length : 0) +
              (result.exploited ? Object.keys(result.exploited).length : 0) +
              (result.epss ? Object.keys(result.epss).length : 0);
            if (result.count > 0 && !result.notModified && producedCount === 0) {
              pushExecutionLog(
                execution!,
                `Feed ${feed.id}: returned ${result.count} items but zero CVEs entered the pipeline — possible ingestion filter issue`,
              );
              await writeEvent(pool, {
                category: 'FEED',
                level: 'WARNING',
                code: 'feed.completeness_gap',
                message: `${feed.name}: returned ${result.count} items but zero CVEs entered the pipeline`,
                runId: execution!.id,
                context: { feedId: feed.id, returnedCount: result.count, pipelineCount: 0 },
              });
            }
          } catch (e) {
            signal?.throwIfAborted();
            if (e instanceof PipelineStopped || connectionLost) throw e;
            const message = e instanceof Error ? e.message : 'Ingestion failed';
            // A record-level rejection is a data defect recovery can fix: keep
            // the rejections it carried so the loss is recorded even though the
            // feed run itself failed, and never let the breaker classify it as a
            // configuration fault (that would mark the source permanently DOWN
            // for one bad record). The feed is DEGRADED, the checkpoint stays
            // before the bad record, and the next run retries the window.
            const carriedRejections = (e as { rejections?: CVERejection[] }).rejections;
            if (carriedRejections?.length) {
              rejectedThisRun.push(...carriedRejections);
              feedUpdates.push({
                ...feed,
                healthStatus: 'DEGRADED',
                latencyMs: Date.now() - start,
                errorLog: message,
                // One bad record is not evidence the source is unreachable: it
                // must not consume the failure budget that opens the breaker.
                consecutiveFailures: feed.consecutiveFailures || 0,
                circuitOpenUntil: feed.circuitOpenUntil ?? null,
              });
              pushExecutionLog(execution!, `Feed ${feed.id}: ${message} (record rejection; window deferred)`);
              continue;
            }
            // Audit H-5: a configuration fault (SSRF-rejected destination,
            // malformed or unsupported URL, unusable checkpoint) cannot be fixed
            // by retrying. Record it as DOWN with no circuit and no failure
            // budget so it stays visible as an operator action item instead of
            // cycling the breaker and suppressing catch-up for that source.
            if (isPermanentFeedFailure(e)) {
              feedUpdates.push({
                ...feed,
                healthStatus: 'DOWN',
                latencyMs: Date.now() - start,
                errorLog: `Configuration error (not retryable): ${message}`,
                consecutiveFailures: feed.consecutiveFailures || 0,
                circuitOpenUntil: null,
              });
              pushExecutionLog(
                execution!,
                `Feed ${feed.id}: configuration error, retry disabled — ${message}`,
              );
              await writeEvent(pool, {
                category: 'FEED',
                level: 'ERROR',
                code: 'feed.configuration_invalid',
                message: `${feed.name}: configuration error (not retryable)`,
                runId: execution!.id,
                context: { feedId: feed.id, error: message },
              }).catch((err) => console.error(JSON.stringify({ level: 'error', event: 'feed.configuration_event', error: describeError(err) })));
            } else if (e instanceof FeedDeadlineExceeded) {
              // Audit R-2: a duration overrun is a capacity signal for this run,
              // not proof the source is unreachable. Recording it as a failure
              // opened the breaker after three long-but-successful bootstraps and
              // suppressed the catch-up the source still owed.
              feedUpdates.push({
                ...feed,
                healthStatus: 'DEGRADED',
                latencyMs: Date.now() - start,
                errorLog: message,
                consecutiveFailures: feed.consecutiveFailures || 0,
                circuitOpenUntil: feed.circuitOpenUntil ?? null,
              });
              pushExecutionLog(execution!, `Feed ${feed.id}: ${message} (not counted as a failure)`);
            } else if (e instanceof FeedDeferred) {
              // Audit R-3: the provider asked us to wait (Retry-After). Deferring
              // to the next run is correct behavior, not evidence the source is
              // unreachable. Record as DEGRADED with no circuit breaker opened
              // and no failure budget consumed, so catch-up still runs on schedule.
              feedUpdates.push({
                ...feed,
                healthStatus: 'DEGRADED',
                latencyMs: Date.now() - start,
                errorLog: message,
                consecutiveFailures: feed.consecutiveFailures || 0,
                circuitOpenUntil: feed.circuitOpenUntil ?? null,
              });
              pushExecutionLog(execution!, `Feed ${feed.id}: ${message} (not counted as a failure)`);
            } else {
              const consecutiveFailures = (feed.consecutiveFailures || 0) + 1;
              feedUpdates.push({
                ...feed,
                healthStatus: 'DOWN',
                latencyMs: Date.now() - start,
                errorLog: message,
                consecutiveFailures,
                circuitOpenUntil: recoveryAt(
                  feed,
                  consecutiveFailures,
                  Date.now(),
                  computeFeedRecoveryDelay(consecutiveFailures),
                ),
                lastRecoveryAttemptAt: new Date().toISOString(),
              });
              pushExecutionLog(execution!, `Feed ${feed.id}: ${message}`);
            }
          }
          await transaction(
            pool,
            async (db) => {
              // A dead lock connection means the write cannot land; the checkpoint
              // throws at once (fails the feed) instead of waiting out the
              // statement timeout on a backend that is already gone.
              await checkpoint(db);
              // Audit L-3: `rawCount`/`results`/`feedUpdates` are mutated by every
              // concurrent worker, so the intermediate progress line raced and
              // could report a count that went backwards. Publish from the
              // execution object's own monotonic counter, and only ever raise it.
              const seen = Number(execution!.stats.rawIngested) || 0;
              execution!.phases[0].durationMs = Date.now() - Date.parse(execution!.startTime);
              execution!.phases[0].details = `${feeds.length} sources processed; ${Math.max(seen, rawCount)} records read`;
              execution!.stats.rawIngested = Math.max(seen, rawCount);
              await saveActiveExecution(db, execution!);
            },
            undefined,
            { locks: ['pipeline-queue'], signal },
          );
        }
      };
      const workers = await Promise.allSettled(Array.from({ length: concurrency }, worker));
      const failure = workers.find((result) => result.status === 'rejected');
      if (failure?.status === 'rejected') throw failure.reason;
    };
    const primaryIngestionStartedAt = Date.now();
    await ingestSources(feeds.filter((feed) => feed.type !== 'EPSS_API'));
    const primaryIngestionDuration = Date.now() - primaryIngestionStartedAt;
    const preliminaryCorpus = mergeCveRecords([
      ...cachedCves,
      ...results.flatMap((result) => result.cves),
      ...streamedCves,
    ]);
    const preliminaryCves = [...preliminaryCorpus.values()];
    // Push structured identity + typed version-range filtering into PostgreSQL.
    // The JS matcher still decides every candidate; this only avoids the full
    // corpus x inventory cross product.
    const preliminaryPairs = await transaction(
      pool,
      (db) =>
        refreshCandidatePairs(db, preliminaryCves, inventory, {
          vendorAliases,
          productAliases,
        }),
      undefined,
      {
        locks: ['match-index'],
        statementTimeoutMs: 60000,
        // Fail fast on a colliding writer instead of parking on a pooled
        // connection (and the match-index lock) for the whole extended statement
        // budget. `refreshCandidatePairs` already retries a transient 55P03.
        lockTimeoutMs: MATCH_INDEX_LOCK_TIMEOUT_MS,
      },
    );
    // Audit M-2/M-3: the preliminary pass used to run the *entire* matcher over
    // the whole corpus solely to decide which CVEs need EPSS scores. That is the
    // most expensive call in the system, and the result was almost always
    // discarded because `preliminarySourceIds` includes every source that
    // returned records (i.e. every normal incremental run), making the reuse
    // check vacuous.
    //
    // EPSS changes risk, not applicability, so a CVE that names no inventory
    // identity never needs a score. Deriving the target list from the candidate
    // index is cheap and errs wide: any CVE the index could not narrow (wildcard
    // or unstructured criteria) is fetched in full, exactly as before.
    const epssTargets = new Set<string>();
    for (const [cveId, assets] of preliminaryPairs) if (assets.size) epssTargets.add(cveId);
    // Conservative widening: a CVE the index dropped entirely (wildcard/aliases)
    // or one whose assets the index could not version-bound is still a plausible
    // correlation, so it must not lose its risk score.
    for (const cve of preliminaryCves) {
      const canonical = normalizeCveId(cve.cveId);
      if (!canonical) continue;
      const unbounded =
        !cve.cpeMatchDetails?.length &&
        (!cve.cpeMatches.length ||
          cve.cpeMatches.some((criteria) => {
            const parsed = parseCPE23(criteria);
            return !parsed.isValid || /[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product);
          }));
      if (unbounded) epssTargets.add(canonical);
    }
    const epssFeeds = feeds.filter((feed) => feed.type === 'EPSS_API');
    const epssIngestionStartedAt = Date.now();
    if (epssFeeds.length) {
      // EPSS changes risk, not product applicability. Query only CVEs that can
      // currently affect inventory, including uncertain matches awaiting review.
      await ingestSources(epssFeeds, [...epssTargets].sort());
    }
    const epssIngestionDuration = Date.now() - epssIngestionStartedAt;
    results.sort((a, b) => (a.sourceId || '').localeCompare(b.sourceId || ''));
    const ingestionDuration = primaryIngestionDuration + epssIngestionDuration;
    execution.phases[0] = {
      name: 'Feed ingestion',
      status:
        succeeded < feeds.length || results.some((result) => result.warnings?.length) ? 'WARNING' : 'SUCCESS',
      durationMs: ingestionDuration,
      details: `${succeeded}/${feeds.length} feeds succeeded; ${rawCount} records read`,
    };
    execution.phases[1].status = 'RUNNING';
    execution.phases[1].details = 'Canonicalizing records and resolving source revisions';
    execution.phases[2].details = 'Waiting for normalized CVEs';
    // Phase transitions are operational events, not just phase-object updates.
    // The execution row is only read by whoever opens the run detail; a stuck
    // run between `pipeline.started` and `pipeline.finished` used to leave NO
    // trace in the operational log, so an operator could not tell whether it was
    // still ingesting or wedged. Each boundary now emits one event carrying the
    // phase name and the elapsed time of the phase that just ended.
    await writeEvent(pool, {
      category: 'PIPELINE',
      code: 'pipeline.phase_completed',
      message: `Phase completed: Feed ingestion`,
      runId: execution!.id,
      context: {
        phase: 'Feed ingestion',
        status: execution.phases[0].status,
        durationMs: ingestionDuration,
        feedsSucceeded: succeeded,
        feedsTotal: feeds.length,
        recordsRead: rawCount,
        next: execution.phases[1].name,
      },
    }).catch(() => undefined);
    await lockedTransaction(async (db) => {
      await checkpoint(db);
      await saveActiveExecution(db, execution!);
    });
    await lockedTransaction(async (db) => {
      await checkpoint(db);
      const currentFeeds = new Map((await list<ThreatFeed>(db, 'feeds')).map((feed) => [feed.id, feed]));
      const validSources = new Set(
        feeds
          .filter((feed) => {
            const current = currentFeeds.get(feed.id);
            return (
              current?.enabled &&
              current.url === feed.url &&
              current.type === feed.type &&
              current.authType === feed.authType &&
              (current.authSecretKey || '') === (feed.authSecretKey || '')
            );
          })
          .map((feed) => feed.id),
      );
      const acceptedResults = results.filter((result) => validSources.has(result.sourceId!));
      succeeded = acceptedResults.length;
      rawCount = acceptedResults.reduce((sum, result) => sum + (result.notModified ? 0 : result.count), 0);
      for (const feed of feeds)
        if (!validSources.has(feed.id))
          execution!.logs.push(
            `Feed ${feed.id}: configuration changed during ingestion; obsolete response ignored`,
          );
      for (const feed of feedUpdates) {
        const current = currentFeeds.get(feed.id);
        // A feed the operator disabled while ingestion was running, or whose
        // source changed (URL/type/auth), is no longer ours to describe: writing
        // the run's health/etag back would resurrect a stale `enabled=true` or
        // overwrite the newly configured source's state, and its ETag belongs to
        // a response the operator has since redirected elsewhere. Such a feed is
        // absent from `validSources` and is skipped here unconditionally.
        //
        // The recovery case is different and is why this is not simply a
        // `validSources` check: a feed that is still configured identically but
        // was DOWN with an open circuit is NOT in `validSources` either (a
        // successful probe clears the circuit), and discarding its cleared
        // failure state would strand a genuinely recovered feed as DOWN. For
        // that case only, a HEALTHY result is carried forward onto the current
        // row — but never its ETag, because the ETag describes the response of a
        // probe that this run's source configuration no longer governs.
        const configurationUnchanged = validSources.has(feed.id);
        const healthy = feed.healthStatus === 'HEALTHY';
        if (!current) continue;
        if (!configurationUnchanged && !healthy) continue;
        // A changed source keeps EVERYTHING the operator just configured, and only
        // has a stale open circuit cleared. A HEALTHY probe proves the endpoint it
        // was sent to is reachable, which is not a claim about the new one.
        const patch: ThreatFeed = configurationUnchanged
          ? {
              ...current,
              healthStatus: feed.healthStatus,
              lastSync: feed.lastSync,
              latencyMs: feed.latencyMs,
              itemCountLastRun: feed.itemCountLastRun,
              errorLog: feed.errorLog,
              ssrfValidated: feed.ssrfValidated,
              etag: feed.etag,
              consecutiveFailures: feed.consecutiveFailures,
              circuitOpenUntil: feed.circuitOpenUntil,
              // The explicit carry-forward keeps a future refactor from resetting
              // the recovery clock. A healthy probe clears it: it records the last
              // *failed* recovery attempt, and `recoveryDue` refuses a new probe for
              // its minimum interval whenever it is set, so keeping it after a
              // recovery delayed the next one.
              lastRecoveryAttemptAt: healthy
                ? null
                : (feed.lastRecoveryAttemptAt ?? current.lastRecoveryAttemptAt ?? null),
              enabled: current.enabled,
            }
          : {
              // Source changed mid-run: keep the operator's configuration and
              // state verbatim, and only clear the failure budget the obsolete
              // probe would otherwise have consumed.
              ...current,
              consecutiveFailures: 0,
              circuitOpenUntil: null,
              lastRecoveryAttemptAt: null,
              enabled: current.enabled,
            };
        await put(db, 'feeds', feed.id, patch);
      }
      if (feeds.length && !succeeded) {
        await appendAudit(
          db,
          'Pipeline warning',
          'All enabled feeds failed; running correlation against cache',
          'worker',
          'PIPELINE',
          'WARNING',
        );
        execution!.logs.push('All feeds failed; proceeding with cached CVE correlation');
      }
      const catchupSettings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
      for (const result of acceptedResults) {
        if (result.syncState?.hasMore) {
          // Remaining daily windows obey the configured automatic run frequency.
          result.syncState = {
            ...result.syncState,
            catch_up: true,
            next_catchup_at: new Date(
              Date.now() + catchupSettings.schedulerIntervalMinutes * 60000,
            ).toISOString(),
          };
        }
        if (result.syncState) {
          const source = currentFeeds.get(result.sourceId!)!;
          // Clear catch_up flag when hasMore is false (catch-up complete).
          const cursorState = result.syncState.hasMore
            ? result.syncState
            : { ...result.syncState, catch_up: false, next_catchup_at: undefined };
          // Dead worker: the data connection is gone, so this write cannot land.
          // Let the checkpoint throw instead of waiting out statement_timeout.
          if (connectionLost) throw new Error('Pipeline worker lost its database lock connection');
          await put(db, 'feedCursors', source.id, {
            ...cursorState,
            fingerprint: sourceFingerprint(source),
          } satisfies FeedCursor);
        }
        if (result.kev && !result.notModified) {
          const source = currentFeeds.get(result.sourceId!)!;
          await put(db, 'feedSnapshots', source.id, {
            fingerprint: sourceFingerprint(source),
            etag: result.etag,
            kev: result.kev,
          } satisfies KevSnapshot);
        }
      }
      for (const update of feedUpdates.filter((feed) => validSources.has(feed.id)))
        await writeEvent(db, {
          category: 'FEED',
          level:
            update.healthStatus === 'DOWN'
              ? 'ERROR'
              : update.healthStatus === 'DEGRADED'
                ? 'WARNING'
                : 'INFO',
          code: 'feed.ingestion',
          message: `${update.name}: ${update.healthStatus}`,
          runId: execution!.id,
          context: {
            feedId: update.id,
            feedType: update.type,
            provider: update.name,
            healthStatus: update.healthStatus,
            consecutiveFailures: update.consecutiveFailures || 0,
            count: update.itemCountLastRun,
            latencyMs: update.latencyMs,
          },
        });
      // Persist every record a feed delivered that failed normalization. Before
      // this, adapters collected `rejections` into an array the pipeline then
      // discarded: a schema change or poisoned record silently removed findings
      // from the corpus. This is a durability requirement, not telemetry, so it
      // runs before the corpus write and raises an ERROR event on any nonzero
      // count. Rejections from a feed whose configuration changed mid-run are
      // excluded for the same reason its results are: they describe a source
      // that is no longer configured. `rejectedThisRun` is filtered by feed id
      // below so an obsolete response cannot populate the live backlog.
      const rejectedRecords = [
        ...acceptedResults.flatMap((result) => result.rejections ?? []),
        ...rejectedThisRun.filter((rejection) => validSources.has(rejection.feedId)),
      ];
      // Commit a durable native-correlation handoff with the source checkpoint.
      // Existing inventory remains authoritative; no record-store assets are copied.
      for (const result of acceptedResults)
        for (const article of result.articles || [])
          await db.query(
            `INSERT INTO correlation_pending(id,payload) VALUES($1,$2)
          ON CONFLICT(id) DO NOTHING`,
            [
              article.id,
              JSON.stringify({
                title: article.title,
                content: article.summary,
                url: article.url,
              }),
            ],
          );
      // Re-read the durable CVE corpus at commit. Operator revisions made while
      // network ingestion was running must remain authoritative and stale feed
      // revisions must not overwrite them.
      //
      // Audit C-1: the previous version loaded the snapshot here but then diffed
      // `byId` against the SAME snapshot it had just merged into, so every record
      // that did not change during ingestion was absent from `changedCves` and
      // was never written. The in-run corpus is now diffed against the state
      // that was current when the run started, and a record current at commit
      // time is only replaced when the run's own revision is genuinely newer.
      const snapshot = await pipelineState(db);
      const commitState = new Map(
        snapshot.cveData.map((cve) => [normalizeCveId(cve.cveId) || cve.cveId, cve]),
      );
      const runStartedAt = Date.parse(execution!.startTime);
      // Re-read alias entries inside the commit transaction: operator alias
      // changes during ingestion (save/promote/revoke) must not be silently
      // overwritten by a stale snapshot loaded before network I/O.
      const aliasEntries = await list<AliasEntry>(db, 'aliases');
      const articles = mergeArticles([
        ...snapshot.intelligenceArticles,
        ...acceptedResults.flatMap((result) => result.articles || []),
      ]);
      await putMany(
        db,
        'intelligenceArticles',
        articles.map((data) => ({ id: data.id, data })),
      );
      const byId = mergeCveRecords([
        ...snapshot.cveData,
        ...acceptedResults.filter((result) => !result.notModified).flatMap((result) => result.cves),
        ...streamedCves,
      ]);
      // Persist rejections now that the merged corpus is known: a rejection whose
      // identity is present in `byId` has been fixed (or an earlier revision of
      // it parses), so it is closed rather than reported forever. Runs before
      // the corpus write so the loss is recorded even if a later step fails.
      if (rejectedRecords.length)
        await persistIngestionRejections(db, rejectedRecords, {
          runId: execution!.id,
          ingestedIds: new Set(byId.keys()),
        });
      // Operator-import records are explicit authoritative revisions. Feed
      // refreshes may add enrichment, but they must never replace an operator
      // correction made while ingestion was in progress.
      for (const operatorRevision of snapshot.cveData) {
        if (operatorRevision.sourceFeeds?.includes('operator-import')) {
          byId.set(normalizeCveId(operatorRevision.cveId) || operatorRevision.cveId, operatorRevision);
        }
      }
      // Audit C-1 / C-2: a record that a different writer committed after this
      // run started but before the commit transaction opened is authoritative.
      // Without this pass the merge above would resurrect the run's pre-ingestion
      // copy of that CVE and feed `reconcileFindings` stale applicability.
      const protectedFromRunCves = new Set<string>();
      for (const [id, stored] of commitState) {
        if (!byId.has(id)) continue;
        const storedAt = Date.parse(stored.modifiedDate);
        const startedBeforeRevision = Number.isFinite(storedAt) && storedAt > runStartedAt;
        const operatorCorrection = stored.sourceFeeds?.includes('operator-import');
        if (operatorCorrection || startedBeforeRevision) {
          byId.set(id, stored);
          protectedFromRunCves.add(id);
        }
      }
      type Withdrawal = { cveId: string; modifiedDate: string };
      const oldWithdrawals = new Map(
        (await list<Withdrawal>(db, 'cveWithdrawals')).map((entry) => [entry.cveId, entry]),
      );
      const withdrawals = new Map(oldWithdrawals);
      for (const entry of acceptedResults.flatMap((result) => result.withdrawals || [])) {
        const old = withdrawals.get(entry.cveId);
        if (!old || Date.parse(entry.modifiedDate) > Date.parse(old.modifiedDate))
          withdrawals.set(entry.cveId, entry);
      }
      const changedWithdrawals = [...withdrawals.values()].filter((entry) => {
        const old = oldWithdrawals.get(entry.cveId);
        return !old || old.modifiedDate !== entry.modifiedDate;
      });
      await putMany(
        db,
        'cveWithdrawals',
        changedWithdrawals.map((entry) => ({ id: entry.cveId, data: entry })),
      );
      for (const entry of withdrawals.values()) {
        // Audit C-2: a withdrawal supersedes a feed revision, but never an
        // operator correction that was imported after the withdrawal. Applying
        // the tombstone blindly deleted the operator's repair.
        const operatorCorrection = byId.get(entry.cveId)?.sourceFeeds?.includes('operator-import');
        if (operatorCorrection) continue;
        const cve = byId.get(entry.cveId);
        if (cve && Date.parse(cve.modifiedDate) <= Date.parse(entry.modifiedDate)) byId.delete(entry.cveId);
      }
      const oldCveMap = mergeCveRecords(snapshot.cveData);
      // Audit H-3: build the change-detection projection once, keyed by
      // canonical id. `oldCveMap` itself is released as soon as the EPSS/KEV
      // carry-forward below finishes, so the run never holds two complete
      // corpora plus a third map of dense strings.
      // Audit H-3: compare only the content view of each stored CVE, built once
      // before the EPSS/KEV enrichment below. The comparison itself must still run
      // AFTER enrichment, because a KEV or EPSS update is a real, persistable
      // change: the previous implementation compared whole records post-merge for
      // exactly that reason, and comparing the pre-enrichment view made KEV
      // enrichment silently unpersisted.
      const oldCveViews = new Map<string, string>();
      // Applicability fingerprints are captured before `oldCveMap` is released.
      // Comparing them after the clear ran against an empty map, so the CPE
      // change set was always empty and a newly added CPE never re-matched an
      // old CVE outside the publication window.
      const oldApplicabilityViews = new Map<string, string>();
      for (const old of oldCveMap.values()) {
        oldCveViews.set(old.cveId, cveContentView(old));
        oldApplicabilityViews.set(old.cveId, cveApplicabilitySignature(old));
      }
      // Records written by another worker during this run are compared against
      // the commit-time value they actually replaced, so their update is not
      // re-applied as an unchanged no-op and the diff stays correct.
      for (const [id, stored] of commitState)
        if (protectedFromRunCves.has(id)) oldCveViews.set(id, cveContentView(stored));
      for (const old of oldCveMap.values()) {
        const current = byId.get(normalizeCveId(old.cveId) || '');
        if (current) {
          current.epss = old.epss;
          current.cisaKev = old.cisaKev;
        }
      }
      // The full previous corpus is no longer needed: change detection reads
      // `oldCveViews`, superseded-alias detection reads `oldCveIds`. Dropping the
      // map here halves peak resident memory on a large corpus (audit H-3).
      const oldCveIds = new Set(oldCveMap.keys());
      oldCveMap.clear();
      const kevReports = acceptedResults.filter((result) => result.kev);
      const cisaKevEnabled = [...currentFeeds.values()].some(
        (feed) => feed.type === 'CISA_KEV' && feed.enabled,
      );
      if (
        cisaKevEnabled &&
        !acceptedResults.some((result) => currentFeeds.get(result.sourceId || '')?.type === 'CISA_KEV')
      )
        execution!.logs.push('CISA KEV was not refreshed; cached KEV flags are retained and may be stale');
      const exploitedReports = acceptedResults.filter((result) => result.exploited && !result.notModified);
      const epssReports = acceptedResults.filter((result) => result.epss && !result.notModified);
      const epssScopes = new Map(epssReports.map((result) => [result, new Set(result.epssScope)]));
      for (const cve of byId.values()) {
        const exploitationSources = exploitedReports
          .filter((result) => result.exploited?.[cve.cveId])
          .map((result) => result.sourceId!)
          .sort();
        if (exploitationSources.length) {
          cve.exploitationSources = [
            ...new Set([...(cve.exploitationSources || []), ...exploitationSources]),
          ];
          if (cve.exploitStatus === 'None') cve.exploitStatus = 'Reported In Wild';
        }
        if (kevReports.length) {
          const hasFullCisaKev = kevReports.some((r) => {
            const feed = currentFeeds.get(r.sourceId || '');
            return feed?.type === 'CISA_KEV';
          });
          const kevMatch = kevReports.map((result) => result.kev![cve.cveId]).find((entry) => entry?.isKev);
          if (kevMatch) {
            cve.cisaKev = kevMatch;
          } else if (hasFullCisaKev) {
            cve.cisaKev = { isKev: false };
          }
        }
        const scopedReports = epssReports.filter((result) => epssScopes.get(result)!.has(cve.cveId));
        if (scopedReports.length) {
          cve.epss = scopedReports.map((result) => result.epss![cve.cveId]).find(Boolean) || {
            score: 0,
            percentile: 0,
          };
        }
      }
      // Audit H-3: compare only the applicability-affecting view computed before
      // the EPSS/KEV enrichment above, so a refreshed score does not force a full
      // re-serialisation of the corpus (and a spurious rewrite of every row).
      const changedCves = [...byId.values()].filter((cve) => {
        const previousView = oldCveViews.get(cve.cveId);
        return previousView === undefined || previousView !== cveContentView(cve);
      });
      // Detect CVEs whose CPE applicability data changed since the last run
      // (e.g. NVD published CPE data for CVE-2026-107154). These CVEs must be
      // re-matched against ALL assets regardless of scopeHours, because the new
      // CPE data may now match assets that previously had no applicable data.
      // Only applicability fields participate: a history-only revision of the
      // title, description, CVSS or modifiedDate is not a reason to notify.
      const cpeChangedCveIdsSet = new Set<string>();
      for (const cve of changedCves) {
        const previousApplicability = oldApplicabilityViews.get(cve.cveId);
        if (previousApplicability === undefined) continue;
        if (previousApplicability === cveApplicabilitySignature(cve)) continue;
        cpeChangedCveIdsSet.add(cve.cveId);
        await writeEvent(db, {
          category: 'PIPELINE',
          level: 'INFO',
          code: 'pipeline.cpe_changed',
          message: `CPE applicability data changed for ${cve.cveId}; will re-match against all assets`,
          runId: execution!.id,
          context: { cveId: cve.cveId, title: cve.title },
        }).catch(() => undefined);
      }
      // Persist the CPE-changed set so a later run can re-evaluate even if
      // this run's scopeHours window excludes them.
      //
      // The backlog MUST be read before it is overwritten. `db` is the single
      // connection/transaction for this whole commit phase, so a `put` here
      // followed by a `get` of the same key further below would only ever
      // observe what THIS run just wrote (read-your-own-writes). Reading first
      // is what carries a previous run's pending re-evaluations forward.
      //
      // The backlog is deliberately bounded. Every entry makes the next run
      // re-evaluate that CVE against the whole inventory outside the
      // publication window, so an ever-growing union turns into a per-run cost
      // that never shrinks with deployment age. A CVE is therefore re-evaluated
      // at most CPE_REMATCH_MAX_RUNS times (or for CPE_REMATCH_MAX_AGE_MS after
      // the change) and is then dropped: an applicability change that produced
      // no match after full-price re-matches in consecutive runs is settled, and
      // a later provider revision re-adds it through the normal diff.
      const previousCpeChangedState = await get<CpeRematchState>(db, 'systemState', 'cpe-changed-cves').catch(
        () => undefined,
      );
      const cpeRematchNow = Date.now();
      const cpeRematch = carryCpeRematchBacklog(
        previousCpeChangedState,
        cpeChangedCveIdsSet,
        new Date(cpeRematchNow).toISOString(),
        cpeRematchNow,
      );
      if (cpeRematch.dropped)
        execution!.logs.push(
          `CPE re-match backlog: ${cpeRematch.dropped} CVE(s) settled after ${CPE_REMATCH_MAX_RUNS} re-evaluation(s)`,
        );
      const cpeChangedBacklog = new Set(cpeRematch.entries.map((entry) => entry.cveId));
      await put(db, 'systemState', 'cpe-changed-cves', {
        cveIds: [...cpeChangedBacklog],
        entries: cpeRematch.entries,
        updatedAt: new Date(cpeRematchNow).toISOString(),
      } satisfies CpeRematchState);
      // Bind published CVEs to their pre-CVE clusters so early-intelligence
      // evidence and operator rulings travel with the canonical identifier.
      // Only CVEs that are new to the corpus (not merely re-versioned) can
      // establish the publication event; a re-publication never re-binds.
      //
      // A bind that loses its bounded lock race throws BIND_LOCK_CONTENDED. That
      // is not "no cluster to bind": swallowing it would record the CVE as
      // already-published, so no later run would retry and the operator's
      // FALSE_POSITIVE/NOT_AFFECTED ruling would never reach the canonical
      // finding. Deferred identities are merged into the pending pin, which the
      // next citation run retries before re-deriving new publications.
      type DeferredBind = { cveId: string; vendor: string; product: string; attempts?: number };
      const deferredBinds: DeferredBind[] = [];
      const previous = await get<{ pending: DeferredBind[] }>(
        db,
        'systemState',
        'correlation-deferred-binds',
      ).catch(() => undefined);
      // At most 500 entries fit in the durable pin, and CVEs beyond the cap are
      // never revisited (a CVE that is already in the corpus is skipped by
      // `oldCveMap.has` on every later run). Defer only what the pin can hold:
      // the rest still inherits its cluster, because bindClusterToCve's own
      // bounded retries already ran and a cluster that genuinely exists is
      // bindable. Losing a bound identity silently is the outcome this list
      // exists to prevent.
      const DEFERRED_BIND_LIMIT = 500;
      const defer = (bind: DeferredBind, attempts = 1) => {
        if (deferredBinds.length >= DEFERRED_BIND_LIMIT) return;
        deferredBinds.push({ ...bind, attempts });
      };
      for (const identity of previous?.pending ?? []) {
        try {
          await bindClusterToCve(db, identity.cveId, identity.vendor, identity.product);
        } catch (error) {
          if ((error as { code?: string }).code !== 'BIND_LOCK_CONTENDED') throw error;
          const attempts = (identity.attempts ?? 0) + 1;
          if (attempts < DEFERRED_BIND_MAX_ATTEMPTS) defer(identity, attempts);
          else
            execution!.logs.push(
              `Pre-CVE disposition inheritance for ${identity.cveId} was deferred ${attempts} times and is now abandoned`,
            );
        }
      }
      for (const cve of changedCves) {
        if (oldCveIds.has(cve.cveId)) continue;
        for (const identity of cveClusterIdentities(cve)) {
          try {
            await bindClusterToCve(db, cve.cveId, identity.vendor, identity.product);
          } catch (error) {
            if ((error as { code?: string }).code !== 'BIND_LOCK_CONTENDED') throw error;
            defer({ cveId: cve.cveId, ...identity }, 1);
          }
        }
      }
      // Retried binds whose CVE has left the changed set are carried forward
      // too; dropping them here is the same loss as never recording them.
      if (deferredBinds.length)
        await put(db, 'systemState', 'correlation-deferred-binds', {
          pending: deferredBinds.slice(0, DEFERRED_BIND_LIMIT),
          updatedAt: new Date().toISOString(),
        });
      else if (previous)
        await put(db, 'systemState', 'correlation-deferred-binds', {
          pending: [],
          updatedAt: new Date().toISOString(),
        });
      await putMany(
        db,
        'cveData',
        changedCves.map((cve) => ({ id: cve.cveId, data: cve })),
      );
      if (protectedFromRunCves.size)
        await writeEvent(db, {
          category: 'PIPELINE',
          level: 'INFO',
          code: 'pipeline.cve_revision_preserved',
          message: 'Concurrent CVE revisions were preserved over stale run data',
          runId: execution!.id,
          context: { cveIds: [...protectedFromRunCves].slice(0, 50), count: protectedFromRunCves.size },
        });
      const keys = await db.query("SELECT id FROM records WHERE kind='cveData'");
      // Batch deletion of superseded/withdrawn CVE aliases into a single query
      // instead of one DELETE per row, reducing O(N) round-trips to O(1).
      const staleIds = keys.rows
        .map((row) => {
          const canonical = normalizeCveId(row.id);
          return canonical &&
            ((canonical !== row.id && byId.has(canonical)) ||
              (withdrawals.has(canonical) && !byId.has(canonical)))
            ? row.id
            : null;
        })
        .filter((id): id is string => id !== null);
      if (staleIds.length)
        await db.query("DELETE FROM records WHERE kind='cveData' AND id = ANY($1::text[])", [staleIds]);
      // Applicability matching is time-bounded to the run window so only CVEs
      // published or modified within scopeHours are matched.
      const settings = { ...snapshot.settings, scopeHours: execution!.scopeHours };
      execution!.logs.push(
        `Applicability matching is time-bounded to the run window (scopeHours=${execution!.scopeHours})`,
      );
      const finalCves = [...byId.values()];
      // Include CPE-changed CVEs regardless of scopeHours: their new applicability
      // data may now match assets that previously had no CPE data. The matching
      // engine still applies scopeHours to the run, but these CVEs are always
      // eligible for re-correlation.
      //
      // `cpeChangedBacklog` already IS the union of whatever was persisted by
      // earlier runs plus what this run just detected (computed above, before
      // the backlog was overwritten) — re-reading the key here would only
      // return the value this same transaction already wrote, not add
      // anything new.
      const cpeChangedCveIds = cpeChangedBacklog;
      const cpeChangedCves = finalCves.filter((cve) => cpeChangedCveIds.has(cve.cveId));
      if (cpeChangedCves.length > 0) {
        execution!.logs.push(
          `CPE data changed for ${cpeChangedCves.length} CVE(s); re-matching against all assets`,
        );
      }
      // Inventory may have changed while this run was ingesting. Re-derive its
      // automatic aliases for the final snapshot so both the PostgreSQL
      // candidate index and the JavaScript matcher use the same expanded keys.
      const finalInventoryAliases = deriveInventoryAliases(snapshot.watchlist, aliasEntries);
      const finalAliasEntries: AliasEntry[] = [...aliasEntries, ...finalInventoryAliases];
      const finalVendorAliases = buildAliasMap(finalAliasEntries, 'VENDOR');
      const finalProductAliases = buildAliasMap(finalAliasEntries, 'PRODUCT');
      // AUDIT FIX: Apply pipeline-news integration correction
      // Derive and calculate final alias maps immediately for both CVE and news matching
      // The index refresh is a full-corpus rewrite and must not share the short
      // statement budget used by interactive work. Measured on a 15,000-CVE
      // corpus: the set-based refresh finishes in seconds when idle, but a
      // concurrent run can multiply that several times over. A 60s ceiling
      // aborted mid-refresh and rolled the run back; the retry helper now has a
      // budget that matches the work, so this is the outer guard, not the plan.
      const finalPairs = await transaction(
        pool,
        (db) =>
          refreshCandidatePairs(db, finalCves, snapshot.watchlist, {
            vendorAliases: finalVendorAliases,
            productAliases: finalProductAliases,
          }),
        undefined,
        {
          locks: ['match-index'],
          statementTimeoutMs: config.MATCH_INDEX_STATEMENT_TIMEOUT_MS,
          lockTimeoutMs: MATCH_INDEX_LOCK_TIMEOUT_MS,
        },
      );
      const correlated = runVulnerabilityPipeline(
        feeds,
        finalCves,
        snapshot.watchlist,
        snapshot.alertedCves,
        snapshot.findings,
        settings,
        'Server worker',
        true,
        finalVendorAliases,
        finalProductAliases,
        finalPairs.size ? finalPairs : undefined,
        aliasEntries,
        undefined,
        cpeChangedCveIds,
      );
      const previousInventory = await get<Record<string, string>>(db, 'systemState', 'matched-inventory-v1');
      // The matching phase is the one operators most often ask about after a
      // slow run, and it previously had no operational event. Emit its duration
      // and match counts at the boundary so a run can be profiled from the event
      // log alone, without opening the execution record.
      await writeEvent(pool, {
        category: 'PIPELINE',
        code: 'pipeline.phase_completed',
        message: 'Phase completed: Product matching',
        runId: execution!.id,
        context: {
          phase: 'Product matching',
          durationMs: correlated.execution.phases[1]?.durationMs ?? 0,
          cvesMatched: correlated.newFindings.length,
          inventoryAssets: snapshot.watchlist.length,
          next: 'Delivery queue',
        },
      }).catch(() => undefined);
      const inventoryFingerprints: Record<string, string> = Object.create(null);
      const changedInventory = snapshot.watchlist.filter((asset) => {
        const fingerprint = createHash('sha256')
          .update(
            JSON.stringify({
              vendor: asset.vendor,
              product: asset.product,
              version: asset.version,
              cpes: [...asset.cpes].sort(),
              purls: [...(asset.purls ?? [])].sort(),
              active: asset.active,
              assetTag: asset.assetTag,
            }),
          )
          .digest('hex');
        inventoryFingerprints[asset.id] = fingerprint;
        return asset.active && previousInventory?.[asset.id] !== fingerprint;
      });
      if (changedInventory.length) {
        const historical = runVulnerabilityPipeline(
          feeds,
          finalCves,
          changedInventory,
          snapshot.alertedCves,
          snapshot.findings,
          { ...settings, scopeHours: 0 },
          'Inventory registration',
          true,
          finalVendorAliases,
          finalProductAliases,
          finalPairs.size ? finalPairs : undefined,
          aliasEntries,
          undefined,
          cpeChangedCveIds,
        );
        const known = new Set(correlated.newFindings.map(findingIdentity));
        correlated.newFindings.push(
          ...historical.newFindings.filter((finding) => !known.has(findingIdentity(finding))),
        );
      }
      correlated.newFindings = assessFindings(correlated.newFindings, feedTypesById, settings);
      await put(db, 'systemState', 'matched-inventory-v1', inventoryFingerprints);
      // `correlated.newFindings` is every current match because the server asks
      // for existing candidates so it can refresh applicability. The execution
      // metric must only count identities that did not exist before this run;
      // otherwise every run reports the whole corpus as a new detection.
      const newDetectionCount = countNewFindings(snapshot.findings, correlated.newFindings);
      // A wholly rejected stale bundle may be rebuilt from current matches. Never
      // automatically resend a bundle with any acceptance or an in-flight delivery.
      const staleBundles = new Set<string>(
        (
          await db.query(
            `SELECT advisory_id FROM outbox GROUP BY advisory_id HAVING bool_and(status='FAILED' AND COALESCE(error,'') LIKE '%no longer applicable%')`,
          )
        ).rows.map((row) => row.advisory_id),
      );
      // Pre-CVE operator rulings suppress their canonical CVE's new findings
      // before reconciliation or any delivery queue sees them. A finding whose
      // asset an operator ruled FALSE_POSITIVE/NOT_AFFECTED during the pre-CVE
      // window is created MONITORED with the ruling recorded, never queued.
      const existingFindingIdentities = new Set(snapshot.findings.map(findingIdentity));
      const newFindingIds = new Set([
        ...new Map(
          correlated.newFindings
            .filter((finding) => !existingFindingIdentities.has(findingIdentity(finding)))
            .map((finding) => [findingIdentity(finding), finding.id]),
        ).values(),
      ]);
      const suppressedNewFindings: Finding[] = [];
      const survivingNewFindings: Finding[] = [];
      {
        const suppressionCache = new Map<string, Set<string>>();
        for (const finding of correlated.newFindings) {
          let suppressed = suppressionCache.get(finding.cveId);
          if (!suppressed) {
            suppressed = await clusterSuppressedAssets(db, finding.cveId);
            suppressionCache.set(finding.cveId, suppressed);
          }
          if (suppressed.has(finding.matchedAssetId))
            suppressedNewFindings.push({
              ...finding,
              ...(newFindingIds.has(finding.id) && { executionId: execution!.id }),
              status: 'FALSE_POSITIVE',
              notificationStatus: 'NOT_APPLICABLE',
              matchingEvidence:
                'Suppressed by operator ruling on the pre-CVE cluster; canonical CVE inherits the earlier decision',
            });
          else
            survivingNewFindings.push(
              newFindingIds.has(finding.id) ? { ...finding, executionId: execution!.id } : finding,
            );
        }
      }
      const reconciled = reconcileFindings(
        snapshot.findings.map((f) =>
          f.advisoryId && staleBundles.has(f.advisoryId) && !f.autoDispatchedAt
            ? { ...f, advisoryId: null }
            : f,
        ),
        survivingNewFindings,
      );
      const vexEnforced = applyVexSuppression(reconciled);
      // Suppressed findings are persisted alongside the surviving set: dropping
      // them would let the next run re-create and queue the same finding.
      const persistedFindings = [...vexEnforced, ...suppressedNewFindings];
      await putMany(
        db,
        'findings',
        persistedFindings.map((f) => ({ id: f.id, data: f })),
      );
      // Persist engine-produced audit logs (authoritative autodispatch,
      // circuit breaker trips) with proper hash-chain chaining. Escalate
      // WARNING-level events to the operational event log so the security
      // team is alerted when autodispatch is being held.
      for (const auditLog of correlated.newAuditLogs) {
        await appendAudit(
          db,
          auditLog.event,
          auditLog.details,
          auditLog.actor,
          auditLog.category,
          auditLog.level,
          auditLog.ipAddress,
          auditLog.context,
        );
        if (
          auditLog.level === 'WARNING' &&
          (auditLog.category === 'PIPELINE' || auditLog.category === 'FEED' || auditLog.category === 'EMAIL')
        ) {
          await writeEvent(db, {
            category: auditLog.category,
            level: auditLog.level,
            code: auditLog.event,
            message: auditLog.details.slice(0, 1000),
            runId: execution!.id,
            context: auditLog.context ?? undefined,
          });
        }
      }
      // Rebuild the automatic alias layer from current inventory and from the
      // correlations that survived this run. Rows that are no longer supported
      // by either source are removed, while operator-managed rows are never
      // touched. The effective maps include this run's changes so news evidence
      // matching also sees the freshly learned names.
      // A stop requested during the commit window must surface before the
      // alias reconciliation writes back: once upserts/removals hit the table,
      // a cancellation can no longer prevent a lossy overwrite of concurrent
      // operator alias edits.
      await checkpoint(db);
      const desiredAutoAliases = [
        ...deriveInventoryAliases(snapshot.watchlist, aliasEntries),
        ...deriveCorrelationAliases(persistedFindings, snapshot.watchlist, byId, aliasEntries),
      ];
      const autoAliases = reconcileAutoAliases(aliasEntries, desiredAutoAliases, undefined, {
        ttlDays: settings.securityPolicy.autoAliasTtlDays,
      });
      // Batched, not per-row (audit finding #10): alias reconciliation can
      // touch hundreds of entries per run; putMany/removeMany issue one
      // parameterised statement each instead of one round trip per row.
      await putMany(
        db,
        'aliases',
        autoAliases.upserts.map((entry) => ({ id: entry.id, data: entry })),
      );
      await removeMany(db, 'aliases', autoAliases.removals);
      const effectiveAliasEntries = autoAliases.aliases;
      const effectiveVendorAliases = buildAliasMap(effectiveAliasEntries, 'VENDOR');
      const effectiveProductAliases = buildAliasMap(effectiveAliasEntries, 'PRODUCT');
      // Audit ML-3: the weights that actually scored this run's news evidence
      // were never recorded, so a bad split could not be attributed to a model
      // version after the fact. Capture them once and persist with the run.
      const credibilityWeights = predictCredibilityWeights();
      const intelligenceMatches: IntelligenceMatch[] = matchIntelligence(
        articles,
        snapshot.watchlist,
        vexEnforced,
        [...byId.values()],
        effectiveVendorAliases,
        effectiveProductAliases,
        // Cached CVEs stay applicable regardless of age, but news vendor +
        // product evidence is limited to the run's published/modified window.
        execution!.scopeHours,
        new Date(),
        credibilityWeights,
        feedTypesById,
      ).map((match) => ({
        ...match,
        calibratedCredibilityScore: calibrateCredibilityScore(match.credibilityScore ?? 0).score,
      }));
      await putMany(
        db,
        'intelligenceMatches',
        intelligenceMatches.map((data) => ({ id: data.id, data })),
      );
      // Apply zero-day rate limiting and digest consolidation before the sweep
      // below, so the rows a digest replaces are deleted in the same pass instead
      // of being written and then immediately removed.
      //
      // Audit C-3: the cap also removes the suppressed matches' counterpart
      // findings. They were persisted but never queued, so exceeding the cap
      // silently lost the notification — the exact storm-to-silence failure the
      // cap was meant to convert into a digest. The digests are now recorded
      // durably so the operator and the UI can see what was withheld.
      const zeroDayCap = Math.max(1, Math.min(MAX_ZERO_DAYS_PER_RUN, Math.floor(getZeroDayCap())));
      // The cap has two effects that must stay in lockstep: the suppressed
      // matches must not reach the ordinary news email, and their counterpart
      // findings must not reach the ordinary finding email. The digest below is
      // the only delivery path for withheld evidence.
      //
      // Eligible findings are the rows this run would actually queue. A row that
      // neither applies nor is dispatchable (NOT_APPLICABLE, VEX-suppressed,
      // security-rejected, resolved/dismissed) is never an outbound message, so
      // it must not consume zero-day budget or become a digest candidate.
      // An earlier version ran the cap over a set that was not the dispatch
      // input, so a capped zero-day could be withheld from the news email,
      // recorded in a digest, and still leave an individually deliverable
      // finding behind -- the storm-to-duplicate failure the cap exists to stop.
      const suppressedStatuses = new Set([
        'NOT_APPLICABLE',
        'SUPPRESSED_VEX_NOT_AFFECTED',
        'SECURITY_REJECTED',
      ]);
      const dispatchableFindings = persistedFindings.filter(
        (finding) =>
          !suppressedStatuses.has(finding.notificationStatus) &&
          !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status),
      );
      const dispatchableFindingIds = new Set(dispatchableFindings.map((finding) => finding.id));
      const rateLimited = rankAndRateLimitZeroDays(dispatchableFindings, intelligenceMatches, zeroDayCap);
      const rateLimitedMatches = rateLimited.matches;
      const zeroDayDigests = rateLimited.digests;
      // A digest may only claim findings the ordinary queue would have sent.
      const withheldFindingIds = new Set(
        zeroDayDigests.flatMap((digest) => digest.findingIds).filter((id) => dispatchableFindingIds.has(id)),
      );
      // Withheld findings stay persisted (the operator keeps seeing the exposure
      // and the next run does not recreate the row) but leave the dispatch set.
      const dispatchFindings = persistedFindings.filter(
        (finding) => dispatchableFindingIds.has(finding.id) && !withheldFindingIds.has(finding.id),
      );
      // The digest is the only delivery path for withheld evidence, so those
      // persisted rows must say so instead of claiming they are on the queue.
      const withheldRows = persistedFindings.filter((finding) => withheldFindingIds.has(finding.id));
      if (withheldRows.length) {
        const digestByFinding = new Map<string, string>();
        for (const digest of zeroDayDigests)
          for (const findingId of digest.findingIds)
            if (withheldFindingIds.has(findingId)) digestByFinding.set(findingId, digest.advisoryId);
        const recordedAt = new Date().toISOString();
        await putMany(
          db,
          'findings',
          withheldRows.map((finding) => ({
            id: finding.id,
            data: {
              ...finding,
              notificationStatus: 'DIGEST_BATCHED' as const,
              timeline: [
                ...(finding.timeline ?? []),
                {
                  timestamp: recordedAt,
                  action: 'Zero-day rate limited',
                  system: 'Server correlation engine',
                  details: `Consolidated into digest ${digestByFinding.get(finding.id) ?? 'unknown'} instead of an individual notification.`,
                },
              ],
            },
          })),
        );
      }
      // Declared with the other queue counters below; hoisted here because the
      // digest delivery happens before the ordinary dispatch block runs.
      let zeroDayDigestNotificationsQueued = 0;
      // (declared once for the run, in `processPipeline`, so the post-commit
      // alert flush below can see it)
      // Materialise each digest once: the persisted record and the queued email
      // must describe exactly the same withheld evidence.
      const allByMatchId = new Map(intelligenceMatches.map((match) => [match.id, match]));
      const articleById = new Map(articles.map((article) => [article.id, article]));
      const digestPayloads = zeroDayDigests.map((digest) => {
        const withheld = digest.matchIds
          .map((id) => allByMatchId.get(id))
          .filter((match): match is IntelligenceMatch => Boolean(match));
        const articleIds = [...new Set(withheld.flatMap((match) => match.articleIds))];
        return {
          retained: {
            ...digest,
            executionId: execution!.id,
            createdAt: new Date().toISOString(),
            // The withheld evidence must remain reviewable: a digest removes it
            // from the notification path, not from the operator's view.
            articles: articleIds,
          },
          payload: {
            digestId: digest.advisoryId,
            vendor: digest.vendor,
            product: digest.product,
            matchIds: digest.matchIds,
            matchCount: digest.matchCount,
            findings: withheld.map((match) => ({
              findingId: match.findingId,
              cveId: match.cveId ?? undefined,
              assetName: match.assetName,
              evidence: match.evidence,
              credibilityScore: match.credibilityScore,
            })),
            articles: articleIds
              .map((id) => articleById.get(id))
              .filter((article): article is IntelligenceArticle => Boolean(article))
              .map((article) => ({
                id: article.id,
                title: article.title,
                url: article.url,
                sourceFeeds: [...article.sourceFeeds],
              })),
          },
        };
      });
      if (digestPayloads.length)
        await putMany(
          db,
          'zeroDayDigests',
          digestPayloads.map(({ retained }) => ({ id: retained.advisoryId, data: retained })),
        );
      await putMany(
        db,
        'intelligenceMatches',
        rateLimitedMatches.map((data) => ({ id: data.id, data })),
      );
      // Audit M-6: the previous `NOT (id = ANY($1))` form bound every match id as
      // a single array parameter and scanned the whole kind on every run — a
      // multi-megabyte parameter for a large corpus. Batching keeps each
      // statement well under the 65,535 bind-parameter limit and lets the
      // primary key drive the delete.
      const liveMatchIds = rateLimitedMatches.map((item) => item.id);
      const liveIdSet = new Set(liveMatchIds);
      const existingMatchIds = (
        await db.query("SELECT id FROM records WHERE kind='intelligenceMatches'")
      ).rows.map((row: { id: string }) => row.id);
      const staleMatchIds = existingMatchIds.filter((id) => !liveIdSet.has(id));
      await removeMany(db, 'intelligenceMatches', staleMatchIds);
      await writeEvent(db, {
        category: 'MATCHING',
        code: 'matching.completed',
        message: 'Structured applicability and news evidence correlation completed',
        runId: execution!.id,
        context: {
          findings: correlated.newFindings.length,
          newDetections: newDetectionCount,
          articles: articles.length,
          credibilityWeights,
          evidenceMatches: rateLimitedMatches.length,
          reviewRequired: rateLimitedMatches.filter((item) => item.status === 'REVIEW_REQUIRED').length,
          zeroDayDigests: zeroDayDigests.length,
          zeroDaysRateLimited: intelligenceMatches.length - rateLimitedMatches.length,
          // Audit M-1/M-9: the cap now also suppresses the counterpart findings,
          // so record exactly what was withheld and under which digest.
          withheldFindings: zeroDayDigests.reduce((sum, digest) => sum + digest.findingIds.length, 0),
          digestGroups: zeroDayDigests.map((digest) => ({
            advisoryId: digest.advisoryId,
            product: `${digest.vendor}/${digest.product}`,
            matches: digest.matchCount,
          })),
        },
      });
      if (zeroDayDigests.length) {
        execution!.logs.push(
          `Zero-day cap (${zeroDayCap}) reached: ${zeroDayDigests.length} digest(s) consolidated ${intelligenceMatches.length - rateLimitedMatches.length} match(es)`,
        );
      }
      // Audit C-3: exceeding the cap must not silence the operator. Each digest
      // is delivered as one consolidated email per Security-team recipient, so
      // the cost bound the cap protects still holds. The findings themselves stay
      // out of the normal dispatch path (see `dispatchFindings` above).
      if (digestPayloads.length) {
        // The digest queue is idempotent per recipient and content revision, so
        // a retried commit cannot send the same digest twice.
        //
        // Queuing a digest is delivery work, not correlation work, and it sits
        // in the middle of the run's only commit transaction (the ordinary
        // finding/news emails are queued further down, in the same transaction).
        // A digest failure that threw here therefore discarded the whole run:
        // the digests, the capped findings and the correlation evidence were
        // rolled back, the run reported FAILED, and the next run re-derived the
        // same zero-days and hit the same failure. A digest that cannot be
        // queued is recorded as an ERROR event; it stays persisted for the
        // operator and must not invalidate the rest of the run.
        const digestFailures: { digestId: string; reason: string }[] = [];
        const digestRecipients = await loadNewsRecipients(db).catch((error: unknown) => {
          const reason = error instanceof Error ? error.message : String(error);
          execution!.logs.push(`Zero-day digests could not be queued: ${reason}`);
          digestFailures.push({ digestId: 'recipients', reason });
          return [];
        });
        for (const { payload } of digestPayloads)
          zeroDayDigestNotificationsQueued += await queueZeroDayDigestNotification(
            db,
            payload,
            digestRecipients,
          ).catch(async (error: unknown) => {
            const reason = error instanceof Error ? error.message : String(error);
            digestFailures.push({ digestId: payload.digestId, reason });
            await writeEvent(db, {
              category: 'EMAIL',
              level: 'ERROR',
              code: 'delivery.zero_day_digest_failed',
              message: `Zero-day digest ${payload.digestId} was recorded but could not be queued`,
              runId: execution!.id,
              context: { digestId: payload.digestId, ...describeError(error) },
            }).catch(() => undefined);
            return 0;
          });
        // Swallowing the failure is what keeps the run's committed work, but a
        // silent swallow would leave the operator with a digest that never
        // arrives and an ERROR event nobody reads. Alert once per cooldown,
        // keyed on the run/incident, through the same deduplicated path the
        // self-healing watchdog uses. Alerting is scheduled only AFTER the
        // digest loop so it cannot itself break the queuing it reports on.
        if (digestFailures.length)
          pendingOperatorAlerts.push({
            incident: 'zero-day-digest-queue',
            subject: 'Zero-day digest delivery failed',
            text:
              `${digestFailures.length} zero-day digest notification(s) could not be queued in run ${execution!.id}. ` +
              `The evidence is recorded and visible to operators, but no digest email was sent. Reasons: ` +
              digestFailures.map((failure) => `${failure.digestId}: ${failure.reason}`).join('; '),
          });
        // Keep zero-day evidence available in the UI without sending a third
        // email repeating the same findings or source articles.
        await writeEvent(db, {
          category: 'MATCHING',
          code: 'matching.zero_day_digests_recorded',
          message: 'Zero-day evidence recorded for consolidated findings and news',
          runId: execution!.id,
          context: {
            digests: digestPayloads.length,
            notificationsQueued: zeroDayDigestNotificationsQueued,
          },
        });
      }
      const queueStarted = Date.now();
      let notificationsQueued = 0,
        advisoriesQueued = 0,
        newsNotificationsQueued = 0,
        newsArticlesQueued = 0;
      // Snapshot all data needed for post-commit delivery queueing so the
      // pipeline-queue advisory lock can be released before delivery enqueues.
      // Run-scoped: see PostCommitDeliverySlot. A concurrent attempt must never
      // be able to observe or overwrite this attempt's snapshot.
      postCommitDelivery.current = {
        rateLimitedMatches,
        articles,
        snapshot,
        settings,
        dispatchFindings,
        zeroDayDigestNotificationsQueued,
        executionId: execution!.id,
        queueStarted,
      } satisfies PostCommitDeliveryInput;
      // Security news is consolidated into ONE email per recipient per run, and an
      // article already delivered to a recipient is never delivered again. The
      // per-match queue could not guarantee that: the matcher re-keys a match on
      // `hash(cveId || articleId)`, so the same story produced new rows (and new
      // emails) whenever it was re-correlated or syndicated through another feed.
      // Security news and finding delivery are queued POST-COMMIT (below), after
      // this transaction releases the pipeline-queue advisory lock. This keeps
      // advisory-lock hold time bounded to correlation work: delivery enqueue
      // failures cannot roll back correlation results or extend lock hold time.
      // Delivery results are merged into the execution record post-commit.
      // Include limited-confidence findings in the SAME recipient email as
      // confirmed findings. The renderer explains the confidence and its reason.
      //
      // `reviewNotifiedAt` is deliberately NOT a filter here (audit follow-up,
      // Finding 1): it is a GLOBAL stamp set when any recipient's email was
      // accepted, so filtering on it dropped findings for every recipient who
      // had not been told yet — including recipients added later. The
      // per-recipient `delivery_claims` record inside the consolidated queue is
      // what decides whether THIS recipient still needs THIS finding.
      //
      // The input is the zero-day-capped set, not the raw persisted set: a finding
      // withheld by the cap is delivered through its digest and must never also
      // be queued for individual delivery.
      // Finding delivery is queued POST-COMMIT (below). The pending set below
      // is reconstructed post-commit with the same filter logic so delivery
      // enqueue failures cannot roll back correlation results.
      const zeroDayLog = zeroDayDigestNotificationsQueued
        ? `; ${zeroDayDigestNotificationsQueued} zero-day digest notifications queued`
        : '';
      let deliveryLog = `${notificationsQueued} jobs queued${newsNotificationsQueued ? `; ${newsNotificationsQueued} consolidated news emails queued` : ''}${zeroDayLog}`;
      // Audit L-2: an ingestion outage and a correlation failure are different
      // incidents. Keep the FAILED status (it drives alerting and the audit
      // level) but state explicitly in the log that correlation completed over
      // the cache, so the run is not misread as having produced nothing.
      const allFeedsFailed = feeds.length > 0 && succeeded === 0;
      execution = {
        ...correlated.execution,
        id: execution!.id,
        startTime: execution!.startTime,
        endTime: new Date().toISOString(),
        status: allFeedsFailed ? 'FAILED' : correlated.execution.status,
        scopeHours: execution!.scopeHours,
        // Audit P-1: bound the merged tail so a completed run's persisted log
        // also stays within the cap (the running array was bounded, but this
        // spread was not). Pinned state lines survive via boundExecutionLogs.
        logs: boundExecutionLogs([
          ...execution!.logs,
          ...(allFeedsFailed
            ? [
                'All enabled feeds failed; correlation completed against the cached corpus and queued findings remain valid',
              ]
            : []),
          `Product matching: ${newDetectionCount} new detections; ${correlated.newFindings.length} current matches; ${reconciled.length} retained findings`,
          `Delivery queue: ${deliveryLog}`,
        ]),
        phases: [
          {
            name: 'Feed ingestion',
            status:
              succeeded < feeds.length || acceptedResults.some((result) => result.warnings?.length)
                ? 'WARNING'
                : 'SUCCESS',
            durationMs: ingestionDuration,
            details: `${succeeded}/${feeds.length} feeds succeeded; ${rawCount} records read; cached intelligence retained`,
          },
          {
            ...correlated.execution.phases[0],
            details: `${byId.size} canonical CVEs; ${correlated.execution.stats.inRunDuplicatesDropped} duplicate records removed`,
          },
          {
            ...correlated.execution.phases[1],
            details: `${byId.size} CVEs evaluated against ${snapshot.watchlist.filter((asset) => asset.active).length} active products; ${correlated.newFindings.length} current matches; ${newDetectionCount} new`,
          },
          {
            name: 'Delivery queue',
            status: 'PENDING',
            durationMs: Date.now() - queueStarted,
            details: `Queued post-commit; zero-day digests: ${zeroDayDigestNotificationsQueued}`,
          },
        ],
      };
      execution.stats = {
        ...execution.stats,
        rawIngested: rawCount,
        matchedWatchlist: newDetectionCount,
        notificationsQueued,
        advisoriesQueued,
        newsNotificationsQueued,
        zeroDayDigestNotificationsQueued,
      };
      await saveActiveExecution(db, execution);
      // Clear next_catchup_run if all feeds have completed their catch-up.
      const pendingCatchup = acceptedResults.some((r) => r.syncState?.catch_up && r.syncState.hasMore);
      if (pendingCatchup) {
        // Back off to the latest per-feed next_catchup_at so the scheduler does
        // not retrigger catch-up before the per-feed cooldown has elapsed.
        const allCatchup = acceptedResults.flatMap((r) =>
          r.syncState?.catch_up && r.syncState?.next_catchup_at
            ? [Date.parse(r.syncState.next_catchup_at)]
            : [],
        );
        const nextCatchupRun = allCatchup.length ? Math.max(...allCatchup) : Date.now() + 60000;
        await db.query('UPDATE scheduler_state SET last_run=now(), next_catchup_run=$1 WHERE id=1', [
          new Date(Math.max(nextCatchupRun, Date.now())).toISOString(),
        ]);
      } else {
        await db.query('UPDATE scheduler_state SET last_run=now(), next_catchup_run=NULL WHERE id=1');
      }
      await writeEvent(db, {
        category: 'PIPELINE',
        level: execution!.status === 'FAILED' ? 'ERROR' : 'INFO',
        code: 'pipeline.finished',
        message: `Pipeline ${execution!.status.toLowerCase()}`,
        runId: execution!.id,
        context: { stats: execution!.stats },
      });
      await appendAudit(
        db,
        execution.status === 'FAILED' ? 'Pipeline failed' : 'Pipeline completed',
        `${execution.id}; ${newDetectionCount} new findings; ${succeeded}/${feeds.length} feeds succeeded`,
        'worker',
        'PIPELINE',
        execution.status === 'FAILED' ? 'ERROR' : undefined,
      );
    });
    // Post-commit delivery queueing: no pipeline-queue advisory lock is held,
    // so delivery enqueue failures cannot roll back correlation work or extend
    // advisory-lock hold time. Delivery results are merged into the execution
    // record below.
    try {
      let notificationsQueued = 0;
      let advisoriesQueued = 0;
      let newsNotificationsQueued = 0;
      let newsArticlesQueued = 0;

      const delivery = await transaction(pool, async (db) => {
        // Read the immutable snapshot once. A missing snapshot means the commit
        // transaction did not publish one, which is a programming error, not a
        // delivery failure: fail loudly instead of queueing nothing silently.
        const postCommit = postCommitDelivery.current;
        if (!postCommit) throw new Error('Post-commit delivery snapshot was not published');
        const {
          rateLimitedMatches,
          articles,
          snapshot,
          settings,
          dispatchFindings,
          zeroDayDigestNotificationsQueued,
          executionId,
          queueStarted,
        } = postCommit;

        // Security news consolidation
        if (rateLimitedMatches.length) {
          const securityRecipients = await loadNewsRecipients(db);
          if (securityRecipients.length) {
            const articleMap = new Map(
              articles.map((article) => [article.id, article] as [string, IntelligenceArticle]),
            );
            const news = await queueConsolidatedNews(db, rateLimitedMatches, articleMap, securityRecipients, {
              template: {
                customization: snapshot.newsDigestCustomization,
                customTemplate: snapshot.newsDigestCustomTemplate,
                timezone: settings.timezone,
              },
              enqueue: async (input) =>
                enqueue(
                  input.db,
                  'email',
                  input.recipient.id,
                  input.advisoryId,
                  {
                    subject: input.subject,
                    text: input.text,
                    html: input.html,
                    cveIds: input.cveIds,
                    newsEvidence: {
                      matchId: input.articles.flatMap((item) => item.matchIds).sort()[0] || input.advisoryId,
                      article: {
                        id: input.articles[0].article.id,
                        title: input.articles[0].article.title,
                        url: input.articles[0].article.url,
                        sourceFeeds: [...input.articles[0].article.sourceFeeds],
                        publishedDate: input.articles[0].article.publishedDate,
                      },
                      articles: input.articles.map((item) => ({
                        id: item.article.id,
                        title: item.article.title,
                        url: item.article.url,
                        sourceFeeds: [...item.article.sourceFeeds],
                        publishedDate: item.article.publishedDate,
                      })),
                      assets: [...new Set(input.articles.flatMap((item) => item.assets))].sort(),
                      asset: {
                        name: input.articles.flatMap((item) => item.assets).sort()[0] || 'unknown asset',
                      },
                      cveIds: input.cveIds,
                      evidence: input.articles.flatMap((item) => item.evidence).join(' | '),
                      zeroDay: input.articles.some((item) => item.zeroDay),
                      credibilityScore: input.articles.reduce<number | undefined>(
                        (best, item) =>
                          typeof item.credibilityScore === 'number'
                            ? Math.max(best ?? 0, item.credibilityScore)
                            : best,
                        undefined,
                      ),
                    },
                    contentRevision: input.contentRevision,
                    recipientEmail: input.recipient.email,
                  },
                  `${input.identity}:email:${input.recipient.id}`,
                  'QUEUED',
                ),
            });
            newsNotificationsQueued += news.emailsQueued;
            newsArticlesQueued += news.articlesIncluded;
            await writeEvent(db, {
              category: 'MATCHING',
              code: 'matching.news_dispatched',
              message: 'Consolidated security-news email dispatched to the security team',
              runId: execution!.id,
              context: {
                matches: rateLimitedMatches.length,
                recipientsNotified: news.emailsQueued,
                articlesIncluded: news.articlesIncluded,
              },
            }).catch(() => undefined);
          }
        }

        // Finding notifications
        const pending = dispatchFindings.filter(
          (f) =>
            !f.dispatchDeferred &&
            !['NOT_APPLICABLE', 'SUPPRESSED_VEX_NOT_AFFECTED', 'SECURITY_REJECTED', 'REVIEW_REQUIRED'].includes(
              f.notificationStatus,
            ) &&
            !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(f.status),
        );
        const mlOrdered = mlOrderFindingsByImportance(pending);
        pending.length = 0;
        pending.push(...mlOrdered);
        if (pending.length) {
          notificationsQueued += await queueConsolidatedFindingNotifications(db, pending);
          advisoriesQueued = notificationsQueued ? 1 : 0;
        }

        return {
          notificationsQueued,
          advisoriesQueued,
          newsNotificationsQueued,
          newsArticlesQueued,
          zeroDayDigestNotificationsQueued,
          queueStarted,
        };
      });

      notificationsQueued = delivery.notificationsQueued;
      advisoriesQueued = delivery.advisoriesQueued;
      newsNotificationsQueued = delivery.newsNotificationsQueued;
      newsArticlesQueued = delivery.newsArticlesQueued;
      const { zeroDayDigestNotificationsQueued, queueStarted } = delivery;

      // Merge delivery results into the persisted execution record.
      await transaction(pool, async (db) => {
        const current = await get<PipelineExecution>(db, 'executions', execution!.id);
        if (!current) return;
        current.stats = {
          ...current.stats,
          notificationsQueued,
          advisoriesQueued,
          newsNotificationsQueued,
          zeroDayDigestNotificationsQueued,
        };
        current.logs = boundExecutionLogs([
          ...current.logs.filter((l) => !l.startsWith('Delivery queue:')),
          `Delivery queue: ${notificationsQueued} jobs queued${newsNotificationsQueued ? `; ${newsNotificationsQueued} consolidated news emails queued` : ''}${zeroDayDigestNotificationsQueued ? `; ${zeroDayDigestNotificationsQueued} zero-day digest notifications queued` : ''}`,
        ]);
        current.phases = current.phases.map((phase) =>
          phase.name === 'Delivery queue'
            ? {
                ...phase,
                status: 'SUCCESS',
                durationMs: Date.now() - queueStarted,
                details: `${notificationsQueued} jobs queued${newsNotificationsQueued ? `; ${newsNotificationsQueued} consolidated news emails queued (${newsArticlesQueued} articles)` : ''}${zeroDayDigestNotificationsQueued ? `; ${zeroDayDigestNotificationsQueued} zero-day digest notifications queued` : ''}; transport acceptance is tracked separately`,
              }
            : phase,
        );
        await put(db, 'executions', execution!.id, current);
      });
    } catch (error) {
      // Delivery queueing failures are non-fatal: correlation work is committed.
      const reason = error instanceof Error ? error.message : String(error);
      execution!.logs.push(`Delivery queueing failed: ${reason}`);
      pendingOperatorAlerts.push({
        incident: 'delivery-queue-failed',
        subject: 'Delivery queueing failed',
        text: `Delivery queueing failed for run ${execution!.id}: ${reason}`,
      });
    }
    // The run is durably committed. Only now may a fault it detected be mailed:
    // an alert sent before the commit would report a failure that a rollback
    // then erased. Alerting is best-effort and cannot fail the run.
    for (const alert of pendingOperatorAlerts) {
      try {
        await queueOperatorAlert(pool, {
          component: 'PIPELINE',
          incident: alert.incident,
          subject: alert.subject,
          text: alert.text,
          cooldownMinutes: 30,
        });
      } catch {
        // Best-effort alerting: one failed alert must not suppress subsequent alerts.
      }
    }
    return true;
  } catch (e) {
    signal?.throwIfAborted();
    // Audit H-4: losing the advisory-lock connection does not mean the run can
    // be abandoned silently. Previously this threw before recording anything,
    // leaving the execution wedged in RUNNING until another worker's recovery
    // pass collected it — during which queueRun() keeps returning the stale
    // execution and no new work is enqueued. Record the failure through the
    // pool (a fresh connection, since the lock client is dead) instead.
    if (connectionLost) {
      if (!execution) throw e;
      // Count lock-loss recoveries on their own counter. They used to share
      // `stats.recoveryAttempts` with the crash sweep, so three related but
      // distinct faults (crashes and dropped lock connections) exhausted one
      // budget between them and parked a run that had hit neither limit. The
      // counter is read under the row lock below, from the committed value.
      await transaction(pool, async (db) => {
        const current = await getForUpdate<PipelineExecution>(db, 'executions', execution!.id);
        if (!current || !['QUEUED', 'RUNNING'].includes(current.status)) return;
        // Read the committed counter under the row lock, so two concurrent
        // recoveries cannot both spend the same budget slot.
        const nextAttempt = countLockRecoveries(current) + 1;
        if (current.stopRequestedAt) {
          const cancelled = {
            ...current,
            status: 'CANCELLED' as const,
            endTime: new Date().toISOString(),
            phases: current.phases.map((phase) =>
              phase.status === 'RUNNING' || phase.status === 'PENDING'
                ? { ...phase, status: 'CANCELLED' as const }
                : phase,
            ),
            logs: boundExecutionLogs([
              ...new Set([...current.logs, 'Operator stop retained; worker did not restart after lock loss']),
            ]),
          };
          await put(db, 'executions', execution!.id, cancelled);
          await writeEvent(db, {
            category: 'PIPELINE',
            level: 'INFO',
            code: 'pipeline.cancelled_after_lock_loss',
            message: 'Pipeline cancelled during lock-loss recovery because stop was requested',
            runId: execution!.id,
          });
          return;
        }
        if (nextAttempt >= 3) {
          const failed = {
            ...current,
            status: 'FAILED' as const,
            endTime: new Date().toISOString(),
            phases: current.phases.map((phase) =>
              phase.status === 'RUNNING' || phase.status === 'PENDING'
                ? { ...phase, status: 'FAILED' as const }
                : phase,
            ),
          stats: {
            ...current.stats,
            lockRecoveryAttempts: nextAttempt,
            recoveryBackoffUntil: Date.now() + recoveryBackoffMs(nextAttempt),
          },
            logs: boundExecutionLogs([
              ...new Set([
                ...current.logs,
                `Recovery limit exceeded (attempt ${nextAttempt}/3); pipeline failed after repeated lock loss`,
              ]),
            ]),
          };
          await put(db, 'executions', execution!.id, failed);
          await writeEvent(db, {
            category: 'ISSUE',
            level: 'ERROR',
            code: 'pipeline.recovery_limit_exceeded',
            message: 'Pipeline recovery limit exceeded after repeated lock loss',
            runId: execution!.id,
            context: { recoveryAttempts: nextAttempt },
          });
          await appendAudit(
            db,
            'Pipeline recovery exhausted',
            `Execution ${execution!.id}; repeated lock loss exhausted 3 recovery attempts`,
            'worker',
            'PIPELINE',
            'ERROR',
          );
          return;
        }
        await put(db, 'executions', execution!.id, {
          ...current,
          // Audit H-4: requeue instead of failing. The worker never reached the
          // commit transaction, so no result was persisted and nothing is
          // half-applied — the run is exactly as resumable as an interrupted
          // one. Marking it FAILED made it unrecoverable, because the recovery
          // sweep only rescues RUNNING/QUEUED records. Hand the run back as
          // QUEUED and count the restart against the lock-loss budget, so a
          // genuinely broken worker still parks the run instead of looping.
          status: 'QUEUED',
          stats: {
            ...current.stats,
            lockRecoveryAttempts: nextAttempt,
            recoveryBackoffUntil: Date.now() + recoveryBackoffMs(nextAttempt),
          },
          phases: current.phases.map((phase) =>
            phase.status === 'RUNNING' ? { ...phase, status: 'PENDING' } : phase,
          ),
          logs: [
            ...current.logs,
            `Recovered interrupted worker (attempt ${nextAttempt}/3); restarting idempotently after lock-connection loss`,
          ],
        });
        await writeEvent(db, {
          category: 'ISSUE',
          level: 'WARNING',
          code: 'pipeline.worker_connection_lost',
          message: 'Pipeline worker lost its database lock connection; run requeued',
          runId: execution!.id,
          context: describeError(e),
        });
        await appendAudit(
          db,
          'Pipeline requeued',
          `Execution ${execution!.id}; worker lost its database lock connection after ${nextAttempt} restart(s)`,
          'worker',
          'PIPELINE',
          'WARNING',
        );
      }).catch(() => undefined);
      // Preserve the worker contract that a lost lock surfaces as a rejected run
      // (the scheduler treats the throw as a failed tick and backing off is
      // correct). The execution row is requeued or terminally failed; the next
      // worker therefore never sees a silently wedged RUNNING record.
      throw e;
    }
    if (execution) {
      const stopped = e instanceof PipelineStopped;
      // Finalize the execution without the aborted signal so cleanup can write
      // the CANCELLED or FAILED state to the database instead of being immediately
      // aborted by transaction()'s signal check.
      await transaction(
        pool,
        async (db) => {
          const current = await getForUpdate<PipelineExecution>(db, 'executions', execution!.id);
          // The row may have been deleted or made terminal while this worker was
          // unwinding. Never recreate a missing execution or overwrite a newer
          // completion/failure with this stale worker's local snapshot.
          if (!current) {
            await writeEvent(db, {
              category: 'ISSUE',
              level: 'ERROR',
              code: 'pipeline.execution_missing',
              message: 'Pipeline worker could not finalize because the execution record disappeared',
              runId: execution!.id,
            });
            await appendAudit(
              db,
              'Pipeline execution record missing',
              `Execution ${execution!.id} could not be finalized by the worker`,
              'worker',
              'PIPELINE',
              'ERROR',
            );
            return;
          }
          if (['COMPLETED', 'FAILED', 'QUARANTINED'].includes(current.status)) {
            await writeEvent(db, {
              category: 'PIPELINE',
              level: 'WARNING',
              code: 'pipeline.stale_worker_result_discarded',
              message: 'Discarded stale worker finalization because the execution is already terminal',
              runId: execution!.id,
              context: { observedStatus: current.status },
            });
            return;
          }

          const stopRequested = Boolean(current.stopRequestedAt);
          const cancelled = stopRequested || current.status === 'CANCELLED';
          // A PipelineStopped sentinel without a persisted cancellation state is
          // a broken state transition, not evidence of an operator stop. Surface
          // it as a failure so the execution cannot be silently misclassified.
          const failure: Record<string, unknown> = cancelled
            ? {}
            : stopped
              ? { error: 'Worker observed cancellation without a persisted stop request or CANCELLED status' }
              : describeError(e);
          const finalStatus = cancelled ? 'CANCELLED' : 'FAILED';
          const finalPhases = current.phases.map((phase) =>
            phase.status === 'RUNNING' || phase.status === 'PENDING'
              ? { ...phase, status: cancelled ? ('CANCELLED' as const) : ('FAILED' as const) }
              : phase,
          );
          await put(db, 'executions', execution!.id, {
            ...current,
            status: finalStatus,
            stopRequestedAt: current.stopRequestedAt,
            phases: finalPhases,
            endTime: new Date().toISOString(),
            logs: boundExecutionLogs([
              ...new Set([...(current?.logs || []), ...execution!.logs]),
              cancelled
                ? stopRequested
                  ? 'Operator requested stop; uncommitted results discarded'
                  : 'Execution was already marked CANCELLED; uncommitted results discarded'
                : e instanceof Error
                  ? e.message
                  : 'Worker failed',
            ]),
          });
          await writeEvent(db, {
            category: cancelled ? 'PIPELINE' : 'ISSUE',
            level: cancelled ? 'INFO' : 'ERROR',
            code: cancelled ? 'pipeline.cancelled' : 'pipeline.failed',
            message: cancelled
              ? 'Pipeline cancelled; uncommitted results discarded'
              : 'Pipeline failed; inspect execution details',
            runId: execution!.id,
            context: { ...failure, stopRequested, observedStatus: current.status },
          });
          await appendAudit(
            db,
            cancelled ? 'Pipeline cancelled' : 'Pipeline failed',
            `Execution ${execution!.id}${
              typeof failure.error === 'string' ? `; ${failure.error.slice(0, 500)}` : ''
            }`,
            'worker',
            'PIPELINE',
            cancelled ? undefined : 'ERROR',
          );
        },
        undefined,
        { locks: ['pipeline-queue'] },
      );
    } else throw e;
    return true;
  } finally {
    signal?.removeEventListener('abort', onAbort);
    if (heartbeat) clearInterval(heartbeat);
    if (locked && !released) {
      try {
        // Inspect the boolean result. `pg_advisory_unlock` returns false (without
        // throwing) when this session does not hold the lock, so awaiting the
        // round-trip is NOT proof of release. A `false` result has to take the
        // same path as a thrown error: the connection may still own the lock and
        // must never return to the pool, where the next checkout would appear to
        // hold the pipeline run lock.
        const unlockQuery = await lock.query<{ released: boolean }>(
          `SELECT pg_advisory_unlock(800003, ${schemaLockKey}) AS released`,
        );
        if (unlockQuery.rows[0]?.released !== true)
          throw new Error('pg_advisory_unlock reported the lock was not held by this session');
        await writeEvent(lock, {
          category: 'PIPELINE',
          level: 'INFO',
          code: 'pipeline.lock_released',
          message: 'Pipeline advisory lock released successfully',
        });
      } catch (unlockError) {
        // A failed unlock means this session may still own the lock. It must never
        // return to the pool: `lock.release(connectionLost)` below destroys the
        // client, and a destroy on an idle client queues the socket close. Mark
        // the connection as lost so the release path takes the "destroy" branch
        // even though the original error listener never fired.
        connectionLost = true;
        await writeEvent(lock, {
          category: 'PIPELINE',
          level: 'ERROR',
          code: 'pipeline.lock_release_failed',
          message: 'Failed to release pipeline advisory lock',
          context: {
            connectionLost,
            error: (unlockError as Error).message,
          },
        }).catch(() => undefined);
        console.error(
          JSON.stringify({
            level: 'error',
            event: 'pipeline_lock_cleanup_failed',
            message: 'Failed to release advisory lock',
            context: {
              connectionLost,
              error: (unlockError as Error).message,
            },
          }),
        );
      }
    }
    lock.removeListener('error', onError);
    if (!released) lock.release(connectionLost);
  }
}
