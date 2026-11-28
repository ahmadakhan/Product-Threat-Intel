import type pg from 'pg';
import {
  get,
  getMany,
  list,
  put,
  safeAdvisoryUnlock,
  transaction,
  schemaLockKey,
  acquireSessionClassLock,
  type Db,
} from './db';
import { writeEvent } from './events';
import { advisoryRevision, enqueue, findingRevision, revision, recipientAllows } from './delivery';
import {
  activeClaims,
  attachClaimsToJob,
  claimItems,
  claimsForJob,
  reconcileDuplicateOutboxClaims,
} from './deliveryClaims';
import { dailyDigestRecipients, uniqueEnabledEmailRecipients } from './emailRecipients';
import { advisoryEmail } from './advisoryEmail';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { shouldSelectForDigest } from './ml/integration';
import { buildAliasMap } from '../src/utils/cpeMatcher';
import { resolveTimezone as resolveSettingsTimezone } from '../src/utils/dateTime';
import { DEFAULT_SETTINGS } from '../shared/state';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  renderDailyDigest,
  renderDailyFindingSummary,
  renderDailyHealthReport,
  renderHeldForReview,
  type DailyDigestParts,
  digestSeveritySummary,
  digestSeverityKpi,
  formatExecutiveSummary,
  formatExecutiveSummaryText,
  countDigestSeverities,
  formatDigestSeverityCounts,
  type DigestFinding,
} from '../src/utils/templateCompiler';
import type {
  Advisory,
  AliasEntry,
  NormalizedCVE,
  WatchListItem,
  AppSettings,
  EmailRecipient,
  Finding,
  TemplateCustomization,
} from '../src/types/index';

/** Advisory-lock class dedicated to the daily digest, distinct from the burst-digest lock (800003). */
const DAILY_LOCK_CLASS = 800004;
const DAILY_SCHEDULE_ID = 'dailyDigest-schedule';
/** Upper bound on a health probe's lock wait, so one stuck read cannot stall the digest. */
const HEALTH_PROBE_LOCK_TIMEOUT_MS = 5_000;
const SEVERITY_RANK: Advisory['severity'][] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/**
 * Daily digest subscription.
 *
 * Unlike the burst digest (which coalesces a live ingestion burst into one email
 * per recipient), the daily digest is a calendar job: once per day, in the
 * operator-configured timezone, it sends each opted-in recipient a single email
 * containing a rolled-up summary of that day's findings plus an operational
 * health-check report.
 *
 * The job is serialized with a session-level advisory lock (mirroring the burst
 * digest and retention workers) and de-duplicated per calendar day via a
 * `systemState` claim row, so a multi-tick window or a multi-replica deployment
 * cannot produce a second 9 AM mail.
 */

// The daily digest runs on the same clock as the UI: the operator-configured
// Settings timezone, or the documented system default when none is stored or
// the stored value is not a zone this runtime knows.
const resolveTimezone = (value: string | undefined): string => resolveSettingsTimezone(value);

const calendarDateKey = (timezone: string, now: number): string =>
  new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(now);

const DIGEST_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// The calendar date is captured in `en-CA` (YYYY-MM-DD) for use as the stable
// advisory-id / de-duplication key. The human-facing title and email subject
// instead render it as ddMMMyyyy (e.g. 31Oct2026) per the daily digest format.
const formatDigestDate = (dateKey: string): string => {
  const [year, month, day] = dateKey.split('-');
  if (!year || !month || !day) return dateKey;
  const monthName = DIGEST_MONTHS[Number(month) - 1];
  return `${day.padStart(2, '0')}${monthName ?? month}${year}`;
};

const wallClock = (timezone: string, now: number): { hour: number; minute: number } => {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    hourCycle: 'h23',
    hour: 'numeric',
    minute: '2-digit',
  }).formatToParts(now);
  let hour = 0;
  let minute = 0;
  for (const part of parts) {
    if (part.type === 'hour') hour = Number(part.value);
    else if (part.type === 'minute') minute = Number(part.value);
  }
  return { hour, minute };
};

const parseTime = (value: string | undefined): { hour: number; minute: number } => {
  const [h, m] = String(value ?? '09:00')
    .split(':')
    .map(Number);
  return { hour: Number.isFinite(h) ? h : 9, minute: Number.isFinite(m) ? m : 0 };
};

async function readDailyDigestConfig(db: Db): Promise<TemplateCustomization> {
  const row = await get<{ dailyDigestCustomization?: TemplateCustomization }>(db, 'template', 'main');
  return row?.dailyDigestCustomization || DEFAULT_DAILY_DIGEST_CUSTOMIZATION;
}

async function readDailyDigestTemplate(db: Db): Promise<string | null> {
  const row = await get<{ dailyDigestCustomTemplate?: string | null }>(db, 'template', 'main');
  return row?.dailyDigestCustomTemplate ?? null;
}

const severityRank = (s: Advisory['severity']) => SEVERITY_RANK.indexOf(s);

const buildRemediationInstructions = (findings: Finding[]): string => {
  const criticals = findings.filter((f) => f.cve.cvss.severity === 'CRITICAL');
  const weaponized = findings.filter(
    (f) => f.cve.exploitStatus === 'Active Weaponized' || f.cve.exploitStatus === 'POC Available',
  );
  const kev = findings.filter((f) => f.cve.cisaKev?.isKev);

  const steps: string[] = [];

  if (kev.length > 0) {
    steps.push(
      `Immediately patch the ${kev.length} CISA Known Exploited Vulnerability${kev.length > 1 ? 'ies' : ''} listed above per the vendor advisory and your CISA KEV remediation timeline.`,
    );
  }
  if (criticals.length > 0 && kev.length === 0) {
    steps.push(
      `Prioritize remediation of the ${criticals.length} Critical-severity finding${criticals.length > 1 ? 's' : ''} above all other items; confirm active exploitation status via your threat intelligence feeds.`,
    );
  }
  if (weaponized.length > 0) {
    steps.push(
      `${weaponized.length} finding${weaponized.length > 1 ? 's' : ''} has active exploit${weaponized.length > 1 ? 's' : ''} in the wild — treat as priority and implement compensating controls if patching is not immediately feasible.`,
    );
  }

  steps.push(
    `Review each finding's applicability against your inventory, apply vendor patches via your change management process, and validate backups before and after remediation.`,
  );

  if (findings.some((f) => f.confidence !== undefined && f.confidence < 90)) {
    steps.push(
      'Findings with confidence below 90% require manual verification — confirm asset applicability and version evidence before acting.',
    );
  }

  return steps.join(' ');
};

const buildDailyDigestAdvisory = (findings: Finding[], settings: AppSettings, dateKey: string): Advisory => {
  const cveIds = Array.from(new Set(findings.map((finding) => finding.cveId))).sort();
  const severity = findings.reduce<Advisory['severity']>(
    (severity, finding) =>
      severityRank(finding.cve.cvss.severity) > severityRank(severity) ? finding.cve.cvss.severity : severity,
    'UNKNOWN',
  );
  const severityCounts = countSeverities(findings);
  return {
    id: `${settings.advisoryPrefix}DAILY_${dateKey.replace(/-/g, '')}`,
    title: `Daily Vulnerability Notification — ${formatDigestDate(dateKey)}`,
    severity,
    cveIds,
    findingIds: findings.map((finding) => finding.id),
    createdDate: new Date().toISOString(),
    deliveryStatus: 'PENDING',
    recipientCount: 0,
    executiveSummary: formatExecutiveSummaryText(findings.length, severityCounts),
    remediationInstructions: buildRemediationInstructions(findings),
    vendorLink:
      Array.from(
        new Set(
          findings
            .map((finding) => finding.cve.remediation?.vendorAdvisoryRef || finding.cve.remediation?.patchUrl)
            .filter(Boolean),
        ),
      ).sort()[0] || '',
    affectedSystems: Array.from(new Set(findings.map((finding) => finding.matchedAssetName))).sort(),
    isDigestBatch: true,
  };
};

const formatSeverityCounts = formatDigestSeverityCounts;

/** Delegates to the canonical bucket counter; see `countDigestSeverities`. */
const countSeverities = (findings: Finding[]): Record<string, number> =>
  countDigestSeverities(findings.map((finding) => ({ severity: finding.cve?.cvss?.severity })));

const formatReportGenerated = (date: Date, timezone: string): string => {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone,
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'shortOffset',
  }).formatToParts(date);
  const day = parts.find((p) => p.type === 'day')?.value || '';
  const month = parts.find((p) => p.type === 'month')?.value || '';
  const year = parts.find((p) => p.type === 'year')?.value || '';
  const hour = parts.find((p) => p.type === 'hour')?.value || '';
  const minute = parts.find((p) => p.type === 'minute')?.value || '';
  const tz = parts.find((p) => p.type === 'timeZoneName')?.value || '';
  return `${day} ${month} ${year} | ${hour}:${minute} ${tz}`;
};

interface HealthSnapshot {
  database: 'connected' | 'degraded';
  databaseLatencyMs: number;
  workerStatus: 'DISABLED' | 'NOT_OBSERVED' | 'STALE' | 'HEALTHY';
  workerHeartbeatAgeSeconds: number | null;
  nextScheduledAttempt: string | null;
  nextDailyDigestAt: string | null;
  backlog: { status: string; count: number }[];
  checkedAt: string;
  systemUptime: string;
  systemUptimePercentage: number | null;
  pipelineJobs: { total: number; succeeded: number; failed: number };
}

async function computeHealth(
  db: Db,
  workerEnabled: boolean,
  workerHeartbeat: string | null,
  timezone: string,
  time: string,
  now: number,
): Promise<HealthSnapshot> {
  const start = performance.now();
  let database: HealthSnapshot['database'] = 'connected';
  // This runs inside the transaction that already claimed the digest day. When
  // `db` is that transaction's client, any failing statement (a missing table, a
  // permission error, an aborted statement) leaves the transaction in the
  // 25P02 "current transaction is aborted" state: the `catch` below swallowed
  // the error and every later statement in the digest failed, so a health-probe
  // fault rolled back the claim and the day's findings were never delivered.
  // A savepoint makes each health probe recoverable: a failure rolls back to it
  // and the digest continues with a degraded health section.
  const guardedHealthQuery = async <T>(run: () => Promise<T>): Promise<T | undefined> => {
    let savepoint = false;
    try {
      await db.query('SAVEPOINT daily_health');
      savepoint = true;
    } catch {
      // A server that does not support savepoints (or a connection outside a
      // transaction) still gets the plain behavior below.
    }
    // These are read-only probes. Without a bound, one probe parked behind a
    // held lock would block the digest (and its day claim) indefinitely. The
    // value is captured and restored afterwards: leaving 5s in place silently
    // applied it to the finding reads, claim writes and enqueue below, so a
    // transient lock on the outbox turned a healthy digest into a failure.
    const priorLockTimeout = (
      await db
        .query<{ value: string }>("SELECT current_setting('lock_timeout') AS value")
        .catch(() => undefined)
    )?.rows[0]?.value;
    try {
      await db.query(`SET LOCAL lock_timeout = '${HEALTH_PROBE_LOCK_TIMEOUT_MS}ms'`);
    } catch {
      // Outside a transaction SET LOCAL is a no-op/errorless; either way the
      // probe below still runs.
    }
    try {
      const result = await run();
      if (savepoint) await db.query('RELEASE SAVEPOINT daily_health').catch(() => undefined);
      return result;
    } catch {
      if (savepoint) await db.query('ROLLBACK TO SAVEPOINT daily_health').catch(() => undefined);
      throw new Error('health query failed');
    } finally {
      if (priorLockTimeout !== undefined)
        await db.query(`SET LOCAL lock_timeout = '${priorLockTimeout}'`).catch(() => undefined);
    }
  };
  try {
    await guardedHealthQuery(() => db.query('SELECT 1'));
  } catch {
    database = 'degraded';
  }
  const databaseLatencyMs = Math.round(performance.now() - start);
  const heartbeatMs = workerHeartbeat ? Date.parse(workerHeartbeat) : NaN;
  const workerHeartbeatAgeSeconds = Number.isFinite(heartbeatMs)
    ? Math.max(0, Math.floor((Date.now() - heartbeatMs) / 1000))
    : null;
  const workerStatus: HealthSnapshot['workerStatus'] = !workerEnabled
    ? 'DISABLED'
    : workerHeartbeatAgeSeconds === null
      ? 'NOT_OBSERVED'
      : workerHeartbeatAgeSeconds > 90
        ? 'STALE'
        : 'HEALTHY';
  // The health report is secondary. A transient queue-table/query failure must
  // not abort the whole daily digest after the day has already been claimed, or
  // the findings would never be delivered.
  let deliveryQueue: { nextScheduledAttempt: string | null } | undefined;
  let backlog: { status: string; count: number }[] = [];
  try {
    const deliveryQueueResult = await guardedHealthQuery(() =>
      db.query<{
        nextScheduledAttempt: string | null;
        expiredLeases: number;
      }>(
        `SELECT
           min(next_attempt) FILTER (WHERE status='QUEUED' AND next_attempt>now()) AS "nextScheduledAttempt",
           count(*) FILTER (WHERE status='SENDING' AND locked_at<now()-interval '2 minutes')::int AS "expiredLeases"
         FROM outbox WHERE status IN ('QUEUED','SENDING')`,
      ),
    );
    deliveryQueue = deliveryQueueResult?.rows[0];
    const backlogResult = await guardedHealthQuery(() =>
      db.query<{ status: string; count: number }>(
        // ACCEPTED is required: the health report derives "Processed" from it.
        // Without it every digest reported `0 processed` next to a non-zero
        // backlog, which reads as a stuck queue even on a healthy day.
        `SELECT status,count(*)::int AS count FROM outbox
          WHERE status IN ('QUEUED','SENDING','FAILED','REVIEW','ACCEPTED')
          GROUP BY status`,
      ),
    );
    backlog = backlogResult?.rows ?? [];
  } catch {
    database = 'degraded';
  }
  // Pipeline execution summary for the last 24 hours, derived from audit events.
  // Events: Pipeline queued / completed / failed / recovered / authoritative auto-dispatch.
  let pipelineJobs = { total: 0, succeeded: 0, failed: 0 };
  try {
    const pipelineAudit = await guardedHealthQuery(() =>
      db.query<{ event: string; count: string }>(
        `SELECT data->>'event' AS event, count(*)::int AS count
         FROM audit
         WHERE data->>'category' = 'PIPELINE'
           AND (data->>'timestamp')::timestamptz > now() - interval '24 hours'
           AND data->>'event' IN ('Pipeline queued','Pipeline completed','Pipeline failed','AUTHORITATIVE_AUTO_DISPATCH','Pipeline recovered')
         GROUP BY data->>'event'`,
      ),
    );
    for (const row of pipelineAudit?.rows ?? []) {
      const count = Number(row.count);
      pipelineJobs.total += count;
      if (
        row.event === 'Pipeline completed' ||
        row.event === 'AUTHORITATIVE_AUTO_DISPATCH' ||
        row.event === 'Pipeline recovered'
      ) {
        pipelineJobs.succeeded += count;
      } else if (row.event === 'Pipeline failed') {
        pipelineJobs.failed += count;
      }
    }
  } catch {
    // Non-fatal: pipeline stats are informational only.
  }
  const uptimeSeconds = process.uptime();
  const uptimeDays = Math.floor(uptimeSeconds / 86400);
  const uptimeHours = Math.floor((uptimeSeconds % 86400) / 3600);
  const dayWord = uptimeDays === 1 ? 'Day' : 'Days';
  const hourWord = uptimeHours === 1 ? 'Hour' : 'Hours';
  const systemUptime = `${uptimeDays} ${dayWord} ${uptimeHours} ${hourWord}`;
  // Today's digest is already claimed. Use the next local calendar day, not
  // 24 elapsed hours, so DST changes preserve the configured send time.
  // The row lock on the schedule row is already held by this transaction, but
  // this statement and the heartbeat read below were NOT guarded: a failure
  // (missing table, malformed `daily.time` such as "25:00" producing an invalid
  // `time` literal) aborted the transaction *after* the day's findings were
  // selected, and every subsequent tick failed the same way — a poison digest.
  // Both are now savepoint-guarded like the outbox probes, degrading the health
  // section instead of losing the day's delivery.
  const { hour, minute } = parseTime(time);
  let nextDailyDigestAt: string;
  try {
    const nextRun = await guardedHealthQuery(() =>
      db.query<{ nextDailyDigestAt: Date }>(
        `SELECT (($1::timestamptz AT TIME ZONE $2)::date + 1 + $3::time)
           AT TIME ZONE $2 AS "nextDailyDigestAt"`,
        [new Date(now).toISOString(), timezone, `${hour}:${String(minute).padStart(2, '0')}`],
      ),
    );
    const nextDate = nextRun?.rows[0]?.nextDailyDigestAt;
    if (!(nextDate instanceof Date) || Number.isNaN(nextDate.getTime())) throw new Error('bad next-run row');
    nextDailyDigestAt = nextDate.toISOString();
  } catch {
    database = 'degraded';
    // Best-effort fallback: the server-side calendar expression is authoritative
    // for DST correctness, but the digest must still render. One plain 24h
    // offset can be wrong across a DST boundary; it is labelled degraded so the
    // operator knows it is approximate.
    nextDailyDigestAt = new Date(now + 86_400_000).toISOString();
  }
  return {
    database,
    databaseLatencyMs,
    workerStatus,
    workerHeartbeatAgeSeconds,
    nextScheduledAttempt: deliveryQueue?.nextScheduledAttempt ?? null,
    nextDailyDigestAt,
    backlog,
    checkedAt: new Date().toISOString(),
    systemUptime, // worker-process uptime, kept for continuity
    systemUptimePercentage: null,
    pipelineJobs,
  };
}

/**
 * Runs the daily digest job. Returns the number of transport jobs queued (0 when
 * the job is not scheduled/claimed, disabled, already sent today, or no recipient
 * has opted in). Intended to be polled on a short interval by the worker; the
 * claim logic guarantees at-most-once execution per calendar day per timezone.
 */
export async function runDailyDigest(pool: pg.Pool, signal?: AbortSignal): Promise<number> {
  const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
  const daily = settings.dailyDigest || DEFAULT_SETTINGS.dailyDigest;
  if (!daily?.enabled) return 0;

  const timezone = resolveTimezone(settings.timezone);
  const now = Date.now();
  const todayKey = calendarDateKey(timezone, now);
  const nowClock = wallClock(timezone, now);
  const targetClock = parseTime(daily.time);
  const pastTarget = nowClock.hour * 60 + nowClock.minute >= targetClock.hour * 60 + targetClock.minute;

  if (!pastTarget) return 0;

  const client = await pool.connect();
  let locked = false;
  let failed = false;
  try {
    // Abort early if the run was cancelled (shutdown, leadership loss, stall watchdog).
    signal?.throwIfAborted();

    // Cheap pre-check without the advisory lock: every tick after the send time
    // (and after today's digest already ran) would otherwise take the session
    // lock and write two INFO events per replica per minute — thousands of
    // no-op events per day. The locked path re-checks the claim row, so a stale
    // pre-check can only cause one extra serialized read, never a duplicate
    // send.
    const precheck = (
      await pool.query<{ data: { lastKey?: string } | null }>(
        "SELECT data FROM records WHERE kind='systemState' AND id=$1",
        [DAILY_SCHEDULE_ID],
      )
    ).rows[0]?.data;
    if (precheck?.lastKey === todayKey) return 0;

    // ATOMIC: Use try_advisory_lock to prevent race conditions
    // ATOMIC: take the digest class lock through the documented order guard so
    // a concurrent holder of a lower-ranked class cannot deadlock here.
    locked = await acquireSessionClassLock(client, DAILY_LOCK_CLASS, schemaLockKey);
    if (!locked) {
      // A peer holding the lock is normal multi-replica behaviour, not an
      // operational event worth a log row per minute.
      return 0;
    }

    return await transaction(
      pool,
      async (db) => {
        const row = await db.query<{ data: Record<string, unknown> }>(
          `SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE`,
          [DAILY_SCHEDULE_ID],
        );
        const data = row.rows[0]?.data ?? {};

        const allRecipients = await list<EmailRecipient>(db, 'recipients');
        // One physical mailbox receives at most one digest. Duplicate recipient
        // configurations that share an address are collapsed to the widest
        // subscription (the same rule the consolidated finding/news queues use).
        // The digest is its own stream in the multi-select subscription list, so
        // an operator opts in by selecting DAILY_DIGEST rather than relying on
        // the separate boolean flag alone (which is still honoured by the
        // normaliser for records written before multi-select).
        const recipients = uniqueEnabledEmailRecipients(dailyDigestRecipients(allRecipients));
        // The day is claimed only when there is somebody to send to. Claiming it
        // first meant that a tick running before any recipient opted in (or with
        // every recipient temporarily disabled) burned the whole day: the claim
        // request repeated every minute, reported "queued for 0 recipient(s)",
        // and never delivered the findings that were right there in the window.
        // A recipient added later that same day now still receives the digest.
        if (!recipients.length) {
          await put(db, 'systemState', DAILY_SCHEDULE_ID, {
            ...data,
            lastCheckedAt: new Date(now).toISOString(),
          });
          await writeEvent(db, {
            category: 'EMAIL',
            level: 'INFO',
            code: 'digest.daily.no_recipients',
            message: 'Daily digest is enabled but no recipients have opted in',
            context: { date: todayKey, time: daily.time, timezone },
          });
          return 0;
        }
        if (data.lastKey === todayKey) {
          await put(db, 'systemState', DAILY_SCHEDULE_ID, {
            ...data,
            lastCheckedAt: new Date(now).toISOString(),
          });
          return 0;
        }
        // Commit the claim before queueing so a crash mid-send cannot re-fire
        // today's digest.
        await put(db, 'systemState', DAILY_SCHEDULE_ID, {
          ...data,
          lastKey: todayKey,
          lastRun: new Date(now).toISOString(),
          lastRecipients: recipients.length,
        });

        const findingRows = await db.query<{ data: Finding }>(
          `SELECT data FROM records WHERE kind='findings' AND created_at > now() - interval '24 hours'`,
        );
        // A daily digest is a summary of the last 24 hours of findings that are
        // still real. Eligibility here is about the *finding*, never about
        // whether some email already mentioned it: `notificationStatus` is
        // written at match time — before anything is sent — so excluding
        // dispatch states here emptied the digest for every freshly matched
        // finding and silently suppressed the whole summary.
        //
        // De-duplication against the consolidated finding email is per recipient
        // and happens below, from the durable `delivery_claims` receipt, which is
        // the only record that answers "has THIS recipient been told?".
        const candidates: Finding[] = findingRows.rows
          .map((r) => r.data)
          .filter(
            (f) =>
              f &&
              f.cveId &&
              !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(f.status) &&
              // States in which the finding can never be summarised, whatever the
              // recipient: it does not apply, a VEX ruling suppressed it, or its
              // own delivery failed permanently.
              !['NOT_APPLICABLE', 'SUPPRESSED_VEX_NOT_AFFECTED', 'DELIVERY_FAILED'].includes(
                f.notificationStatus,
              ) &&
              // Already carried by an advisory that was raised and delivered as
              // its own email; repeating it in the summary would duplicate it.
              !f.advisoryId,
          );

        // Reassess against today's inventory and policy, including findings
        // held under an older threshold. Never treat a stored hold as approval.
        const ids = [...new Set(candidates.map((f) => f.cveId))];
        // Serial, not Promise.all: `db` is one pooled client inside this
        // transaction, and pg serialises (and deprecates) concurrent queries on
        // a single connection. Issuing four at once races the protocol queue and
        // the results are only ordered by luck.
        const cached = await getMany<NormalizedCVE>(db, 'cveData', ids);
        // The inventory is read as records, not as a map. `getMany` returns a
        // `Map<id, data>`, so passing `.values()` handed the engine the raw JSONB
        // values (plain objects with no methods, untyped) instead of
        // `WatchListItem`s; every asset then failed `assetsForCve`, the rematch
        // produced zero findings, and the digest fell through to the stored-
        // finding path with an empty result. That is what rendered "0 TOTAL
        // FINDINGS / 0 ASSETS" on a day with real matches. The pipeline's own
        // snapshot uses `list<WatchListItem>`; this does the same.
        const assets = await list<WatchListItem>(db, 'watchlist');
        const withdrawals = await getMany<{ modifiedDate: string }>(db, 'cveWithdrawals', ids);
        const aliases = await list<AliasEntry>(db, 'aliases');
        // Build the corpus from real CVE records only. `|| f.cve` was a truthiness
        // check on a `Map#get` result, so a candidate whose cache row was pruned
        // put the finding's own embedded copy (possibly a stale or partial object)
        // into the corpus and reported itself as newly matched. A finding with no
        // cached CVE is handled by the stored-deliverable fallback below.
        const cves: NormalizedCVE[] = [];
        for (const candidate of candidates) {
          const cve = cached.get(candidate.cveId);
          if (cve?.cveId) cves.push(cve);
        }
        const current = runVulnerabilityPipeline(
          [],
          cves,
          assets,
          [],
          [],
          { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
          'Daily digest',
          false,
          buildAliasMap(aliases, 'VENDOR'),
          buildAliasMap(aliases, 'PRODUCT'),
          undefined,
          aliases,
        ).newFindings;
        const matches = new Map(current.map((f) => [`${f.cveId}:${f.matchedAssetId}`, f]));
        const findings = candidates.flatMap((f) => {
          const match = matches.get(`${f.cveId}:${f.matchedAssetId}`);
          const withdrawal = withdrawals.get(f.cveId);
          // A withdrawn CVE is never summarised: the advisory no longer applies.
          // The comparison is on the cached revision date. An unparseable or
          // missing `modifiedDate` used to yield NaN, and `NaN <= x` is false, so
          // a finding whose cached CVE had no revision date survived every
          // withdrawal check and was summarised after the advisory was pulled.
          // Unknown provenance now counts as potentially pre-withdrawal.
          const modifiedMs = Date.parse(f.cve?.modifiedDate ?? '');
          if (
            withdrawal &&
            (!Number.isFinite(modifiedMs) || modifiedMs <= Date.parse(withdrawal.modifiedDate))
          )
            return [];
          // The rematch is authoritative when it produced a verdict. When it did
          // not, the finding must not silently vanish from the digest: that
          // happens when the CVE cache entry was pruned by retention or the
          // inventory item was disabled after the finding was created, neither
          // of which invalidates the delivery that was already queued. Such a
          // finding keeps its stored (already-delivered) applicability.
          // A held (limited-confidence) match is summarised like any other: there
          // is no review queue, and the rendered document states the confidence
          // limitation and its reason on the finding itself. Dropping it here
          // silently hid real exposure from the daily summary.
          if (match) return [{ ...f, ...match, id: f.id }];
          const storedDeliverable =
            f.notificationStatus === 'QUEUED_FOR_DISPATCH' ||
            f.notificationStatus === 'AUTO_DISPATCHED' ||
            f.notificationStatus === 'DELIVERED';
          return storedDeliverable ? [f] : [];
        });

        // Attach the workspace timezone so the server-rendered timestamps match
        // every other view in the product instead of hard-coding UTC.
        const dailyConfig = { ...(await readDailyDigestConfig(db)), timezone };
        const dailyDigestTemplate = await readDailyDigestTemplate(db);
        const advisory = buildDailyDigestAdvisory(findings, settings, todayKey);
        // Count of findings dispatched today with a stated confidence limitation.
        // There is no review queue: the figure tells the team how many alerts need
        // a follow-up applicability check, and is the same on every recipient's
        // email because a limited-confidence finding is not tier-specific.
        const heldForReview = findingRows.rows.filter(
          (r) => r.data?.cveId && r.data.notificationStatus === 'REVIEW_REQUIRED',
        ).length;
        // The heartbeat read used to be unguarded; a missing or unreadable
        // scheduler_state table aborted the whole transaction after the day had
        // been selected, losing the digest over an informational field.
        const workerRow = await (async () => {
          try {
            return await db.query<{ heartbeat: string | null }>(
              'SELECT heartbeat FROM scheduler_state WHERE id=1',
            );
          } catch {
            // Informational field only; a missing/unreadable scheduler_state
            // table must not abort a transaction that already holds the day's
            // claim and has the findings selected.
            return undefined;
          }
        })();
        const worker = workerRow?.rows[0];
        const health = daily.includeHealthReport
          ? await computeHealth(
              db,
              settings.schedulerEnabled,
              worker?.heartbeat ?? null,
              timezone,
              daily.time,
              now,
            )
          : null;
        const healthReportHtml = health ? renderDailyHealthReport(health, dailyConfig) : '';
        // No findings and no health report means there is nothing to email. Skip
        // enqueueing to avoid deliverNext rejecting an empty advisory as stale
        // and triggering a futile pipeline rebuild every day.
        if (!findings.length && !health) {
          await writeEvent(db, {
            category: 'EMAIL',
            level: 'INFO',
            code: 'digest.daily.no_findings',
            message: 'Daily digest skipped: no findings in the last 24 hours and health report disabled',
            context: { date: todayKey },
          });
          return 0;
        }
        // Per-recipient de-duplication against the consolidated finding email.
        // `delivery_claims` records, per recipient, which findings that mailbox
        // has been told about, so a recipient that already received an immediate
        // consolidated email does not see the same findings repeated here — while
        // a recipient added after that email still gets them. This replaces the
        // global `notificationStatus` filter that could not tell "already
        // emailed" from "matched but never sent".
        const deliveredToRecipient = await activeClaims(
          db,
          allRecipients.map((recipient) => recipient.id),
          'finding',
          findings.map((finding) => finding.id),
        );
        // Two recipient records can share one mailbox. The consolidated path
        // treats them as one delivery target, so their receipts are unioned here
        // as well or the digest would re-send what the mailbox already has.
        const mailboxReceived = (recipient: EmailRecipient): Set<string> => {
          const received = new Set<string>();
          const mailbox = recipient.email.trim().toLowerCase();
          for (const alias of allRecipients)
            if (alias.email.trim().toLowerCase() === mailbox)
              for (const findingId of deliveredToRecipient.get(alias.id) ?? []) received.add(findingId);
          return received;
        };
        let jobs = 0;
        for (const recipient of recipients) {
          signal?.throwIfAborted();
          // Relevance ranks eligible findings; it must never override subscriptions or hide an alert.
          const received = mailboxReceived(recipient);
          const candidate = findings
            .filter((finding) => recipientAllows(recipient, finding) && !received.has(finding.id))
            .map((finding) => ({
              finding,
              relevance: shouldSelectForDigest({
                cvssScore: finding.cve.cvss.score,
                epssScore: finding.cve.epss?.score ?? 0,
                cisaKev: finding.cve.cisaKev?.isKev === true,
                exploitStatus: Math.max(
                  0,
                  ['None', 'POC Available', 'Reported In Wild', 'Active Weaponized'].indexOf(
                    finding.cve.exploitStatus,
                  ),
                ),
                daysSincePublished:
                  Math.max(0, (Date.now() - Date.parse(finding.cve.publishedDate)) / 86400000) || 0,
                sourceFeedWeight: 0,
                credibilityScore: finding.confidence ?? 0,
                assetCriticality: 0,
                recipientTier: 'SUBSCRIBED_ONLY',
                findingInDigest: true,
                timeInDigestMinutes: 0,
              }),
            }))
            .sort((a, b) => b.relevance - a.relevance)
            .map(({ finding }) => finding);
          // Write side of the claim. The `activeClaims` read above is only an
          // optimization: it cannot serialise two concurrent queue passes. The
          // claim is taken in this same transaction as the enqueue, so a digest
          // and a consolidated finding email racing for the same mailbox can
          // never both carry the same finding.
          let claimed: ReturnType<typeof claimsForJob> = [];
          let included = candidate;
          if (candidate.length) {
            const claim = await claimItems(
              db,
              claimsForJob(
                recipient.id,
                'finding',
                candidate.map((finding) => finding.id),
              ),
            );
            claimed = claim.granted;
            const granted = new Set(claimed.map((request) => request.itemId));
            included = candidate.filter((finding) => granted.has(finding.id));
          }
          // An email that carries no findings and no health report has nothing to
          // say. Previously only the health-less case was skipped, so a recipient
          // whose findings were all already delivered got a digest headed with
          // "0 TOTAL FINDINGS / 0 ASSETS" beside a health table — a contradictory
          // document that also read as "nothing happened today". The day is still
          // recorded above, so this is not a reason to retry.
          if (!included.length && !(health && healthReportHtml)) continue;
          const view = buildDailyDigestAdvisory(included, settings, todayKey);
          const severityCounts = countSeverities(included);
          const criticalCount = severityCounts.CRITICAL ?? 0;
          const highCount = severityCounts.HIGH ?? 0;
          const mediumCount = severityCounts.MEDIUM ?? 0;
          const lowCount = severityCounts.LOW ?? 0;
          // `asset_count` is "assets with at least one finding in this email", the
          // same scope as every other KPI on the card. When the recipient has no
          // findings (health-report-only digest) it must be 0, not the size of a
          // set built from an empty list under a different name.
          const uniqueAssets = new Set(included.map((finding) => finding.matchedAssetId).filter(Boolean));
          const reportGenerated = formatReportGenerated(new Date(), timezone);
          // Keep the narrative's scope and counts identical to the recipient's KPIs.
          const executiveSummary = formatExecutiveSummary(included.length, severityCounts);
          const parts: DailyDigestParts = {
            advisory_id: view.id,
            advisory_title: view.title,
            dispatch_date: new Date().toISOString(),
            severity: view.severity,
            finding_count: included.length,
            severity_counts: formatSeverityCounts(severityCounts),
            findings_summary: renderDailyFindingSummary(
              included.map((finding) => ({
                cveId: finding.cveId,
                severity: finding.cve.cvss.severity,
                assetName: finding.matchedAssetName,
                vendor: finding.matchedAssetVendor,
                sourceUrl: `https://nvd.nist.gov/vuln/detail/${finding.cveId}`,
                cvssScore: finding.cve.cvss.score,
                exploitStatus: finding.cve.exploitStatus,
                epssScore: finding.cve.epss?.score,
                cisaKev: finding.cve.cisaKev?.isKev,
              })),
              dailyConfig,
            ),
            health_report: healthReportHtml,
            recipient_name: recipient.name || recipient.email,
            critical_count: criticalCount,
            high_count: highCount,
            medium_count: mediumCount,
            low_count: lowCount,
            asset_count: uniqueAssets.size,
            executive_summary: executiveSummary,
            report_generated: reportGenerated,
            held_for_review: renderHeldForReview(heldForReview, dailyConfig),
            critical_summary: digestSeveritySummary('CRITICAL', criticalCount, dailyConfig),
            high_summary: digestSeveritySummary('HIGH', highCount, dailyConfig),
            medium_summary: digestSeveritySummary('MEDIUM', mediumCount, dailyConfig),
            low_summary: digestSeveritySummary('LOW', lowCount, dailyConfig),
            critical_kpi: digestSeverityKpi('CRITICAL', criticalCount, dailyConfig),
            high_kpi: digestSeverityKpi('HIGH', highCount, dailyConfig),
            medium_kpi: digestSeverityKpi('MEDIUM', mediumCount, dailyConfig),
            low_kpi: digestSeverityKpi('LOW', lowCount, dailyConfig),
          };
          const html = renderDailyDigest(dailyConfig, parts, dailyDigestTemplate ?? undefined);
          // Recorded so approval can prove the stored body is unchanged. The
          // union `advisory` here is built from every recipient's findings, so a
          // recipient-specific view must not be re-hashed against it.
          const contentRevision = advisoryRevision(view, included);
          const payload = {
            ...advisoryEmail(view, html, undefined, { findings: included }),
            cveIds: view.cveIds,
            recipientEmail: recipient.email,
            includedFindingIds: included.map((finding) => finding.id),
            // Content-revision evidence, so the delivery worker can prove the
            // queued body still describes the current CVE cache instead of
            // rejecting it as a revision-less legacy payload.
            findingRevisions: Object.fromEntries(
              included.map((finding) => [finding.id, findingRevision(finding)]),
            ),
            cveRevisions: Object.fromEntries(
              included.map((finding) => [finding.cveId, revision(finding.cve)]),
            ),
            digestKey: `daily:${todayKey}`,
            contentRevision,
            dailyDigest: true,
          };
          const dedupeKey = `daily:${todayKey}:email:${recipient.id}`;
          const jobId = await enqueue(
            db,
            'email',
            recipient.id,
            advisory.id,
            payload,
            dedupeKey,
            // Every recipient receives the digest: there is no review queue.
            'QUEUED',
          );
          if (jobId) {
            // The claim and the outbox job are committed together, so the
            // delivery worker promotes exactly the claims this digest carried.
            if (claimed.length) await attachClaimsToJob(db, jobId, claimed);
            jobs++;
          } else if (claimed.length) {
            // The outbox dedupe key already existed (or email delivery is
            // disabled). Never leak the claims taken above: attach them to the
            // existing job, promote an accepted receipt, or release them when
            // no job can possibly send.
            await reconcileDuplicateOutboxClaims(db, dedupeKey, claimed);
          }
        }

        advisory.recipientCount = jobs;
        advisory.deliveryStatus = 'PENDING';
        await put(db, 'advisories', advisory.id, advisory);
        await writeEvent(db, {
          category: 'EMAIL',
          level: 'INFO',
          code: 'digest.daily.sent',
          message: `Daily digest queued for ${jobs} recipient(s) with ${findings.length} finding(s)`,
          context: {
            advisoryId: advisory.id,
            recipients: jobs,
            findings: findings.length,
            heldForReview,
            date: todayKey,
            time: daily.time,
            timezone,
          },
        });
        return jobs;
      },
      client,
      { signal },
    );
  } catch (error) {
    // A transport-level failure can leave the connection unusable; release with
    // the failure flag so the pool destroys it instead of recycling it.
    failed = true;
    throw error;
  } finally {
    // Inspect the unlock result; a lock that was not actually released must not
    // go back to the pool, or a later checkout would appear to own the daily
    // digest lock and silently suppress the next day's send. Destroying the
    // connection is safe because PostgreSQL drops a session's advisory locks
    // when the backend terminates.
    if (locked && !(await safeAdvisoryUnlock(client, DAILY_LOCK_CLASS, schemaLockKey, 'daily-digest'))) {
      failed = true;
    }
    client.release(failed);
  }
}
