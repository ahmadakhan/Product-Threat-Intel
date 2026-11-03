import type { Db } from '../../db.ts';
import type { Finding, EmailDeliveryLog, IntelligenceArticle, IntelligenceMatch } from '../../../src/types/index.ts';
import { parseCPE23 } from '../../../src/utils/cpeMatcher.ts';
import { FEED_WEIGHTS } from '../../../src/utils/intelligenceMatcher.ts';
import type { FindingFeatures } from '../models/reviewRanker.ts';
import type { CronTrainingData } from './cron.ts';
import type { TrainingDataSources } from './orchestrator.ts';

const finite = (value: unknown, fallback = 0) =>
  typeof value === 'number' && Number.isFinite(value) ? value : fallback;
const daysSince = (value: string | undefined) => {
  const time = Date.parse(value || '');
  return Number.isFinite(time) ? Math.max(0, (Date.now() - time) / 86_400_000) : 0;
};

/** Read the application schema, not the separate native text-correlation tables. */
export class CronDataProvider {
  private snapshot?: Promise<Finding[]>;
  constructor(readonly lookbackDays = 30) {}
  private cutoff() {
    return new Date(Date.now() - this.lookbackDays * 86_400_000).toISOString();
  }

  private async loadFindings(db: Db): Promise<Finding[]> {
    const result = await db.query<{ data: Finding }>(
      "SELECT data FROM records WHERE kind='findings' AND updated_at >= $1 ORDER BY id",
      [this.cutoff()],
    );
    return result.rows.map((row) => row.data).filter((f) => f && f.cve && typeof f.cveId === 'string');
  }
  /** Memoized per provider instance so every collector shares one query. */
  private findings(db: Db): Promise<Finding[]> {
    this.snapshot ??= this.loadFindings(db);
    return this.snapshot;
  }

  private features(f: Finding): FindingFeatures {
    const version = parseCPE23(f.matchedCpe || '');
    const exploitStatus = ['None', 'Reported In Wild', 'POC Available', 'Active Weaponized'].indexOf(
      f.cve.exploitStatus,
    );
    return {
      matchConfidence: finite(f.confidence),
      cvssScore: finite(f.cve.cvss?.score),
      epssScore: finite(f.cve.epss?.score),
      cisaKev: f.cve.cisaKev?.isKev === true,
      exploitStatus: Math.max(0, exploitStatus),
      cweRiskLevel: 0,
      signalDensity: 0,
      matchMethod: f.matchingMethod,
      sourceFeedWeight: 0,
      assetCriticality: 0,
      hasVersionEvidence:
        version.isValid && !['*', '-'].includes(version.version) && !/[?*]/.test(version.version),
      daysSincePublished: daysSince(f.cve.publishedDate),
      negated: false,
    };
  }
  // A delivered email or an unresolved finding is not an analyst relevance label.
  private adjudicated(f: Finding) {
    return f.status === 'FALSE_POSITIVE' || f.status === 'PATCH_APPLIED';
  }

  async collectCpeStrings(db: Db): Promise<string[]> {
    const result = await db.query<{ kind: string; data: { matchedCpe?: string; cpes?: string[] } }>(
      "SELECT kind,data FROM records WHERE kind IN ('findings','watchlist') AND updated_at >= $1 ORDER BY kind,id",
      [this.cutoff()],
    );
    const values = result.rows.flatMap(({ kind, data }) =>
      kind === 'findings' ? [data.matchedCpe] : Array.isArray(data.cpes) ? data.cpes : [],
    );
    return [
      ...new Set(
        values.filter((value): value is string => typeof value === 'string' && parseCPE23(value).isValid),
      ),
    ];
  }

  async collectDispatchOutcomes(db: Db): Promise<CronTrainingData['dispatchOutcomes']> {
    return (await this.findings(db))
      .filter((f) => this.adjudicated(f))
      .map((f) => ({
        confidence: finite(f.confidence),
        dispatched: Boolean(f.autoDispatchedAt),
        wasFalsePositive: f.status === 'FALSE_POSITIVE',
        foundTruePositive: f.status === 'PATCH_APPLIED',
      }));
  }
  async collectReviewOutcomeHistory(db: Db): Promise<CronTrainingData['reviewOutcomeHistory']> {
    return (await this.findings(db))
      .filter((f) => this.adjudicated(f))
      .map((f) => {
        const times = (f.timeline || []).map((e) => Date.parse(e.timestamp)).filter(Number.isFinite);
        return {
          features: this.features(f),
          statusAfterReview: f.status === 'PATCH_APPLIED' ? 'PATCHED' : 'FALSE_POSITIVE',
          daysToAction:
            times.length > 1 ? Math.max(0, (Math.max(...times) - Math.min(...times)) / 86_400_000) : 0,
        };
      });
  }
  async collectRemediationFindings(db: Db): Promise<CronTrainingData['remediationFindings']> {
    return (await this.findings(db))
      .filter((f) => f.cve.remediation)
      .map((f) => {
        const features = this.features(f);
        return { features, playbook: { ...f.cve.remediation } };
      });
  }
  async collectMatchConfidenceSamples(db: Db): Promise<CronTrainingData['matchConfidenceSamples']> {
    return (await this.findings(db))
      .filter((f) => this.adjudicated(f))
      .map((f) => {
        const features = this.features(f);
        return {
          features: {
            ...features,
            versionVerifiedInRange: features.hasVersionEvidence && f.matchingMethod === 'STRICT_CPE_INTERVAL',
          },
          isTruePositive: f.status === 'PATCH_APPLIED',
        };
      });
  }
  async collectImportanceRankSamples(db: Db): Promise<CronTrainingData['importanceRankSamples']> {
    const reviewed = await this.collectReviewOutcomeHistory(db);
    return reviewed.map((row) => ({
      features: { ...row.features, credibilityScore: 0 },
      wasActionable: row.statusAfterReview === 'PATCHED',
      daysToAction: row.daysToAction,
    }));
  }
  async collectAliasConfidenceSamples(db: Db): Promise<CronTrainingData['aliasConfidenceSamples']> {
    return (await this.findings(db))
      .filter(
        (f) =>
          this.adjudicated(f) &&
          ['VENDOR_PRODUCT_ALIAS', 'VENDOR_PRODUCT_FALLBACK', 'KEYWORD'].includes(f.matchingMethod),
      )
      .map((f) => ({ features: this.features(f), isConfirmed: f.status === 'PATCH_APPLIED' }));
  }

  private async deliveryRows(db: Db) {
    return (
      await db.query<{
        channel: string;
        attempts: number;
        error: string | null;
        updated_at: string;
        log: EmailDeliveryLog | null;
      }>(
        `SELECT o.channel,o.attempts,o.error,o.updated_at,l.data AS log
      FROM outbox o LEFT JOIN records l ON l.kind='emailLogs' AND l.id=o.id::text
      WHERE o.updated_at >= $1 AND o.status IN ('ACCEPTED','FAILED','QUEUED')`,
        [this.cutoff()],
      )
    ).rows;
  }
  async collectDeliveryOutcomes(_db: Db): Promise<CronTrainingData['deliveryOutcomes']> {
    // Per-attempt elapsed times are not persisted. Final outbox rows cannot
    // reconstruct retry performance, so leave the optimizer on its default policy.
    return [];
  }
  async collectDeliveryErrorSamples(db: Db): Promise<CronTrainingData['deliveryErrorSamples']> {
    return (await this.deliveryRows(db))
      .filter((row) => row.channel === 'email' && row.error)
      .map((row) => {
        const statusCode = Number(/HTTP\s+(\d{3})\b/i.exec(row.error || '')?.[1] || 0);
        return {
          provider: row.log?.provider || 'unknown',
          statusCode,
          errorMessage: row.error || '',
          attemptNumber: row.attempts,
          hourOfDay: new Date(row.updated_at).getUTCHours(),
          isPermanent: statusCode >= 400 && statusCode < 500 && ![408, 429].includes(statusCode),
        };
      });
  }

  // These histories/labels are not stored by this application. Empty samples
  // make the orchestrator skip their models rather than invent training data
  // or query tables that migrations never created.
  async collectTelemetry(_db: Db): Promise<CronTrainingData['telemetryHistory']> {
    return [];
  }
  async collectCalibrationPairs(_db: Db): Promise<CronTrainingData['calibrationPairs']> {
    return [];
  }
  async collectExploitRiskSamples(_db: Db): Promise<CronTrainingData['exploitRiskSamples']> {
    return [];
  }
  async collectCredibilityWeightSamples(db: Db): Promise<CronTrainingData['credibilityWeightSamples']> {
    try {
      const [matchRows, articleRows, findings] = await Promise.all([
        db.query<{ id: string; data: IntelligenceMatch; updated_at: string }>(
          "SELECT id,data,updated_at FROM records WHERE kind='intelligenceMatches' AND updated_at >= $1 ORDER BY updated_at ASC,id LIMIT 5000",
          [this.cutoff()],
        ),
        db.query<{ id: string; data: IntelligenceArticle }>(
          "SELECT id,data FROM records WHERE kind='intelligenceArticles' AND updated_at >= $1 ORDER BY id LIMIT 5000",
          [this.cutoff()],
        ),
        this.findings(db),
      ]);
      const articles = new Map(articleRows.rows.map((row) => [row.id, row.data]));
      const findingById = new Map(findings.map((finding) => [finding.id, finding]));

      const samples = [] as CronTrainingData['credibilityWeightSamples'];
      for (const row of matchRows.rows) {
        const match = row.data;
        if (!match || typeof match.id !== 'string') continue;
        const finding = match.findingId ? findingById.get(match.findingId) : undefined;
        // Audit ML-2: the previous filter accepted only PATCH_APPLIED and
        // FALSE_POSITIVE. PATCH_APPLIED is the sole positive label and depends
        // on an operator change-ticket action, so production sample sets were
        // effectively all-negative; the orchestrator then skipped training with
        // "chronological holdout lacks class coverage" and fell back to the
        // default weights. RESOLVED is an equally strong positive outcome (the
        // evidence led to a disposition) and is included so the positive class
        // can form without a ticketing integration.
        if (!finding || !['PATCH_APPLIED', 'RESOLVED', 'FALSE_POSITIVE'].includes(finding.status)) continue;
        const related = match.articleIds.map((id) => articles.get(id)).filter((article): article is IntelligenceArticle => Boolean(article));
        if (!related.length) continue;
        const computedFeedWeight = Math.max(...related.flatMap((article) =>
          article.sourceFeeds.map((feed) => FEED_WEIGHTS[feed] ?? 10),
        ), 10);
        // Never reconstruct a feature from the outcome label. Only evidence
        // persisted at match time is eligible for training.
        const feedWeight = typeof match.sourceFeedWeight === 'number'
          ? match.sourceFeedWeight
          : computedFeedWeight;
        if (typeof match.keywordScore !== 'number') continue;
        const keywordScore = Math.max(0, Math.min(100, match.keywordScore));
        samples.push({
          feedWeight,
          keywordScore,
          isActionable: finding.status === 'PATCH_APPLIED' || finding.status === 'RESOLVED',
          timestamp: row.updated_at,
          groupKey: `${match.assetId}:${match.cveId || 'ZERO_DAY'}`,
        });
      }
      return samples.slice(-5000);
    } catch {
      // Training collections are optional; schema/query failures must not poison the pipeline.
      return [];
    }
  }
  async collectZeroDayRateLimitSamples(_db: Db): Promise<CronTrainingData['zeroDayRateLimitSamples']> {
    return [];
  }
  async collectDigestSelectionSamples(_db: Db): Promise<CronTrainingData['digestSelectionSamples']> {
    return [];
  }
  async collectSeverityTierSamples(_db: Db): Promise<CronTrainingData['severityTierSamples']> {
    return [];
  }
  async collectFeedRecoverySamples(db: Db): Promise<CronTrainingData['feedRecoverySamples']> {
    try {
      const result = await db.query<{
        occurred_at: string;
        context: Record<string, unknown> | null;
      }>(
        `SELECT occurred_at, context
         FROM operational_events
         WHERE category='FEED' AND code='feed.ingestion'
           AND occurred_at >= $1
         ORDER BY occurred_at ASC`,
        [this.cutoff()],
      );
      const lastDown = new Map<string, { at: number; failureCount: number; delayMinutes: number }>();
      const samples: Array<{
        feedType: string;
        provider: string;
        timeOfDay: number;
        failureCount: number;
        delayMinutes: number;
        recovered: boolean;
        recoveryLatencyMinutes: number;
        observedAt?: string;
      }> = [];
      for (const row of result.rows) {
        const context = row.context && typeof row.context === 'object' ? row.context : {};
        const feedId = typeof context.feedId === 'string' ? context.feedId : '';
        if (!feedId) continue;
        const observedAtMs = Date.parse(row.occurred_at);
        if (!Number.isFinite(observedAtMs)) continue;
        const status = typeof context.healthStatus === 'string' ? context.healthStatus : '';
        if (status === 'DOWN') {
          const failureCount = typeof context.consecutiveFailures === 'number'
            ? Math.max(1, Math.floor(context.consecutiveFailures))
            : 1;
          lastDown.set(feedId, { at: observedAtMs, failureCount, delayMinutes: 0 });
          continue;
        }
        if (status !== 'HEALTHY' && status !== 'DEGRADED') continue;
        const down = lastDown.get(feedId);
        if (!down) continue;
        const recoveryLatencyMinutes = Math.max(0, (observedAtMs - down.at) / 60_000);
        const delayMinutes = typeof context.circuitOpenUntil === 'string'
          ? 0
          : recoveryLatencyMinutes;
        // A health transition supplies an observed recovery outcome. For DEGRADED,
        // require it to carry a successful sync before counting a recovery.
        const recovered = status === 'HEALTHY' || status === 'DEGRADED';
        samples.push({
          feedType: typeof context.feedType === 'string' ? context.feedType : 'UNKNOWN',
          provider: typeof context.provider === 'string' ? context.provider : feedId,
          timeOfDay: new Date(down.at).getUTCHours(),
          failureCount: down.failureCount,
          delayMinutes: delayMinutes > 0 ? delayMinutes : 5,
          recovered,
          recoveryLatencyMinutes,
          observedAt: new Date(observedAtMs).toISOString(),
        });
        lastDown.delete(feedId);
      }
      return samples;
    } catch {
      // Training collections are optional; missing history must never block workers.
      return [];
    }
  }

  async collectAll(db: Db): Promise<TrainingDataSources> {
    // Reuse one finding snapshot within this cycle; later cycles always refresh.
    this.snapshot = this.loadFindings(db);
    try {
      await this.snapshot;
      return {
        cpeStrings: await this.collectCpeStrings(db),
        telemetryHistory: await this.collectTelemetry(db),
        dispatchOutcomes: await this.collectDispatchOutcomes(db),
        reviewOutcomeHistory: await this.collectReviewOutcomeHistory(db),
        calibrationPairs: await this.collectCalibrationPairs(db),
        deliveryOutcomes: await this.collectDeliveryOutcomes(db),
        remediationFindings: await this.collectRemediationFindings(db),
        exploitRiskSamples: await this.collectExploitRiskSamples(db),
        matchConfidenceSamples: await this.collectMatchConfidenceSamples(db),
        importanceRankSamples: await this.collectImportanceRankSamples(db),
        credibilityWeightSamples: await this.collectCredibilityWeightSamples(db),
        deliveryErrorSamples: await this.collectDeliveryErrorSamples(db),
        zeroDayRateLimitSamples: await this.collectZeroDayRateLimitSamples(db),
        digestSelectionSamples: await this.collectDigestSelectionSamples(db),
        severityTierSamples: await this.collectSeverityTierSamples(db),
        feedRecoverySamples: await this.collectFeedRecoverySamples(db),
        aliasConfidenceSamples: await this.collectAliasConfidenceSamples(db),
        emailCompositionSamples: [],
      };
    } finally {
      this.snapshot = undefined;
    }
  }
}
