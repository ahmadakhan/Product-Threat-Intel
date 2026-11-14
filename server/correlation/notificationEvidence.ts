import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { Db } from '../db.ts';
import type { Job } from '../delivery.ts';
export const nativeDeliverySchema = z
  .object({
    advisoryId: z.uuid(),
    evidenceHash: z.string().regex(/^[a-f0-9]{64}$/),
    /**
     * The advisory-level verdict. Only HIGH and MEDIUM are deliverable: LOW
     * evidence is never attributed to an asset and stays in review.
     */
    confidence: z.enum(['HIGH', 'MEDIUM']),
  })
  .strict();
export type NativeDelivery = z.infer<typeof nativeDeliverySchema>;
interface EvidenceMatch {
  assetId: string;
  vendor: string;
  product: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  assetRevision: string | null;
  currentRevision: string | null;
}
export async function readNativeEvidence(db: Db, advisoryId: string) {
  const article = await db.query<{ title: string; url: string; fingerprint: string; content: string }>(
    'SELECT title,url,fingerprint,content FROM unstructured_advisories WHERE id=$1',
    [advisoryId],
  );
  const matches = await db.query<EvidenceMatch>(
    `SELECT m.asset_id AS "assetId",m.vendor,m.product,m.confidence,m.reason,
     e.asset_revision AS "assetRevision",i.revision AS "currentRevision" FROM correlation_matches m
     LEFT JOIN correlation_match_evidence e ON e.advisory_id=m.advisory_id AND e.asset_id=m.asset_id
     LEFT JOIN correlation_asset_inventory i ON i.id=m.asset_id WHERE m.advisory_id=$1 ORDER BY m.asset_id LIMIT 1001`,
    [advisoryId],
  );
  // Matches derived before the stored match rows have evidence committed (or
  // whose asset changed since) carry no fresh evidence and are not reported.
  const freshMatches = matches.rows
    .filter((match) => match.assetRevision && match.assetRevision === match.currentRevision)
    // LOW-confidence matches are review evidence only: negated advisories
    // ("not affected", "false positive") and bare vendor/product co-occurrence
    // with no version bound. They must never be delivered as alerts, whatever
    // the low-confidence switch says. Keeping them here would demote a real
    // advisory to MEDIUM and assert exposure the source denies.
    .filter((match) => match.confidence !== 'LOW');
  if (!article.rows[0] || matches.rows.length > 1000) return null;
  // No attributed asset means no alert. The review buffer holds exactly the
  // evidence that could not be tied to an installed asset — including advisories
  // whose text negates applicability — so it is never a delivery source.
  if (!freshMatches.length) return null;
  const unconfirmedMatches = freshMatches.filter((match) => match.confidence !== 'HIGH');
  const confidence: 'HIGH' | 'MEDIUM' = unconfirmedMatches.length ? 'MEDIUM' : 'HIGH';
  const evidenceHash = createHash('sha256')
    .update(JSON.stringify([article.rows[0], freshMatches]))
    .digest('hex');
  return {
    article: article.rows[0],
    matches: freshMatches,
    /** Matches that could not be confirmed and therefore need operator review. */
    unconfirmedMatches,
    confidence,
    evidenceHash,
  };
}
export async function validateNativeDelivery(db: Db, job: Job): Promise<NativeDelivery> {
  const input = nativeDeliverySchema.parse(job.payload.nativeCorrelation);
  if (job.advisory_id !== `NATIVE:${input.advisoryId}`)
    throw new Error('Native notification identity mismatch');
  const policy = await db.query<{ notifications_enabled: boolean }>(
    'SELECT notifications_enabled FROM correlation_policy WHERE id=1',
  );
  if (!policy.rows[0]?.notifications_enabled) throw new Error('Native notification policy is disabled');
  const evidence = await readNativeEvidence(db, input.advisoryId);
  if (!evidence || evidence.evidenceHash !== input.evidenceHash || evidence.confidence !== input.confidence)
    throw new Error('Native evidence is no longer applicable; operator verification required');
  return input;
}
