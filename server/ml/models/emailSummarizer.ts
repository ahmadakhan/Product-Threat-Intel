/**
 * Email Summarizer Model — condenses an existing long advisory into a short,
 * email-ready summary.
 *
 * Unlike AdvisoryComposerModel (which composes a full advisory from finding
 * metadata using ML-selected templates), this model takes an *already composed*
 * advisory (subject, executive summary, remediation instructions, severity
 * summary) and produces a condensed version suitable for email body preview,
 * notification digests, or mobile alerts.
 *
 * All output is deterministic extractive text — sentences are scored and
 * selected from the input advisory, never free-form generated from untrusted
 * input. ML only selects summary style, length, key-action emphasis, and
 * subject template. When untrained, deterministic evidence ranking still
 * produces a useful summary without inventing claims.
 *
 * Summary targets:
 *   - summaryStyle     → URGENT | STANDARD | INFORMATIONAL  (classification)
 *   - summaryLength    → SHORT | MEDIUM | LONG              (classification)
 *   - keyActionEmphasis → PATCH | MONITOR | REVIEW           (classification)
 *   - subjectTemplate  → selected template index              (classification)
 *
 * Text is produced by extractive sentence selection (position + keyword +
 * length scoring), so output is always a verbatim subset of the input advisory.
 *
 * A model artifact may learn presentation choices from validated labels. Until
 * then, the shared extractive fallback preserves the overview and selects the
 * most actionable evidence without inventing claims.
 */

import { LogisticRegression } from '../algorithms/logisticRegression.ts';
import { BaseModel } from '../baseModel.ts';
import type { ModelArtifact, ModelMetadata, PredictionResult, TrainingSample } from '../types.ts';

export const SUMMARY_STYLES: string[] = ['URGENT', 'STANDARD', 'INFORMATIONAL'];
export type SummaryStyle = (typeof SUMMARY_STYLES)[number];

export const SUMMARY_LENGTHS: string[] = ['SHORT', 'MEDIUM', 'LONG'];
export type SummaryLength = (typeof SUMMARY_LENGTHS)[number];

export const KEY_ACTION_EMPHASES: string[] = ['PATCH', 'MONITOR', 'REVIEW'];
export type KeyActionEmphasis = (typeof KEY_ACTION_EMPHASES)[number];

export const SUBJECT_TEMPLATES: string[] = [
  'Security summary: {count} {sev} finding(s)',
  'Vulnerability alert: {count} {sev} finding(s) need attention',
  'Security digest: {count} {sev} vulnerability(ies) on monitored assets',
  'Action required: {count} {sev} finding(s) summarized',
];
export type SubjectTemplate = (typeof SUBJECT_TEMPLATES)[number];

export const EMAIL_SUMMARIZER_FEATURE_NAMES: string[] = [
  'advisory_text_length',
  'sentence_count',
  'finding_count',
  'critical_count',
  'high_count',
  'medium_count',
  'low_count',
  'unknown_count',
  'max_cvss_score',
  'avg_cvss_score',
  'kev_count',
  'weaponized_count',
  'reported_in_wild_count',
  'poc_count',
  'max_days_since_published',
  'has_patch_info',
  'has_workarounds',
  'recipient_count',
];

export type EmailSummarizerFeatureNames = (typeof EMAIL_SUMMARIZER_FEATURE_NAMES)[number];

export interface EmailSummaryFeatures {
  advisoryTextLength: number;
  sentenceCount: number;
  findingCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  unknownCount: number;
  maxCvssScore: number;
  avgCvssScore: number;
  kevCount: number;
  weaponizedCount: number;
  reportedInWildCount: number;
  pocCount: number;
  maxDaysSincePublished: number;
  hasPatchInfo: number;
  hasWorkarounds: number;
  recipientCount: number;
}

export interface EmailSummaryPrediction {
  summaryStyle: SummaryStyle;
  summaryLength: SummaryLength;
  keyActionEmphasis: KeyActionEmphasis;
  subjectTemplate: SubjectTemplate;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  modelVersion: string;
  reason: string;
}

export interface EmailSummaryText {
  subject: string;
  summary: string;
  keyActions: string[];
  severityLine: string;
}

function extractFeatures(f: EmailSummaryFeatures): Record<string, number> {
  return {
    advisory_text_length: f.advisoryTextLength,
    sentence_count: f.sentenceCount,
    finding_count: f.findingCount,
    critical_count: f.criticalCount,
    high_count: f.highCount,
    medium_count: f.mediumCount,
    low_count: f.lowCount,
    unknown_count: f.unknownCount,
    max_cvss_score: f.maxCvssScore,
    avg_cvss_score: f.avgCvssScore,
    kev_count: f.kevCount,
    weaponized_count: f.weaponizedCount,
    reported_in_wild_count: f.reportedInWildCount,
    poc_count: f.pocCount,
    max_days_since_published: f.maxDaysSincePublished,
    has_patch_info: f.hasPatchInfo,
    has_workarounds: f.hasWorkarounds,
    recipient_count: f.recipientCount,
  };
}

function buildSubject(template: SubjectTemplate, features: EmailSummaryFeatures): string {
  const sevCounts: [string, number][] = [
    ['Critical', features.criticalCount],
    ['High', features.highCount],
    ['Medium', features.mediumCount],
    ['Low', features.lowCount],
  ];
  const nonzero = sevCounts.filter(([, c]) => c > 0);
  const topSev = nonzero.length ? nonzero[0][0] : 'Unknown';
  const topCount = nonzero.length ? nonzero[0][1] : 0;
  const totalCount = features.findingCount;
  const severitySummary = nonzero.map(([sev, c]) => `${c} ${sev}`).join(', ');

  return template
    .replace('{count}', String(totalCount))
    .replace('{sev}', topSev)
    .replace('{count_sev}', `${topCount} ${topSev}`)
    .replace('{severity_summary}', severitySummary);
}

function buildSeverityLine(features: EmailSummaryFeatures): string {
  const parts: string[] = [];
  if (features.criticalCount) parts.push(`${features.criticalCount} Critical`);
  if (features.highCount) parts.push(`${features.highCount} High`);
  if (features.mediumCount) parts.push(`${features.mediumCount} Medium`);
  if (features.lowCount) parts.push(`${features.lowCount} Low`);
  if (features.unknownCount) parts.push(`${features.unknownCount} Unknown`);
  return parts.length ? parts.join(', ') : '0 vulnerabilities';
}

/** Split advisory text into sentences, trimming whitespace. */
function splitIntoSentences(text: string): string[] {
  return text
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/\s+/g, ' ')
    // Keep decimal CVSS values intact; split at punctuation only when the
    // following token looks like a new sentence.
    .split(/(?<=[.!?])\s+(?=[A-Z0-9])/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Score each sentence for extractive summarization. Higher score = more
 * important to include. Deterministic — no randomness, no external models.
 *
 * Signals:
 *   - Position: earlier sentences score higher (lead bias).
 *   - Length: medium-length sentences preferred (too short = fragment, too long = rambling).
 *   - Keywords: CVE IDs, severity words, patch/exploit/KEV/remediation terms.
 *   - Severity words: Critical, High, Medium, Low boost score.
 */
function scoreSentences(sentences: string[]): number[] {
  const keywordBoost = [
    /cve-\d{4}-\d+/i,
    /critical/i,
    /patch/i,
    /exploit/i,
    /kev/i,
    /remediat/i,
    /vulnerab/i,
    /weaponized/i,
    /in.?wild/i,
    /poc/i,
  ];
  const severityBoost = /critical|high|medium|low/i;

  const scores: number[] = [];
  const n = sentences.length;
  for (let i = 0; i < n; i++) {
    const s = sentences[i];
    let score = 0;

    // Position bias: first sentence gets the highest lead weight.
    score += (n - i) / n * 2.0;

    // Length preference: sweet spot 40–200 chars.
    const len = s.length;
    if (len >= 40 && len <= 200) score += 1.5;
    else if (len > 0 && len < 40) score += 0.5;
    else if (len > 200) score += 0.8;

    // Keyword matches.
    let kwMatches = 0;
    for (const re of keywordBoost) {
      if (re.test(s)) kwMatches++;
    }
    score += Math.min(kwMatches, 4) * 0.75;

    // Severity word presence.
    if (severityBoost.test(s)) score += 0.5;

    scores.push(score);
  }

  // Normalize to [0, 1].
  let maxScore = 0;
  for (const sc of scores) maxScore = Math.max(maxScore, sc);
  if (maxScore > 0) {
    for (let i = 0; i < n; i++) scores[i] = scores[i] / maxScore;
  }
  return scores;
}

/** Shared deterministic extractive fallback used without a validated artifact. */
export function extractiveSummaryText(advisoryText: string, maxSentences = 3): string {
  const sentences = splitIntoSentences(advisoryText);
  if (!sentences.length) return '';
  const scores = scoreSentences(sentences);
  // Always keep the overview sentence, then choose the strongest evidence or
  // mitigation sentences while preserving their original order.
  const limit = Math.max(1, Math.min(4, Math.floor(maxSentences)));
  const ranked = sentences
    .map((sentence, index) => ({ sentence, index, score: scores[index] ?? 0 }))
    .filter((entry) => entry.index !== 0)
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .slice(0, limit - 1)
    .sort((a, b) => a.index - b.index);
  return [sentences[0], ...ranked.map((entry) => entry.sentence)].join(' ');
}

/**
 * Select top sentences for the extractive summary, capped by target length.
 * Preserves original sentence order.
 */
function selectSentences(
  sentences: string[],
  targetLength: SummaryLength,
): string[] {
  const maxSentences = targetLength === 'SHORT' ? 2 : targetLength === 'MEDIUM' ? 3 : 4;
  const summary = extractiveSummaryText(sentences.join(' '), maxSentences);
  return splitIntoSentences(summary);
}

export class EmailSummarizerModel extends BaseModel {
  private styleModels = new Map<string, LogisticRegression>();
  private lengthModels = new Map<string, LogisticRegression>();
  private actionModels = new Map<string, LogisticRegression>();
  private subjectModels = new Map<string, LogisticRegression>();
  private readonly featureNames: string[] = [...EMAIL_SUMMARIZER_FEATURE_NAMES];

  constructor() {
    const metadata: ModelMetadata = {
      id: 'email-summarizer',
      type: 'logistic',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...EMAIL_SUMMARIZER_FEATURE_NAMES],
      description: 'Summarizes composed advisory text into a short email: summary style, length, key-action emphasis, subject template, and extractive sentence selection',
    };
    super(metadata);
  }

  train(samples: TrainingSample[]): void {
    if (samples.length < 20) {
      this.trained = false;
      return;
    }

    const trainCategory = (
      categories: string[],
      labelToIdx: (label: number) => number | null,
    ): Map<string, LogisticRegression> => {
      const models = new Map<string, LogisticRegression>();
      for (const cat of categories) {
        const catSamples: TrainingSample[] = [];
        for (const s of samples) {
          const rawLabel = typeof s.label === 'boolean' ? (s.label ? 1 : 0) : s.label;
          const idx = labelToIdx(rawLabel);
          if (idx === null) continue;
          const catLabel = idx === categories.indexOf(cat) ? 1 : 0;
          catSamples.push({ ...s, label: catLabel });
        }
        const pos = catSamples.filter((s) => s.label === 1).length;
        const neg = catSamples.filter((s) => s.label === 0).length;
        if (pos >= 4 && neg >= 4) {
          const lr = new LogisticRegression();
          lr.train(catSamples, { threshold: 0.5, iterations: 1000, l2: 0.001 });
          models.set(cat, lr);
        }
      }
      return models;
    };

    this.styleModels.clear();
    this.lengthModels.clear();
    this.actionModels.clear();
    this.subjectModels.clear();

    // Label encoding packed into a single integer:
    //   label = styleIdx * 1 + lengthIdx * 10 + actionIdx * 100 + subjectIdx * 1000 + wasOpened * 10000
    const styleLabel = (label: number) => label % 10;
    const lengthLabel = (label: number) => Math.floor(label / 10) % 10;
    const actionLabel = (label: number) => Math.floor(label / 100) % 10;
    const subjectLabel = (label: number) => Math.floor(label / 1000) % 10;

    this.styleModels = trainCategory(SUMMARY_STYLES, styleLabel);
    this.lengthModels = trainCategory(SUMMARY_LENGTHS, lengthLabel);
    this.actionModels = trainCategory(KEY_ACTION_EMPHASES, actionLabel);
    this.subjectModels = trainCategory(SUBJECT_TEMPLATES.map((_, i) => String(i)), subjectLabel);

    const anyTrained =
      this.styleModels.size > 0 ||
      this.lengthModels.size > 0 ||
      this.actionModels.size > 0;
    this.trained = anyTrained;
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  predict(features: Record<string, number>): PredictionResult {
    if (!this.trained) {
      return { score: 0.5, probability: 0.5, confidence: 'LOW', reason: 'model untrained — rule-based summarization' };
    }
    const x = extractFeaturesFromFlat(features);
    const style = this.predictCategory(SUMMARY_STYLES, this.styleModels, x);
    const length = this.predictCategory(SUMMARY_LENGTHS, this.lengthModels, x);
    const action = this.predictCategory(KEY_ACTION_EMPHASES, this.actionModels, x);
    const subjectIdx = this.predictCategory(SUBJECT_TEMPLATES.map((_, i) => String(i)), this.subjectModels, x);

    const probs = [style.probability, length.probability, action.probability];
    const minProb = Math.min(...probs);
    const confidence: PredictionResult['confidence'] = minProb >= 0.7 ? 'HIGH' : minProb >= 0.4 ? 'MEDIUM' : 'LOW';

    return {
      score: minProb,
      probability: minProb,
      confidence,
      reason: `style=${style.label} (P=${style.probability.toFixed(2)}), length=${length.label} (P=${length.probability.toFixed(2)}), action=${action.label} (P=${action.probability.toFixed(2)}), subject=${subjectIdx}`,
    };
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }

  private predictCategory(
    categories: string[],
    models: Map<string, LogisticRegression>,
    x: Record<string, number>,
  ): { label: string; probability: number } {
    let best = categories[0];
    let bestProb = 0;
    for (const cat of categories) {
      const lr = models.get(cat);
      if (!lr) continue;
      const pred = lr.predict(x);
      const p = pred.probability ?? pred.score;
      if (p > bestProb) {
        bestProb = p;
        best = cat;
      }
    }
    return { label: best, probability: bestProb };
  }

  /**
   * Summarize composed advisory text into a short email summary.
   *
   * @param advisoryText — the full composed advisory text (subject + body).
   * @param features — aggregate features derived from the findings/advisory.
   * @returns deterministic extractive summary text plus ML-selected parameters.
   */
  summarize(
    advisoryText: string,
    features: EmailSummaryFeatures,
  ): { text: EmailSummaryText; prediction: EmailSummaryPrediction } {
    const x = extractFeatures(features);
    const summaryStyle = this.predictCategory(SUMMARY_STYLES, this.styleModels, x).label as SummaryStyle;
    const summaryLength = this.predictCategory(SUMMARY_LENGTHS, this.lengthModels, x).label as SummaryLength;
    const keyActionEmphasis = this.predictCategory(KEY_ACTION_EMPHASES, this.actionModels, x).label as KeyActionEmphasis;
    const subjectIdx = Number(
      this.predictCategory(SUBJECT_TEMPLATES.map((_, i) => String(i)), this.subjectModels, x).label,
    );
    const subjectTemplate = SUBJECT_TEMPLATES[Math.max(0, Math.min(subjectIdx, SUBJECT_TEMPLATES.length - 1))];

    const sentences = splitIntoSentences(advisoryText);
    const selected = selectSentences(sentences, summaryLength);

    let summary = selected.join(' ');
    if (!summary && sentences.length > 0) {
      // Absolute fallback: use the first sentence(s).
      summary = sentences.slice(0, summaryLength === 'SHORT' ? 1 : 2).join(' ');
    }
    if (!summary) {
      summary = 'No actionable content detected in advisory.';
    }

    const keyActions = this.buildKeyActions(features, keyActionEmphasis);
    const subject = buildSubject(subjectTemplate, features);
    const severityLine = buildSeverityLine(features);

    const pred = this.predict(x);
    return {
      text: { subject, summary, keyActions, severityLine },
      prediction: {
        summaryStyle,
        summaryLength,
        keyActionEmphasis,
        subjectTemplate,
        confidence: pred.confidence,
        modelVersion: this.metadata.version,
        reason: pred.reason,
      },
    };
  }

  /**
   * Predict summarization parameters without generating text — useful for diagnostics.
   */
  summarizePrediction(
    advisoryText: string,
    features: EmailSummaryFeatures,
  ): EmailSummaryPrediction {
    const x = extractFeatures(features);
    const summaryStyle = this.predictCategory(SUMMARY_STYLES, this.styleModels, x).label as SummaryStyle;
    const summaryLength = this.predictCategory(SUMMARY_LENGTHS, this.lengthModels, x).label as SummaryLength;
    const keyActionEmphasis = this.predictCategory(KEY_ACTION_EMPHASES, this.actionModels, x).label as KeyActionEmphasis;
    const subjectIdx = Number(
      this.predictCategory(SUBJECT_TEMPLATES.map((_, i) => String(i)), this.subjectModels, x).label,
    );
    const subjectTemplate = SUBJECT_TEMPLATES[Math.max(0, Math.min(subjectIdx, SUBJECT_TEMPLATES.length - 1))];
    const pred = this.predict(x);
    return {
      summaryStyle,
      summaryLength,
      keyActionEmphasis,
      subjectTemplate,
      confidence: pred.confidence,
      modelVersion: this.metadata.version,
      reason: pred.reason,
    };
  }

  private buildKeyActions(
    features: EmailSummaryFeatures,
    emphasis: KeyActionEmphasis,
  ): string[] {
    const actions: string[] = [];
    if (emphasis === 'PATCH') {
      actions.push('Apply vendor patches through change management.');
      if (features.kevCount > 0) actions.push('Prioritize CISA KEV vulnerabilities per organizational SLA.');
      actions.push('Validate remediation after patch deployment.');
    } else if (emphasis === 'MONITOR') {
      actions.push('Monitor affected systems for anomalous activity.');
      actions.push('Prepare remediation during the next maintenance window.');
      if (features.pocCount > 0) actions.push('Review POC availability before exposure increases.');
    } else {
      actions.push('Submit findings to security-team review for disposition.');
      actions.push('Confirm applicability to your environment before action.');
    }
    return actions;
  }

  serialize(): ModelArtifact {
    const serializeMap = (m: Map<string, LogisticRegression>): Record<string, unknown> => {
      const obj: Record<string, unknown> = {};
      for (const [k, v] of m) obj[k] = v.serialize();
      return obj;
    };
    return {
      metadata: this.metadata,
      weights: {
        styleModels: serializeMap(this.styleModels),
        lengthModels: serializeMap(this.lengthModels),
        actionModels: serializeMap(this.actionModels),
        subjectModels: serializeMap(this.subjectModels),
        featureNames: [...this.featureNames],
      },
    };
  }

  load(artifact: ModelArtifact): void {
    const data = artifact.weights as {
      styleModels: Record<string, unknown>;
      lengthModels: Record<string, unknown>;
      actionModels: Record<string, unknown>;
      subjectModels: Record<string, unknown>;
      featureNames: string[];
    };

    this.styleModels.clear();
    this.lengthModels.clear();
    this.actionModels.clear();
    this.subjectModels.clear();

    for (const cat of SUMMARY_STYLES) {
      const w = data.styleModels[cat];
      if (w) {
        const lr = new LogisticRegression();
        lr.load(w as ReturnType<LogisticRegression['serialize']>);
        this.styleModels.set(cat, lr);
      }
    }
    for (const cat of SUMMARY_LENGTHS) {
      const w = data.lengthModels[cat];
      if (w) {
        const lr = new LogisticRegression();
        lr.load(w as ReturnType<LogisticRegression['serialize']>);
        this.lengthModels.set(cat, lr);
      }
    }
    for (const cat of KEY_ACTION_EMPHASES) {
      const w = data.actionModels[cat];
      if (w) {
        const lr = new LogisticRegression();
        lr.load(w as ReturnType<LogisticRegression['serialize']>);
        this.actionModels.set(cat, lr);
      }
    }
    for (let i = 0; i < SUBJECT_TEMPLATES.length; i++) {
      const w = data.subjectModels[String(i)];
      if (w) {
        const lr = new LogisticRegression();
        lr.load(w as ReturnType<LogisticRegression['serialize']>);
        this.subjectModels.set(String(i), lr);
      }
    }

    this.metadata = artifact.metadata;
    this.trained =
      this.styleModels.size > 0 || this.lengthModels.size > 0 || this.actionModels.size > 0;
  }

  getFeatureNames(): string[] {
    return [...this.featureNames];
  }

  getSummaryStyles(): string[] {
    return [...SUMMARY_STYLES];
  }

  getSummaryLengths(): string[] {
    return [...SUMMARY_LENGTHS];
  }

  getKeyActionEmphases(): string[] {
    return [...KEY_ACTION_EMPHASES];
  }

  getSubjectTemplates(): string[] {
    return [...SUBJECT_TEMPLATES];
  }

  static collectTrainingData(samples: Array<{
    features: EmailSummaryFeatures;
    summaryStyle: SummaryStyle;
    summaryLength: SummaryLength;
    keyActionEmphasis: KeyActionEmphasis;
    subjectTemplate: SubjectTemplate;
    wasOpened: boolean;
  }>): TrainingSample[] {
    return samples.map((s, i) => {
      const styleIdx = SUMMARY_STYLES.indexOf(s.summaryStyle);
      const lengthIdx = SUMMARY_LENGTHS.indexOf(s.summaryLength);
      const actionIdx = KEY_ACTION_EMPHASES.indexOf(s.keyActionEmphasis);
      const subjectIdx = SUBJECT_TEMPLATES.indexOf(s.subjectTemplate);
      const label =
        styleIdx * 1 + lengthIdx * 10 + actionIdx * 100 + subjectIdx * 1000 + (s.wasOpened ? 10000 : 0);
      return {
        id: `email-summarizer-${i}`,
        features: extractFeatures(s.features),
        label,
        weight: s.wasOpened ? 2 : 1,
        timestamp: new Date().toISOString(),
      };
    });
  }
}

function extractFeaturesFromFlat(features: Record<string, number>): Record<string, number> {
  return { ...features };
}
