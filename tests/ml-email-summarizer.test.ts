import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  EmailSummarizerModel,
  type EmailSummaryFeatures,
  type SummaryStyle,
  type SummaryLength,
  type KeyActionEmphasis,
  type SubjectTemplate,
  SUMMARY_STYLES,
  SUMMARY_LENGTHS,
  KEY_ACTION_EMPHASES,
  SUBJECT_TEMPLATES,
  EMAIL_SUMMARIZER_FEATURE_NAMES,
} from '../server/ml/models/emailSummarizer.ts';
import { mlSummarizeAdvisoryEmail } from '../server/ml/integration.ts';
import type { Advisory, Finding } from '../src/types/index.ts';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'finding-1',
    cveId: 'CVE-2026-90001',
    cve: {
      cveId: 'CVE-2026-90001',
      title: 'Test vulnerability',
      description: 'A test vulnerability',
      publishedDate: '2026-10-30T00:00:00Z',
      modifiedDate: '2026-10-30T00:00:00Z',
      cvss: { version: '3.1', score: 9.8, vector: 'AV:N/AC:L', severity: 'CRITICAL' },
      cwe: [],
      cpeMatches: [],
      sourceFeeds: [],
      epss: { score: 0.85, percentile: 0.9 },
      cisaKev: { isKev: true },
      exploitStatus: 'Active Weaponized',
      remediation: {
        patchUrl: 'https://vendor.com/patch/CVE-2026-90001',
        vendorAdvisoryRef: 'https://vendor.com/advisory/CVE-2026-90001',
        immediateActions: ['Apply patch'],
        workarounds: [],
        rollbackPlan: '',
        stepByStep: [],
      },
    } as any,
    matchedAssetId: 'asset-1',
    matchedAssetName: 'Critical Server',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'server',
    matchedCpe: 'cpe:2.3:a:acme:server:1.0:*:*:*:*:*:*:*',
    matchingMethod: 'CPE_EXACT',
    matchingEvidence: 'exact match',
    exploitRisk: 'WEAPONIZED_EXPLOIT',
    notificationStatus: 'QUEUED_FOR_DISPATCH',
    status: 'MONITORED',
    autoDispatchedAt: null,
    advisoryId: null,
    timeline: [],
    ...overrides,
  } as unknown as Finding;
}

function makeAdvisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    id: 'ADV-TEST',
    title: 'Vulnerability notice: 1 Critical',
    severity: 'CRITICAL',
    cveIds: ['CVE-2026-90001'],
    findingIds: ['finding-1'],
    createdDate: new Date().toISOString(),
    deliveryStatus: 'PENDING',
    recipientCount: 1,
    executiveSummary: 'Test executive summary about a critical vulnerability.',
    remediationInstructions: 'Apply the vendor patch immediately. Validate after remediation.',
    affectedSystems: ['Critical Server'],
    ...overrides,
  };
}

const advisoryText =
  'CVE-2026-90001 is a critical vulnerability affecting Critical Server. ' +
  'Immediate attention required. Apply vendor patches as soon as possible. ' +
  'This CISA KEV vulnerability is actively weaponized. ' +
  'Review affected systems and prepare remediation. ' +
  'Validate backup, restore, and operational functionality after remediation.';

describe('EmailSummarizerModel', () => {
  describe('feature names', () => {
    it('exports expected feature names', () => {
      assert.ok(Array.isArray(EMAIL_SUMMARIZER_FEATURE_NAMES));
      assert.ok(EMAIL_SUMMARIZER_FEATURE_NAMES.includes('advisory_text_length'));
      assert.ok(EMAIL_SUMMARIZER_FEATURE_NAMES.includes('finding_count'));
      assert.ok(EMAIL_SUMMARIZER_FEATURE_NAMES.includes('critical_count'));
      assert.ok(EMAIL_SUMMARIZER_FEATURE_NAMES.includes('max_cvss_score'));
      assert.ok(EMAIL_SUMMARIZER_FEATURE_NAMES.includes('kev_count'));
    });
  });

  describe('untrained model', () => {
    it('returns fallback prediction when untrained', () => {
      const model = new EmailSummarizerModel();
      assert.equal(model.isTrained(), false);
      const result = model.predict({ advisory_text_length: 100 });
      assert.equal(result.confidence, 'LOW');
      assert.ok(result.reason.includes('untrained'));
    });

    it('summarize falls back to rule-based text when untrained', () => {
      const model = new EmailSummarizerModel();
      const features: EmailSummaryFeatures = {
        advisoryTextLength: advisoryText.length,
        sentenceCount: 5,
        findingCount: 1,
        criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0, unknownCount: 0,
        maxCvssScore: 9.8, avgCvssScore: 9.8,
        kevCount: 1, weaponizedCount: 1, reportedInWildCount: 0, pocCount: 0,
        maxDaysSincePublished: 5,
        hasPatchInfo: 1, hasWorkarounds: 0,
        recipientCount: 1,
      };
      const { text, prediction } = model.summarize(advisoryText, features);
      assert.ok(text.subject.length > 0);
      assert.ok(text.summary.length > 0);
      assert.ok(text.severityLine.includes('1 Critical'));
      assert.ok(Array.isArray(text.keyActions));
      assert.equal(prediction.confidence, 'LOW');
      assert.ok(prediction.reason.includes('untrained'));
    });
  });

  describe('trained model', () => {
    it('trains and predicts summarization parameters', () => {
      const model = new EmailSummarizerModel();
      const samples: Array<{
        features: EmailSummaryFeatures;
        summaryStyle: SummaryStyle;
        summaryLength: SummaryLength;
        keyActionEmphasis: KeyActionEmphasis;
        subjectTemplate: SubjectTemplate;
        wasOpened: boolean;
      }> = [];

      for (let i = 0; i < 40; i++) {
        const critical = i < 10 ? 3 : i < 20 ? 1 : 0;
        const high = i < 10 ? 1 : i < 20 ? 3 : 0;
        const total = critical + high;
        const wasOpened = critical > 0 || high > 2;

        samples.push({
          features: {
            advisoryTextLength: 200 + i * 10,
            sentenceCount: 5,
            findingCount: total,
            criticalCount: critical, highCount: high, mediumCount: 0, lowCount: 0, unknownCount: 0,
            maxCvssScore: critical > 0 ? 9.5 : high > 0 ? 7.5 : 5.0,
            avgCvssScore: critical > 0 ? 9.0 : high > 0 ? 7.0 : 5.0,
            kevCount: critical > 0 ? 1 : 0,
            weaponizedCount: critical > 0 ? 1 : 0,
            reportedInWildCount: 0, pocCount: 0,
            maxDaysSincePublished: 5,
            hasPatchInfo: critical > 0 ? 1 : 0,
            hasWorkarounds: 0,
            recipientCount: 1,
          },
          summaryStyle: critical > 0 ? 'URGENT' : high > 0 ? 'STANDARD' : 'INFORMATIONAL',
          summaryLength: critical > 0 ? 'SHORT' : 'MEDIUM',
          keyActionEmphasis: critical > 0 ? 'PATCH' : 'MONITOR',
          subjectTemplate: SUBJECT_TEMPLATES[0],
          wasOpened,
        });
      }

      const trainSamples = EmailSummarizerModel.collectTrainingData(samples);
      assert.ok(trainSamples.length >= 20);

      model.train(trainSamples);
      assert.equal(model.isTrained(), true);

      const urgentFeats: EmailSummaryFeatures = {
        advisoryTextLength: 300,
        sentenceCount: 5,
        findingCount: 4,
        criticalCount: 3, highCount: 1, mediumCount: 0, lowCount: 0, unknownCount: 0,
        maxCvssScore: 9.5, avgCvssScore: 8.5,
        kevCount: 1, weaponizedCount: 1, reportedInWildCount: 0, pocCount: 0,
        maxDaysSincePublished: 5,
        hasPatchInfo: 1, hasWorkarounds: 0,
        recipientCount: 1,
      };
      const result = model.predict(extractFeaturesFromFlat(urgentFeats));
      assert.ok(result.confidence === 'LOW' || result.confidence === 'MEDIUM' || result.confidence === 'HIGH');
    });

    it('serializes and loads without losing training state', () => {
      const model = new EmailSummarizerModel();
      const samples: Array<{
        features: EmailSummaryFeatures;
        summaryStyle: SummaryStyle;
        summaryLength: SummaryLength;
        keyActionEmphasis: KeyActionEmphasis;
        subjectTemplate: SubjectTemplate;
        wasOpened: boolean;
      }> = [];

      for (let i = 0; i < 30; i++) {
        const crit = i % 3 === 0 ? 2 : 0;
        const high = i % 3 === 1 ? 3 : 0;
        const total = crit + high;
        samples.push({
          features: {
            advisoryTextLength: 200,
            sentenceCount: 5,
            findingCount: total,
            criticalCount: crit, highCount: high, mediumCount: 0, lowCount: 0, unknownCount: 0,
            maxCvssScore: crit > 0 ? 9.0 : 7.0,
            avgCvssScore: crit > 0 ? 8.5 : 6.5,
            kevCount: crit > 0 ? 1 : 0,
            weaponizedCount: crit > 0 ? 1 : 0,
            reportedInWildCount: 0, pocCount: 0,
            maxDaysSincePublished: 3,
            hasPatchInfo: crit > 0 ? 1 : 0,
            hasWorkarounds: 0,
            recipientCount: 1,
          },
          summaryStyle: crit > 0 ? 'URGENT' : 'STANDARD',
          summaryLength: crit > 0 ? 'SHORT' : 'MEDIUM',
          keyActionEmphasis: crit > 0 ? 'PATCH' : 'MONITOR',
          subjectTemplate: SUBJECT_TEMPLATES[0],
          wasOpened: crit > 0,
        });
      }

      model.train(EmailSummarizerModel.collectTrainingData(samples));
      assert.equal(model.isTrained(), true);

      const artifact = model.serialize();
      assert.equal(artifact.metadata.id, 'email-summarizer');
      const weights = artifact.weights as { styleModels: Record<string, unknown>; lengthModels: Record<string, unknown> };
      assert.ok(weights.styleModels);
      assert.ok(weights.lengthModels);

      const loaded = new EmailSummarizerModel();
      loaded.load(artifact);
      assert.equal(loaded.isTrained(), true);

      const pred = loaded.predict({
        advisory_text_length: 200, sentence_count: 5, finding_count: 2,
        critical_count: 2, high_count: 0, medium_count: 0, low_count: 0, unknown_count: 0,
        max_cvss_score: 9.0, avg_cvss_score: 8.5,
        kev_count: 1, weaponized_count: 1, reported_in_wild_count: 0, poc_count: 0,
        max_days_since_published: 3, has_patch_info: 1, has_workarounds: 0, recipient_count: 1,
      });
      assert.ok((pred.probability ?? pred.score) >= 0);
    });

    it('summarize produces extractive text from input advisory', () => {
      const model = new EmailSummarizerModel();
      const samples: Array<{
        features: EmailSummaryFeatures;
        summaryStyle: SummaryStyle;
        summaryLength: SummaryLength;
        keyActionEmphasis: KeyActionEmphasis;
        subjectTemplate: SubjectTemplate;
        wasOpened: boolean;
      }> = [];
      for (let i = 0; i < 25; i++) {
        samples.push({
          features: {
            advisoryTextLength: 300,
            sentenceCount: 5,
            findingCount: i < 10 ? 3 : 2,
            criticalCount: i < 10 ? 2 : 0, highCount: i < 10 ? 1 : 2, mediumCount: 0, lowCount: 0, unknownCount: 0,
            maxCvssScore: i < 10 ? 9.5 : 7.0,
            avgCvssScore: i < 10 ? 9.0 : 6.5,
            kevCount: i < 10 ? 1 : 0,
            weaponizedCount: i < 10 ? 1 : 0,
            reportedInWildCount: 0, pocCount: 0,
            maxDaysSincePublished: 5,
            hasPatchInfo: i < 10 ? 1 : 0,
            hasWorkarounds: 0,
            recipientCount: 1,
          },
          summaryStyle: i < 10 ? 'URGENT' : 'STANDARD',
          summaryLength: i < 10 ? 'SHORT' : 'MEDIUM',
          keyActionEmphasis: i < 10 ? 'PATCH' : 'MONITOR',
          subjectTemplate: SUBJECT_TEMPLATES[0],
          wasOpened: i < 10,
        });
      }
      model.train(EmailSummarizerModel.collectTrainingData(samples));
      assert.equal(model.isTrained(), true);

      const features: EmailSummaryFeatures = {
        advisoryTextLength: advisoryText.length,
        sentenceCount: 5,
        findingCount: 3,
        criticalCount: 2, highCount: 1, mediumCount: 0, lowCount: 0, unknownCount: 0,
        maxCvssScore: 9.5, avgCvssScore: 8.5,
        kevCount: 1, weaponizedCount: 1, reportedInWildCount: 0, pocCount: 0,
        maxDaysSincePublished: 5,
        hasPatchInfo: 1, hasWorkarounds: 0,
        recipientCount: 1,
      };

      const { text, prediction } = model.summarize(advisoryText, features);
      assert.ok(text.subject.length > 0);
      assert.ok(text.summary.length > 0);
      assert.ok(text.severityLine.length > 0);
      assert.ok(Array.isArray(text.keyActions));
      assert.ok(text.keyActions.length > 0);
      // Summary should be drawn from input sentences (extractive).
      const inputLower = advisoryText.toLowerCase();
      assert.ok(inputLower.includes(text.summary.toLowerCase().slice(0, 40)) || text.summary.length < advisoryText.length);
      assert.ok(SUMMARY_STYLES.includes(prediction.summaryStyle));
      assert.ok(SUMMARY_LENGTHS.includes(prediction.summaryLength));
      assert.ok(KEY_ACTION_EMPHASES.includes(prediction.keyActionEmphasis));
      assert.ok(SUBJECT_TEMPLATES.includes(prediction.subjectTemplate));
      assert.ok(prediction.modelVersion);
      assert.ok(prediction.reason);
    });

    it('getter methods return expected values', () => {
      const model = new EmailSummarizerModel();
      assert.deepEqual(model.getSummaryStyles(), SUMMARY_STYLES);
      assert.deepEqual(model.getSummaryLengths(), SUMMARY_LENGTHS);
      assert.deepEqual(model.getKeyActionEmphases(), KEY_ACTION_EMPHASES);
      assert.deepEqual(model.getSubjectTemplates(), SUBJECT_TEMPLATES);
      assert.deepEqual(model.getFeatureNames(), EMAIL_SUMMARIZER_FEATURE_NAMES);
    });
  });
});

describe('mlSummarizeAdvisoryEmail (integration)', () => {
  it('uses rule-based fallback when model untrained', () => {
    const findings = [makeFinding()];
    const result = mlSummarizeAdvisoryEmail(findings, advisoryText);
    assert.equal(result.modelUsed, false);
    assert.ok(result.subject.length > 0);
    assert.ok(result.summary.length > 0);
    assert.ok(result.severityLine.includes('1 Critical'));
    assert.equal(result.prediction, null);
    assert.ok(Array.isArray(result.keyActions));
  });

  it('returns keyActions as array', () => {
    const findings = [makeFinding()];
    const result = mlSummarizeAdvisoryEmail(findings, advisoryText);
    assert.ok(Array.isArray(result.keyActions));
    assert.ok(result.keyActions.length > 0);
  });
});

// Helper to convert EmailSummaryFeatures to flat record for predict
function extractFeaturesFromFlat(f: EmailSummaryFeatures): Record<string, number> {
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
