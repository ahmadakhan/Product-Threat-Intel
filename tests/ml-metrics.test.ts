import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MetricsRegistry } from '../server/ml/metrics.ts';

test('ML metrics retain one series per complete label set', () => {
  const metrics = new MetricsRegistry();
  metrics.gauge('vulnstream_ml_model_last_trained_age_seconds', 120, { modelId: 'review-ranker' });
  metrics.gauge('vulnstream_ml_model_last_trained_age_seconds', 30, { modelId: 'cpe-validity-gate' });
  metrics.counter('vulnstream_ml_quality_gate_failed_total', 1, { modelId: 'review-ranker' });
  metrics.counter('vulnstream_ml_quality_gate_failed_total', 1, { modelId: 'review-ranker' });

  assert.equal(metrics.entriesFor('vulnstream_ml_model_last_trained_age_seconds').length, 2);
  assert.deepEqual(metrics.valuesForModel('review-ranker'), {
    vulnstream_ml_model_last_trained_age_seconds: 120,
    vulnstream_ml_quality_gate_failed_total: 2,
  });

  const rendered = metrics.render();
  assert.match(rendered, /# TYPE vulnstream_ml_model_last_trained_age_seconds gauge/);
  assert.match(rendered, /last_trained_age_seconds\{modelId="review-ranker"\} 120/);
  assert.match(rendered, /last_trained_age_seconds\{modelId="cpe-validity-gate"\} 30/);
  assert.match(rendered, /quality_gate_failed_total\{modelId="review-ranker"\} 2/);
});
