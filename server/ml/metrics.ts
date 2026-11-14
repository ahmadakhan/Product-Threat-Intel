/**
 * Minimal in-memory metrics registry for ML model state.
 *
 * Exposes gauges and counters that a Prometheus exporter can scrape.
 * Values are process-local; in a multi-replica deployment each replica
 * tracks its own state and the alert rules evaluate per-instance.
 *
 * Metric identity is the name *plus* its complete label set. The previous
 * implementation keyed only by name, so a per-model gauge overwrote every
 * earlier model and the exporter emitted one unlabeled sample. That made
 * per-model drift/staleness alerts impossible to evaluate.
 */
export type MetricType = 'gauge' | 'counter';

export interface MetricEntry {
  type: MetricType;
  value: number;
  labels: Record<string, string>;
}

const labelKey = (labels: Record<string, string>): string =>
  Object.keys(labels)
    .sort()
    .map((key) => `${key}=${JSON.stringify(labels[key])}`)
    .join(',');

const metricKey = (name: string, labels: Record<string, string>): string =>
  `${name}\u0000${labelKey(labels)}`;

const formatLabels = (labels: Record<string, string>): string => {
  const keys = Object.keys(labels).sort();
  if (!keys.length) return '';
  return `{${keys
    .map((key) => `${key}="${String(labels[key]).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`)
    .join(',')}}`;
};

export class MetricsRegistry {
  private metrics = new Map<string, MetricEntry>();

  gauge(name: string, value: number, labels: Record<string, string> = {}): void {
    this.metrics.set(metricKey(name, labels), { type: 'gauge', value, labels: { ...labels } });
  }

  counter(name: string, value: number, labels: Record<string, string> = {}): void {
    const key = metricKey(name, labels);
    const existing = this.metrics.get(key);
    const current = existing && existing.type === 'counter' ? existing.value : 0;
    this.metrics.set(key, { type: 'counter', value: current + value, labels: { ...labels } });
  }

  inc(name: string, labels: Record<string, string> = {}): void {
    this.counter(name, 1, labels);
  }

  /**
   * Look up an exact label set. Without labels, return the first sample for the
   * name for backwards compatibility; Prometheus rendering uses `entriesFor`.
   */
  get(name: string, labels?: Record<string, string>): MetricEntry | undefined {
    if (labels) return this.metrics.get(metricKey(name, labels));
    for (const [key, entry] of this.metrics) {
      if (key.startsWith(`${name}\u0000`)) return entry;
    }
    return undefined;
  }

  entriesFor(name: string): MetricEntry[] {
    return [...this.metrics.entries()]
      .filter(([key]) => key.startsWith(`${name}\u0000`))
      .map(([, entry]) => entry);
  }

  /** A compact `metricName -> value` map for one model's labeled metrics. */
  valuesForModel(modelId: string): Record<string, number> {
    const values: Record<string, number> = {};
    for (const [key, entry] of this.metrics) {
      if (entry.labels.modelId !== modelId) continue;
      const name = key.slice(0, key.indexOf('\u0000'));
      values[name] = entry.value;
    }
    return values;
  }

  all(): [string, MetricEntry][] {
    return [...this.metrics.entries()];
  }

  /** Render selected metric names in Prometheus text exposition format. */
  renderNames(names: readonly string[]): string {
    const allowed = new Set(names);
    const selected = this.all().filter(([key]) => allowed.has(key.slice(0, key.indexOf('\u0000'))));
    return this.renderEntries(selected);
  }

  /** Render every registered metric in Prometheus text exposition format. */
  render(): string {
    return this.renderEntries(this.all());
  }

  private renderEntries(entries: [string, MetricEntry][]): string {
    const byName = new Map<string, { type: MetricType; samples: MetricEntry[] }>();
    for (const [key, entry] of entries) {
      const name = key.slice(0, key.indexOf('\u0000'));
      let group = byName.get(name);
      if (!group) {
        group = { type: entry.type, samples: [] };
        byName.set(name, group);
      }
      group.samples.push(entry);
    }

    const lines: string[] = [];
    for (const [name, group] of byName) {
      lines.push(`# TYPE ${name} ${group.type}`);
      for (const sample of group.samples) lines.push(`${name}${formatLabels(sample.labels)} ${sample.value}`);
      lines.push('');
    }
    return lines.join('\n');
  }
}

export const mlMetrics = new MetricsRegistry();
