import { runVulnerabilityPipeline } from './src/engine/pipelineEngine';
import { renderFindingsDocument } from './server/deliveryDocument';
import { DEFAULT_SETTINGS } from './shared/state';
import type { Advisory, NormalizedCVE, WatchListItem } from './src/types/index';

const cpe = 'cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*';
const asset = {
  id: 'asset', vendor: 'example', product: 'widget', version: '1.5',
  cpes: [cpe], assetTag: 'Production', ownerGroup: 'Security', active: true,
  createdAt: new Date().toISOString(),
} as unknown as WatchListItem;

const cve = {
  cveId: 'CVE-2026-98104', title: 'Security update', description: 'Fixture',
  publishedDate: new Date().toISOString(), modifiedDate: new Date().toISOString(),
  cvss: { version: '3.1', score: 8, severity: 'HIGH', vector: '' },
  cwe: [], cpeMatches: [cpe], sourceFeeds: [],
  epss: { score: 0, percentile: 0 }, cisaKev: { isKev: false }, exploitStatus: 'None',
  remediation: { patchUrl: 'https://example.com/current-patch', vendorAdvisoryRef: '',
    immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
} as unknown as NormalizedCVE;

const finding = runVulnerabilityPipeline([], [cve], [asset], [], [],
  { ...DEFAULT_SETTINGS, scopeHours: 0, autoDispatchConfidenceThreshold: 99 },
  'probe', false).newFindings[0];

const advisory = {
  id: 'ADV-DAILY_20261107', title: 'Daily Vulnerability Notification', severity: 'HIGH',
  cveIds: [finding.cveId], findingIds: [finding.id], createdDate: new Date().toISOString(),
  deliveryStatus: 'PENDING', recipientCount: 1, executiveSummary: 'summary',
  remediationInstructions: 'remediate', vendorLink: '', affectedSystems: [finding.matchedAssetName],
  isDigestBatch: true,
} as Advisory;

const doc = renderFindingsDocument({ advisory, findings: [finding], generatedAt: new Date() });
console.log(JSON.stringify({
  confidence: finding.confidence,
  status: finding.notificationStatus,
  hasLowConfidence: doc.html.includes('Low confidence'),
  hasPlainNotice: doc.text.includes('Limited confidence'),
}));
