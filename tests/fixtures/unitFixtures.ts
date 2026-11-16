import type { Finding, NormalizedCVE, WatchListItem } from '../../src/types/index.ts';

/**
 * Test-only fixtures.
 *
 * These shapes used to live in `seedData.ts` (as INITIAL_NORMALIZED_CVES,
 * INITIAL_WATCHLIST and INITIAL_FINDINGS) and shared that file with the seed
 * script, which made them look like seed data. The seed registers the feed
 * catalog only and leaves the product inventory to the operator, so what is
 * here is for tests: a shape to spread over, named so it cannot be mistaken for
 * something npm run seed writes.
 *
 * Every overrideable field starts at an inert value, so a spread does not
 * depend on another suite having edited the object first.
 */

export function createTestCve(overrides: Partial<NormalizedCVE> = {}): NormalizedCVE {
  return {
    cveId: 'CVE-2026-1001',
    title: 'Test widget vulnerability',
    description: 'A vulnerability in the test widget.',
    publishedDate: '2026-10-18T14:30:00Z',
    modifiedDate: '2026-10-19T21:45:00Z',
    cvss: {
      version: '3.1',
      score: 9.8,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      severity: 'CRITICAL',
    },
    cwe: ['CWE-77'],
    cpeMatches: ['cpe:2.3:a:vendor:widget:*:*:*:*:*:*:*:*'],
    versionRange: { versionStartIncluding: '1.0', versionEndExcluding: '3.0' },
    cpeMatchDetails: [],
    purls: [],
    vex: undefined,
    sourceFeeds: ['Test feed'],
    epss: { score: 0.1, percentile: 50 },
    cisaKev: { isKev: false },
    exploitStatus: 'None',
    remediation: {
      patchUrl: 'https://example.com/advisory',
      vendorAdvisoryRef: 'EXAMPLE-001',
      immediateActions: [],
      workarounds: [],
      rollbackPlan: 'N/A',
      stepByStep: [],
    },
    ...overrides,
  };
}

export function createTestAsset(overrides: Partial<WatchListItem> = {}): WatchListItem {
  return {
    id: 'asset-test',
    vendor: 'vendor',
    product: 'widget',
    version: '2.0',
    purls: undefined,
    targetHw: undefined,
    cpes: ['cpe:2.3:a:vendor:widget:2.0:*:*:*:*:*:*:*'],
    exposure: 'DMZ',
    assetTag: 'TEST-ASSET',
    ownerGroup: 'Cyber',
    active: true,
    notes: 'Test fixture',
    createdAt: '2026-09-01T08:00:00Z',
    ...overrides,
  };
}

export function createTestFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'fnd-test',
    cveId: 'CVE-2024-3400',
    cve: createTestCve(),
    matchedAssetId: 'asset-fw-01',
    matchedAssetName: 'EDGE-FW-HQ-PRIMARY (PAN-OS GlobalProtect)',
    matchedCpe: 'cpe:2.3:a:vendor:widget:2.0:*:*:*:*:*:*:*',
    matchingMethod: 'STRICT_CPE_INTERVAL',
    matchingEvidence: 'asset v2.0 is within [1.0, 3.0)',
    status: 'MONITORED',
    exploitRisk: 'STANDARD',
    confidence: 90,
    notificationStatus: 'REVIEW_REQUIRED',
    autoDispatchedAt: null,
    advisoryId: null,
    timeline: [
      {
        timestamp: '2026-10-19T21:00:00Z',
        action: 'Test fixture created',
        system: 'tests',
        details: 'Synthetic finding used by test suites; not produced by the pipeline.',
      },
    ],
  };
}
