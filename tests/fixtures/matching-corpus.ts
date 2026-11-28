import type { MatchingCase } from '../../src/utils/matchingMetrics.ts';

interface CpeParts {
  part?: string;
  vendor: string;
  product: string;
  version?: string;
  update?: string;
  edition?: string;
  language?: string;
  swEdition?: string;
  targetSw?: string;
  targetHw?: string;
  other?: string;
}

const cpe = (parts: CpeParts): string =>
  [
    'cpe:2.3',
    parts.part ?? 'a',
    parts.vendor,
    parts.product,
    parts.version ?? '*',
    parts.update ?? '*',
    parts.edition ?? '*',
    parts.language ?? '*',
    parts.swEdition ?? '*',
    parts.targetSw ?? '*',
    parts.targetHw ?? '*',
    parts.other ?? '*',
  ].join(':');

const benignText = {
  vulnTitle: 'Quarterly security bulletin',
  vulnDescription: 'Routine maintenance information published by the vendor.',
};

/**
 * Labelled correlation corpus used by `npm run matching:evaluate` and
 * `tests/matching-quality.test.ts`.
 *
 * Every case names the evidence class it expects, not just match/no-match.
 * That is deliberate: a matcher can be "right" for the wrong reason (an alias
 * match where strict CPE was expected), and that would hide a confidence or
 * review-gating regression. Add real-world cases here when a production
 * mismatch is investigated; the harness turns them into a permanent gate.
 */
export const MATCHING_CORPUS: MatchingCase[] = [
  {
    id: 'strict-exact',
    description: 'Identical structured CPE tokens match at the strict tier',
    tags: ['strict', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      ...benignText,
    },
    expected: { matched: true, methods: ['STRICT_CPE'], confidence: 90, requiresReview: false },
  },
  {
    id: 'strict-interval',
    description: 'Strict CPE plus a verified version interval reaches 100% dispatch confidence',
    tags: ['strict', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.5' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.5' })],
      versionRange: { versionStartIncluding: '1.0', versionEndExcluding: '2.0' },
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['STRICT_CPE_INTERVAL'],
      confidence: 100,
      requiresReview: false,
    },
  },
  {
    id: 'strict-case-insensitive',
    description: 'CPE components are compared case-insensitively',
    tags: ['strict', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'Example', product: 'Widget', version: '1.0' })],
      assetVendor: 'Example',
      assetProduct: 'Widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      ...benignText,
    },
    expected: { matched: true, methods: ['STRICT_CPE'], confidence: 90 },
  },
  {
    id: 'registered-all-versions',
    description: 'A registered all-version product intentionally covers concrete vulnerable versions',
    tags: ['strict', 'wildcard', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '*' })],
      assetVendor: 'example', assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.5' })],
      versionRange: { versionEndExcluding: '2.0' },
      ...benignText,
    },
    expected: { matched: true, methods: ['STRICT_CPE_INTERVAL'], confidence: 100, requiresReview: false },
  },
  {
    id: 'generic-cpe-resolved',
    description: 'A wildcard inventory CPE resolved to a concrete vendor/product is a confident match',
    tags: ['generic', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: '*', product: '*', version: '1.5' })],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'acme', product: 'widget', version: '1.5' })],
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['STRICT_CPE'],
      confidence: 90,
      requiresReview: false,
    },
  },
  {
    id: 'purl-exact',
    description: 'Identical package identities with concrete versions match at the PURL tier',
    tags: ['purl', 'positive'],
    input: {
      assetVendor: 'example',
      assetProduct: 'widget',
      assetPurls: ['pkg:npm/widget@1.2.3'],
      vulnPurls: ['pkg:npm/widget@1.2.3'],
      ...benignText,
    },
    expected: { matched: true, methods: ['PURL_EXACT'], confidence: 95, requiresReview: false },
  },
  {
    id: 'purl-name-only-review',
    description: 'A version-less package identity is review-only, never auto-dispatchable',
    tags: ['purl', 'positive'],
    input: {
      assetVendor: 'example',
      assetProduct: 'widget',
      assetPurls: ['pkg:npm/widget'],
      vulnPurls: ['pkg:npm/widget'],
      ...benignText,
    },
    expected: { matched: true, methods: ['PURL_EXACT'], confidence: 70, requiresReview: true },
  },
  {
    id: 'alias-built-in-vendor',
    description: 'Built-in vendor aliases resolve a structured spelling difference at 85%',
    tags: ['alias', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'microsoft', product: 'exchange_server', version: '15' })],
      assetVendor: 'microsoft',
      assetProduct: 'exchange_server',
      vulnCpes: [cpe({ vendor: 'msft', product: 'exchange_server', version: '15' })],
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['VENDOR_PRODUCT_ALIAS'],
      confidence: 85,
      requiresReview: false,
    },
  },
  {
    id: 'alias-built-in-product',
    description: 'Punctuation-only product differences resolve through normalization at 85%',
    tags: ['alias', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget_pro', version: '1.0' })],
      assetVendor: 'example',
      assetProduct: 'widget_pro',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget-pro', version: '1.0' })],
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['VENDOR_PRODUCT_ALIAS'],
      confidence: 85,
    },
  },
  {
    id: 'alias-operator-custom',
    description: 'Operator aliases broaden vendor identity without changing the confidence tier',
    tags: ['alias', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'acme', product: 'widget', version: '1.0' })],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'acme_corp', product: 'widget', version: '1.0' })],
      customVendorAliases: { acme: ['acme_corp'] },
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['VENDOR_PRODUCT_ALIAS'],
      confidence: 85,
    },
  },
  {
    id: 'fallback-text',
    description: 'Whole-word vendor and product prose is the last-resort review-only match',
    tags: ['fallback', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'asset_vendor', product: 'asset_widget', version: '1.5' })],
      assetVendor: 'asset_vendor',
      assetProduct: 'asset_widget',
      vulnCpes: [cpe({ vendor: 'nvd_vendor', product: 'nvd_widget', version: '*' })],
      vulnTitle: 'Asset Vendor Asset Widget security advisory',
      vulnDescription: 'A flaw was found in the Asset Widget product family.',
    },
    expected: {
      matched: true,
      methods: ['VENDOR_PRODUCT_FALLBACK'],
      confidence: 70,
    },
  },
  {
    id: 'fallback-in-range',
    description: 'Prose fallback still verifies a comparable version range before matching',
    tags: ['fallback', 'positive'],
    input: {
      assetVendor: 'acme',
      assetProduct: 'widget',
      assetVersion: '1.5',
      vulnTitle: 'Acme Widget vulnerability',
      vulnDescription: 'Versions before 2.0 are affected.',
      versionRange: { versionEndExcluding: '2.0' },
    },
    expected: {
      matched: true,
      methods: ['VENDOR_PRODUCT_FALLBACK'],
      confidence: 70,
    },
  },
  {
    id: 'unknown-update-requires-review',
    description: 'An unconstrained inventory update field cannot prove a service-pack criterion',
    tags: ['strict', 'positive', 'review'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [
        cpe({ vendor: 'example', product: 'widget', version: '1.0', update: 'sp1' }),
      ],
      ...benignText,
    },
    expected: {
      matched: true,
      methods: ['STRICT_CPE'],
      confidence: 90,
      requiresReview: false,
    },
  },

  // Negative cases: these are the errors that matter operationally.
  {
    id: 'negative-purl-version',
    description: 'A concrete PURL version mismatch is authoritative',
    tags: ['purl', 'negative'],
    input: {
      assetVendor: 'example',
      assetProduct: 'widget',
      assetPurls: ['pkg:npm/widget@1.0.0'],
      vulnPurls: ['pkg:npm/widget@2.0.0'],
      ...benignText,
    },
    expected: { matched: false },
  },
  {
    id: 'negative-purl-identity',
    description: 'Different package identities never correlate through prose',
    tags: ['purl', 'negative'],
    input: {
      assetVendor: 'example',
      assetProduct: 'widget',
      assetPurls: ['pkg:npm/widget@1.0.0'],
      vulnPurls: ['pkg:npm/gadget@1.0.0'],
      vulnTitle: 'Example Widget vulnerability',
      vulnDescription: 'Example Widget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-version-token',
    description: 'Identical product identity with a different explicit CPE version is an exclusion',
    tags: ['version', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '3.0' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      vulnTitle: 'Example Widget vulnerability',
      vulnDescription: 'Example Widget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-range-exclusion',
    description: 'A comparable version outside the advisory interval cannot fall through to prose',
    tags: ['version', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'acme', product: 'widget', version: '3.0' })],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'acme', product: 'widget', version: '*' })],
      versionRange: { versionEndExcluding: '2.0' },
      vulnTitle: 'Acme Widget vulnerability',
      vulnDescription: 'Acme Widget before 2.0 is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-platform-same-names',
    description: 'A target-OS conflict is authoritative when the product names match',
    tags: ['platform', 'negative'],
    input: {
      assetCpes: [
        cpe({ vendor: 'microsoft', product: 'exchange', version: '15', targetSw: 'linux' }),
      ],
      assetVendor: 'microsoft',
      assetProduct: 'exchange',
      vulnCpes: [
        cpe({ vendor: 'microsoft', product: 'exchange', version: '15', targetSw: 'windows' }),
      ],
      vulnTitle: 'Microsoft Exchange vulnerability',
      vulnDescription: 'Microsoft Exchange is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-platform-alias-names',
    description: 'Alias resolution does not erase a target-OS exclusion',
    tags: ['platform', 'alias', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'msft', product: 'exchange', version: '15', targetSw: 'linux' })],
      assetVendor: 'microsoft',
      assetProduct: 'exchange',
      vulnCpes: [
        cpe({ vendor: 'microsoft', product: 'exchange', version: '15', targetSw: 'windows' }),
      ],
      vulnTitle: 'Microsoft Exchange vulnerability',
      vulnDescription: 'Microsoft Exchange is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-part',
    description: 'Application and hardware CPE parts never correlate',
    tags: ['platform', 'negative'],
    input: {
      assetCpes: [cpe({ part: 'a', vendor: 'example', product: 'widget', version: '1.0' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ part: 'h', vendor: 'example', product: 'widget', version: '1.0' })],
      vulnTitle: 'Example Widget vulnerability',
      vulnDescription: 'Example Widget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-edition',
    description: 'An explicit edition conflict is authoritative',
    tags: ['platform', 'negative'],
    input: {
      assetCpes: [
        cpe({ vendor: 'example', product: 'widget', version: '1.0', edition: 'enterprise' }),
      ],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [
        cpe({ vendor: 'example', product: 'widget', version: '1.0', edition: 'community' }),
      ],
      vulnTitle: 'Example Widget vulnerability',
      vulnDescription: 'Example Widget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-architecture',
    description: 'A target-architecture conflict is authoritative',
    tags: ['platform', 'negative'],
    input: {
      assetCpes: [
        cpe({ vendor: 'example', product: 'widget', version: '1.0', targetHw: 'x86_64' }),
      ],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0', targetHw: 'arm64' })],
      vulnTitle: 'Example Widget vulnerability',
      vulnDescription: 'Example Widget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-architecture-argument',
    description: 'The explicit architecture de-noising argument also rejects a mismatch',
    tags: ['platform', 'negative'],
    input: {
      assetVendor: 'example',
      assetProduct: 'widget',
      assetTargetHw: 'x86_64',
      vulnTargetHw: 'arm64',
      ...benignText,
    },
    expected: { matched: false },
  },
  {
    id: 'negative-short-vendor-substring',
    description: 'A two-letter vendor such as `os` is not prose evidence inside `most`',
    tags: ['fallback', 'token-boundary', 'negative'],
    input: {
      assetVendor: 'os',
      assetProduct: 'widget',
      vulnTitle: 'Most widgets are patched',
      vulnDescription: 'Almost every widget ships with the fix.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-short-token-identity',
    description: 'An all-short identity is too ambiguous for prose matching',
    tags: ['fallback', 'token-boundary', 'negative'],
    input: {
      assetVendor: 'ai',
      assetProduct: 'go',
      vulnTitle: 'Maintain good practices',
      vulnDescription: 'Teams should maintain good operational practices.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-short-token-mixed-identity',
    description: 'A short token inside a mixed identity cannot be dropped from prose evidence',
    tags: ['fallback', 'token-boundary', 'negative'],
    input: {
      assetVendor: 'acme',
      assetProduct: 'big_ip_2',
      vulnTitle: 'Acme Big IP vulnerability',
      vulnDescription: 'Acme Big IP is affected by a critical flaw.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-glued-words',
    description: 'Identity words must be whole tokens, not substrings of a longer word',
    tags: ['fallback', 'token-boundary', 'negative'],
    input: {
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnTitle: 'Acmewidgetgadget release notes',
      vulnDescription: 'Unrelated product documentation.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-wrong-product-same-vendor',
    description: 'A shared vendor alone cannot correlate a different product',
    tags: ['strict', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'acme', product: 'widget', version: '1.0' })],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'acme', product: 'gadget', version: '*' })],
      vulnTitle: 'Acme Gadget vulnerability',
      vulnDescription: 'Acme Gadget is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-generic-cpe-other-product',
    description: 'A generic inventory CPE cannot match an unrelated advisory product',
    tags: ['generic', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: '*', product: '*', version: '1.5' })],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'other', product: 'thing', version: '1.5' })],
      vulnTitle: 'Other Thing vulnerability',
      vulnDescription: 'Other Thing is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-wildcard-version-intersection',
    description: 'Non-overlapping wildcard version patterns do not intersect',
    tags: ['version', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '2.*' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.*' })],
      ...benignText,
    },
    expected: { matched: false },
  },
  {
    id: 'negative-unrelated-prose',
    description: 'Unrelated prose with no identity words never correlates',
    tags: ['fallback', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'example', product: 'widget', version: '1.0' })],
      assetVendor: 'example',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'other', product: 'thing', version: '*' })],
      vulnTitle: 'Quarterly newsletter',
      vulnDescription: 'Office hours and travel announcements.',
    },
    expected: { matched: false },
  },
  {
    id: 'positive-wildcard-product-any-concrete-product',
    description: 'A wildcard product in the advisory CPE matches any concrete asset product from the same vendor',
    tags: ['strict', 'wildcard', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'php', product: 'myapp', version: '1.0' })],
      assetVendor: 'php',
      assetProduct: 'myapp',
      vulnCpes: [cpe({ vendor: 'php', product: '*', version: '*' })],
      ...benignText,
    },
    expected: { matched: true, methods: ['STRICT_CPE'], confidence: 90 },
  },
  {
    id: 'positive-wildcard-vendor-any-concrete-vendor',
    description: 'A wildcard vendor in the advisory CPE matches any concrete asset vendor with the same product',
    tags: ['strict', 'wildcard', 'positive'],
    input: {
      assetCpes: [cpe({ vendor: 'apache', product: 'php', version: '1.0' })],
      assetVendor: 'apache',
      assetProduct: 'php',
      vulnCpes: [cpe({ vendor: '*', product: 'php', version: '*' })],
      ...benignText,
    },
    expected: { matched: true, methods: ['STRICT_CPE'], confidence: 90 },
  },
  {
    id: 'negative-wildcard-product-different-vendor',
    description: 'A wildcard product does not match a different vendor',
    tags: ['strict', 'wildcard', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'apache', product: 'myapp', version: '1.0' })],
      assetVendor: 'apache',
      assetProduct: 'myapp',
      vulnCpes: [cpe({ vendor: 'php', product: '*', version: '*' })],
      vulnTitle: 'PHP vulnerability',
      vulnDescription: 'A flaw in PHP is affected.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-concrete-product-vs-wildcard-product',
    description: 'A concrete product does not match a different concrete product even with shared vendor',
    tags: ['strict', 'negative'],
    input: {
      assetCpes: [cpe({ vendor: 'php', product: 'myapp', version: '1.0' })],
      assetVendor: 'php',
      assetProduct: 'myapp',
      vulnCpes: [cpe({ vendor: 'php', product: 'php', version: '*' })],
      vulnTitle: 'PHP product vulnerability',
      vulnDescription: 'The PHP product is affected.',
    },
    expected: { matched: false },
  },

  // Prose attribution: the identity must be the affected subject, not the
  // language, plugin container, dependency or platform a flaw was reported in.
  // This class is vocabulary-independent on purpose - an unlisted framework name
  // is caught by the same structural rule, so no stop-list needs extending.
  {
    id: 'negative-prose-nested-product-name',
    description: 'A name that only begins another product name is not that product',
    tags: ['fallback', 'attribution', 'negative'],
    input: {
      assetVendor: 'acme',
      assetProduct: 'quicksilver',
      vulnTitle: 'Acme Quicksilver Builder plugin file upload',
      vulnDescription: 'A SQL injection in the Acme Quicksilver Builder plugin allows file uploads.',
    },
    expected: { matched: false },
  },
  {
    id: 'positive-prose-longer-subject-name',
    description: 'A longer name in subject position keeps its first word inside the affected product',
    tags: ['fallback', 'attribution', 'positive'],
    input: {
      assetVendor: 'acme',
      assetProduct: 'quicksilver',
      vulnTitle: 'Acme Quicksilver Data Center flaw',
      vulnDescription: 'Acme Quicksilver Data Center is vulnerable to a SQL injection.',
    },
    expected: { matched: true, methods: ['VENDOR_PRODUCT_FALLBACK'], confidence: 70 },
  },
  {
    id: 'negative-prose-language-vehicle',
    description: 'A language named only as the vehicle of the flaw is not the affected product',
    tags: ['fallback', 'attribution', 'negative'],
    input: {
      assetVendor: 'acme storefront',
      assetProduct: 'acme storefront',
      vulnTitle: 'Checkout export endpoint disclosure',
      vulnDescription:
        'A vulnerability in the Acme Storefront checkout module allows an unauthenticated attacker to read order records through an application written in Acme Storefront.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-prose-plugin-container',
    description: 'A product named only as the container of a plugin is not the affected subject',
    tags: ['fallback', 'attribution', 'negative'],
    input: {
      assetVendor: 'acme',
      assetProduct: 'storefront',
      vulnTitle: 'Third-party plugin file upload',
      vulnDescription:
        'A file upload flaw affects the ImagePress extension distributed for Acme Storefront sites',
    },
    expected: { matched: false },
  },
  {
    id: 'positive-prose-subject-position',
    description: 'The same identity stated as the affected subject still matches',
    tags: ['fallback', 'attribution', 'positive'],
    input: {
      assetVendor: 'acme',
      assetProduct: 'storefront',
      vulnTitle: 'Storefront order export flaw',
      vulnDescription:
        'A vulnerability in Acme Storefront allows an unauthenticated attacker to read order records via the export endpoint.',
    },
    expected: { matched: true, methods: ['VENDOR_PRODUCT_FALLBACK'], confidence: 70 },
  },
  {
    id: 'negative-prose-negated',
    description: 'A sentence that negates applicability is not evidence of exposure',
    tags: ['fallback', 'attribution', 'negative'],
    input: {
      assetVendor: 'acme',
      assetProduct: 'storefront',
      vulnTitle: 'Acme Storefront security notice',
      vulnDescription: 'Acme Storefront is not affected by this flaw.',
    },
    expected: { matched: false },
  },
  {
    id: 'negative-structural-wildcard-identity',
    description: 'A partial-glob vendor in the inventory CPE is not an identity assertion for a different product',
    tags: ['strict', 'wildcard', 'negative'],
    input: {
      // The declared identity is acme/widget; the CPE is a broad scope over all
      // `acme.*` vendors. It must not make the asset match an advisory for a
      // different product (acme/storefront) merely through the glob.
      assetCpes: ['cpe:2.3:a:acme.*:widget:1.0:*:*:*:*:*:*:*'],
      assetVendor: 'acme',
      assetProduct: 'widget',
      vulnCpes: [cpe({ vendor: 'acme', product: 'storefront', version: '1.0' })],
      vulnTitle: 'Acme Storefront vulnerability',
      vulnDescription: 'A flaw in Acme Storefront allows uploads.',
    },
    expected: { matched: false },
  },
];
