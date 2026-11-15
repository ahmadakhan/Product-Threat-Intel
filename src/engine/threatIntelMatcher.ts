/**
 * Unified threat-intelligence matching and dispatch preparation.
 *
 * This module is the single deterministic path from a raw vulnerability record
 * (NVD 2.0, VulnCheck, OSV, a vendor advisory, or a news item) and an
 * operator-owned Vendor+Product list to one deduplicated dispatch plan.
 *
 * The contract is deliberately stricter than a "best effort" matcher:
 *
 *  - Every applicable inventory identity appears in `matches`, either queued
 *    for dispatch or suppressed as an already-delivered duplicate. A match is
 *    only removed when the inventory version is provably outside the advisory
 *    range (or the source explicitly negates applicability).
 *  - Structured evidence is evaluated first (CPE, then PURL). Unstructured
 *    evidence is a fallback, and it cannot re-admit an asset whose structured
 *    version evidence proves it is patched.
 *  - A non-CVE record gets a deterministic `VulXXXXX` identity derived from
 *    the canonical vendor, product and incident topic. Re-running the same
 *    incident therefore produces the same identifier.
 *  - One consolidated email contains every queued finding. The count is
 *    checked against the rendered item list before the plan is returned.
 *
 * The pure functions here are also used by the correlation layer for synthetic
 * non-CVE identifiers, so this module must not depend on PostgreSQL or Express.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { evaluateVersionInRange, type NvdVersionRange } from '../utils/versionComparator.ts';
import { evaluateVersion } from '../../server/correlation/version.ts';
import {
  isNegatedSentence,
  isPassivePlatformMention,
  textSupportsExposure,
} from '../utils/textEvidenceGuards.ts';
import {
  DEFAULT_PRODUCT_ALIASES,
  DEFAULT_VENDOR_ALIASES,
  normalizeAliasToken,
} from '../utils/cpeMatcher.ts';

/* -------------------------------------------------------------------------- */
/* Public types                                                               */
/* -------------------------------------------------------------------------- */

export type CaseLabel = 'Case 1' | 'Case 2' | 'Case 3' | 'Case 4';

export type CaseCode =
  | 'CASE_1_VENDOR_EXACT_PRODUCT'
  | 'CASE_2_VENDOR_WILDCARD_PRODUCT'
  | 'CASE_3_VENDOR_ADVISORY'
  | 'CASE_4_VENDOR_PRODUCT_GENERAL_FEED';

export type SourceCategory = 'VENDOR_ADVISORY' | 'THIRD_PARTY_FEED' | 'STRIPPED_AMBIGUOUS';

export type MatchPrecision = 'Exact' | 'Wildcard';

export type MatchMethod = 'CPE' | 'PURL' | 'Text';

export type DeliveryStatus = 'QUEUED_FOR_DISPATCH' | 'SUPPRESSED_DUPLICATE';

export type VersionVerdict = 'IN_RANGE' | 'OUT_OF_RANGE' | 'INCONCLUSIVE';

export interface VendorProductInput {
  vendor?: string;
  product?: string;
  version?: string | number;
  versions?: Array<string | number>;
  cpe?: string;
  cpes?: string[] | string;
  purl?: string;
  purls?: string[] | string;
  packageUrl?: string;
  assetTag?: string;
  id?: string;
  [key: string]: unknown;
}

export interface ParsedPurl {
  raw: string;
  type: string;
  namespace: string;
  name: string;
  version: string;
  qualifiers: string;
  subpath: string;
  /** `pkg:type/namespace/name`, lower-cased, no version/qualifiers. */
  basePurl: string;
  /** Snake-case mirror of `basePurl` for feed adapters that use PURL JSON. */
  base_purl: string;
  isValid: boolean;
}

export interface ParsedCpe {
  raw: string;
  part: string;
  vendor: string;
  product: string;
  version: string;
  update: string;
  edition: string;
  language: string;
  swEdition: string;
  targetSw: string;
  targetHw: string;
  other: string;
  isValid: boolean;
}

export interface ThreatMatch {
  /** CVE-... or deterministic VulXXXXX. */
  finding_id: string;
  cve_id: string | null;
  case_classification: CaseLabel;
  case_classification_code: CaseCode;
  source_category: SourceCategory;
  match_precision: MatchPrecision;
  match_method: MatchMethod;
  matched_vendor: string;
  matched_product: string;
  inventory_rule: string;
  /** Stable key for the inventory row used for intra-batch deduplication. */
  inventory_key?: string;
  version_verification_needed: boolean;
  audit_verified: true;
  delivery_status?: DeliveryStatus;
  suppression_reason?: string;
  previously_dispatched?: boolean;
  material_escalation: string[];
  new_escalations: string[];
  severity: SeverityLabel | null;
  cvss_score: number | null;
  kev: boolean;
  exploited: boolean;
  zero_day: boolean;
  vendor_patch: boolean;
  topic_signature: string;
  source_reference: string;
  advisory_ids: string[];
  evidence: string;
  matched_cpe?: string;
  matched_purl?: string;
}

export type SeverityLabel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface ConsolidatedEmailItem {
  finding_id: string;
  cve_id: string | null;
  case_classification: CaseLabel;
  match_precision: MatchPrecision;
  matched_vendor: string;
  matched_product: string;
  severity: SeverityLabel | null;
  cvss_score: number | null;
  priority_group: string;
  source_reference: string;
}

export interface ConsolidatedEmail {
  send_email: boolean;
  subject: string | null;
  body_markdown: string | null;
  queued_for_email_count: number;
  items: ConsolidatedEmailItem[];
  groups: { id: string; title: string; item_count: number }[];
}

export interface DeliveryReport {
  total_matches: number;
  delivered_count: number;
  suppressed_duplicate_count: number;
  queued_for_email_count: number;
  all_findings_delivered: boolean;
  all_findings_accounted_for: boolean;
  deliveries: ThreatMatch[];
  matches: ThreatMatch[];
  consolidated_email: ConsolidatedEmail;
  send_email: boolean;
  subject: string | null;
  body_markdown: string | null;
}

export interface DispatchedLogEntry {
  key: string;
  ids: Set<string>;
  topics: Set<string>;
  state: Set<string>;
  raw: unknown;
}

export interface ParsedDispatchedLog {
  ids: Set<string>;
  topics: Set<string>;
  entries: DispatchedLogEntry[];
}

export type PreviouslyDispatchedLog =
  | string
  | string[]
  | Record<string, unknown>
  | Array<Record<string, unknown>>
  | null
  | undefined;

export interface MatcherOptions {
  previouslyDispatchedLog?: PreviouslyDispatchedLog;
  previously_dispatched_log?: PreviouslyDispatchedLog;
  vendorAliases?: Record<string, string[]>;
  productAliases?: Record<string, string[]>;
  now?: Date | string;
}

export interface ThreatIntelAnalysisInput {
  vendor_products?: VendorProductInput[] | VendorProductInput;
  vendorProducts?: VendorProductInput[] | VendorProductInput;
  vendor_product_list?: VendorProductInput[] | VendorProductInput;
  vendorProductList?: VendorProductInput[] | VendorProductInput;
  inventory?: VendorProductInput[] | VendorProductInput;
  products?: VendorProductInput[] | VendorProductInput;
  assets?: VendorProductInput[] | VendorProductInput;
  watchlist?: VendorProductInput[] | VendorProductInput;
  records?: unknown[] | unknown;
  feed?: unknown[] | unknown;
  incoming?: unknown[] | unknown;
  incoming_feed?: unknown[] | unknown;
  items?: unknown[] | unknown;
  text?: unknown;
  article?: unknown;
  advisory?: unknown;
  previously_dispatched_log?: PreviouslyDispatchedLog;
  previouslyDispatchedLog?: PreviouslyDispatchedLog;
  options?: MatcherOptions;
}

/* -------------------------------------------------------------------------- */
/* Small, strict value helpers                                                */
/* -------------------------------------------------------------------------- */

type JsonRecord = Record<string, unknown>;

const isRecord = (value: unknown): value is JsonRecord =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function asArray<T>(value: T | T[] | null | undefined): T[] {
  if (value === null || value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  }
  return undefined;
}

function firstNumber(...values: unknown[]): number | null {
  for (const value of values) {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) return Number(value);
  }
  return null;
}

function getPath(value: unknown, path: readonly (string | number)[]): unknown {
  let current: unknown = value;
  for (const key of path) {
    if (typeof key === 'number') {
      if (!Array.isArray(current)) return undefined;
      current = current[key];
      continue;
    }
    if (!isRecord(current)) return undefined;
    current = current[key];
  }
  return current;
}

function flagValue(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', 'yes', 'y', '1', 'kev', 'known exploited', 'active', 'confirmed'].includes(normalized))
      return true;
    if (['false', 'no', 'n', '0', 'none', 'unknown'].includes(normalized)) return false;
    return undefined;
  }
  if (Array.isArray(value)) {
    if (!value.length) return false;
    return value.some((entry) => flagValue(entry) === true);
  }
  if (isRecord(value)) {
    for (const key of ['isKev', 'is_kev', 'kev', 'knownExploited', 'known_exploited', 'exploited', 'active']) {
      const nested = flagValue(value[key]);
      if (nested !== undefined) return nested;
    }
  }
  return undefined;
}

function readFlag(record: unknown, paths: readonly (readonly (string | number)[])[]): boolean {
  for (const path of paths) {
    const value = getPath(record, path);
    const flag = flagValue(value);
    if (flag !== undefined) return flag;
  }
  return false;
}

function readString(record: unknown, paths: readonly (readonly (string | number)[])[]): string {
  for (const path of paths) {
    const value = getPath(record, path);
    if (typeof value === 'string' && value.trim()) return value.trim();
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  }
  return '';
}

function uniqueStrings(values: Iterable<string>): string[] {
  return [...new Set([...values].map((value) => value.trim()).filter(Boolean))];
}

/* -------------------------------------------------------------------------- */
/* Vendor / product normalization and aliases                                 */
/* -------------------------------------------------------------------------- */

const VENDOR_CANONICAL_RAW: Record<string, string> = {
  vmware: 'broadcom',
  'vmware inc': 'broadcom',
  broadcom: 'broadcom',
  paloaltonetworks: 'palo alto networks',
  'palo_alto': 'palo alto networks',
  'palo-alto': 'palo alto networks',
  paloalto: 'palo alto networks',
  'palo alto': 'palo alto networks',
  'palo alto networks': 'palo alto networks',
  panw: 'palo alto networks',
  unit42: 'palo alto networks',
  ms: 'microsoft',
  msft: 'microsoft',
  microsoft: 'microsoft',
  'microsoft corp': 'microsoft',
  'microsoft corporation': 'microsoft',
  fireeye: 'trellix',
  'fireeye inc': 'trellix',
  trellix: 'trellix',
  'org.apache.logging.log4j': 'apache',
  'apache software foundation': 'apache',
  apache: 'apache',
  'cisco systems': 'cisco',
  'cisco-systems': 'cisco',
  cisco: 'cisco',
  fortinet: 'fortinet',
  'fortinet technologies': 'fortinet',
  nginx: 'nginx',
  'f5 networks': 'f5',
  f5: 'f5',
  'kubernetes': 'kubernetes',
  k8s: 'kubernetes',
  postgres: 'postgresql',
  postgresql: 'postgresql',
  ubuntu: 'canonical',
  canonical: 'canonical',
};

const PRODUCT_CANONICAL_RAW: Record<string, string> = {
  'azure ad': 'entra id',
  'azure active directory': 'entra id',
  'azure ad premium': 'entra id',
  'microsoft entra id': 'entra id',
  'entra id': 'entra id',
  panos: 'pan os',
  'pan-os': 'pan os',
  'pan os': 'pan os',
};

/**
 * Lower-cases and normalizes a vendor/product name while preserving the
 * characters that are meaningful in product names (`+`, `#`, `.` and `*`).
 * Separators become single spaces so CPE spellings (`windows_server_2022`),
 * prose spellings (`Windows Server 2022`) and PURL spellings (`windows-server`)
 * compare through the same key.
 */
function normalizedName(value: string): string {
  return value
    .normalize('NFKC')
    .toLowerCase()
    .replace(/\\(.)/g, '$1')
    .replace(/[_\-]+/g, ' ')
    .replace(/[^\p{L}\p{N}+#.*\s]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function normalizeVendor(value: string): string {
  const clean = normalizedName(value ?? '');
  if (!clean) return '';
  const direct = VENDOR_CANONICAL_RAW[clean] ?? VENDOR_CANONICAL_RAW[clean.replace(/\s+/g, '')];
  if (direct) return direct;
  // `palo_alto_networks` -> `palo alto networks`; already handled by the table.
  // Removing the separator entirely catches spellings such as `paloaltonetworks`.
  const compact = clean.replace(/\s+/g, '');
  return VENDOR_CANONICAL_RAW[compact] ?? clean;
}

export function normalizeProduct(value: string): string {
  const clean = normalizedName(value ?? '');
  if (!clean) return '';
  return PRODUCT_CANONICAL_RAW[clean] ?? clean;
}

function aliasGroupEntries(
  canonical: string,
  base: Record<string, string[]>,
  custom: Record<string, string[]>,
  normalizer: (value: string) => string,
): Set<string> {
  const target = normalizer(canonical);
  const group = new Set<string>([target]);
  const tables = [base, custom];
  for (const table of tables) {
    for (const [entryCanonical, aliases] of Object.entries(table)) {
      const entries = [entryCanonical, ...aliases].map((entry) => normalizer(entry));
      if (!entries.includes(target)) continue;
      for (const entry of entries) group.add(entry);
    }
  }
  return group;
}

function vendorGroup(
  vendor: string,
  custom: Record<string, string[]> = {},
): Set<string> {
  const canonical = normalizeVendor(vendor);
  const group = aliasGroupEntries(canonical, DEFAULT_VENDOR_ALIASES, custom, normalizeVendor);
  // The canonical target table is not part of DEFAULT_VENDOR_ALIASES in every
  // direction (for example Broadcom -> VMware). Add every raw spelling that
  // normalizes to this vendor.
  for (const [raw, target] of Object.entries(VENDOR_CANONICAL_RAW))
    if (target === canonical) group.add(normalizeVendor(raw));
  return group;
}

function productGroup(
  product: string,
  custom: Record<string, string[]> = {},
): Set<string> {
  const canonical = normalizeProduct(product);
  const group = aliasGroupEntries(canonical, DEFAULT_PRODUCT_ALIASES, custom, normalizeProduct);
  for (const [raw, target] of Object.entries(PRODUCT_CANONICAL_RAW))
    if (target === canonical) group.add(normalizeProduct(raw));
  return group;
}

function identityGroupsOverlap(
  left: Set<string>,
  right: Set<string>,
): boolean {
  for (const value of left) if (right.has(value)) return true;
  return false;
}

function hasWildcard(value: string): boolean {
  return value.includes('*');
}

function wildcardPattern(value: string): RegExp {
  const normalized = normalizedName(value);
  const source = normalized
    .split(/(\*)/)
    .map((part) => (part === '*' ? '.*' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    .join('')
    .replace(/\s+/g, '[\\s_.\\-]+');
  return new RegExp(`^${source}$`, 'u');
}

/**
 * Matches a feed's vendor/product component against an inventory component.
 *
 * Wildcards are accepted on either side: some feeds publish a wildcard
 * criterion, and operators deliberately register `Vendor | *` or
 * `Vendor | Product-*`. When neither side contains one, the built-in and
 * operator-supplied alias thesauri are consulted.
 */
function componentMatches(
  feedValue: string,
  inventoryValue: string,
  type: 'vendor' | 'product',
  customAliases: Record<string, string[]>,
): boolean {
  const feed = (type === 'vendor' ? normalizeVendor(feedValue) : normalizeProduct(feedValue)) || '*';
  const inventory =
    (type === 'vendor' ? normalizeVendor(inventoryValue) : normalizeProduct(inventoryValue)) || '*';

  if (feed === '*' || inventory === '*') return true;
  if (hasWildcard(feed) || hasWildcard(inventory)) {
    if (hasWildcard(feed) && !hasWildcard(inventory)) return wildcardPattern(feed).test(inventory);
    if (!hasWildcard(feed) && hasWildcard(inventory)) return wildcardPattern(inventory).test(feed);
    return wildcardPattern(feed).source === wildcardPattern(inventory).source;
  }
  if (feed === inventory) return true;
  if (normalizeAliasToken(feed) === normalizeAliasToken(inventory)) return true;
  const feedGroup = type === 'vendor' ? vendorGroup(feed, customAliases) : productGroup(feed, customAliases);
  const inventoryGroup =
    type === 'vendor' ? vendorGroup(inventory, customAliases) : productGroup(inventory, customAliases);
  return identityGroupsOverlap(feedGroup, inventoryGroup);
}

function humanizeFeedProduct(value: string): string {
  return value.replace(/_/g, ' ').replace(/\s+/g, ' ').trim() || '*';
}

/* -------------------------------------------------------------------------- */
/* CPE / PURL parsers                                                         */
/* -------------------------------------------------------------------------- */

function unescapeCpe(value: string): string {
  return value.replace(/\\(.)/g, '$1');
}

/** Parses a CPE 2.3 URI and tolerates legacy CPE 2.2 (`cpe:/a:...`) input. */
export function parseCpe(value: string): ParsedCpe {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) return emptyCpe(raw, false);

  if (raw.startsWith('cpe:2.3:')) {
    const fields = splitCpeFields(raw.slice(8));
    if (fields.length === 11)
      return {
        raw,
        part: unescapeCpe(fields[0]).toLowerCase() || '*',
        vendor: unescapeCpe(fields[1]).toLowerCase() || '*',
        product: unescapeCpe(fields[2]).toLowerCase() || '*',
        version: unescapeCpe(fields[3]).toLowerCase() || '*',
        update: unescapeCpe(fields[4]).toLowerCase() || '*',
        edition: unescapeCpe(fields[5]).toLowerCase() || '*',
        language: unescapeCpe(fields[6]).toLowerCase() || '*',
        swEdition: unescapeCpe(fields[7]).toLowerCase() || '*',
        targetSw: unescapeCpe(fields[8]).toLowerCase() || '*',
        targetHw: unescapeCpe(fields[9]).toLowerCase() || '*',
        other: unescapeCpe(fields[10]).toLowerCase() || '*',
        isValid: true,
      };
  }

  if (raw.startsWith('cpe:/')) {
    const fields = raw.slice(5).split(':');
    if (fields.length >= 3) {
      return {
        raw,
        part: (fields[0] || '*').toLowerCase(),
        vendor: unescapeCpe(fields[1] || '*').toLowerCase(),
        product: unescapeCpe(fields[2] || '*').toLowerCase(),
        version: unescapeCpe(fields[3] || '*').toLowerCase(),
        update: unescapeCpe(fields[4] || '*').toLowerCase(),
        edition: (fields[5] || '*').toLowerCase(),
        language: (fields[6] || '*').toLowerCase(),
        swEdition: '*',
        targetSw: '*',
        targetHw: '*',
        other: '*',
        isValid: true,
      };
    }
  }

  return emptyCpe(raw, false);
}

function emptyCpe(raw: string, isValid: boolean): ParsedCpe {
  return {
    raw,
    part: '*',
    vendor: '*',
    product: '*',
    version: '*',
    update: '*',
    edition: '*',
    language: '*',
    swEdition: '*',
    targetSw: '*',
    targetHw: '*',
    other: '*',
    isValid,
  };
}

function splitCpeFields(value: string): string[] {
  const fields: string[] = [];
  let current = '';
  let escaped = false;
  for (const character of value) {
    if (escaped) {
      current += character;
      escaped = false;
    } else if (character === '\\') {
      current += character;
      escaped = true;
    } else if (character === ':') {
      fields.push(current);
      current = '';
    } else current += character;
  }
  fields.push(current);
  // A trailing escape has no valid meaning; treat it as malformed.
  if (escaped) return [];
  return fields;
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * Parses `pkg:type/namespace/name@version?qualifiers#subpath`.
 *
 * Versions are not stripped by a naive `lastIndexOf('@')`: in an npm scoped
 * package (`pkg:npm/@scope/name`) that character is part of the namespace.
 */
export function parsePurl(value: string): ParsedPurl | null {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw.toLowerCase().startsWith('pkg:')) return null;

  const fragmentAt = raw.indexOf('#');
  const withoutFragment = fragmentAt >= 0 ? raw.slice(0, fragmentAt) : raw;
  const queryAt = withoutFragment.indexOf('?');
  const withoutQuery = queryAt >= 0 ? withoutFragment.slice(0, queryAt) : withoutFragment;
  const qualifiers = queryAt >= 0 ? raw.slice(queryAt + 1, fragmentAt >= 0 ? fragmentAt : raw.length) : '';
  const subpath = fragmentAt >= 0 ? raw.slice(fragmentAt + 1) : '';
  const body = withoutQuery.slice(4);
  const lastSlash = body.lastIndexOf('/');
  const at = body.lastIndexOf('@');
  const versionAt = at > lastSlash ? at : -1;
  const pathPart = versionAt >= 0 ? body.slice(0, versionAt) : body;
  const version = versionAt >= 0 ? safeDecode(body.slice(versionAt + 1)) : '';
  const segments = pathPart.split('/').filter(Boolean).map(safeDecode);
  if (segments.length < 2) return null;

  const type = segments[0].toLowerCase();
  const name = segments[segments.length - 1];
  const namespace = segments.slice(1, -1).join('/').replace(/^@/, '');
  const basePurl = `pkg:${type}/${namespace ? `${namespace}/` : ''}${name}`.toLowerCase();
  return {
    raw,
    type,
    namespace,
    name,
    version,
    qualifiers,
    subpath,
    basePurl,
    base_purl: basePurl,
    isValid: true,
  };
}

export function purlBaseIdentity(value: string): string | null {
  const parsed = parsePurl(value);
  return parsed ? parsed.basePurl : null;
}

/* -------------------------------------------------------------------------- */
/* Inventory normalization                                                    */
/* -------------------------------------------------------------------------- */

interface NormalizedInventory {
  index: number;
  raw: VendorProductInput;
  vendor: string;
  product: string;
  canonicalVendor: string;
  canonicalProduct: string;
  versionCandidates: string[];
  cpes: ParsedCpe[];
  purls: ParsedPurl[];
  wildcard: boolean;
  rule: string;
}

function toInputArray(value: unknown): VendorProductInput[] {
  const entries: unknown[] = asArray(value as unknown | unknown[]);
  return entries
    .map((entry): VendorProductInput | null => {
      if (isRecord(entry)) return entry;
      // Accept the compact operator notation "Vendor | Product | Version".
      if (typeof entry === 'string' && entry.includes('|')) {
        const [vendor, product, version] = entry.split('|').map((part) => part.trim());
        if (vendor && product) return { vendor, product, ...(version ? { version } : {}) };
      }
      return null;
    })
    .filter((entry): entry is VendorProductInput => Boolean(entry));
}

function normalizeInventory(value: unknown): NormalizedInventory[] {
  return toInputArray(value)
    .map((entry, index) => {
      const cpeValues = uniqueStrings([
        ...asArray(entry.cpes).filter((item): item is string => typeof item === 'string'),
        ...asArray(entry.cpe).filter((item): item is string => typeof item === 'string'),
        ...asArray(entry.CPEs).filter((item): item is string => typeof item === 'string'),
        ...asArray(entry.CPE).filter((item): item is string => typeof item === 'string'),
      ]);
      const purlValues = uniqueStrings([
        ...asArray(entry.purls).filter((item): item is string => typeof item === 'string'),
        ...asArray(entry.purl).filter((item): item is string => typeof item === 'string'),
        ...asArray(entry.packageUrl).filter((item): item is string => typeof item === 'string'),
        ...asArray(entry.PURLs).filter((item): item is string => typeof item === 'string'),
        ...asArray(entry.PURL).filter((item): item is string => typeof item === 'string'),
      ]);
      const cpes = cpeValues.map(parseCpe).filter((cpe) => cpe.isValid);
      const purls = purlValues.map(parsePurl).filter((purl): purl is ParsedPurl => Boolean(purl));
      const cpe = cpes[0];
      const purl = purls[0];

      const vendor = firstString(entry.vendor, entry.Vendor, cpe?.vendor, purl?.namespace, purl?.type) ?? '';
      const product = firstString(entry.product, entry.Product, cpe?.product, purl?.name) ?? '';
      if (!vendor || !product) return null;

      const versionCandidates = uniqueStrings([
        ...asArray(entry.version).map((version) => String(version)),
        ...asArray(entry.Version).map((version) => String(version)),
        ...asArray(entry.versions).map((version) => String(version)),
        ...cpes
          .map((cpe) => cpe.version)
          .filter((version) => version && version !== '*' && version !== '-'),
        ...purls.map((purl) => purl.version).filter(Boolean),
      ]);
      const canonicalVendor = normalizeVendor(vendor);
      const canonicalProduct = normalizeProduct(product);
      const wildcard =
        hasWildcard(vendor) ||
        hasWildcard(product) ||
        cpes.some((cpe) => hasWildcard(cpe.vendor) || hasWildcard(cpe.product)) ||
        purls.some((purl) => hasWildcard(purl.basePurl));

      return {
        index,
        raw: entry,
        vendor,
        product,
        canonicalVendor,
        canonicalProduct,
        versionCandidates,
        cpes,
        purls,
        wildcard,
        rule: `${vendor} | ${product}`,
      };
    })
    .filter((entry): entry is NormalizedInventory => Boolean(entry));
}

/* -------------------------------------------------------------------------- */
/* Source metadata, severity, and escalation state                            */
/* -------------------------------------------------------------------------- */

interface SourceInfo {
  caseLabel: CaseLabel;
  caseCode: CaseCode;
  sourceCategory: SourceCategory;
  isAdvisory: boolean;
  isNews: boolean;
}

const VENDOR_SOURCE_TYPES = new Set([
  'vendor_advisory',
  'vendor advisory',
  'vendor',
  'psirt',
  'official',
  'security_advisory',
  'security advisory',
  'vendor_psirt',
]);

const NEWS_SOURCE_TYPES = new Set([
  'news',
  'article',
  'blog',
  'social',
  'threat_blog',
  'threat feed',
  'threat_feed',
  'rss',
  'rss_atom',
  'third_party',
  'third party',
  'third_party_feed',
  'general_feed',
  'google_cse',
]);

const THIRD_PARTY_CNAS = new Set([
  'mitre',
  'vulncheck',
  'cisa-adp',
  'cisa adp',
  'patchstack',
  'wordfence',
  'github',
  'osv',
  'nvd',
  'cve',
]);

const CASE_CODES: Record<CaseLabel, CaseCode> = {
  'Case 1': 'CASE_1_VENDOR_EXACT_PRODUCT',
  'Case 2': 'CASE_2_VENDOR_WILDCARD_PRODUCT',
  'Case 3': 'CASE_3_VENDOR_ADVISORY',
  'Case 4': 'CASE_4_VENDOR_PRODUCT_GENERAL_FEED',
};

function readSourceType(record: unknown): string {
  return (
    readString(record, [
      ['source_type'],
      ['sourceType'],
      ['feed_type'],
      ['feedType'],
      ['type'],
      ['source', 'type'],
    ]) || ''
  )
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
}

function readCna(record: unknown): string {
  return readString(record, [
    ['sourceIdentifier'],
    ['source_identifier'],
    ['assignerShortName'],
    ['assigner_short_name'],
    ['assigner'],
    ['cna'],
    ['cveMetadata', 'assignerShortName'],
    ['cve', 'sourceIdentifier'],
    ['cve', 'assignerShortName'],
  ]);
}

function advisoryTagPresent(record: unknown): boolean {
  if (
    readFlag(record, [
      ['vendor_advisory'],
      ['vendorAdvisory'],
      ['is_vendor_advisory'],
      ['isVendorAdvisory'],
      ['psirt'],
      ['official'],
    ])
  )
    return true;

  const advisoryType = readString(record, [['advisory_type'], ['advisoryType']]).toLowerCase();
  if (advisoryType && /vendor|psirt|security advisory/.test(advisoryType)) return true;

  const reference = readString(record, [
    ['remediation', 'vendorAdvisoryRef'],
    ['vendorAdvisoryRef'],
    ['vendor_advisory_ref'],
    ['vendor_advisory_url'],
  ]);
  if (reference) return true;

  const references = [
    ...asArray(getPath(record, ['references'])),
    ...asArray(getPath(record, ['cve', 'references'])),
    ...asArray(getPath(record, ['containers', 'cna', 'references'])),
  ];
  for (const entry of references) {
    if (typeof entry === 'string') {
      if (/vendor advisory|vendor advisory\/psirt|psirt|security advisory/i.test(entry)) return true;
      continue;
    }
    if (!isRecord(entry)) continue;
    const tags = [entry.tags, entry.tag, entry.name, entry.type]
      .flatMap((value) => asArray(value))
      .filter((value): value is string => typeof value === 'string')
      .join(' ');
    if (/vendor advisory|psirt|vendor security advisory/i.test(tags)) return true;
  }
  return false;
}

function sourceInfo(record: unknown, candidateVendors: string[]): SourceInfo {
  const sourceType = readSourceType(record);
  const cna = readCna(record);
  const cnaCanonical = normalizeVendor(cna);
  const isAdvisory =
    VENDOR_SOURCE_TYPES.has(sourceType) ||
    advisoryTagPresent(record) ||
    (Boolean(cnaCanonical) && candidateVendors.some((vendor) => matchVendorForSource(cnaCanonical, vendor)));
  const isNews =
    !isAdvisory &&
    (NEWS_SOURCE_TYPES.has(sourceType) ||
      (Boolean(cna) && !candidateVendors.some((vendor) => matchVendorForSource(cnaCanonical, vendor))) ||
      THIRD_PARTY_CNAS.has(cnaCanonical));

  if (isAdvisory)
    return {
      caseLabel: 'Case 3',
      caseCode: CASE_CODES['Case 3'],
      sourceCategory: 'VENDOR_ADVISORY',
      isAdvisory: true,
      isNews: false,
    };
  if (isNews)
    return {
      caseLabel: 'Case 4',
      caseCode: CASE_CODES['Case 4'],
      sourceCategory: 'THIRD_PARTY_FEED',
      isAdvisory: false,
      isNews: true,
    };
  return {
    caseLabel: 'Case 1',
    caseCode: CASE_CODES['Case 1'],
    sourceCategory: 'STRIPPED_AMBIGUOUS',
    isAdvisory: false,
    isNews: false,
  };
}

function matchVendorForSource(left: string, right: string): boolean {
  const a = normalizeVendor(left);
  const b = normalizeVendor(right);
  if (!a || !b) return false;
  if (a === b) return true;
  return identityGroupsOverlap(vendorGroup(a), vendorGroup(b));
}

function caseFor(source: SourceInfo, precision: MatchPrecision): { caseLabel: CaseLabel; caseCode: CaseCode } {
  if (source.isAdvisory) return { caseLabel: 'Case 3', caseCode: CASE_CODES['Case 3'] };
  if (source.isNews) return { caseLabel: 'Case 4', caseCode: CASE_CODES['Case 4'] };
  return precision === 'Wildcard'
    ? { caseLabel: 'Case 2', caseCode: CASE_CODES['Case 2'] }
    : { caseLabel: 'Case 1', caseCode: CASE_CODES['Case 1'] };
}

const KEV_PATHS: readonly (readonly string[])[] = [
  ['kev'],
  ['isKev'],
  ['is_kev'],
  ['cisaKev', 'isKev'],
  ['cisa_kev', 'is_kev'],
  ['cisaKev'],
  ['knownExploited'],
  ['known_exploited'],
  ['activelyExploited'],
  ['actively_exploited'],
  ['vulncheck', 'kev'],
  ['vulnCheck', 'kev'],
  ['vulncheck', 'knownExploited'],
  ['vulncheck', 'known_exploited'],
  ['vulncheck', 'exploited'],
  ['exploited'],
  ['is_exploited'],
];

const ZERO_DAY_PATHS: readonly (readonly string[])[] = [
  ['zero_day'],
  ['zeroDay'],
  ['isZeroDay'],
  ['is_zero_day'],
  ['zero_day_exploited'],
  ['zeroDayExploited'],
];

const PUBLIC_EXPLOIT_PATHS: readonly (readonly string[])[] = [
  ['poc'],
  ['pocAvailable'],
  ['poc_available'],
  ['exploitAvailable'],
  ['exploit_available'],
  ['public_exploit'],
  ['weaponized'],
  ['exploit_published'],
  ['exploitPublished'],
];

const PATCH_PATHS: readonly (readonly string[])[] = [
  ['patch_available'],
  ['patchAvailable'],
  ['vendor_patch'],
  ['vendorPatch'],
  ['patched'],
  ['fixed_version'],
  ['fixedVersion'],
];

function extractEscalations(record: unknown): string[] {
  if (!isRecord(record)) return [];
  const reasons = new Set<string>();
  const kev = readFlag(record, KEV_PATHS);
  const exploitStatus = readString(record, [
    ['exploitStatus'],
    ['exploit_status'],
    ['vulncheck', 'exploitStatus'],
    ['vulnCheck', 'exploitStatus'],
    ['exploitation', 'status'],
  ]).toLowerCase();
  const activeStatus = /active|weaponized|in the wild|known exploited|exploited/.test(exploitStatus);
  if (kev) reasons.add('KEV');
  if (activeStatus) reasons.add('ACTIVE_EXPLOITATION');
  if (readFlag(record, ZERO_DAY_PATHS) || /zero[- ]day/.test(exploitStatus)) reasons.add('ZERO_DAY');
  if (readFlag(record, PUBLIC_EXPLOIT_PATHS) || /poc|proof.of.concept|public exploit/.test(exploitStatus))
    reasons.add('PUBLIC_EXPLOIT');
  if (readFlag(record, PATCH_PATHS)) reasons.add('VENDOR_PATCH');
  const explicitPatch = readString(record, [
    ['fixed_version'],
    ['fixedVersion'],
    ['remediation', 'fixedVersion'],
    ['remediation', 'patchedVersion'],
  ]);
  if (explicitPatch) reasons.add('VENDOR_PATCH');

  for (const value of asArray(getPath(record, ['material_escalation']))) {
    if (typeof value === 'string' && value.trim()) reasons.add(value.trim().toUpperCase().replace(/\s+/g, '_'));
  }
  for (const value of asArray(getPath(record, ['escalations']))) {
    if (typeof value === 'string' && value.trim()) reasons.add(value.trim().toUpperCase().replace(/\s+/g, '_'));
  }
  if (readFlag(record, [['material_escalation'], ['escalated']])) reasons.add('MATERIAL_ESCALATION');
  return [...reasons].sort();
}

function extractSeverity(record: unknown): { severity: SeverityLabel | null; score: number | null } {
  if (!isRecord(record)) return { severity: null, score: null };
  const score = firstNumber(
    getPath(record, ['cvss_score']),
    getPath(record, ['cvssScore']),
    getPath(record, ['baseScore']),
    getPath(record, ['cvss', 'baseScore']),
    getPath(record, ['cvss', 'score']),
    getPath(record, ['cvss', 'cvssData', 'baseScore']),
    getPath(record, ['metrics', 'cvssMetricV31', 0, 'cvssData', 'baseScore']),
    getPath(record, ['metrics', 'cvssMetricV30', 0, 'cvssData', 'baseScore']),
    getPath(record, ['metrics', 'cvssMetricV2', 0, 'cvssData', 'baseScore']),
    getPath(record, ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'baseScore']),
  );
  const rawSeverity = readString(record, [
    ['severity'],
    ['cvss', 'severity'],
    ['cvss', 'cvssData', 'baseSeverity'],
    ['cve', 'metrics', 'cvssMetricV31', 0, 'cvssData', 'baseSeverity'],
  ]).toUpperCase();
  const validSeverity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].includes(rawSeverity)
    ? (rawSeverity as SeverityLabel)
    : null;
  if (validSeverity) return { severity: validSeverity, score };
  if (score === null) return { severity: 'UNKNOWN', score: null };
  return {
    severity: score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : score > 0 ? 'LOW' : 'UNKNOWN',
    score,
  };
}

/* -------------------------------------------------------------------------- */
/* Record unwrapping and field extraction                                     */
/* -------------------------------------------------------------------------- */

function unwrapRecord(input: unknown): unknown {
  if (!isRecord(input)) return input;
  // NVD 2.0 wraps the vulnerability in `cve`.
  if (isRecord(input.cve)) return { ...input, ...input.cve };
  // CVE JSON 5.0.
  if (isRecord(input.cveMetadata) || isRecord(input.containers)) {
    const container = isRecord(input.containers) && isRecord(input.containers.cna) ? input.containers.cna : {};
    return { ...container, ...input, cveMetadata: input.cveMetadata };
  }
  // OSV permits a vulnerability wrapper.
  if (isRecord(input.vulnerability) && !getPath(input, ['affected']))
    return { ...input, ...input.vulnerability };
  return input;
}

function extractRecordText(record: unknown): string {
  if (!isRecord(record)) return '';
  const parts: string[] = [];
  const add = (value: unknown) => {
    if (typeof value === 'string' && value.trim()) parts.push(value.trim());
    else if (isRecord(value)) {
      const nested = firstString(value.value, value.text, value.description, value.summary);
      if (nested) parts.push(nested);
    }
  };
  for (const key of [
    'title',
    'headline',
    'name',
    'summary',
    'description',
    'text',
    'body',
    'content',
    'abstract',
    'details',
    'shortDescription',
    'problemtype',
    'details',
  ])
    add(record[key]);

  for (const key of ['descriptions', 'description'])
    for (const entry of asArray(record[key])) add(entry);

  for (const path of [
    ['cve', 'descriptions'],
    ['containers', 'cna', 'descriptions'],
    ['containers', 'cna', 'affected'],
    ['affected'],
  ]) {
    for (const entry of asArray(getPath(record, path))) {
      if (!isRecord(entry)) continue;
      add(entry.summary);
      add(entry.details);
      add(entry.description);
      for (const child of asArray(entry.descriptions)) add(child);
    }
  }

  return uniqueStrings(parts).join('\n');
}

const CVE_ID_PATTERN = /\bCVE-\d{4}-\d{4,}\b/gi;
// `Vul` + five digits, the spec spelling (Vul10492). The hyphenated legacy
// spelling still matches so a Previously_Dispatched_Log written before the
// fix keeps suppressing the same incident instead of re-emailing it.
const VUL_ID_PATTERN = /^Vul-?\d{5}$/i;

export function normalizeCveIdValue(value: string): string | null {
  const match = /CVE-\d{4}-\d{4,}/i.exec(value);
  return match ? match[0].toUpperCase() : null;
}

function extractCveIds(record: unknown): string[] {
  if (!isRecord(record)) return [];
  const ids = new Set<string>();
  const add = (value: unknown, recurse = false) => {
    if (typeof value === 'string') {
      const normalized = normalizeCveIdValue(value);
      if (normalized) ids.add(normalized);
      if (recurse) for (const match of value.match(CVE_ID_PATTERN) ?? []) ids.add(match.toUpperCase());
    } else if (isRecord(value)) {
      add(value.cveId ?? value.cve_id ?? value.id ?? value.value, recurse);
    }
  };
  for (const path of [
    ['cveId'],
    ['cve_id'],
    ['cveID'],
    ['id'],
    ['cve', 'id'],
    ['cve', 'cveId'],
    ['cveMetadata', 'cveId'],
  ])
    add(getPath(record, path));

  for (const key of ['cve_ids', 'cveIds', 'cves', 'aliases', 'identifiers']) {
    for (const entry of asArray(record[key])) add(entry, true);
  }
  for (const entry of asArray(record.references)) add(entry, true);
  for (const entry of asArray(getPath(record, ['cve', 'references']))) add(entry, true);
  return [...ids];
}

function extractAdvisoryIds(record: unknown): string[] {
  if (!isRecord(record)) return [];
  const ids = new Set<string>();
  const add = (value: unknown) => {
    if (typeof value !== 'string' || !value.trim()) return;
    const clean = value.trim();
    if (/^CVE-\d{4}-\d{4,}$/i.test(clean) || VUL_ID_PATTERN.test(clean)) return;
    if (/^[A-Za-z][A-Za-z0-9]*(?:[-_:][A-Za-z0-9]+)+$/.test(clean) && /\d/.test(clean))
      ids.add(clean.toUpperCase());
  };
  for (const key of ['advisory_id', 'advisoryId', 'advisory_ids', 'advisoryIds', 'vendor_advisory_id'])
    for (const entry of asArray(record[key])) add(entry);
  for (const entry of asArray(record.identifiers)) {
    if (isRecord(entry)) add(firstString(entry.value, entry.id));
  }
  return [...ids];
}

function extractExplicitVulId(record: unknown): string | null {
  if (!isRecord(record)) return null;
  for (const value of [
    record.finding_id,
    record.findingId,
    record.vul_id,
    record.vulId,
    record.vulnerability_id,
    record.vulnerabilityId,
  ]) {
    if (typeof value === 'string' && VUL_ID_PATTERN.test(value.trim())) return value.trim();
  }
  return null;
}

function extractSourceReference(record: unknown): string {
  if (!isRecord(record)) return '';
  return (
    readString(record, [
      ['source_url'],
      ['sourceUrl'],
      ['url'],
      ['link'],
      ['advisory_url'],
      ['advisoryUrl'],
      ['reference'],
      ['remediation', 'vendorAdvisoryRef'],
      ['cve', 'references', 0, 'url'],
    ]) || ''
  );
}

/* -------------------------------------------------------------------------- */
/* Structured evidence extraction                                             */
/* -------------------------------------------------------------------------- */

interface CpeCriterion {
  criteria: string;
  range?: NvdVersionRange;
  literalVersion?: string;
}

interface PurlCriterion {
  purl: string;
  range?: NvdVersionRange;
  versions: string[];
}

function rangeFrom(value: unknown): NvdVersionRange | undefined {
  if (!isRecord(value)) return undefined;
  const nested = isRecord(value.range) ? value.range : undefined;
  const pick = (key: keyof NvdVersionRange): string | undefined =>
    firstString(value[key], nested?.[key]);
  const range: NvdVersionRange = {
    versionStartIncluding: pick('versionStartIncluding'),
    versionStartExcluding: pick('versionStartExcluding'),
    versionEndIncluding: pick('versionEndIncluding'),
    versionEndExcluding: pick('versionEndExcluding'),
  };
  return Object.values(range).some(Boolean) ? range : undefined;
}

/**
 * Recursively extracts only applicable CPE criteria.
 *
 * NVD/VulnCheck `cpeMatch` objects must say `vulnerable: true`; entries marked
 * `vulnerable: false` are the underlying platform (`running on Windows`) and
 * are never evaluated. Direct `cpeMatches` arrays are the normalized form and
 * are trusted as already filtered.
 */
export function extractVulnerableCpes(record: unknown): CpeCriterion[] {
  const out: CpeCriterion[] = [];
  const seen = new Set<string>();
  const add = (criteria: unknown, range?: NvdVersionRange) => {
    if (typeof criteria !== 'string' || !criteria.trim()) return;
    const parsed = parseCpe(criteria);
    if (!parsed.isValid) return;
    const key = `${criteria}\u0000${JSON.stringify(range ?? {})}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      criteria: criteria.trim(),
      range,
      literalVersion:
        parsed.version && parsed.version !== '*' && parsed.version !== '-' ? parsed.version : undefined,
    });
  };
  const addObject = (entry: JsonRecord, trusted: boolean) => {
    if (entry.vulnerable === false || entry.vulnerable === 'false' || entry.vulnerable === 0) return;
    if (!trusted && entry.vulnerable !== true) return;
    const criteria = firstString(
      entry.criteria,
      entry.cpe23Uri,
      entry.cpe23uri,
      entry.cpeName,
      entry.cpe_name,
      entry.cpe,
      entry.uri,
    );
    add(criteria, rangeFrom(entry));
  };
  const visitNode = (node: unknown, depth: number) => {
    if (!isRecord(node) || depth > 12) return;
    for (const key of ['cpeMatch', 'cpe_match']) {
      for (const entry of asArray(node[key])) {
        if (typeof entry === 'string') add(entry);
        else if (isRecord(entry)) addObject(entry, false);
      }
    }
    for (const key of ['nodes', 'children', 'configurations']) {
      for (const child of asArray(node[key])) visitNode(child, depth + 1);
    }
  };
  if (!isRecord(record)) return out;

  for (const entry of asArray(record.cpe_matches)) {
    if (typeof entry === 'string') add(entry);
    else if (isRecord(entry)) addObject(entry, false);
  }
  for (const key of ['cpeMatches', 'cpeMatchDetails', 'cpe_match']) {
    for (const entry of asArray(record[key])) {
      if (typeof entry === 'string') add(entry);
      else if (isRecord(entry)) addObject(entry, true);
    }
  }
  if (typeof record.cpe === 'string') add(record.cpe);
  if (typeof record.criteria === 'string') add(record.criteria);
  for (const entry of asArray(record.vulnerable_cpes)) add(entry);

  for (const configuration of asArray(record.configurations)) visitNode(configuration, 0);
  visitNode(record, 0);
  return out;
}

/** Extracts PURL criteria and ignores entries explicitly marked unaffected. */
export function extractVulnerablePurls(record: unknown): PurlCriterion[] {
  const out: PurlCriterion[] = [];
  const seen = new Set<string>();
  const add = (value: unknown, range?: NvdVersionRange, versions: string[] = []) => {
    if (typeof value !== 'string' || !value.trim()) return;
    const parsed = parsePurl(value);
    if (!parsed) return;
    const key = `${parsed.raw}\u0000${JSON.stringify(range ?? {})}\u0000${versions.join(',')}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ purl: value.trim(), range, versions: uniqueStrings(versions) });
  };
  const addObject = (entry: JsonRecord, trusted: boolean) => {
    if (entry.vulnerable === false || entry.vulnerable === 'false' || entry.vulnerable === 0) return;
    if (!trusted && entry.vulnerable === false) return;
    const purl = firstString(entry.purl, entry.packageUrl, entry.package_url, entry.value);
    const versions = asArray(entry.versions)
      .map((version) => (typeof version === 'string' ? version : firstString(version)))
      .filter((version): version is string => Boolean(version));
    add(purl, rangeFrom(entry), versions);
  };
  const visit = (value: unknown, depth: number) => {
    if (depth > 10) return;
    if (Array.isArray(value)) {
      for (const entry of value) visit(entry, depth + 1);
      return;
    }
    if (!isRecord(value)) return;
    if (isRecord(value.package)) addObject({ ...value.package, ...value }, true);
    for (const key of ['purls', 'purl', 'package_urls', 'identifiers', 'package']) {
      for (const entry of asArray(value[key])) {
        if (typeof entry === 'string') add(entry);
        else if (isRecord(entry)) {
          if (key === 'identifiers' && firstString(entry.type)?.toLowerCase() !== 'purl') continue;
          addObject(entry, true);
        }
      }
    }
    if (isRecord(value.package)) visit(value.package, depth + 1);
    for (const key of ['packages', 'artifacts']) {
      for (const entry of asArray(value[key])) visit(entry, depth + 1);
    }
  };
  if (!isRecord(record)) return out;
  visit(record, 0);

  // OSV represents the vulnerable interval as introduced/fixed events.
  for (const affected of asArray(record.affected)) {
    if (!isRecord(affected) || !isRecord(affected.package)) continue;
    const purl = firstString(affected.package.purl);
    if (!purl) continue;
    const versions = asArray(affected.versions)
      .map((version) => firstString(version))
      .filter((version): version is string => Boolean(version));
    for (const range of asArray(affected.ranges)) {
      if (!isRecord(range)) continue;
      const mapped: NvdVersionRange = {};
      for (const event of asArray(range.events)) {
        if (!isRecord(event)) continue;
        const introduced = firstString(event.introduced);
        const fixed = firstString(event.fixed);
        const lastAffected = firstString(event.last_affected);
        const limit = firstString(event.limit);
        if (introduced && introduced !== '0') mapped.versionStartIncluding = introduced;
        if (fixed) mapped.versionEndExcluding = fixed;
        if (lastAffected) mapped.versionEndIncluding = lastAffected;
        if (limit) mapped.versionEndExcluding = limit;
      }
      add(purl, Object.values(mapped).some(Boolean) ? mapped : undefined, versions);
    }
    if (!asArray(affected.ranges).length) add(purl, undefined, versions);
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* Version constraints                                                        */
/* -------------------------------------------------------------------------- */

interface VersionConstraint {
  kind: 'bounds' | 'exact' | 'prefix' | 'range' | 'versions' | 'none';
  range?: NvdVersionRange;
  exact?: string;
  prefix?: string;
  rangeText?: string;
  versions?: string[];
}

interface VersionEvaluation {
  verdict: VersionVerdict;
  verificationNeeded: boolean;
  reason: string;
}

function hasBounds(range?: NvdVersionRange): boolean {
  return Boolean(range && Object.values(range).some(Boolean));
}

function constraintForCpe(criterion: CpeCriterion): VersionConstraint {
  if (hasBounds(criterion.range)) return { kind: 'bounds', range: criterion.range };
  const version = criterion.literalVersion;
  if (!version) return { kind: 'none' };
  if (hasWildcard(version)) return { kind: 'prefix', prefix: version };
  return { kind: 'exact', exact: version };
}

function constraintForPurl(criterion: PurlCriterion): VersionConstraint {
  if (hasBounds(criterion.range)) return { kind: 'bounds', range: criterion.range };
  if (criterion.versions.length) return { kind: 'versions', versions: criterion.versions };
  const parsed = parsePurl(criterion.purl);
  if (!parsed?.version) return { kind: 'none' };
  if (hasWildcard(parsed.version)) return { kind: 'prefix', prefix: parsed.version };
  return { kind: 'exact', exact: parsed.version };
}

function constraintFromRecord(record: unknown, text: string): VersionConstraint {
  if (!isRecord(record)) return { kind: 'none' };
  const explicitRange =
    rangeFrom(getPath(record, ['versionRange'])) ??
    rangeFrom(getPath(record, ['version_range'])) ??
    rangeFrom(getPath(record, ['affectedVersionRange']));
  if (explicitRange) return { kind: 'bounds', range: explicitRange };

  for (const key of ['affected_versions', 'affectedVersions', 'versions', 'affected_version', 'version']) {
    const values = asArray(record[key]).filter((value): value is string | number =>
      typeof value === 'string' || typeof value === 'number',
    );
    if (!values.length) continue;
    const strings = values.map((value) => String(value).trim()).filter(Boolean);
    if (strings.length === 1 && /^[<>]=?\s*\d/.test(strings[0]))
      return { kind: 'range', rangeText: strings[0] };
    return { kind: 'versions', versions: strings };
  }

  const rangeText = /[<>]=?\s*\d/.test(text) ? text : '';
  if (rangeText) {
    try {
      // naturalLanguageRange lives in the shared comparator; evaluateVersion is
      // the only function that translates prose to an interval safely.
      const verdict = evaluateVersion('0.0.1', rangeText);
      if (verdict !== 'REVIEW') return { kind: 'range', rangeText };
    } catch {
      // The prose was not a comparable interval; fail open below.
    }
  }
  const natural = text.match(/\b(?:before|prior to|below|earlier than|patched in|fixed in|up to)\s+v?\d+(?:\.\d+){0,3}\b/i);
  if (natural) return { kind: 'range', rangeText: natural[0] };
  return { kind: 'none' };
}

function evaluateVersionForInventory(
  inventory: NormalizedInventory,
  constraint: VersionConstraint,
): VersionEvaluation {
  const versions = inventory.versionCandidates.filter(Boolean);
  if (!versions.length || versions.every((version) => version === '*' || version === '-'))
    return {
      verdict: 'INCONCLUSIVE',
      verificationNeeded: true,
      reason: 'Inventory has no comparable version; applicability requires verification',
    };
  if (constraint.kind === 'none')
    return {
      verdict: 'INCONCLUSIVE',
      verificationNeeded: true,
      reason: 'The source does not state a comparable version bound; applicability requires verification',
    };

  const verdicts = versions.map((version) => evaluateOneVersion(version, constraint));
  const inRange = verdicts.find((verdict) => verdict.verdict === 'IN_RANGE');
  if (inRange) return { ...inRange, verificationNeeded: inRange.verificationNeeded };
  if (verdicts.every((verdict) => verdict.verdict === 'OUT_OF_RANGE'))
    return {
      verdict: 'OUT_OF_RANGE',
      verificationNeeded: false,
      reason: verdicts[0]?.reason ?? 'Version is outside the vulnerable range',
    };
  return {
    verdict: 'INCONCLUSIVE',
    verificationNeeded: true,
    reason: verdicts.find((verdict) => verdict.verdict === 'INCONCLUSIVE')?.reason ??
      'At least one inventory version could not be compared',
  };
}

function evaluateOneVersion(version: string, constraint: VersionConstraint): VersionEvaluation {
  switch (constraint.kind) {
    case 'bounds':
      return boundedVerdict(version, constraint.range);
    case 'exact':
      return exactVerdict(version, constraint.exact ?? '');
    case 'prefix':
      return prefixVerdict(version, constraint.prefix ?? '');
    case 'versions':
      return evaluateVersionList(version, constraint.versions ?? []);
    case 'range':
      return proseVerdict(version, constraint.rangeText ?? '');
    case 'none':
      return {
        verdict: 'INCONCLUSIVE',
        verificationNeeded: true,
        reason: 'No version bound supplied',
      };
  }
}

function boundedVerdict(version: string, range?: NvdVersionRange): VersionEvaluation {
  if (!hasBounds(range))
    return {
      verdict: 'INCONCLUSIVE',
      verificationNeeded: true,
      reason: 'No version bounds supplied',
    };
  const result = evaluateVersionInRange(version, range!);
  return {
    verdict: result.verdict === 'IN_RANGE' ? 'IN_RANGE' : result.verdict === 'OUT_OF_RANGE' ? 'OUT_OF_RANGE' : 'INCONCLUSIVE',
    verificationNeeded: result.verdict === 'INCONCLUSIVE',
    reason: result.reason,
  };
}

function exactVerdict(version: string, exact: string): VersionEvaluation {
  if (!exact)
    return { verdict: 'INCONCLUSIVE', verificationNeeded: true, reason: 'No version supplied' };
  if (hasWildcard(exact)) return prefixVerdict(version, exact);
  const result = evaluateVersionInRange(version, {
    versionStartIncluding: exact,
    versionEndIncluding: exact,
  });
  return {
    verdict: result.verdict === 'IN_RANGE' ? 'IN_RANGE' : result.verdict === 'OUT_OF_RANGE' ? 'OUT_OF_RANGE' : 'INCONCLUSIVE',
    verificationNeeded: result.verdict === 'INCONCLUSIVE',
    reason: result.reason,
  };
}

function prefixVerdict(version: string, prefix: string): VersionEvaluation {
  if (!prefix)
    return { verdict: 'INCONCLUSIVE', verificationNeeded: true, reason: 'No version prefix supplied' };
  const normalizedPrefix = prefix.replace(/\*+$/g, '').replace(/[._-]+$/, '');
  if (!normalizedPrefix)
    return { verdict: 'INCONCLUSIVE', verificationNeeded: true, reason: 'Wildcard-only version prefix' };
  const normalizedVersion = version.trim().toLowerCase();
  const normalizedPrefixLower = normalizedPrefix.toLowerCase();
  if (
    normalizedVersion === normalizedPrefixLower ||
    normalizedVersion.startsWith(`${normalizedPrefixLower}.`) ||
    normalizedVersion.startsWith(`${normalizedPrefixLower}-`)
  )
    return { verdict: 'IN_RANGE', verificationNeeded: false, reason: `Version matches ${prefix}` };
  const prefixParts = normalizedPrefixLower.split('.');
  const versionParts = normalizedVersion.split(/[._-]/);
  if (prefixParts.every((part, index) => versionParts[index] === part))
    return { verdict: 'IN_RANGE', verificationNeeded: false, reason: `Version matches ${prefix}` };
  if (/^\d+(?:\.\d+)*$/.test(normalizedPrefixLower) && /^\d+(?:\.\d+)*$/.test(normalizedVersion)) {
    const verdict = evaluateVersionInRange(normalizedVersion, {
      versionStartIncluding: normalizedPrefixLower,
      versionEndIncluding: `${normalizedPrefixLower}.999999999`,
    });
    if (verdict.verdict === 'OUT_OF_RANGE')
      return { verdict: 'OUT_OF_RANGE', verificationNeeded: false, reason: verdict.reason };
  }
  return {
    verdict: 'INCONCLUSIVE',
    verificationNeeded: true,
    reason: `Version ${version} could not be compared with prefix ${prefix}`,
  };
}

function evaluateVersionList(version: string, versions: string[]): VersionEvaluation {
  if (!versions.length)
    return { verdict: 'INCONCLUSIVE', verificationNeeded: true, reason: 'No affected versions supplied' };
  const verdicts = versions.map((candidate) =>
    hasWildcard(candidate) ? prefixVerdict(version, candidate) : exactVerdict(version, candidate),
  );
  const inRange = verdicts.find((verdict) => verdict.verdict === 'IN_RANGE');
  if (inRange) return inRange;
  if (verdicts.every((verdict) => verdict.verdict === 'OUT_OF_RANGE'))
    return { verdict: 'OUT_OF_RANGE', verificationNeeded: false, reason: verdicts[0].reason };
  return {
    verdict: 'INCONCLUSIVE',
    verificationNeeded: true,
    reason: 'The inventory version could not be compared with every listed affected version',
  };
}

function proseVerdict(version: string, rangeText: string): VersionEvaluation {
  try {
    const verdict = evaluateVersion(version, rangeText);
    if (verdict === 'AFFECTED')
      return { verdict: 'IN_RANGE', verificationNeeded: false, reason: `${version} matches "${rangeText}"` };
    if (verdict === 'UNAFFECTED')
      return { verdict: 'OUT_OF_RANGE', verificationNeeded: false, reason: `${version} is outside "${rangeText}"` };
  } catch {
    // Fall through to review.
  }
  return {
    verdict: 'INCONCLUSIVE',
    verificationNeeded: true,
    reason: `The prose range "${rangeText}" is ambiguous for ${version}`,
  };
}

/**
 * Public boolean compatibility helper. It is intentionally conservative:
 * `false` means the version is *provably* outside the range. Missing or
 * ambiguous data returns `true` so the caller can retain the finding.
 */
export function isVersionVulnerable(
  inventoryVersion: string | null | undefined,
  bounds: NvdVersionRange = {},
  explicitFeedVersion = '*',
): boolean {
  const version = inventoryVersion?.trim() ?? '';
  if (!version || version === '*' || version === '-') return true;
  if (hasBounds(bounds)) return boundedVerdict(version, bounds).verdict !== 'OUT_OF_RANGE';
  if (explicitFeedVersion && explicitFeedVersion !== '*' && explicitFeedVersion !== '-' && explicitFeedVersion !== '') {
    return exactVerdict(version, explicitFeedVersion).verdict !== 'OUT_OF_RANGE';
  }
  return true;
}

/* -------------------------------------------------------------------------- */
/* Finding identity and incident-topic signature                              */
/* -------------------------------------------------------------------------- */

const TOPIC_PATTERNS: Array<[RegExp, string]> = [
  [/zero[- ]day|0[- ]day/i, 'zero-day'],
  [/actively exploited|exploited in the wild|under active attack|under attack|in-the-wild exploitation/i, 'active-exploitation'],
  [/remote code execution|\brce\b/i, 'rce'],
  [/privilege escalation|elevation of privilege/i, 'privilege-escalation'],
  [/authentication bypass|auth(?:entication)? bypass|bypass auth/i, 'auth-bypass'],
  [/sql injection|\bsqli\b/i, 'sql-injection'],
  [/cross[- ]site scripting|\bxss\b/i, 'xss'],
  [/denial of service|\bdos\b/i, 'denial-of-service'],
  [/information disclosure|info(?:rmation)? leak/i, 'information-disclosure'],
  [/path traversal|directory traversal/i, 'path-traversal'],
  [/deseriali[sz]ation/i, 'deserialization'],
  [/buffer overflow|heap overflow|stack overflow/i, 'buffer-overflow'],
  [/ransomware/i, 'ransomware'],
  [/backdoor|implant/i, 'backdoor'],
  [/supply[- ]chain/i, 'supply-chain'],
  [/phishing/i, 'phishing'],
  [/spoofing|impersonation/i, 'spoofing'],
  [/open redirect/i, 'open-redirect'],
  [/request smuggling/i, 'request-smuggling'],
];

const TOPIC_STOPWORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'by', 'for', 'from', 'has', 'have', 'in', 'into',
  'is', 'it', 'its', 'of', 'on', 'or', 'that', 'the', 'their', 'this', 'to', 'was', 'were', 'with',
  'new', 'now', 'report', 'reports', 'reported', 'news', 'article', 'blog', 'post', 'today', 'week',
  'security', 'vulnerability', 'vulnerabilities', 'flaw', 'flaws', 'issue', 'issues', 'bug', 'bugs',
  'critical', 'high', 'severe', 'important', 'patch', 'patches', 'patched', 'update', 'updates',
  'fixed', 'fix', 'fixes', 'affected', 'affects', 'impact', 'impacted', 'exposed', 'exposure',
  'exploit', 'exploits', 'exploited', 'exploitation', 'attacker', 'attackers', 'attack', 'attacks',
  'researcher', 'researchers', 'discovered', 'discovery', 'found', 'warning', 'warns', 'advisory',
  'bleepingcomputer', 'thehackernews', 'hackernews', 'securityweek', 'cybersecurity', 'cisa',
  'vulncheck', 'mitre', 'vendor', 'software', 'remote', 'code', 'execution',
]);

const ADVISORY_ID_PATTERN = /\b(?:RHSA|RHBA|RHEA|MSRC|CISCO|PAN-SA|ZDI|GHSA|DSA|USN|VMSA|SSA|APSB|ELSA|ALAS|AVG|JVN|JVNDB|VU|TA|AA)[-:_]?\d[\w:.-]*\b/gi;

function firstAdvisoryReference(text: string): string {
  const match = ADVISORY_ID_PATTERN.exec(text);
  ADVISORY_ID_PATTERN.lastIndex = 0;
  return match ? match[0].toUpperCase() : '';
}

/**
 * Builds a stable identity for the *incident*, not the headline.
 *
 * Explicit advisory identifiers and CVE identifiers are authoritative. In
 * their absence, vulnerability class + affected version + distinctive named
 * tokens survive syndication rewrites, while outlet names, publication verbs
 * and generic words are removed.
 */
export function incidentTopicSignature(record: unknown, text?: string): string {
  const body = `${text ?? extractRecordText(record)}`;
  const title = isRecord(record) ? readString(record, [['title'], ['headline'], ['name']]) : '';
  const combined = `${title}\n${body}`;
  const explicitTopic = isRecord(record)
    ? readString(record, [['topic'], ['news_topic'], ['newsTopic'], ['incident'], ['story']])
    : '';
  if (explicitTopic) return normalizeTopic(explicitTopic);

  const advisory = firstAdvisoryReference(combined);
  if (advisory) return `advisory:${advisory}`;

  const classes = TOPIC_PATTERNS.filter(([pattern]) => pattern.test(combined)).map(([, label]) => label);
  const versions = [...combined.matchAll(/\bv?\d+(?:\.\d+){2,4}\b/gi)]
    .map((match) => match[0].replace(/^v/i, ''))
    .filter((version) => version.length <= 40);
  // A named vulnerability class plus the affected release is the canonical
  // incident topic. Headline-specific nouns ("gang", "under attack", outlet
  // names) are deliberately excluded here: two syndicated articles describing
  // the same zero-day must produce the same Vul-XXXXX even when their editors
  // rewrote the headline. When no class is present, distinctive tokens are the
  // only available identity and are kept.
  if (classes.length)
    return [
      [...new Set(classes)].sort().join('+'),
      [...new Set(versions)].sort().slice(0, 3).join('+'),
    ]
      .filter(Boolean)
      .join('|');
  const tokens = new Map<string, number>();
  for (const token of combined.toLowerCase().match(/[\p{L}\p{N}+#.]{3,}/gu) ?? []) {
    const clean = token.replace(/^\.+|\.+$/g, '');
    if (!clean || TOPIC_STOPWORDS.has(clean) || /^\d+$/.test(clean)) continue;
    if (clean.startsWith('cve') || clean.startsWith('vul')) continue;
    tokens.set(clean, (tokens.get(clean) ?? 0) + 1);
  }
  const distinctive = [...tokens.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([token]) => token)
    .filter((token) => !classes.some((label) => label.includes(token)))
    .slice(0, 10)
    .sort();
  return [
    classes.length ? classes.sort().join('+') : '',
    versions.length ? [...new Set(versions)].sort().slice(0, 3).join('+') : '',
    distinctive.join(' '),
  ]
    .filter(Boolean)
    .join('|');
}

function normalizeTopic(value: string): string {
  return value
    .normalize('NFKC')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/[^\p{L}\p{N}+#.| ]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Deterministic 5-digit identifier derived from `(vendor, product, topic)`.
 * Leading zeroes are preserved because the contract is strict `VulXXXXX`
 * (`Vul` followed by exactly five digits).
 */
export function generateVulId(vendor: string, product: string, topic: string): string {
  const canonical = [normalizeVendor(vendor), normalizeProduct(product), normalizeTopic(topic)].join('|');
  const hex = bytesToHex(sha256(utf8ToBytes(canonical))).slice(0, 8);
  // The contract is exactly `Vul` + five digits (`Vul10492`). The modulus uses
  // the full 00000-99999 space (no sample-range bias), and padding keeps
  // leading zeroes so every identifier has five digits (`Vul00001`).
  const numeric = Number.parseInt(hex, 16) % 100_000;
  // Zero-pad, and only zero-pad: width 5 with values < 100000 never truncates.
  return `Vul${String(numeric).padStart(5, '0')}`;
}

function resolveFindingId(
  cveId: string | null,
  explicitVulId: string | null,
  inventory: NormalizedInventory,
  topic: string,
): string {
  if (cveId) return cveId;
  if (explicitVulId) return explicitVulId;
  return generateVulId(inventory.vendor, inventory.product, topic);
}

/* -------------------------------------------------------------------------- */
/* Text matching                                                              */
/* -------------------------------------------------------------------------- */

function sentenceList(text: string): string[] {
  return text
    .normalize('NFKC')
    .split(/[.!?\n\r]+/)
    .map((sentence) => sentence.trim())
    .filter(Boolean);
}

function identitySpellings(
  value: string,
  type: 'vendor' | 'product',
  custom: Record<string, string[]>,
): string[] {
  const canonical = type === 'vendor' ? normalizeVendor(value) : normalizeProduct(value);
  if (!canonical) return [];
  const group = type === 'vendor' ? vendorGroup(canonical, custom) : productGroup(canonical, custom);
  group.add(canonical);
  group.add(type === 'vendor' ? normalizeVendor(value) : normalizeProduct(value));
  return [...group].filter(Boolean);
}

function identityRegex(value: string, capture = false): RegExp {
  const normalized = normalizedName(value);
  const source = normalized
    .split(/(\*)/)
    .map((part) =>
      part === '*' ? '.*?' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    )
    .join('')
    .replace(/\s+/g, '[\\s_.\\-]+');
  const body = capture ? `(${source})` : source;
  return new RegExp(`(?<![\\p{L}\\p{N}+])${body}(?![\\p{L}\\p{N}+#])`, 'iu');
}

function textMentions(sentence: string, spellings: string[]): boolean {
  return spellings.some((spelling) => {
    try {
      return identityRegex(spelling).test(sentence);
    } catch {
      return sentence.toLowerCase().includes(spelling.toLowerCase());
    }
  });
}

function textProductMatch(
  sentence: string,
  inventory: NormalizedInventory,
  customAliases: Record<string, string[]>,
): string | null {
  if (inventory.canonicalProduct === '*') return '*';
  const spellings = identitySpellings(inventory.product, 'product', customAliases);
  for (const spelling of spellings) {
    try {
      const match = identityRegex(spelling, true).exec(sentence);
      if (!match) continue;
      if (hasWildcard(inventory.product)) {
        const captured = match[1]?.replace(/[\s_.-]+$/g, '').trim();
        return captured || humanizeFeedProduct(inventory.product.replace(/\*/g, '').trim()) || inventory.product;
      }
      return inventory.product;
    } catch {
      if (sentence.toLowerCase().includes(spelling.toLowerCase())) return inventory.product;
    }
  }
  return null;
}

const NON_SUBJECT_PHRASES = [
  'attacker infrastructure',
  'attack infrastructure',
  'command and control',
  'command-and-control',
  'c2 server',
  'c2 infrastructure',
  'malware infrastructure',
  'prerequisite',
  'prerequisites',
];

function isNonSubjectSentence(sentence: string): boolean {
  const normalized = sentence.toLowerCase();
  return NON_SUBJECT_PHRASES.some((phrase) => normalized.includes(phrase));
}

function isPassiveForProduct(sentence: string, inventory: NormalizedInventory): boolean {
  const product = inventory.canonicalProduct === '*'
    ? inventory.vendor
    : inventory.product.replace(/\*/g, '').trim() || inventory.product;
  try {
    return isPassivePlatformMention(sentence, product);
  } catch {
    return false;
  }
}

interface TextSupport {
  sentence: string;
  product: string;
}

function findTextSupport(
  text: string,
  inventory: NormalizedInventory,
  customVendorAliases: Record<string, string[]>,
  customProductAliases: Record<string, string[]>,
): TextSupport | null {
  if (!text.trim()) return null;
  const vendorSpellings = identitySpellings(inventory.vendor, 'vendor', customVendorAliases);
  if (!vendorSpellings.length) return null;

  for (const sentence of sentenceList(text)) {
    if (!textMentions(sentence, vendorSpellings)) continue;
    const product = textProductMatch(sentence, inventory, customProductAliases);
    if (product === null) continue;
    if (isNegatedSentence(sentence)) continue;
    if (isPassiveForProduct(sentence, inventory)) continue;
    if (isNonSubjectSentence(sentence)) continue;
    return { sentence, product };
  }

  // Punctuation or a headline may split the vendor and product across sentence
  // boundaries. The identity check already passed for the whole record, so use
  // the document-level guard rather than silently losing the finding.
  const fullTextVendor = textMentions(text, vendorSpellings);
  const fullTextProduct = textProductMatch(text, inventory, customProductAliases);
  if (fullTextVendor && fullTextProduct !== null) {
    const guardProduct = inventory.canonicalProduct === '*' ? inventory.vendor : inventory.product.replace(/\*/g, '').trim();
    const support = textSupportsExposure(text, inventory.vendor, guardProduct || inventory.vendor);
    if (support === undefined && !isNonSubjectSentence(text))
      return { sentence: text.trim(), product: fullTextProduct };
  }
  return null;
}

function matchTextForInventory(
  record: unknown,
  text: string,
  inventory: NormalizedInventory,
  cveId: string | null,
  explicitVulId: string | null,
  topic: string,
  source: SourceInfo,
  options: MatcherOptions,
): { match: ThreatMatch; verdict: VersionVerdict } | null {
  const support = findTextSupport(
    text,
    inventory,
    options.vendorAliases ?? {},
    options.productAliases ?? {},
  );
  if (!support) return null;

  const constraint = constraintFromRecord(record, text);
  const version = evaluateVersionForInventory(inventory, constraint);
  if (version.verdict === 'OUT_OF_RANGE') return null;

  const precision: MatchPrecision = inventory.wildcard ? 'Wildcard' : 'Exact';
  const classified = caseFor(source, precision);
  const escalations = extractEscalations(record);
  const severity = extractSeverity(record);
  const findingId = resolveFindingId(cveId, explicitVulId, inventory, topic);

  return {
    match: {
      finding_id: findingId,
      cve_id: cveId,
      case_classification: classified.caseLabel,
      case_classification_code: classified.caseCode,
      source_category: source.sourceCategory,
      match_precision: precision,
      match_method: 'Text',
      matched_vendor: inventory.vendor,
      matched_product: support.product,
      inventory_rule: inventory.rule,
      inventory_key: `${inventory.index}:${inventory.rule}`,
      version_verification_needed: version.verificationNeeded,
      audit_verified: true,
      material_escalation: escalations,
      new_escalations: [],
      severity: severity.severity,
      cvss_score: severity.score,
      kev: escalations.includes('KEV'),
      exploited:
        escalations.includes('KEV') ||
        escalations.includes('ACTIVE_EXPLOITATION') ||
        escalations.includes('PUBLIC_EXPLOIT') ||
        escalations.includes('ZERO_DAY'),
      zero_day: escalations.includes('ZERO_DAY'),
      vendor_patch: escalations.includes('VENDOR_PATCH'),
      topic_signature: topic,
      source_reference: extractSourceReference(record),
      advisory_ids: extractAdvisoryIds(record),
      evidence: support.sentence,
    },
    verdict: version.verdict,
  };
}

/* -------------------------------------------------------------------------- */
/* CPE matching                                                               */
/* -------------------------------------------------------------------------- */

interface StructuredMatchResult {
  match: ThreatMatch | null;
  verdict: VersionVerdict;
  excluded: boolean;
}

function matchCpeForInventory(
  record: unknown,
  criterion: CpeCriterion,
  inventory: NormalizedInventory,
  cveId: string | null,
  explicitVulId: string | null,
  topic: string,
  options: MatcherOptions,
): StructuredMatchResult | null {
  const cpe = parseCpe(criterion.criteria);
  if (!cpe.isValid) return null;

  const vendorMatches = componentMatches(cpe.vendor, inventory.vendor, 'vendor', options.vendorAliases ?? {});
  const productMatches = componentMatches(cpe.product, inventory.product, 'product', options.productAliases ?? {});
  const inventoryCpeMatches = inventory.cpes.some(
    (inventoryCpe) =>
      componentMatches(cpe.vendor, inventoryCpe.vendor, 'vendor', options.vendorAliases ?? {}) &&
      componentMatches(cpe.product, inventoryCpe.product, 'product', options.productAliases ?? {}),
  );
  if (!(vendorMatches && productMatches) && !inventoryCpeMatches) return null;

  const version = evaluateVersionForInventory(inventory, constraintForCpe(criterion));
  if (version.verdict === 'OUT_OF_RANGE')
    return { match: null, verdict: 'OUT_OF_RANGE', excluded: true };

  const candidateVendors = [inventory.canonicalVendor, normalizeVendor(cpe.vendor)].filter(Boolean);
  const source = sourceInfo(record, candidateVendors);
  const precision: MatchPrecision = inventory.wildcard ? 'Wildcard' : 'Exact';
  const classified = caseFor(source, precision);
  const escalations = extractEscalations(record);
  const severity = extractSeverity(record);
  const findingId = resolveFindingId(cveId, explicitVulId, inventory, topic);
  const matchedProduct =
    inventory.canonicalProduct === '*' || inventory.wildcard
      ? humanizeFeedProduct(cpe.product)
      : inventory.product;

  return {
    match: {
      finding_id: findingId,
      cve_id: cveId,
      case_classification: classified.caseLabel,
      case_classification_code: classified.caseCode,
      source_category: source.sourceCategory,
      match_precision: precision,
      match_method: 'CPE',
      matched_vendor: inventory.vendor,
      matched_product: matchedProduct,
      inventory_rule: inventory.rule,
      inventory_key: `${inventory.index}:${inventory.rule}`,
      version_verification_needed: version.verificationNeeded,
      audit_verified: true,
      material_escalation: escalations,
      new_escalations: [],
      severity: severity.severity,
      cvss_score: severity.score,
      kev: escalations.includes('KEV'),
      exploited:
        escalations.includes('KEV') ||
        escalations.includes('ACTIVE_EXPLOITATION') ||
        escalations.includes('PUBLIC_EXPLOIT') ||
        escalations.includes('ZERO_DAY'),
      zero_day: escalations.includes('ZERO_DAY'),
      vendor_patch: escalations.includes('VENDOR_PATCH'),
      topic_signature: topic,
      source_reference: extractSourceReference(record),
      advisory_ids: extractAdvisoryIds(record),
      evidence: `CPE ${criterion.criteria}: ${version.reason}`,
      matched_cpe: criterion.criteria,
    },
    verdict: version.verdict,
    excluded: false,
  };
}

/* -------------------------------------------------------------------------- */
/* PURL matching                                                              */
/* -------------------------------------------------------------------------- */

function purlBaseMatchesFeed(feed: ParsedPurl, inventory: ParsedPurl): boolean {
  if (feed.basePurl === inventory.basePurl) return true;
  if (hasWildcard(inventory.basePurl)) return wildcardPattern(inventory.basePurl).test(feed.basePurl);
  if (hasWildcard(feed.basePurl)) return wildcardPattern(feed.basePurl).test(inventory.basePurl);
  return false;
}

function matchPurlForInventory(
  record: unknown,
  criterion: PurlCriterion,
  inventory: NormalizedInventory,
  cveId: string | null,
  explicitVulId: string | null,
  topic: string,
  options: MatcherOptions,
): StructuredMatchResult | null {
  const feed = parsePurl(criterion.purl);
  if (!feed) return null;

  const candidateVendors = uniqueStrings([feed.type, feed.namespace].map(normalizeVendor));
  const matchingInventoryPurls = inventory.purls.filter((inventoryPurl) => purlBaseMatchesFeed(feed, inventoryPurl));
  let identityMatches = matchingInventoryPurls.length > 0;
  if (inventory.purls.length) {
    if (!identityMatches) return null;
  } else {
    identityMatches =
      candidateVendors.some((candidate) => matchVendorForSource(candidate, inventory.canonicalVendor)) &&
      componentMatches(feed.name, inventory.product, 'product', options.productAliases ?? {});
    if (!identityMatches) return null;
  }

  const version = evaluateVersionForInventory(inventory, constraintForPurl(criterion));
  if (version.verdict === 'OUT_OF_RANGE')
    return { match: null, verdict: 'OUT_OF_RANGE', excluded: true };

  const source = sourceInfo(record, candidateVendors.length ? candidateVendors : [inventory.canonicalVendor]);
  const precision: MatchPrecision = inventory.wildcard ? 'Wildcard' : 'Exact';
  const classified = caseFor(source, precision);
  const escalations = extractEscalations(record);
  const severity = extractSeverity(record);
  const findingId = resolveFindingId(cveId, explicitVulId, inventory, topic);
  const matchedProduct = inventory.wildcard ? humanizeFeedProduct(feed.name) : inventory.product;

  return {
    match: {
      finding_id: findingId,
      cve_id: cveId,
      case_classification: classified.caseLabel,
      case_classification_code: classified.caseCode,
      source_category: source.sourceCategory,
      match_precision: precision,
      match_method: 'PURL',
      matched_vendor: inventory.vendor,
      matched_product: matchedProduct,
      inventory_rule: inventory.rule,
      inventory_key: `${inventory.index}:${inventory.rule}`,
      version_verification_needed: version.verificationNeeded,
      audit_verified: true,
      material_escalation: escalations,
      new_escalations: [],
      severity: severity.severity,
      cvss_score: severity.score,
      kev: escalations.includes('KEV'),
      exploited:
        escalations.includes('KEV') ||
        escalations.includes('ACTIVE_EXPLOITATION') ||
        escalations.includes('PUBLIC_EXPLOIT') ||
        escalations.includes('ZERO_DAY'),
      zero_day: escalations.includes('ZERO_DAY'),
      vendor_patch: escalations.includes('VENDOR_PATCH'),
      topic_signature: topic,
      source_reference: extractSourceReference(record),
      advisory_ids: extractAdvisoryIds(record),
      evidence: `PURL ${criterion.purl}: ${version.reason}`,
      matched_purl: criterion.purl,
    },
    verdict: version.verdict,
    excluded: false,
  };
}

/* -------------------------------------------------------------------------- */
/* Match dedupe and merge                                                     */
/* -------------------------------------------------------------------------- */

const METHOD_STRENGTH: Record<MatchMethod, number> = { CPE: 3, PURL: 2, Text: 1 };
const CASE_STRENGTH: Record<CaseLabel, number> = { 'Case 3': 4, 'Case 4': 3, 'Case 1': 2, 'Case 2': 1 };

function deliveryIdentity(match: ThreatMatch): string {
  // The inventory rule is the stable identity of a registered Vendor+Product
  // entry. Using the observed feed product would split one wildcard asset into
  // separate entries when CPE evidence names `ios_xe_17` and prose names
  // `IOS XE 17.9`; those are the same inventory registration and the same
  // finding, so they must merge before delivery.
  return [
    match.finding_id.toUpperCase(),
    normalizeVendor(match.matched_vendor),
    normalizeProduct(match.inventory_rule).replace(/\*/g, '').trim(),
  ].join('|');
}

function mergeMatch(target: ThreatMatch, incoming: ThreatMatch): void {
  if (METHOD_STRENGTH[incoming.match_method] > METHOD_STRENGTH[target.match_method]) {
    target.match_method = incoming.match_method;
    target.matched_cpe = incoming.matched_cpe;
    target.matched_purl = incoming.matched_purl;
    target.evidence = incoming.evidence;
  }
  if (CASE_STRENGTH[incoming.case_classification] > CASE_STRENGTH[target.case_classification]) {
    target.case_classification = incoming.case_classification;
    target.case_classification_code = incoming.case_classification_code;
  }
  target.match_precision = target.match_precision === 'Exact' || incoming.match_precision === 'Exact'
    ? 'Exact'
    : 'Wildcard';
  target.version_verification_needed =
    target.version_verification_needed || incoming.version_verification_needed;
  target.material_escalation = uniqueStrings([
    ...target.material_escalation,
    ...incoming.material_escalation,
  ]).sort();
  target.new_escalations = uniqueStrings([...target.new_escalations, ...incoming.new_escalations]).sort();
  target.advisory_ids = uniqueStrings([...target.advisory_ids, ...incoming.advisory_ids]);
  target.severity = strongerSeverity(target.severity, incoming.severity);
  target.cvss_score = Math.max(target.cvss_score ?? 0, incoming.cvss_score ?? 0) || null;
  target.kev = target.kev || incoming.kev;
  target.exploited = target.exploited || incoming.exploited;
  target.zero_day = target.zero_day || incoming.zero_day;
  target.vendor_patch = target.vendor_patch || incoming.vendor_patch;
  if (!target.source_reference && incoming.source_reference) target.source_reference = incoming.source_reference;
}

function strongerSeverity(left: SeverityLabel | null, right: SeverityLabel | null): SeverityLabel | null {
  const rank: Record<SeverityLabel, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1 };
  if (!left) return right;
  if (!right) return left;
  return rank[left] >= rank[right] ? left : right;
}

/* -------------------------------------------------------------------------- */
/* Previously-dispatched log parsing                                          */
/* -------------------------------------------------------------------------- */

function normalizeDispatchedId(value: string): string | null {
  const clean = value.trim();
  if (!clean) return null;
  const cve = normalizeCveIdValue(clean);
  if (cve) return cve;
  // Both spellings are accepted so a log written before this fix (Vul-04342)
  // still suppresses the finding the engine now calls Vul04342. The canonical
  // output is the spec's `Vul` + five digits.
  const vul = /^Vul-?(\d{5})$/i.exec(clean);
  if (vul) return `Vul${vul[1]}`;
  if (/^[A-Za-z][A-Za-z0-9]*(?:[-_:][A-Za-z0-9]+)+$/.test(clean) && /\d/.test(clean))
    return clean.toUpperCase();
  return null;
}

function addLogEntry(
  parsed: ParsedDispatchedLog,
  value: unknown,
  fallback?: string,
): DispatchedLogEntry | null {
  const entry: DispatchedLogEntry = {
    key: '',
    ids: new Set(),
    topics: new Set(),
    state: new Set(),
    raw: value,
  };
  const addId = (candidate: unknown) => {
    if (typeof candidate !== 'string') return;
    const id = normalizeDispatchedId(candidate);
    if (!id) return;
    entry.ids.add(id);
    parsed.ids.add(id);
  };
  const addTopic = (candidate: unknown) => {
    if (typeof candidate !== 'string' || !candidate.trim()) return;
    const topic = normalizeTopic(candidate);
    if (!topic) return;
    entry.topics.add(topic);
    parsed.topics.add(topic);
  };

  if (typeof value === 'string') {
    const id = normalizeDispatchedId(value);
    if (id) addId(id);
    else addTopic(value);
  } else if (Array.isArray(value)) {
    for (const item of value) addLogEntry(parsed, item, fallback);
    return null;
  } else if (isRecord(value)) {
    for (const key of [
      'finding_id', 'findingId', 'cve_id', 'cveId', 'vul_id', 'vulId',
      'advisory_id', 'advisoryId', 'id', 'identifier',
    ])
      for (const item of asArray(value[key])) addId(item);
    for (const key of [
      'topic', 'news_topic', 'newsTopic', 'incident', 'story', 'subject', 'headline', 'title', 'event',
    ])
      for (const item of asArray(value[key])) addTopic(item);
    for (const reason of extractEscalations(value)) entry.state.add(reason);
    for (const key of ['material_escalation', 'materialEscalation', 'escalations', 'escalation'])
      for (const item of asArray(value[key]))
        if (typeof item === 'string' && item.trim())
          entry.state.add(item.trim().toUpperCase().replace(/\s+/g, '_'));
  } else return null;

  if (fallback && !DISPATCH_LOG_ARRAY_KEYS.has(fallback)) {
    const id = normalizeDispatchedId(fallback);
    if (id) addId(id);
    else addTopic(fallback);
  }
  if (!entry.ids.size && !entry.topics.size) return null;
  entry.key = entry.ids.values().next().value ?? entry.topics.values().next().value ?? fallback ?? '';
  parsed.entries.push(entry);
  return entry;
}

const DISPATCH_LOG_ARRAY_KEYS = new Set([
  'dispatched', 'sent', 'emails', 'items', 'entries', 'history', 'records',
  'cve_ids', 'cveIds', 'vul_ids', 'vulIds', 'advisory_ids', 'advisoryIds',
  'news_topics', 'newsTopics', 'topics', 'ids', 'findings', 'deliveries',
]);

export function parseDispatchedLog(log: PreviouslyDispatchedLog): ParsedDispatchedLog {
  const parsed: ParsedDispatchedLog = { ids: new Set(), topics: new Set(), entries: [] };
  if (!log) return parsed;
  const seen = new WeakSet<object>();

  const visit = (value: unknown, keyHint?: string) => {
    if (value === null || value === undefined) return;
    if (typeof value === 'string') {
      addLogEntry(parsed, value, keyHint);
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) visit(item, keyHint);
      return;
    }
    if (!isRecord(value)) return;
    if (seen.has(value)) return;
    seen.add(value);

    // A single log entry object.
    const hasEntryFields = [
      'finding_id', 'findingId', 'cve_id', 'cveId', 'vul_id', 'vulId',
      'advisory_id', 'advisoryId', 'identifier', 'topic', 'news_topic',
      'newsTopic', 'incident', 'story', 'subject', 'headline', 'title',
    ].some((key) => key in value);
    if (hasEntryFields) {
      addLogEntry(parsed, value, keyHint);
      return;
    }

    for (const [key, nested] of Object.entries(value)) {
      if (DISPATCH_LOG_ARRAY_KEYS.has(key)) {
        // The container key is not an incident topic. Passing it as a hint
        // would add "cve_ids" or "topics" to every entry's topic set.
        visit(nested);
        continue;
      }
      const id = normalizeDispatchedId(key);
      if (id) {
        const entry = addLogEntry(parsed, nested, key);
        if (entry && isRecord(nested)) {
          for (const reason of extractEscalations(nested)) entry.state.add(reason);
        }
        continue;
      }
      if (isRecord(nested) || Array.isArray(nested)) visit(nested, key);
    }
  };

  visit(log);
  return parsed;
}

function topicTokenSet(value: string): Set<string> {
  return new Set(
    normalizeTopic(value)
      .split(/[^\p{L}\p{N}+#.]+/u)
      .filter(
        (token) =>
          token.length >= 3 &&
          !TOPIC_STOPWORDS.has(token) &&
          !/^\d+$/.test(token) &&
          // A version is part of the compact signature but is routinely absent
          // from the headline stored in the delivered log. It must not prevent
          // the class phrase ("zero-day") from identifying the same incident.
          !/^\d+(?:\.\d+)+$/.test(token),
      ),
  );
}

function topicsMatch(left: string, right: string): boolean {
  const a = normalizeTopic(left);
  const b = normalizeTopic(right);
  if (!a || !b) return false;
  if (a === b) return true;
  if (normalizeDispatchedId(a) || normalizeDispatchedId(b)) return false;
  const leftTokens = topicTokenSet(a);
  const rightTokens = topicTokenSet(b);
  if (leftTokens.size < 2 || rightTokens.size < 2) return false;
  let shared = 0;
  for (const token of leftTokens) if (rightTokens.has(token)) shared++;
  // Containment is the right test for a headline versus the compact incident
  // signature: "PAN-OS zero-day exploited" and "zero-day|11.1.4" share the
  // complete class phrase even though the headline adds outlet-specific words.
  const smaller = Math.min(leftTokens.size, rightTokens.size);
  return shared >= 2 && smaller > 0 && shared / smaller >= 0.8;
}

function combineLogEntries(entries: readonly DispatchedLogEntry[]): DispatchedLogEntry {
  const combined: DispatchedLogEntry = {
    key: entries[0]?.key ?? '',
    ids: new Set(),
    topics: new Set(),
    state: new Set(),
    raw: entries.map((entry) => entry.raw),
  };
  for (const entry of entries) {
    for (const id of entry.ids) combined.ids.add(id);
    for (const topic of entry.topics) combined.topics.add(topic);
    for (const reason of entry.state) combined.state.add(reason);
  }
  return combined;
}

function findDispatchedEntry(
  match: ThreatMatch,
  parsed: ParsedDispatchedLog,
): DispatchedLogEntry | undefined {
  const ids = new Set(
    [match.finding_id, match.cve_id, ...match.advisory_ids]
      .filter((id): id is string => Boolean(id))
      .map((id) => normalizeDispatchedId(id))
      .filter((id): id is string => Boolean(id)),
  );
  const idMatches = parsed.entries.filter((entry) =>
    [...entry.ids].some((id) => ids.has(id)),
  );
  // A JSON log can contain both a flat `cve_ids` list and a richer entry for
  // the same CVE. Returning the first entry would lose the escalation state
  // stored on the other one, so combine every matching record.
  if (idMatches.length) return combineLogEntries(idMatches);

  // Topic identity is for non-CVE/non-advisory intelligence. Applying it to a
  // CVE match could suppress a genuinely different CVE that shares a product.
  if (!match.cve_id && !match.advisory_ids.length) {
    const topicMatches = parsed.entries.filter((entry) =>
      [...entry.topics].some((topic) => topicsMatch(topic, match.topic_signature)),
    );
    if (topicMatches.length) return combineLogEntries(topicMatches);
  }
  return undefined;
}

/* -------------------------------------------------------------------------- */
/* Consolidated email                                                        */
/* -------------------------------------------------------------------------- */

const GROUP_TITLES: Record<string, string> = {
  critical: 'Critical Exploited / KEV',
  advisory: 'Vendor Advisories (Case 3)',
  feed: 'Threat Feeds & News (Case 4)',
  match: 'Product Matches (Case 1/2)',
};

function itemPriorityGroup(item: ThreatMatch): string {
  if (item.kev || item.exploited || item.zero_day) return 'critical';
  if (item.case_classification === 'Case 3') return 'advisory';
  if (item.case_classification === 'Case 4') return 'feed';
  return 'match';
}

function severityRank(value: SeverityLabel | null): number {
  return { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1 }[value ?? 'UNKNOWN'];
}

function markdownSafe(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').replace(/([\\`*_{}[\]()#+!|>])/g, '\\$1').trim();
}

export function buildConsolidatedEmail(queued: readonly ThreatMatch[]): ConsolidatedEmail {
  const items: ConsolidatedEmailItem[] = [...queued]
    .sort(
      (a, b) =>
        Object.keys(GROUP_TITLES).indexOf(itemPriorityGroup(a)) -
          Object.keys(GROUP_TITLES).indexOf(itemPriorityGroup(b)) ||
        severityRank(b.severity) - severityRank(a.severity) ||
        (b.cvss_score ?? 0) - (a.cvss_score ?? 0) ||
        a.finding_id.localeCompare(b.finding_id) ||
        a.matched_vendor.localeCompare(b.matched_vendor) ||
        a.matched_product.localeCompare(b.matched_product),
    )
    .map((match) => ({
      finding_id: match.finding_id,
      cve_id: match.cve_id,
      case_classification: match.case_classification,
      match_precision: match.match_precision,
      matched_vendor: match.matched_vendor,
      matched_product: match.matched_product,
      severity: match.severity,
      cvss_score: match.cvss_score,
      priority_group: itemPriorityGroup(match),
      source_reference: match.source_reference,
    }));

  const groupOrder = Object.keys(GROUP_TITLES);
  const groups = groupOrder
    .map((id) => ({
      id,
      title: GROUP_TITLES[id],
      item_count: items.filter((item) => item.priority_group === id).length,
    }))
    .filter((group) => group.item_count > 0);

  if (!items.length)
    return {
      send_email: false,
      subject: null,
      body_markdown: null,
      queued_for_email_count: 0,
      items: [],
      groups: [],
    };

  const body: string[] = [
    '# Security Intelligence Digest',
    '',
    `**${items.length} finding${items.length === 1 ? '' : 's'} require action.**`,
    '',
  ];
  for (const group of groups) {
    body.push(`## ${group.title}`, '');
    for (const item of items.filter((candidate) => candidate.priority_group === group.id)) {
      const severity = item.severity && item.severity !== 'UNKNOWN' ? ` · ${item.severity}` : '';
      const score = item.cvss_score !== null ? ` (CVSS ${item.cvss_score.toFixed(1)})` : '';
      body.push(
        `- **${markdownSafe(item.finding_id)}** — ${markdownSafe(item.matched_vendor)} ${markdownSafe(item.matched_product)} · ${item.case_classification} · ${item.match_precision}${severity}${score}`,
      );
      if (item.source_reference) body.push(`  - Source: ${markdownSafe(item.source_reference)}`);
    }
    body.push('');
  }

  return {
    send_email: true,
    subject: `Security Intelligence Digest: ${items.length} finding${items.length === 1 ? '' : 's'} require action`,
    body_markdown: body.join('\n').trimEnd(),
    queued_for_email_count: items.length,
    items,
    groups,
  };
}

/* -------------------------------------------------------------------------- */
/* Public delivery API                                                        */
/* -------------------------------------------------------------------------- */

function ensureMatchIdentity(match: ThreatMatch): ThreatMatch {
  const copy: ThreatMatch = {
    ...match,
    material_escalation: [...(match.material_escalation ?? [])],
    new_escalations: [...(match.new_escalations ?? [])],
    advisory_ids: [...(match.advisory_ids ?? [])],
  };
  if (!copy.cve_id) copy.cve_id = null;
  if (!copy.finding_id)
    copy.finding_id = generateVulId(
      copy.matched_vendor,
      copy.matched_product,
      copy.topic_signature ?? '',
    );
  if (!copy.topic_signature) copy.topic_signature = '';
  return copy;
}

/**
 * Applies cross-source deduplication and the previously-dispatched log, then
 * renders the single consolidated digest.
 *
 * Every input match appears in `deliveries`. A duplicate discovered inside the
 * batch is retained with `SUPPRESSED_DUPLICATE` and `DUPLICATE_IN_BATCH`, so a
 * caller can account for 100% of the matches without sending a second email.
 */
export function deliverFindings(
  findings: readonly ThreatMatch[],
  options: MatcherOptions = {},
): DeliveryReport {
  const parsedLog = parseDispatchedLog(
    options.previouslyDispatchedLog ?? options.previously_dispatched_log,
  );
  const canonical = new Map<string, ThreatMatch>();
  const deliveries: ThreatMatch[] = [];

  for (const raw of findings) {
    const match = ensureMatchIdentity(raw);
    const prior = findDispatchedEntry(match, parsedLog);
    const newEscalations = prior
      ? match.material_escalation.filter((reason) => !prior.state.has(reason))
      : [];
    const shouldQueue = !prior || newEscalations.length > 0;

    match.previously_dispatched = Boolean(prior);
    match.new_escalations = newEscalations;
    if (!shouldQueue) {
      match.delivery_status = 'SUPPRESSED_DUPLICATE';
      match.suppression_reason = 'ALREADY_DISPATCHED';
    } else {
      match.delivery_status = 'QUEUED_FOR_DISPATCH';
      match.suppression_reason = prior && newEscalations.length ? 'MATERIAL_ESCALATION' : undefined;
    }

    const key = deliveryIdentity(match);
    const existing = canonical.get(key);
    if (!existing) {
      canonical.set(key, match);
      deliveries.push(match);
      continue;
    }

    // Same finding from another source. Merge its evidence into the canonical
    // entry, promote it when the duplicate carries a newly confirmed
    // escalation, and account for the duplicate explicitly.
    mergeMatch(existing, match);
    const existingPrior = findDispatchedEntry(existing, parsedLog);
    const existingNewEscalations = existingPrior
      ? existing.material_escalation.filter((reason) => !existingPrior.state.has(reason))
      : [];
    if (!existingPrior || existingNewEscalations.length) {
      existing.delivery_status = 'QUEUED_FOR_DISPATCH';
      existing.suppression_reason =
        existingPrior && existingNewEscalations.length ? 'MATERIAL_ESCALATION' : undefined;
      existing.new_escalations = existingNewEscalations;
    }
    match.delivery_status = 'SUPPRESSED_DUPLICATE';
    match.suppression_reason = 'DUPLICATE_IN_BATCH';
    deliveries.push(match);
  }

  const queued = deliveries.filter((match) => match.delivery_status === 'QUEUED_FOR_DISPATCH');
  const consolidated = buildConsolidatedEmail(queued);
  if (consolidated.queued_for_email_count !== queued.length)
    throw new Error('Consolidated email item count does not match queued finding count');

  return {
    total_matches: deliveries.length,
    delivered_count: queued.length,
    suppressed_duplicate_count: deliveries.length - queued.length,
    queued_for_email_count: queued.length,
    all_findings_delivered: deliveries.length === findings.length,
    all_findings_accounted_for: deliveries.length === findings.length,
    deliveries,
    matches: deliveries,
    consolidated_email: consolidated,
    send_email: consolidated.send_email,
    subject: consolidated.subject,
    body_markdown: consolidated.body_markdown,
  };
}

/* -------------------------------------------------------------------------- */
/* Record matching                                                            */
/* -------------------------------------------------------------------------- */

function matchRecord(
  inventory: readonly NormalizedInventory[],
  record: unknown,
  options: MatcherOptions,
): ThreatMatch[] {
  // A raw news payload is frequently just the article text. Treat it as a
  // description so a text-only ingestion path cannot silently produce zero
  // matches.
  const normalizedRecord = typeof record === 'string' ? { text: record } : record;
  const unwrapped = unwrapRecord(normalizedRecord);
  const cves = extractCveIds(unwrapped);
  const explicitVulId = extractExplicitVulId(unwrapped);
  const text = extractRecordText(unwrapped);
  const topic = incidentTopicSignature(unwrapped, text);
  const cpes = extractVulnerableCpes(unwrapped);
  const purls = extractVulnerablePurls(unwrapped);
  const matches = new Map<string, ThreatMatch>();

  const add = (match: ThreatMatch | null) => {
    if (!match) return;
    const key = deliveryIdentity(match);
    const existing = matches.get(key);
    if (existing) mergeMatch(existing, match);
    else matches.set(key, match);
  };

  // A record with no CVE produces one deterministic Vul ID per matched
  // inventory identity. A record with one or more CVEs produces a match for
  // every CVE so no officially-assigned identifier is lost.
  const findingIds: Array<string | null> = cves.length ? cves : [null];
  for (const findingId of findingIds) {
    for (const product of inventory) {
      let sawOutOfRange = false;
      let sawInRangeOrInconclusive = false;

      for (const criterion of cpes) {
        const result = matchCpeForInventory(
          unwrapped,
          criterion,
          product,
          findingId,
          explicitVulId,
          topic,
          options,
        );
        if (!result) continue;
        if (result.verdict === 'OUT_OF_RANGE') {
          sawOutOfRange = true;
          continue;
        }
        sawInRangeOrInconclusive = true;
        add(result.match);
      }

      for (const criterion of purls) {
        const result = matchPurlForInventory(
          unwrapped,
          criterion,
          product,
          findingId,
          explicitVulId,
          topic,
          options,
        );
        if (!result) continue;
        if (result.verdict === 'OUT_OF_RANGE') {
          sawOutOfRange = true;
          continue;
        }
        sawInRangeOrInconclusive = true;
        add(result.match);
      }

      // Structured evidence is authoritative. A text mention may not re-admit
      // an asset whose every matching CPE/PURL constraint proved it patched.
      if (sawOutOfRange && !sawInRangeOrInconclusive) continue;

      // Text classification depends on the matched vendor, so derive the
      // source metadata per inventory entry rather than once per record.
      const candidateVendors = uniqueStrings([
        product.canonicalVendor,
        ...cpes.map((criterion) => normalizeVendor(parseCpe(criterion.criteria).vendor)),
      ]);
      const source = sourceInfo(unwrapped, candidateVendors);
      const textResult = matchTextForInventory(
        unwrapped,
        text,
        product,
        findingId,
        explicitVulId,
        topic,
        source,
        options,
      );
      if (textResult) add(textResult.match);
    }
  }

  return [...matches.values()];
}

/**
 * Matches one raw record against an inventory list without assigning delivery
 * status. This is the pure function used by feed adapters and tests.
 */
export function matchFeedRecord(
  inventory: VendorProductInput[] | VendorProductInput,
  record: unknown,
  options: MatcherOptions = {},
): { total_matches: number; matches: ThreatMatch[] } {
  const normalized = normalizeInventory(inventory);
  const matches = matchRecord(normalized, record, options);
  return { total_matches: matches.length, matches };
}

/**
 * End-to-end batch processor. It scans every record, matches every applicable
 * inventory identity, applies the previously-dispatched log, and returns one
 * consolidated email for every queued finding.
 */
export function matchAndDeliverFindings(
  inventory: VendorProductInput[] | VendorProductInput,
  records: unknown[] | unknown,
  options: MatcherOptions = {},
): DeliveryReport {
  const normalized = normalizeInventory(inventory);
  const allMatches: ThreatMatch[] = [];
  for (const record of asArray(records)) allMatches.push(...matchRecord(normalized, record, options));
  return deliverFindings(allMatches, options);
}

/** Accepts the JSON-shaped `{vendor_products, incoming, previously_dispatched_log}` input. */
export function analyzeThreatIntel(input: ThreatIntelAnalysisInput): DeliveryReport {
  const inventory =
    input.vendor_products ??
    input.vendorProducts ??
    input.vendor_product_list ??
    input.inventory ??
    input.vendorProductList ??
    input.products ??
    input.assets ??
    input.watchlist ??
    [];
  const records =
    input.records ??
    input.feed ??
    input.incoming ??
    input.incoming_feed ??
    input.items ??
    input.text ??
    input.article ??
    input.advisory ??
    [];
  const options: MatcherOptions = {
    ...(input.options ?? {}),
    previouslyDispatchedLog:
      input.previously_dispatched_log ??
      input.previouslyDispatchedLog ??
      input.options?.previouslyDispatchedLog ??
      input.options?.previously_dispatched_log,
  };
  return matchAndDeliverFindings(inventory, records, options);
}

/* -------------------------------------------------------------------------- */
/* Snake-case compatibility exports for feed/JSON adapters                    */
/* -------------------------------------------------------------------------- */

export const normalize_vendor = normalizeVendor;
export const normalize_product = normalizeProduct;
export const parse_purl = parsePurl;
export const parse_cpe = parseCpe;
export const extract_vulnerable_cpes = extractVulnerableCpes;
export const extract_vulnerable_purls = extractVulnerablePurls;
export const is_version_vulnerable = isVersionVulnerable;
export const determine_case = (isAdvisory: boolean, isNews: boolean, isWildcard: boolean): CaseLabel =>
  isAdvisory ? 'Case 3' : isNews ? 'Case 4' : isWildcard ? 'Case 2' : 'Case 1';
export const match_feed_record = matchFeedRecord;
export const match_and_deliver_findings = matchAndDeliverFindings;
export const deliver_findings = deliverFindings;
export const generate_vul_id = generateVulId;
export const analyze_threat_intel = analyzeThreatIntel;
