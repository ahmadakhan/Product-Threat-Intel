import type { WatchListItem } from '../types/index.ts';
import { isProductWildcard, dictionaryEntryMatchesWildcard, productWildcardCpe } from './registrationCpe.ts';
import { buildStrictCpe23 } from '../data/vendorCatalog.ts';
import { parseCPE23, normalizeCpeForComparison } from './cpeMatcher.ts';

export function orderWatchlist(items: WatchListItem[]): WatchListItem[] {
  return [...items].sort((a, b) => {
    const createdOrder = Date.parse(b.createdAt) - Date.parse(a.createdAt);
    return Number.isFinite(createdOrder) && createdOrder !== 0 ? createdOrder : a.id.localeCompare(b.id);
  });
}

export function editedWatchlistCpe(
  item: WatchListItem,
  fields: {
    cpeExpression: string;
    vendor: string;
    product: string;
    part: 'a' | 'o' | 'h';
    version: string;
    targetHw: string;
  },
): string {
  const original = parseCPE23(item.cpes[0] || '');
  const formChanged =
    fields.vendor.trim() !== (original.isValid ? original.vendor : item.vendor) ||
    fields.product.trim() !== (original.isValid ? original.product : item.product) ||
    fields.part !== (original.part === 'o' || original.part === 'h' ? original.part : 'a') ||
    fields.version !== (original.version || '*') ||
    fields.targetHw !== (original.isValid ? original.targetHw : item.targetHw || '*');

  return formChanged
    ? buildStrictCpe23(fields.part, fields.vendor, fields.product, fields.version, fields.targetHw)
    : fields.cpeExpression.trim();
}

/** Turn verified names or product patterns into inventory rows without adding fallback identifiers. */
export function registrationAssetsFromCpes(
  cpes: string[],
  details: { assetTag: string; ownerGroup: string; notes: string; purls: string[] },
): Array<Omit<WatchListItem, 'id' | 'createdAt'>> {
  const groups = new Map<string, { parsed: ReturnType<typeof parseCPE23>; cpes: string[] }>();
  for (const raw of cpes) {
    const cpe = raw.trim();
    const parsed = parseCPE23(cpe);
    if (!productWildcardCpe(cpe)) {
      throw new Error('Select a valid product CPE from the NVD dictionary.');
    }
    const key = JSON.stringify([parsed.part, parsed.vendor.toLowerCase(), parsed.product.toLowerCase()]);
    const group = groups.get(key) ?? { parsed, cpes: [] };
    if (!group.cpes.some((entry) => entry.toLowerCase() === cpe.toLowerCase())) group.cpes.push(cpe);
    groups.set(key, group);
  }
  if (!groups.size) throw new Error('Select at least one verified NVD CPE before registering a product.');
  return [...groups.values()].map(({ parsed, cpes }, index) => {
    const versions = new Set(cpes.map((cpe) => parseCPE23(cpe).version));
    const architectures = new Set(cpes.map((cpe) => parseCPE23(cpe).targetHw));
    return {
      vendor: parsed.vendor,
      product: parsed.product,
      version: versions.size === 1 ? parsed.version : '*',
      cpes,
      targetHw: architectures.size === 1 && parsed.targetHw !== '*' ? parsed.targetHw : undefined,
      assetTag: `${details.assetTag.trim()}${groups.size > 1 ? `-${index + 1}` : ''}`,
      ownerGroup: details.ownerGroup.trim() || 'Cyber',
      notes: details.notes.trim(),
      purls: details.purls.length ? details.purls : undefined,
      active: true,
    };
  });
}

/** Verify exact dictionary names or product-scoped wildcard patterns before any write.
 *
 * CPEs listed in `custom` are operator-entered custom expressions: they are
 * validated as well-formed CPE 2.3 and saved as-is without an NVD dictionary
 * match, so monitored inventory can register unverified custom CPEs.
 */
export async function verifyRegistrationCpes(
  cpes: string[],
  lookup: (cpe: string) => Promise<{ results: Array<{ cpeName: string }> }>,
  custom: string[] = [],
): Promise<string[]> {
  if (!cpes.length) throw new Error('Select at least one verified NVD CPE before saving.');
  const verified: string[] = [];
  const seen = new Set<string>();
  const customSet = new Set(custom.map((entry) => entry.trim().toLowerCase()));
  for (const cpe of cpes.map((entry) => entry.trim())) {
    if (seen.has(cpe.toLowerCase())) continue;
    seen.add(cpe.toLowerCase());
    if (customSet.has(cpe.toLowerCase())) {
      if (!parseCPE23(cpe).isValid) throw new Error(`Invalid CPE 2.3 expression: ${cpe}`);
      verified.push(cpe);
      continue;
    }
    if (!parseCPE23(cpe).isValid) throw new Error(`Invalid CPE 2.3 expression: ${cpe}`);
    const response = await lookup(cpe);
    if (
      isProductWildcard(cpe) &&
      response.results.some((entry) => dictionaryEntryMatchesWildcard(cpe, entry.cpeName))
    ) {
      verified.push(cpe);
      continue;
    }
    let match = response.results.find(
      (entry) => normalizeCpeForComparison(entry.cpeName) === normalizeCpeForComparison(cpe),
    );
    if (!match) {
      const parsed = parseCPE23(cpe);
      if (parsed.isValid) {
        const fields = [
          'part',
          'product',
          'version',
          'update',
          'edition',
          'language',
          'swEdition',
          'targetSw',
          'targetHw',
          'other',
        ] as const;
        const compatible = response.results.filter((entry) => {
          const published = parseCPE23(entry.cpeName);
          return (
            published.isValid &&
            fields.every(
              (field) =>
                normalizeCpeForComparison(published[field]) === normalizeCpeForComparison(parsed[field]),
            )
          );
        });
        const unique = new Map(compatible.map((entry) => [normalizeCpeForComparison(entry.cpeName), entry]));
        // A canonical vendor spelling can be resolved only when the rest of the CPE
        // is identical and NVD returns a single unambiguous identity.
        if (unique.size === 1) match = [...unique.values()][0];
      }
    }
    if (!match)
      throw new Error(
        `CPE is not an active NVD dictionary entry: ${cpe}. Search NVD and select a published identifier.`,
      );
    if (!verified.some((entry) => entry.toLowerCase() === match.cpeName.toLowerCase()))
      verified.push(match.cpeName);
  }
  return verified;
}

/** Replace a generated suggestion only with dictionary names for the same
 * vendor/product identity. Strict matching ensures that CPEs from unrelated
 * vendors — even ones that share a product name — are never silently
 * substituted. */
export function dictionaryCpesForCandidate(candidate: string, dictionaryCpes: string[]): string[] {
  const parsed = parseCPE23(candidate);
  if (!parsed.isValid) return [candidate];
  const matches = dictionaryCpes.filter((cpe) => {
    const entry = parseCPE23(cpe);
    return (
      entry.isValid &&
      entry.part === parsed.part &&
      entry.vendor.toLowerCase() === parsed.vendor.toLowerCase() &&
      entry.product.toLowerCase() === parsed.product.toLowerCase()
    );
  });
  return matches.length ? matches : [candidate];
}

/** Preserve every row's ownership and IDs while saving the identifiers NVD actually verified. */
export async function verifyRegistrationAssets<T extends Omit<WatchListItem, 'id' | 'createdAt'>>(
  items: T[],
  lookup: (cpe: string) => Promise<{ results: Array<{ cpeName: string }> }>,
  customCpes: string[] = [],
): Promise<T[]> {
  const cache = new Map<string, Promise<{ results: Array<{ cpeName: string }> }>>();
  const cachedLookup = (cpe: string) => {
    const key = normalizeCpeForComparison(cpe);
    if (!cache.has(key)) cache.set(key, lookup(cpe));
    return cache.get(key)!;
  };
  const verifiedItems: T[] = [];
  for (const item of items) {
    // An inventory row may legitimately have no CPE: NVD does not publish a
    // dictionary identifier for every vendor/product. Such rows must reach the
    // importer unchanged (and disabled) instead of failing the whole batch.
    if (!item.cpes.length) {
      verifiedItems.push(item);
      continue;
    }
    const cpes = await verifyRegistrationCpes(item.cpes, cachedLookup, customCpes);
    const primary = parseCPE23(cpes[0]);
    const versions = new Set(cpes.map((cpe) => parseCPE23(cpe).version));
    const architectures = new Set(cpes.map((cpe) => parseCPE23(cpe).targetHw));
    verifiedItems.push({
      ...item,
      cpes,
      vendor: primary.vendor,
      product: primary.product,
      version: versions.size === 1 ? primary.version : '*',
      targetHw: architectures.size === 1 ? primary.targetHw : '*',
    });
  }
  return verifiedItems;
}

/** Value(s) that mean "NVD publishes no CPE for this vendor/product". */
const ABSENT_CPE_MARKERS = new Set(['', 'na', 'n/a', 'none', 'null', '-']);

export interface BulkRegistrationRecord {
  vendor?: unknown;
  product?: unknown;
  version?: unknown;
  targetHw?: unknown;
  cpes?: unknown;
  cpe?: unknown;
  purls?: unknown;
  assetTag?: unknown;
  ownerGroup?: unknown;
  notes?: unknown;
  active?: unknown;
}

export type BulkRegistrationResult =
  | { rows: Array<Omit<WatchListItem, 'id' | 'createdAt'>> }
  | { error: string };

/**
 * Turn one bulk-import JSON record into inventory rows.
 *
 * Every supplied CPE is parsed here and verified later by
 * `verifyRegistrationAssets`; a malformed non-absent value is an error rather
 * than a silently dropped identifier. A record whose CPE field is missing,
 * empty, `null`, or an N/A marker is accepted with no CPE and is imported
 * disabled unless it carries a PURL and explicitly requests `active: true`.
 */
export function bulkRegistrationAssets(
  record: BulkRegistrationRecord,
  fallbackAssetTag: string,
): BulkRegistrationResult {
  const vendor = typeof record.vendor === 'string' ? record.vendor.trim() : '';
  const product = typeof record.product === 'string' ? record.product.trim() : '';
  if (!vendor || !product) return { error: 'Missing required vendor or product name.' };

  // Accept both the documented `cpes` field and a singular `cpe` alias.
  const rawCpes = record.cpes === undefined ? record.cpe : record.cpes;
  const cpes: string[] = [];
  if (rawCpes !== undefined && rawCpes !== null) {
    const values = Array.isArray(rawCpes) ? rawCpes : [rawCpes];
    for (const value of values) {
      if (value === null || value === undefined) continue;
      if (typeof value !== 'string')
        return {
          error: 'CPE identifiers must be a string or an array of strings; use "NA" or an empty value when NVD publishes none.',
        };
      const trimmed = value.trim();
      if (ABSENT_CPE_MARKERS.has(trimmed.toLowerCase())) continue;
      if (!parseCPE23(trimmed).isValid) return { error: `Invalid CPE 2.3 expression: ${trimmed}.` };
      cpes.push(trimmed);
    }
  }

  const purls: string[] = [];
  if (record.purls !== undefined && record.purls !== null) {
    if (!Array.isArray(record.purls) || record.purls.some((purl) => typeof purl !== 'string'))
      return { error: 'purls must be an array of strings.' };
    for (const purl of record.purls) {
      const trimmed = purl.trim();
      if (trimmed) purls.push(trimmed);
    }
  }
  const details = {
    assetTag:
      typeof record.assetTag === 'string' && record.assetTag.trim()
        ? record.assetTag.trim()
        : fallbackAssetTag,
    ownerGroup:
      typeof record.ownerGroup === 'string' && record.ownerGroup.trim()
        ? record.ownerGroup.trim()
        : 'Imported-Inventory',
    notes: typeof record.notes === 'string' && record.notes.trim() ? record.notes : 'Bulk imported product asset',
    purls,
  };

  if (cpes.length) {
    try {
      return {
        rows: registrationAssetsFromCpes(cpes, details).map((row) => ({
          ...row,
          active: record.active !== false,
        })),
      };
    } catch (error) {
      // A structurally valid CPE with a wildcard vendor or product still cannot
      // become a monitored identity. Report it against this row instead of
      // aborting the whole batch.
      return { error: (error as Error).message };
    }
  }

  // An explicit enable still needs a structured identifier. Without a CPE a
  // PURL is the only thing the matcher can use, and the server enforces the
  // same rule; catching it here keeps the error attached to the row.
  if (record.active === true && !purls.length)
    return {
      error:
        'An active product requires a CPE or PURL. Import it inactive, then enable it after adding a published identifier.',
    };

  return {
    rows: [
      {
        vendor,
        product,
        version:
          typeof record.version === 'string' && record.version.trim() ? record.version.trim() : '*',
        cpes: [],
        targetHw:
          typeof record.targetHw === 'string' && record.targetHw.trim() ? record.targetHw.trim() : undefined,
        ...details,
        active: record.active === true,
      },
    ],
  };
}
