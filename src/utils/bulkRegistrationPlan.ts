import type { WatchListItem } from '../types/index.ts';
import type { BulkRegistrationRecord } from './watchlist.ts';
import { bulkRegistrationAssets } from './watchlist.ts';
import { watchlistConfirmationToken, watchlistIdentity } from '../../shared/watchlistIdentity.ts';

/**
 * Upsert key the command layer uses for `asset.import`: assetTag plus the
 * product identifiers from `watchlistIdentity`, ignoring notes/ownerGroup/active.
 * Two records that share it are one write, and an insert whose identity an
 * existing non-replaced row already carries joins that row.
 */
type UpsertKey = string;

/** A JSON product record the caller has already proven is a non-null object. */
export type BulkRegistrationJsonRecord = BulkRegistrationRecord;
export type BulkRegistrationRow = Omit<WatchListItem, 'id' | 'createdAt'>;

/** Shape shared by stored inventory rows and the rows an import would write. */
interface ConfirmationItem {
  id?: string;
  vendor: string;
  product: string;
  cpes: string[];
  purls?: string[];
  assetTag?: string;
  version?: string;
  targetHw?: string;
  ownerGroup?: string;
  active?: boolean;
  notes?: string;
}
type StoredConfirmationItem = ConfirmationItem & { id: string };

/** What one row of the batch does to the stored inventory. */
export type BulkRegistrationAction = 'create' | 'update' | 'enable' | 'disable' | 'unchanged' | 'invalid';

/** One row the request would write, as the confirmation dialog reports it. */
export interface BulkRegistrationChange {
  action: BulkRegistrationAction;
  /**
   * Token used to prove this row is stored after the request. Null when the
   * batch cannot restate it (an assetTag was generated for this request, or the
   * row would be rejected), so it is never reported as applied.
   */
  token: string | null;
  assetTag: string;
  vendor: string;
  product: string;
  /** Whether the stored form the dialog describes would match vulnerabilities. */
  matchable: boolean;
  /** Why this row cannot match a vulnerability, or null when it can. */
  inertReason: string | null;
  /** Why this row would be rejected on save, or null when it is valid. */
  invalidReason: string | null;
  /** Fields an update would change on the stored row, or null for a create. */
  overwriteReason: string | null;
}

/** Pending changes for one upsert key, grouped so the dialog can call out an overwrite. */
export interface BulkRegistrationIdentityPlan {
  identity: UpsertKey;
  /** The row the server's last-wins Map keeps for this key. */
  records: ConfirmationItem[];
  /** Whether the batch supplies this key more than once, so earlier rows are discarded. */
  splits: boolean;
  /** Stored rows already on this upsert key that the batch does not replace. */
  competing: StoredConfirmationItem[];
  active: BulkRegistrationChange[];
  disabled: BulkRegistrationChange[];
}

export interface BulkRegistrationPlan {
  /** Inventory rows the batch represents, counting one per rejected input record. */
  rows: number;
  /** Rows that would be written enabled. */
  activeRows: number;
  /** Rows that would be written disabled, including rejected input records. */
  disabledRows: number;
  /** Input records the command-layer parser rejects. */
  invalidRows: number;
  /**
   * Rows the batch would turn on. An active record whose identity a stored row
   * already carries, whose fields all match, is a no-op unless that stored row
   * is disabled, in which case it is a re-enable.
   */
  enableRows: number;
  /** Enabled rows the batch overwrites with identical fields (no visible change). */
  unchangedActiveRows: number;
  /** Stored rows that already match these records and carry an inactive flag: these rows are re-enabled. */
  reactivatedRows: number;
  changedRecords: BulkRegistrationChange[];
  identities: BulkRegistrationIdentityPlan[];
  /**
   * Stored rows that share an assetTag with this batch but are not on one of its
   * upsert keys. The command layer upserts by key and never deletes, so these
   * rows stay in inventory next to the imported rows.
   */
  overlappingRows: number;
}

function emptyPlan(): BulkRegistrationPlan {
  return {
    rows: 0,
    activeRows: 0,
    disabledRows: 0,
    invalidRows: 0,
    enableRows: 0,
    unchangedActiveRows: 0,
    reactivatedRows: 0,
    changedRecords: [],
    identities: [],
    overlappingRows: 0,
  };
}

function token(record: {
  vendor?: string;
  product?: string;
  cpes: string[];
  purls?: string[];
  assetTag?: string;
}): string | null {
  return watchlistConfirmationToken({
    vendor: record.vendor || '',
    product: record.product || '',
    cpes: record.cpes,
    purls: record.purls,
    assetTag: record.assetTag,
  });
}

/** The command layer's upsert key: assetTag plus the product identity. */
function keyOf(record: ConfirmationItem): UpsertKey {
  return JSON.stringify([(record.assetTag || '').trim(), watchlistIdentity(record)]);
}

/**
 * Why a row cannot match a vulnerability, or null when it can.
 *
 * Only the stored flag is authoritative: the correlation engine filters on
 * `WHERE active` alone, so an enabled row without identifiers is visible in the
 * table but still matches nothing. The second clause exists so a record whose
 * only identifiers were `"NA"` is described accurately rather than as live.
 */
function inertReason(record: ConfirmationItem): string | null {
  if (record.active === false) return 'imported disabled';
  if (!record.cpes.length && !(record.purls || []).length) return 'no published CPE or PURL to match';
  return null;
}

function sameStoredRow(left: ConfirmationItem, right: ConfirmationItem): boolean {
  if (watchlistIdentity(left) !== watchlistIdentity(right)) return false;
  const fields = ['assetTag', 'ownerGroup', 'version', 'targetHw', 'notes', 'active'] as const;
  const normal = (value: unknown) => (value === undefined || value === null ? '' : String(value).trim());
  return fields.every((field) => normal(left[field]) === normal(right[field]));
}

/**
 * Why a record would overwrite a stored row with the same identity, or null
 * when every field it can write already matches the stored value.
 */
function overwriteReason(record: ConfirmationItem, stored: ConfirmationItem): string | null {
  const text = (value: unknown) => (value === undefined || value === null ? '' : String(value).trim());
  const ownerGroup = text(record.ownerGroup);
  if (ownerGroup && ownerGroup !== text(stored.ownerGroup))
    return `owner group "${text(stored.ownerGroup)}" -> "${ownerGroup}"`;
  if (record.notes !== undefined && text(record.notes) !== text(stored.notes))
    return `notes "${text(stored.notes)}" -> "${text(record.notes)}"`;
  if (record.active !== undefined && record.active !== (stored.active !== false))
    return `active ${stored.active !== false ? 'on' : 'off'} -> ${record.active ? 'on' : 'off'}`;
  return null;
}

/** True when only the enabled flag separates the incoming row from the stored one. */
function matchesExceptActive(record: ConfirmationItem, stored: ConfirmationItem): boolean {
  return sameStoredRow({ ...record, active: stored.active }, stored);
}

function recordChange(
  plan: BulkRegistrationPlan,
  identity: BulkRegistrationIdentityPlan,
  change: BulkRegistrationChange,
): void {
  plan.changedRecords.push(change);
  (change.action === 'disable' ? identity.disabled : identity.active).push(change);
}

/**
 * Classify the surviving row for one upsert key against the stored inventory.
 * The server's `Map` keeps the last record for a key, so earlier records are
 * reported through `splits` instead of being treated as separate writes.
 */
function describeGroup(
  plan: BulkRegistrationPlan,
  key: UpsertKey,
  records: ConfirmationItem[],
  target: ConfirmationItem[],
): void {
  const final = records[records.length - 1];
  const storedRows = target.filter((item) => keyOf(item) === key) as StoredConfirmationItem[];
  // `asset.import` builds its existing map with `new Map(inventory.map(...))`,
  // so the last stored row for a key is the one it updates.
  const stored = storedRows[storedRows.length - 1];
  const identity: BulkRegistrationIdentityPlan = {
    identity: key,
    records: [final],
    splits: records.length > 1,
    competing: storedRows.slice(0, -1),
    active: [],
    disabled: [],
  };
  plan.identities.push(identity);

  const active = final.active !== false;
  const inert = inertReason(final);
  const base: Omit<BulkRegistrationChange, 'action' | 'overwriteReason'> = {
    token: token(final),
    assetTag: (final.assetTag || '').trim(),
    vendor: final.vendor,
    product: final.product,
    matchable: inert === null,
    inertReason: inert,
    invalidReason: null,
  };

  if (!stored) {
    if (active) plan.enableRows++;
    recordChange(plan, identity, { ...base, action: 'create', overwriteReason: null });
    return;
  }

  if (sameStoredRow(final, stored)) {
    if (active) plan.unchangedActiveRows++;
    return;
  }

  if (active && stored.active === false) {
    plan.enableRows++;
    if (matchesExceptActive(final, stored)) plan.reactivatedRows++;
    recordChange(plan, identity, {
      ...base,
      action: 'enable',
      overwriteReason: overwriteReason(final, stored),
    });
    return;
  }

  recordChange(plan, identity, {
    ...base,
    action: active ? 'update' : 'disable',
    overwriteReason: overwriteReason(final, stored),
  });
}

function describeGroups(
  plan: BulkRegistrationPlan,
  groups: Map<UpsertKey, ConfirmationItem[]>,
  target: ConfirmationItem[],
): void {
  for (const [key, records] of groups) describeGroup(plan, key, records, target);

  const keys = new Set(groups.keys());
  const assetTags = new Set(
    [...groups.values()]
      .flat()
      .map((record) => (record.assetTag || '').trim())
      .filter(Boolean),
  );
  plan.overlappingRows = target.filter(
    (item) => assetTags.has((item.assetTag || '').trim()) && !keys.has(keyOf(item)),
  ).length;
}

function buildPlan(
  rows: BulkRegistrationRow[],
  target: ConfirmationItem[],
  invalid: BulkRegistrationChange[],
): BulkRegistrationPlan {
  const plan = emptyPlan();
  const groups = new Map<UpsertKey, ConfirmationItem[]>();

  for (const change of invalid) {
    plan.rows++;
    plan.invalidRows++;
    plan.disabledRows++;
    plan.changedRecords.push(change);
    plan.identities.push({
      identity: `\u0000invalid:${plan.invalidRows}`,
      records: [],
      splits: false,
      competing: [],
      active: [],
      disabled: [change],
    });
  }

  for (const row of rows) {
    plan.rows++;
    if (row.active === false) plan.disabledRows++;
    else plan.activeRows++;
    const key = keyOf(row);
    const group = groups.get(key) ?? [];
    group.push(row);
    groups.set(key, group);
  }

  describeGroups(plan, groups, target);
  return plan;
}

function invalidChange(record: unknown, error: string): BulkRegistrationChange {
  const text = (value: unknown) => (typeof value === 'string' ? value.trim() : '');
  const source = record && typeof record === 'object' ? (record as Record<string, unknown>) : {};
  return {
    action: 'invalid',
    token: null,
    assetTag: text(source.assetTag),
    vendor: text(source.vendor),
    product: text(source.product),
    matchable: false,
    inertReason: null,
    invalidReason: error,
    overwriteReason: null,
  };
}

/**
 * Plan an already-parsed and verified set of inventory rows.
 *
 * The bulk-import dialog verifies CPEs before it asks for confirmation, which
 * can rewrite an alias into the NVD spelling; planning the verified rows keeps
 * the reported identity, token, and overwrite decision equal to what will be
 * written.
 */
export function planBulkRegistrationRows(
  rows: BulkRegistrationRow[],
  target: WatchListItem[] = [],
): BulkRegistrationPlan {
  return buildPlan(rows, target, []);
}

/**
 * Describe the pending changes for a bulk `asset.import` before it is written,
 * so the confirmation dialog can show what the request will do instead of only
 * how many rows it carries.
 *
 * The plan mirrors the command layer rather than re-implementing it: records are
 * grouped by the same assetTag + identity upsert key, and when a group holds
 * several records the last one wins, exactly as the server's Map collapses them.
 * Each surviving row is compared with the stored row for that key so the dialog
 * can separate a create from an overwrite, and an active row on a disabled stored
 * row is reported as a re-enable rather than as an unrelated addition.
 *
 * `target` is the stored inventory snapshot as the caller last received it. A
 * record that fails `bulkRegistrationAssets` is reported through the returned
 * plan as an invalid row with its reason, so the caller can block the import and
 * show the operator the same message the import itself would have produced.
 *
 * `fallbackAssetTag` must match the generator the caller uses for the rows it
 * actually sends, or a row without an explicit assetTag is planned under a
 * different identity than the one that is written.
 */
export function planBulkRegistration(
  records: unknown[],
  target: WatchListItem[] = [],
  fallbackAssetTag: (index: number) => string = (index) => `BULK-${index + 1}`,
): BulkRegistrationPlan {
  const rows: BulkRegistrationRow[] = [];
  const invalid: BulkRegistrationChange[] = [];

  for (const [index, record] of records.entries()) {
    const result = bulkRegistrationAssets(
      record && typeof record === 'object' ? (record as BulkRegistrationRecord) : {},
      fallbackAssetTag(index),
    );
    if ('error' in result) {
      invalid.push(invalidChange(record, result.error));
      continue;
    }
    rows.push(...result.rows);
  }

  return buildPlan(rows, target, invalid);
}
