/**
 * Entry creation — the provision half of the agent-blind lifecycle
 * (plan section 9.3).
 *
 * Parity target: src/seedpass/core/entry_management.py add_* methods. Each
 * function appends an entry to the index and returns its id; none of them
 * return secret material. Field shapes match Python exactly (the parity test
 * rebuilds the Python-generated fixture index from scratch).
 *
 * Not ported here: Python's index0 event emission (`_system` bookkeeping),
 * checksum/backup side effects, and creation-time validation of derived
 * SSH/PGP key pairs (that key material is not ported yet).
 */

import { deriveTotpSecret } from "../derive/totp.js";
import { generateFingerprint } from "../derive/fingerprint.js";
import { Bip85 } from "../derive/bip85.js";
import { CURRENT_PASSWORD_GEN_VERSION } from "../derive/password.js";
import type { VaultIndex } from "../schema/entries.js";

type Dict = Record<string, unknown>;

export interface Clock {
  nowUnix(): number;
}

export const systemClock: Clock = {
  nowUnix: () => Math.floor(Date.now() / 1000),
};

/** Python: datetime.fromtimestamp(ts, tz=utc).isoformat() -> "+00:00" suffix. */
export function isoFromUnix(ts: number): string {
  const iso = new Date(Math.trunc(ts) * 1000).toISOString();
  return iso.replace(/\.\d{3}Z$/, "+00:00");
}

/**
 * max(int keys) + 1, or 0 for an empty index (get_next_index).
 *
 * Every key must be a plain non-negative integer within the safe range. A
 * non-numeric key makes Math.max return NaN and a huge key makes +1 a no-op,
 * and `insert` would then assign the same id repeatedly — each new entry
 * silently overwriting the last. Such an index can arrive through import or
 * a merge, so refuse it loudly rather than destroying entries.
 */
export function nextIndex(index: VaultIndex): number {
  const keys = Object.keys(index.entries);
  const ids: number[] = [];
  for (const key of keys) {
    if (!/^(0|[1-9][0-9]*)$/.test(key)) {
      throw new Error(
        `vault index contains a non-numeric entry id ${JSON.stringify(key)}; ` +
          `refusing to allocate a new id that could overwrite an existing entry`,
      );
    }
    const id = Number(key);
    if (!Number.isSafeInteger(id)) {
      throw new Error(
        `vault index contains entry id ${key}, which is outside the safe integer ` +
          `range; refusing to allocate a new id`,
      );
    }
    ids.push(id);
  }
  const liveFloor = ids.length > 0 ? Math.max(...ids) + 1 : 0;
  // Never allocate below the high-watermark. Scanning live entries alone is
  // not enough: an entry id doubles as the BIP-85 derivation index for
  // managed_account (and seed) entries, and sync deletion removes entries via
  // tombstones — so max(live)+1 could reissue a deleted #184 to a NEW entry
  // that then re-derives the departed identity's exact child seed and npub.
  // Tombstone ids are folded in so vaults from before the watermark existed
  // heal on their next allocation (for tombstones still within retention).
  return Math.max(liveFloor, storedNextIndex(index), tombstoneFloor(index));
}

/** The persisted allocation watermark, 0 when absent (pre-watermark vault). */
function storedNextIndex(index: VaultIndex): number {
  const meta = (index as unknown as Dict)["_sync_meta"];
  if (typeof meta !== "object" || meta === null || Array.isArray(meta)) return 0;
  const raw = Number((meta as Dict)["next_index"]);
  return Number.isSafeInteger(raw) && raw > 0 ? raw : 0;
}

/** One past the highest tombstoned id. Non-numeric tombstone keys are historical junk and skipped. */
function tombstoneFloor(index: VaultIndex): number {
  const meta = (index as unknown as Dict)["_sync_meta"];
  if (typeof meta !== "object" || meta === null || Array.isArray(meta)) return 0;
  const tombstones = (meta as Dict)["tombstones"];
  if (typeof tombstones !== "object" || tombstones === null || Array.isArray(tombstones)) return 0;
  let floor = 0;
  for (const key of Object.keys(tombstones)) {
    if (!/^(0|[1-9][0-9]*)$/.test(key)) continue;
    const id = Number(key);
    if (Number.isSafeInteger(id) && id + 1 > floor) floor = id + 1;
  }
  return floor;
}

/**
 * Record that `id` has been allocated: the watermark becomes at least id+1
 * and never decreases. Kept in _sync_meta because both implementations
 * already round-trip that block (it carries the tombstones), so old builds
 * preserve it without a schema bump.
 */
function bumpNextIndex(index: VaultIndex, id: number): void {
  const container = index as unknown as Dict;
  const meta =
    typeof container["_sync_meta"] === "object" &&
    container["_sync_meta"] !== null &&
    !Array.isArray(container["_sync_meta"])
      ? (container["_sync_meta"] as Dict)
      : {};
  meta["next_index"] = Math.max(storedNextIndex(index), id + 1);
  container["_sync_meta"] = meta;
}

/** Next TOTP derivation index: max over totp entries' index field + 1. */
export function nextTotpIndex(index: VaultIndex): number {
  const indices = Object.values(index.entries as unknown as Record<string, Dict>)
    .filter((e) => e["type"] === "totp" || e["kind"] === "totp")
    .map((e) => Math.trunc(Number(e["index"] ?? 0)));
  return indices.length > 0 ? Math.max(...indices) + 1 : 0;
}

function stamp(clock: Clock): { now_unix: number; now_iso: string } {
  const nowUnix = clock.nowUnix();
  return { now_unix: nowUnix, now_iso: isoFromUnix(nowUnix) };
}

function insert(index: VaultIndex, id: number, entry: Dict): string {
  const key = String(id);
  // Never silently replace an entry: allocation bugs show up here first.
  if (Object.prototype.hasOwnProperty.call(index.entries, key)) {
    throw new Error(`refusing to overwrite existing entry ${key}`);
  }
  (index.entries as unknown as Dict)[key] = entry;
  // Covers explicit-id inserts too: an entry created at #500 pushes the
  // watermark past 500 even though nextIndex never saw it.
  bumpNextIndex(index, id);
  return key;
}

export interface CommonOptions {
  archived?: boolean;
  notes?: string;
  tags?: string[];
  clock?: Clock;
}

export interface AddPasswordOptions extends CommonOptions {
  username?: string;
  url?: string;
  customFields?: Dict[];
  policy?: Partial<{
    include_special_chars: boolean;
    allowed_special_chars: string;
    special_mode: string;
    exclude_ambiguous: boolean;
    min_uppercase: number;
    min_lowercase: number;
    min_digits: number;
    min_special: number;
  }>;
}

export function addPasswordEntry(
  index: VaultIndex,
  label: string,
  length: number,
  opts: AddPasswordOptions = {},
): string {
  const id = nextIndex(index);
  const { now_unix, now_iso } = stamp(opts.clock ?? systemClock);
  const entry: Dict = {
    label,
    length,
    gen_version: CURRENT_PASSWORD_GEN_VERSION,
    username: opts.username ?? "",
    url: opts.url ?? "",
    archived: opts.archived ?? false,
    type: "password",
    kind: "password",
    notes: opts.notes ?? "",
    modified_ts: now_unix,
    date_added: now_iso,
    date_modified: now_iso,
    custom_fields: opts.customFields ?? [],
    tags: opts.tags ?? [],
    links: [],
  };
  if (opts.policy && Object.keys(opts.policy).length > 0) {
    entry["policy"] = { ...opts.policy };
  }
  return insert(index, id, entry);
}

export interface AddTotpOptions extends CommonOptions {
  period?: number;
  digits?: number;
  /** Derivation index for deterministic secrets; auto-allocated if omitted. */
  index?: number;
}

/** Deterministic TOTP: the secret derives from the parent seed on demand. */
export function addTotpDeterministic(
  index: VaultIndex,
  label: string,
  mnemonic: string,
  opts: AddTotpOptions = {},
): string {
  const id = nextIndex(index);
  const derivationIndex = opts.index ?? nextTotpIndex(index);
  // Derive once to validate, exactly as Python does — the value is dropped.
  deriveTotpSecret(mnemonic, derivationIndex);
  const { now_unix, now_iso } = stamp(opts.clock ?? systemClock);
  return insert(index, id, {
    type: "totp",
    kind: "totp",
    label,
    modified_ts: now_unix,
    date_added: now_iso,
    date_modified: now_iso,
    index: derivationIndex,
    period: opts.period ?? 30,
    digits: opts.digits ?? 6,
    archived: opts.archived ?? false,
    notes: opts.notes ?? "",
    tags: opts.tags ?? [],
    deterministic: true,
    links: [],
  });
}

const B32_RE = /^[A-Z2-7]+=*$/;

/** Imported TOTP: stores the provided base32 secret. */
export function addTotpImported(
  index: VaultIndex,
  label: string,
  secret: string,
  opts: AddTotpOptions = {},
): string {
  const normalized = secret.trim().toUpperCase();
  if (!B32_RE.test(normalized)) throw new Error("Invalid TOTP secret");
  const id = nextIndex(index);
  const { now_unix, now_iso } = stamp(opts.clock ?? systemClock);
  return insert(index, id, {
    type: "totp",
    kind: "totp",
    label,
    secret: normalized,
    modified_ts: now_unix,
    date_added: now_iso,
    date_modified: now_iso,
    period: opts.period ?? 30,
    digits: opts.digits ?? 6,
    archived: opts.archived ?? false,
    notes: opts.notes ?? "",
    tags: opts.tags ?? [],
    deterministic: false,
    links: [],
  });
}

export function addSshKeyEntry(
  index: VaultIndex,
  label: string,
  opts: CommonOptions & { index?: number } = {},
): string {
  const id = opts.index ?? nextIndex(index);
  const { now_unix, now_iso } = stamp(opts.clock ?? systemClock);
  return insert(index, id, {
    type: "ssh",
    kind: "ssh",
    index: id,
    label,
    modified_ts: now_unix,
    date_added: now_iso,
    date_modified: now_iso,
    notes: opts.notes ?? "",
    archived: opts.archived ?? false,
    tags: opts.tags ?? [],
    custom_fields: [],
    links: [],
  });
}

export function addNostrKeyEntry(
  index: VaultIndex,
  label: string,
  opts: CommonOptions & { index?: number } = {},
): string {
  const id = opts.index ?? nextIndex(index);
  const { now_unix, now_iso } = stamp(opts.clock ?? systemClock);
  return insert(index, id, {
    type: "nostr",
    kind: "nostr",
    index: id,
    label,
    modified_ts: now_unix,
    date_added: now_iso,
    date_modified: now_iso,
    notes: opts.notes ?? "",
    archived: opts.archived ?? false,
    tags: opts.tags ?? [],
    links: [],
  });
}

export function addKeyValueEntry(
  index: VaultIndex,
  label: string,
  key: string,
  value: string,
  opts: CommonOptions & { customFields?: Dict[] } = {},
): string {
  const id = nextIndex(index);
  const { now_unix, now_iso } = stamp(opts.clock ?? systemClock);
  return insert(index, id, {
    type: "key_value",
    kind: "key_value",
    label,
    key,
    value,
    modified_ts: now_unix,
    date_added: now_iso,
    date_modified: now_iso,
    notes: opts.notes ?? "",
    archived: opts.archived ?? false,
    tags: opts.tags ?? [],
    custom_fields: opts.customFields ?? [],
    links: [],
  });
}

export function addDocumentEntry(
  index: VaultIndex,
  label: string,
  content: string,
  opts: CommonOptions & { fileType?: string } = {},
): string {
  const id = nextIndex(index);
  const { now_unix, now_iso } = stamp(opts.clock ?? systemClock);
  return insert(index, id, {
    type: "document",
    kind: "document",
    label,
    content,
    file_type: opts.fileType ?? "txt",
    modified_ts: now_unix,
    date_added: now_iso,
    date_modified: now_iso,
    notes: opts.notes ?? "",
    archived: opts.archived ?? false,
    tags: opts.tags ?? [],
    custom_fields: [],
    links: [],
  });
}

export function addSeedEntry(
  index: VaultIndex,
  label: string,
  opts: CommonOptions & { index?: number; wordCount?: 12 | 18 | 24 } = {},
): string {
  const id = opts.index ?? nextIndex(index);
  const { now_unix, now_iso } = stamp(opts.clock ?? systemClock);
  return insert(index, id, {
    type: "seed",
    kind: "seed",
    index: id,
    label,
    modified_ts: now_unix,
    date_added: now_iso,
    date_modified: now_iso,
    word_count: opts.wordCount ?? 24,
    notes: opts.notes ?? "",
    archived: opts.archived ?? false,
    tags: opts.tags ?? [],
    links: [],
  });
}

/** Managed accounts always use a 12-word child seed. */
export function addManagedAccountEntry(
  index: VaultIndex,
  label: string,
  mnemonic: string,
  opts: CommonOptions & { index?: number } = {},
): string {
  const id = opts.index ?? nextIndex(index);
  const child = Bip85.fromMnemonic(mnemonic).deriveMnemonic(id, 12);
  const fingerprint = generateFingerprint(child);
  const { now_unix, now_iso } = stamp(opts.clock ?? systemClock);
  return insert(index, id, {
    type: "managed_account",
    kind: "managed_account",
    index: id,
    label,
    modified_ts: now_unix,
    date_added: now_iso,
    date_modified: now_iso,
    word_count: 12,
    notes: opts.notes ?? "",
    fingerprint,
    archived: opts.archived ?? false,
    tags: opts.tags ?? [],
    custom_fields: [],
    links: [],
  });
}

export function addPgpKeyEntry(
  index: VaultIndex,
  label: string,
  opts: CommonOptions & { index?: number; keyType?: string; userId?: string } = {},
): string {
  const id = opts.index ?? nextIndex(index);
  const { now_unix, now_iso } = stamp(opts.clock ?? systemClock);
  return insert(index, id, {
    type: "pgp",
    kind: "pgp",
    index: id,
    label,
    modified_ts: now_unix,
    date_added: now_iso,
    date_modified: now_iso,
    key_type: opts.keyType ?? "ed25519",
    user_id: opts.userId ?? "",
    notes: opts.notes ?? "",
    archived: opts.archived ?? false,
    tags: opts.tags ?? [],
    links: [],
  });
}
