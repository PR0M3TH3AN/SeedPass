/**
 * Entry modification, archive/restore, and typed links.
 *
 * Parity target: src/seedpass/core/entry_management.py modify_entry,
 * add_link, remove_link, get_links, archive_entry, restore_entry and
 * _normalize_links. Same allowed-field matrix per kind, same link
 * normalization (dedupe on target/relation/note), same timestamp touching.
 * index0 event emission is not ported (matrix: atlas milestone).
 */

import type { VaultIndex } from "../schema/entries.js";
import { isoFromUnix, systemClock, type Clock } from "./entryOps.js";

type Dict = Record<string, unknown>;

export interface EntryLink {
  target_id: number;
  relation: string;
  note: string;
}

/** Canonical, de-duplicated links (EntryManager._normalize_links). */
export function normalizeLinks(rawLinks: unknown): EntryLink[] {
  if (!Array.isArray(rawLinks)) return [];
  const normalized: EntryLink[] = [];
  const seen = new Set<string>();
  for (const item of rawLinks) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) continue;
    const dict = item as Dict;
    const targetRaw = dict["target_id"];
    const targetId =
      typeof targetRaw === "number"
        ? Math.trunc(targetRaw)
        : typeof targetRaw === "string" && /^[+-]?\d+$/.test(targetRaw.trim())
          ? parseInt(targetRaw.trim(), 10)
          : null;
    if (targetId === null) continue;
    const relation = String(dict["relation"] ?? "related_to").trim().toLowerCase();
    const note = String(dict["note"] ?? "").trim();
    if (targetId < 0 || !relation) continue;
    const key = JSON.stringify([targetId, relation, note]);
    if (seen.has(key)) continue;
    seen.add(key);
    normalized.push({ target_id: targetId, relation, note });
  }
  return normalized;
}

export interface ModifyChanges {
  label?: string;
  username?: string;
  url?: string;
  archived?: boolean;
  notes?: string;
  period?: number;
  digits?: number;
  key?: string;
  value?: string;
  content?: string;
  file_type?: string;
  custom_fields?: Dict[];
  tags?: string[];
  links?: Dict[];
  include_special_chars?: boolean;
  allowed_special_chars?: string;
  special_mode?: string;
  exclude_ambiguous?: boolean;
  min_uppercase?: number;
  min_lowercase?: number;
  min_digits?: number;
  min_special?: number;
}

const COMMON_FIELDS = ["label", "archived", "notes", "custom_fields", "tags", "links"];
const POLICY_FIELDS = [
  "include_special_chars",
  "allowed_special_chars",
  "special_mode",
  "exclude_ambiguous",
  "min_uppercase",
  "min_lowercase",
  "min_digits",
  "min_special",
];

const ALLOWED_FIELDS: Record<string, Set<string>> = {
  password: new Set([...COMMON_FIELDS, "username", "url", ...POLICY_FIELDS]),
  totp: new Set([...COMMON_FIELDS, "period", "digits"]),
  key_value: new Set([...COMMON_FIELDS, "key", "value"]),
  managed_account: new Set([...COMMON_FIELDS, "value"]),
  document: new Set([...COMMON_FIELDS, "content", "file_type"]),
  ssh: new Set(COMMON_FIELDS),
  pgp: new Set(COMMON_FIELDS),
  nostr: new Set(COMMON_FIELDS),
  seed: new Set(COMMON_FIELDS),
};

function entryDict(index: VaultIndex, id: string): Dict {
  const entry = (index.entries as unknown as Record<string, Dict>)[id];
  if (typeof entry !== "object" || entry === null) {
    throw new Error(`Entry not found: ${id}`);
  }
  return entry;
}

function touch(entry: Dict, clock: Clock): void {
  if (!("date_added" in entry)) {
    entry["date_added"] = isoFromUnix(Math.trunc(Number(entry["modified_ts"] ?? 0)));
  }
  const now = clock.nowUnix();
  entry["modified_ts"] = now;
  entry["date_modified"] = isoFromUnix(now);
}

/** Modify an entry with the Python allowed-field matrix and timestamps. */
export function modifyEntry(
  index: VaultIndex,
  id: string,
  changes: ModifyChanges,
  clock: Clock = systemClock,
): void {
  const entry = entryDict(index, id);
  const entryType = String(entry["type"] ?? entry["kind"] ?? "password");
  const allowed = ALLOWED_FIELDS[entryType] ?? new Set<string>();

  const provided = Object.entries(changes).filter(([, v]) => v !== undefined);
  const invalid = provided.map(([k]) => k).filter((k) => !allowed.has(k));
  if (invalid.length > 0) {
    throw new Error(
      `Entry type '${entryType}' does not support fields: ${invalid.sort().join(", ")}`,
    );
  }

  for (const [field, value] of provided) {
    if (field === "links") {
      entry["links"] = normalizeLinks(value);
    } else if (field === "file_type") {
      entry["file_type"] = String(value).trim().toLowerCase();
    } else if (POLICY_FIELDS.includes(field)) {
      const policy = (entry["policy"] as Dict | undefined) ?? {};
      policy[field] = field.startsWith("min_") ? Math.trunc(Number(value)) : value;
      entry["policy"] = policy;
    } else {
      entry[field] = value;
    }
  }
  if (changes.archived !== undefined) {
    delete entry["blacklisted"];
  }

  touch(entry, clock);
}

export function archiveEntry(index: VaultIndex, id: string, clock: Clock = systemClock): void {
  modifyEntry(index, id, { archived: true }, clock);
}

export function restoreEntry(index: VaultIndex, id: string, clock: Clock = systemClock): void {
  modifyEntry(index, id, { archived: false }, clock);
}

/** Create or update a typed relationship between two entries. */
export function addLink(
  index: VaultIndex,
  id: string,
  targetId: number,
  options: { relation?: string; note?: string; clock?: Clock } = {},
): EntryLink[] {
  const src = entryDict(index, id);
  entryDict(index, String(targetId)); // must exist
  if (parseInt(id, 10) === Math.trunc(targetId)) {
    throw new Error("Self-referential links are not allowed");
  }
  const relation = String(options.relation ?? "related_to").trim().toLowerCase();
  const note = String(options.note ?? "").trim();
  const links = normalizeLinks(src["links"] ?? []);
  links.push({ target_id: Math.trunc(targetId), relation, note });
  src["links"] = normalizeLinks(links);
  touch(src, options.clock ?? systemClock);
  return src["links"] as EntryLink[];
}

/** Remove links to targetId (optionally only a specific relation). */
export function removeLink(
  index: VaultIndex,
  id: string,
  targetId: number,
  options: { relation?: string; clock?: Clock } = {},
): EntryLink[] {
  const src = entryDict(index, id);
  const relationNorm =
    options.relation !== undefined ? options.relation.trim().toLowerCase() : null;
  const links = normalizeLinks(src["links"] ?? []);
  const filtered = links.filter((link) => {
    const matchesTarget = link.target_id === Math.trunc(targetId);
    const matchesRelation = relationNorm === null || link.relation === relationNorm;
    return !(matchesTarget && matchesRelation);
  });
  if (filtered.length !== links.length) {
    src["links"] = filtered;
    touch(src, options.clock ?? systemClock);
  }
  return (src["links"] ?? []) as EntryLink[];
}

export interface ResolvedLink extends EntryLink {
  target_label: string | null;
  target_kind: string | null;
}

/** Links for an entry with resolved target metadata. */
export function getLinks(index: VaultIndex, id: string): ResolvedLink[] {
  const src = entryDict(index, id);
  const entries = index.entries as unknown as Record<string, Dict>;
  return normalizeLinks(src["links"] ?? []).map((link) => {
    const target = entries[String(link.target_id)];
    return {
      ...link,
      target_label: target ? String(target["label"] ?? target["website"] ?? "") : null,
      target_kind: target ? String(target["type"] ?? target["kind"] ?? "") : null,
    };
  });
}
