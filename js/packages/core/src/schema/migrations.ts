/**
 * Index schema migrations 0 -> 4.
 *
 * Parity target: src/seedpass/core/migrations.py. A user with an older
 * Python profile must be able to open it here; refusing to migrate would
 * strand them on the Python implementation.
 *
 * Each step mirrors its Python counterpart exactly, including the quirks
 * (v1->v2 drops `website` only for password entries after copying it to
 * `label`; `kind` is NOT backfilled — Python leaves pre-v2 entries with
 * only `type`, and readers fall back to it).
 */

import { CURRENT_SCHEMA_VERSION } from "./entries.js";

type Dict = Record<string, unknown>;

function isDict(v: unknown): v is Dict {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** v0 -> v1: stamp the schema version onto a pre-versioned index. */
function v0ToV1(data: Dict): Dict {
  data["schema_version"] = 1;
  return data;
}

/** v1 -> v2: `passwords` becomes `entries`; `website` becomes `label`. */
function v1ToV2(data: Dict): Dict {
  const passwords = isDict(data["passwords"]) ? (data["passwords"] as Dict) : {};
  delete data["passwords"];
  const entries: Dict = {};
  for (const [key, raw] of Object.entries(passwords)) {
    if (!isDict(raw)) continue;
    const entry = raw;
    if (entry["type"] === undefined) entry["type"] = "password";
    if (entry["notes"] === undefined) entry["notes"] = "";
    if (entry["label"] === undefined && entry["website"] !== undefined) {
      entry["label"] = entry["website"];
    }
    if (entry["type"] === "password" && entry["website"] !== undefined) {
      delete entry["website"];
    }
    entries[key] = entry;
  }
  data["entries"] = entries;
  data["schema_version"] = 2;
  return data;
}

/** v2 -> v3: default `custom_fields` and `origin` on every entry. */
function v2ToV3(data: Dict): Dict {
  const entries = isDict(data["entries"]) ? (data["entries"] as Dict) : {};
  for (const raw of Object.values(entries)) {
    if (!isDict(raw)) continue;
    if (raw["custom_fields"] === undefined) raw["custom_fields"] = [];
    if (raw["origin"] === undefined) raw["origin"] = "";
    if ((raw["type"] ?? "password") === "password") {
      if (raw["label"] === undefined && raw["website"] !== undefined) {
        raw["label"] = raw["website"];
      }
      delete raw["website"];
    }
  }
  data["schema_version"] = 3;
  return data;
}

/** v3 -> v4: default `tags` on every entry. */
function v3ToV4(data: Dict): Dict {
  const entries = isDict(data["entries"]) ? (data["entries"] as Dict) : {};
  for (const raw of Object.values(entries)) {
    if (!isDict(raw)) continue;
    if (raw["tags"] === undefined) raw["tags"] = [];
  }
  data["schema_version"] = 4;
  return data;
}

const MIGRATIONS: Record<number, (data: Dict) => Dict> = {
  0: v0ToV1,
  1: v1ToV2,
  2: v2ToV3,
  3: v3ToV4,
};

export class SchemaMigrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SchemaMigrationError";
  }
}

/**
 * Upgrade an index payload to the current schema version.
 *
 * Operates on a copy — callers keep their input intact so a failed
 * migration can never leave a half-converted vault behind.
 */
export function applyMigrations(input: unknown): Dict {
  if (!isDict(input)) throw new SchemaMigrationError("index payload is not an object");
  const data = structuredClone(input) as Dict;
  let current = Number(data["schema_version"] ?? 0);
  if (!Number.isFinite(current)) current = 0;
  if (current > CURRENT_SCHEMA_VERSION) {
    throw new SchemaMigrationError(
      `Unsupported schema version ${current} (this build supports ${CURRENT_SCHEMA_VERSION})`,
    );
  }
  while (current < CURRENT_SCHEMA_VERSION) {
    const migrate = MIGRATIONS[current];
    if (!migrate) {
      throw new SchemaMigrationError(`No migration available from version ${current}`);
    }
    const next = migrate(data);
    const reported = Number(next["schema_version"] ?? current + 1);
    current = Number.isFinite(reported) ? reported : current + 1;
  }
  return data;
}

/** True when the payload predates the current schema version. */
export function needsMigration(input: unknown): boolean {
  if (!isDict(input)) return false;
  return Number(input["schema_version"] ?? 0) < CURRENT_SCHEMA_VERSION;
}
