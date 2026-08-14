/**
 * Entry and vault-index schemas, current schema_version 4.
 *
 * Parity targets: src/seedpass/core/entry_types.py, entry_management.py and
 * migrations.py. Schemas are intentionally tolerant of unknown extra fields
 * (loose objects) so that entries written by a newer minor revision survive a
 * read/write cycle — but an index whose schema_version is above
 * CURRENT_SCHEMA_VERSION must be refused, never silently rewritten
 * (plan section 13, Milestone 3 exit criteria).
 */

import { z } from "zod";
import { applyMigrations } from "./migrations.js";

export const CURRENT_SCHEMA_VERSION = 4;

export const customFieldSchema = z
  .object({
    label: z.string(),
    value: z.string(),
    is_hidden: z.boolean().optional(),
  })
  .loose();

/** Fields shared by every entry kind (docs/entry_types.md). */
const baseEntry = {
  type: z.string(),
  kind: z.string(),
  label: z.string(),
  archived: z.boolean().default(false),
  date_added: z.string().optional(),
  date_modified: z.string().optional(),
  modified_ts: z.number().int().optional(),
  notes: z.string().default(""),
  tags: z.array(z.string()).default([]),
  links: z.array(z.unknown()).default([]),
  custom_fields: z.array(customFieldSchema).optional(),
  origin: z.string().optional(),
};

export const passwordEntrySchema = z
  .object({
    ...baseEntry,
    type: z.literal("password"),
    kind: z.literal("password"),
    length: z.number().int().min(8).max(128),
    // Absent gen_version means v1 (frozen); see password_generation.py
    gen_version: z.number().int().optional(),
    username: z.string().optional(),
    url: z.string().optional(),
  })
  .loose();

export const totpEntrySchema = z
  .object({
    ...baseEntry,
    type: z.literal("totp"),
    kind: z.literal("totp"),
    deterministic: z.boolean().optional(),
    period: z.number().int().positive().default(30),
    digits: z.number().int().positive().default(6),
    /** Derivation index — present for deterministic entries. */
    index: z.number().int().nonnegative().optional(),
    /** Imported base32 secret — present for non-deterministic entries. */
    secret: z.string().optional(),
  })
  .loose()
  .check((ctx) => {
    if (ctx.value.index === undefined && ctx.value.secret === undefined) {
      ctx.issues.push({
        code: "custom",
        message: "totp entry needs a derivation index or an imported secret",
        input: ctx.value,
      });
    }
  });

export const sshEntrySchema = z
  .object({
    ...baseEntry,
    type: z.literal("ssh"),
    kind: z.literal("ssh"),
    index: z.number().int().nonnegative(),
  })
  .loose();

export const seedEntrySchema = z
  .object({
    ...baseEntry,
    type: z.literal("seed"),
    kind: z.literal("seed"),
    index: z.number().int().nonnegative(),
    word_count: z.union([z.literal(12), z.literal(18), z.literal(24)]),
  })
  .loose();

export const pgpEntrySchema = z
  .object({
    ...baseEntry,
    type: z.literal("pgp"),
    kind: z.literal("pgp"),
    index: z.number().int().nonnegative(),
    key_type: z.string().default("ed25519"),
    user_id: z.string().default(""),
  })
  .loose();

export const nostrEntrySchema = z
  .object({
    ...baseEntry,
    type: z.literal("nostr"),
    kind: z.literal("nostr"),
    index: z.number().int().nonnegative(),
  })
  .loose();

export const keyValueEntrySchema = z
  .object({
    ...baseEntry,
    type: z.literal("key_value"),
    kind: z.literal("key_value"),
    key: z.string(),
    value: z.string(),
  })
  .loose();

export const managedAccountEntrySchema = z
  .object({
    ...baseEntry,
    type: z.literal("managed_account"),
    kind: z.literal("managed_account"),
    index: z.number().int().nonnegative(),
    word_count: z.union([z.literal(12), z.literal(18), z.literal(24)]),
    fingerprint: z.string().regex(/^[0-9A-F]{16}$/),
  })
  .loose();

export const documentEntrySchema = z
  .object({
    ...baseEntry,
    type: z.literal("document"),
    kind: z.literal("document"),
    content: z.string(),
    file_type: z.string().default("txt"),
  })
  .loose();

/**
 * Pre-v2 Python entries carry only `type`; `kind` arrived later and Python's
 * migrations deliberately do not backfill it (its readers fall back to
 * `type`). Fill it in for validation so legacy entries can be discriminated,
 * which also brings them to the shape Python writes for new entries.
 */
function withKind(value: unknown): unknown {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const entry = value as Record<string, unknown>;
    if (entry["kind"] === undefined && typeof entry["type"] === "string") {
      return { ...entry, kind: entry["type"] };
    }
  }
  return value;
}

export const entryUnionSchema = z.discriminatedUnion("kind", [
  passwordEntrySchema,
  totpEntrySchema,
  sshEntrySchema,
  seedEntrySchema,
  pgpEntrySchema,
  nostrEntrySchema,
  keyValueEntrySchema,
  managedAccountEntrySchema,
  documentEntrySchema,
]);

export const entrySchema = z.preprocess(withKind, entryUnionSchema);

export type Entry = z.infer<typeof entryUnionSchema>;
export type PasswordEntry = z.infer<typeof passwordEntrySchema>;
export type TotpEntry = z.infer<typeof totpEntrySchema>;

export const vaultIndexSchema = z
  .object({
    schema_version: z.number().int(),
    entries: z.record(z.string(), entrySchema),
  })
  .loose();

export type VaultIndex = z.infer<typeof vaultIndexSchema>;

export class UnsupportedSchemaVersionError extends Error {
  constructor(public readonly version: number) {
    super(
      `Vault index schema_version ${version} is newer than supported ` +
        `${CURRENT_SCHEMA_VERSION}; refusing to read it. Upgrade this client.`,
    );
    this.name = "UnsupportedSchemaVersionError";
  }
}

/**
 * Parse a decrypted vault index, migrating older schema versions forward.
 *
 * Future versions are refused rather than silently rewritten: a newer client
 * may have written fields this build would drop on save.
 *
 * Pass `{ migrate: false }` to reject anything that is not already current —
 * useful where a caller must not silently upgrade on-disk data.
 */
export function parseVaultIndex(
  data: unknown,
  options: { migrate?: boolean } = {},
): VaultIndex {
  // A pre-v1 index has no schema_version field at all, so the probe must
  // tolerate its absence and treat it as version 0.
  const versionProbe = z
    .object({ schema_version: z.number().int().default(0) })
    .loose()
    .parse(data);
  if (versionProbe.schema_version > CURRENT_SCHEMA_VERSION) {
    throw new UnsupportedSchemaVersionError(versionProbe.schema_version);
  }
  if (versionProbe.schema_version < CURRENT_SCHEMA_VERSION) {
    if (options.migrate === false) {
      throw new Error(
        `Vault index schema_version ${versionProbe.schema_version} needs migration`,
      );
    }
    return vaultIndexSchema.parse(applyMigrations(data));
  }
  return vaultIndexSchema.parse(data);
}
