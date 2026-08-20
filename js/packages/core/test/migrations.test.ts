/**
 * Schema migration parity: TS must migrate legacy indexes to exactly what
 * Python's apply_migrations produces, so an old Python profile opens here.
 */

import { describe, expect, it } from "vitest";
import { migrationCases, migrationLatestVersion } from "@seedpass/test-vectors";
import {
  applyMigrations,
  needsMigration,
  parseVaultIndex,
  SchemaMigrationError,
  CURRENT_SCHEMA_VERSION,
  UnsupportedSchemaVersionError,
} from "@seedpass/core";

describe("schema migrations", () => {
  it("agrees with Python on the current version", () => {
    expect(CURRENT_SCHEMA_VERSION).toBe(migrationLatestVersion);
  });

  it.each(migrationCases)("migrates $name exactly as Python does", (c) => {
    expect(applyMigrations(c.input)).toEqual(c.migrated);
  });

  it("does not mutate the caller's payload", () => {
    const input = migrationCases[0]!.input;
    const snapshot = JSON.stringify(input);
    applyMigrations(input);
    expect(JSON.stringify(input)).toBe(snapshot);
  });

  it("is idempotent on an already-current index", () => {
    const migrated = applyMigrations(migrationCases[0]!.input);
    expect(applyMigrations(migrated)).toEqual(migrated);
    expect(needsMigration(migrated)).toBe(false);
  });

  it("parseVaultIndex opens legacy indexes by migrating them", () => {
    for (const c of migrationCases) {
      const index = parseVaultIndex(c.input);
      expect(index.schema_version).toBe(CURRENT_SCHEMA_VERSION);
      expect(Object.keys(index.entries).length).toBeGreaterThan(0);
      for (const entry of Object.values(index.entries)) {
        expect(entry.tags).toBeDefined();
      }
    }
  });

  it("parseVaultIndex can refuse to migrate when asked", () => {
    expect(() => parseVaultIndex(migrationCases[0]!.input, { migrate: false })).toThrow(
      /needs migration/,
    );
  });

  it("refuses future schema versions in both paths", () => {
    const future = { schema_version: 99, entries: {} };
    expect(() => applyMigrations(future)).toThrow(SchemaMigrationError);
    expect(() => parseVaultIndex(future)).toThrow(UnsupportedSchemaVersionError);
  });

  it("recovers a v0 password entry's label from its website field", () => {
    const v0 = migrationCases.find((c) => c.name === "v0")!;
    const index = parseVaultIndex(v0.input);
    const labels = Object.values(index.entries).map((e) => e.label);
    expect(labels).toContain("legacy-site.example");
    for (const entry of Object.values(index.entries)) {
      expect(entry).not.toHaveProperty("website");
    }
  });
});
