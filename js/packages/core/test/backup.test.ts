/** Portable backup parity against Python-generated fixtures. */

import { describe, expect, it } from "vitest";
import { base64 } from "@scure/base";
import { portableBackup, mnemonics } from "@seedpass/test-vectors";
import {
  importBackup,
  exportBackup,
  BackupImportError,
  canonicalHash,
  hexToBytes,
} from "@seedpass/core";

const mnemonic = () => mnemonics[portableBackup.mnemonic_id]!;

describe("portable backup", () => {
  it("imports the Python encrypted export", async () => {
    const index = await importBackup(JSON.stringify(portableBackup.encrypted_wrapper), {
      mnemonic: mnemonic(),
    });
    expect(index).toEqual(portableBackup.index);
  });

  it("imports the Python plaintext export", async () => {
    const index = await importBackup(JSON.stringify(portableBackup.plaintext_wrapper));
    expect(index).toEqual(portableBackup.index);
  });

  it("computes the same canonical checksum as Python", () => {
    expect(canonicalHash(portableBackup.index)).toBe(portableBackup.canonical_json_sha256);
  });

  it("re-exports byte-identically with pinned nonce and timestamp", async () => {
    const w = portableBackup.encrypted_wrapper;
    const pinnedNonce = base64.decode(w.payload).slice(3, 15);
    const reExported = await exportBackup(portableBackup.index, {
      mnemonic: mnemonic(),
      fingerprint: w.fingerprint,
      createdAt: w.created_at,
      nonce: pinnedNonce,
    });
    expect(reExported).toEqual(w);
  });

  it("roundtrips its own encrypted export", async () => {
    const wrapper = await exportBackup(portableBackup.index, {
      mnemonic: mnemonic(),
      fingerprint: portableBackup.encrypted_wrapper.fingerprint,
    });
    const index = await importBackup(JSON.stringify(wrapper), { mnemonic: mnemonic() });
    expect(index).toEqual(portableBackup.index);
  });

  it("rejects a tampered checksum", async () => {
    const bad = {
      ...portableBackup.plaintext_wrapper,
      checksum: hexToBytes(portableBackup.canonical_json_sha256)
        .reverse()
        .reduce((s, b) => s + b.toString(16).padStart(2, "0"), ""),
    };
    await expect(importBackup(JSON.stringify(bad))).rejects.toThrow("Checksum mismatch");
  });

  it("rejects unsupported format versions", async () => {
    const bad = { ...portableBackup.plaintext_wrapper, format_version: 2 };
    await expect(importBackup(JSON.stringify(bad))).rejects.toThrow(BackupImportError);
  });

  it("requires the seed for seed-only backups", async () => {
    await expect(
      importBackup(JSON.stringify(portableBackup.encrypted_wrapper)),
    ).rejects.toThrow("parent seed required");
  });
});
