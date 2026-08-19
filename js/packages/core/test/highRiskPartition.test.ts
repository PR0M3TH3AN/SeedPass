/**
 * High-risk partition file format.
 *
 * The load-bearing tests are the interop ones: the fixtures were produced by
 * Python, so "TS reads them" proves the format is genuinely shared rather
 * than merely self-consistent. A partition only either implementation can
 * open would be worse than none — the entries are SSH keys, PGP keys and
 * seeds, and a user who cannot open them has lost them.
 */

import { describe, expect, it } from "vitest";
import { base64 } from "@scure/base";
import {
  decryptPartition,
  encryptPartition,
  buildPartitionEnvelope,
  unwrapPartitionKey,
  generatePartitionKey,
  partitionKeyTag,
  partitionStub,
  isPartitionStub,
  HighRiskError,
} from "@seedpass/core";
import { highRiskFixture as fx } from "@seedpass/test-vectors";

describe("interop with Python", () => {
  it("derives the same partition key tag", () => {
    expect(partitionKeyTag(fx.partition_key)).toBe(fx.tag);
  });

  it("unwraps an envelope Python wrapped", async () => {
    expect(await unwrapPartitionKey(fx.envelope, fx.factor)).toBe(fx.partition_key);
  });

  it("reads a partition file Python wrote", async () => {
    const entries = await decryptPartition(base64.decode(fx.partition_file_b64), fx.tag);
    expect(entries).toEqual(fx.entries);
  });

  it("writes a partition file that round-trips", async () => {
    // Byte-identical output is impossible — the Fernet IV is random — so the
    // check is that the payload survives, with the canonical JSON shape both
    // implementations serialize.
    const blob = await encryptPartition(fx.entries, fx.tag, { updatedAt: 1700000000 });
    expect(await decryptPartition(blob, fx.tag)).toEqual(fx.entries);
  });
});

describe("the factor is what protects the partition", () => {
  it("refuses the wrong factor with Python's reason string", async () => {
    await expect(unwrapPartitionKey(fx.envelope, "not-the-factor")).rejects.toMatchObject({
      reason: "high_risk_factor_invalid",
    });
  });

  it("refuses to decrypt a partition under the wrong tag", async () => {
    const blob = base64.decode(fx.partition_file_b64);
    const wrongTag = partitionKeyTag(generatePartitionKey());
    await expect(decryptPartition(blob, wrongTag)).rejects.toMatchObject({
      reason: "invalid_partition_key_tag",
    });
  });

  it("gives a different tag for every generated key", () => {
    const tags = new Set(Array.from({ length: 16 }, () => partitionKeyTag(generatePartitionKey())));
    expect(tags.size).toBe(16);
  });

  it("rejects an envelope of an unknown version rather than guessing", async () => {
    await expect(
      unwrapPartitionKey({ ...fx.envelope, version: 99 }, fx.factor),
    ).rejects.toMatchObject({ reason: "unsupported_partition_envelope_version" });
  });

  it("rejects a truncated envelope", async () => {
    for (const missing of ["salt_b64", "wrapped_partition_key"]) {
      const envelope = { ...fx.envelope, [missing]: "" };
      await expect(unwrapPartitionKey(envelope, fx.factor)).rejects.toBeInstanceOf(HighRiskError);
    }
  });

  it("round-trips a freshly built envelope", async () => {
    const key = generatePartitionKey();
    // Low iteration count purely to keep the test quick; production uses the
    // PARTITION_KDF_ITERATIONS default.
    const envelope = await buildPartitionEnvelope(key, "correct horse", { iterations: 1000 });
    expect(await unwrapPartitionKey(envelope, "correct horse")).toBe(key);
    await expect(unwrapPartitionKey(envelope, "wrong horse")).rejects.toBeInstanceOf(
      HighRiskError,
    );
  });
});

describe("index stubs", () => {
  const entry = {
    kind: "ssh",
    type: "ssh",
    label: "prod-server",
    index: 3,
    notes: "deployment key",
    archived: false,
    modified_ts: 1700000000,
    secret: "THE-ACTUAL-KEY-MATERIAL",
  };

  it("keeps nothing secret in the stub", () => {
    const stub = partitionStub("3", entry, "ssh", 1700000000);
    // A stub is what stays in the vault index, which is readable with the
    // master password alone. It must disclose that a high-risk entry exists
    // and nothing more — otherwise moving the entry bought nothing.
    const serialized = JSON.stringify(stub);
    expect(serialized).not.toContain("THE-ACTUAL-KEY-MATERIAL");
    expect(serialized).not.toContain("deployment key");
    expect(stub["label"]).toBe("prod-server");
    expect(stub["kind"]).toBe("ssh");
    expect(stub["partition"]).toBe("high_risk");
    expect(stub["partition_ref"]).toBe("3");
  });

  it("is recognizable as a stub", () => {
    expect(isPartitionStub(partitionStub("3", entry, "ssh", 1700000000))).toBe(true);
    expect(isPartitionStub(entry)).toBe(false);
    expect(isPartitionStub({})).toBe(false);
  });

  it("matches the shape Python leaves behind", () => {
    // Python's migrate writes exactly these keys; a listing that reads one
    // implementation's stub must not find the other's malformed.
    const stub = partitionStub("3", entry, "ssh", 1700000000);
    expect(Object.keys(stub).sort()).toEqual(
      ["archived", "index", "kind", "label", "modified_ts", "partition", "partition_ref", "type"],
    );
  });
});
