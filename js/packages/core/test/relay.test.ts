/**
 * End-to-end relay sync over a live (in-process) NIP-01 relay: publish a
 * chunked snapshot, restore it from the relay alone, publish/replay deltas,
 * and survive a corrupted-chunk relay response.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { base64 } from "@scure/base";
import { mnemonics, nostrKeyCases, vaultV3Payload } from "@seedpass/test-vectors";
import {
  RelayPool,
  publishSnapshot,
  fetchLatestSnapshot,
  publishDelta,
  fetchDeltasSince,
  deriveKeyIndex,
  deriveIndexKeyBytes,
  decryptV3,
  encryptV3,
  mergeIndexPayloads,
  parseEncryptedFile,
  utf8,
  bytesToHex,
} from "@seedpass/core";
import { sha256 } from "@noble/hashes/sha2.js";
import { MockRelay } from "./mockRelay.js";

// jsdom's WebSocket shim cannot make real connections; transport tests run
// in Node here and in real browsers with the Milestone 6 web-app CI.
const IS_JSDOM = typeof navigator !== "undefined" && navigator.userAgent.includes("jsdom");

const MNEMONIC = mnemonics["abandon12"]!;
const PRIVKEY = nostrKeyCases.find(
  (c) => c.mnemonic_id === "abandon12" && c.account_index === 0,
)!.private_key_hex;

let relay: MockRelay;
let pool: RelayPool;

beforeAll(async () => {
  if (IS_JSDOM) return;
  relay = new MockRelay();
  await relay.start();
  pool = new RelayPool([relay.url], { timeoutMs: 3000 });
});

afterAll(async () => {
  if (IS_JSDOM) return;
  await pool.close();
  await relay.stop();
});

describe.skipIf(IS_JSDOM)("relay snapshot round trip", () => {
  const encrypted = () => base64.decode(vaultV3Payload.payload_b64);

  it("publishes a chunked snapshot and restores it from the relay", async () => {
    const keyIndex = deriveKeyIndex(MNEMONIC);
    const published = await publishSnapshot(pool, PRIVKEY, keyIndex, encrypted(), {
      limit: 400,
    });
    expect(published.chunkEventIds.length).toBeGreaterThan(1);
    expect(relay.events.filter((e) => e.kind === 30071).length).toBe(
      published.chunkEventIds.length,
    );

    const fetched = await fetchLatestSnapshot(pool, PRIVKEY);
    expect(fetched).not.toBeNull();
    expect(base64.encode(fetched!.encrypted)).toBe(vaultV3Payload.payload_b64);
    expect(fetched!.manifest.delta_since).toBe(published.manifest.delta_since);

    // The restored payload decrypts with the index key like any local vault
    const key = deriveIndexKeyBytes(MNEMONIC);
    const plain = await decryptV3(key, fetched!.encrypted);
    expect(bytesToHex(sha256(plain))).toBe(vaultV3Payload.plaintext_sha256);
  });

  it("publishes deltas and replays them onto the snapshot state", async () => {
    const key = deriveIndexKeyBytes(MNEMONIC);
    const t = 1700000000;
    const deltaIndex = {
      schema_version: 4,
      entries: {
        "99": {
          type: "password", kind: "password", label: "from-delta",
          length: 16, archived: false, notes: "", tags: [], modified_ts: t + 50,
        },
      },
    };
    const deltaBytes = await encryptV3(key, utf8(JSON.stringify(deltaIndex)));
    const fetched = await fetchLatestSnapshot(pool, PRIVKEY);
    await publishDelta(pool, PRIVKEY, fetched!.manifestEvent.id, deltaBytes, {
      createdAt: (fetched!.manifest.delta_since ?? 0) + 10,
    });

    const deltas = await fetchDeltasSince(pool, PRIVKEY, fetched!.manifest.delta_since ?? 0);
    expect(deltas).toHaveLength(1);

    // Replay: decrypt snapshot state, merge each delta deterministically
    let state = JSON.parse(
      new TextDecoder().decode(await decryptV3(key, fetched!.encrypted)),
    ) as Record<string, unknown>;
    for (const delta of deltas) {
      const incoming = JSON.parse(new TextDecoder().decode(await decryptV3(key, delta)));
      state = mergeIndexPayloads(state, incoming, bytesToHex(sha256(delta)).slice(0, 16));
    }
    const entries = state["entries"] as Record<string, { label: string }>;
    expect(entries["99"]!.label).toBe("from-delta");
  });

  it("restores a snapshot whose payload is a kdf/ct wrapper (Python's format)", async () => {
    // Python index files wrap the ciphertext in a JSON envelope, and a
    // published snapshot carries whatever the local file held. Restoring
    // must parse that wrapper rather than decrypting the envelope bytes.
    const key = deriveIndexKeyBytes(MNEMONIC);
    const inner = base64.decode(vaultV3Payload.payload_b64);
    const wrapped = utf8(
      JSON.stringify({
        kdf: { name: "pbkdf2", version: 1, params: { iterations: 200000 }, salt_b64: "" },
        ct: Buffer.from(inner).toString("base64"),
      }),
    );

    const wrapRelay = new MockRelay();
    await wrapRelay.start();
    const wrapPool = new RelayPool([wrapRelay.url], { timeoutMs: 3000 });
    try {
      await publishSnapshot(wrapPool, PRIVKEY, deriveKeyIndex(MNEMONIC), wrapped, {
        limit: 500,
      });
      const fetched = await fetchLatestSnapshot(wrapPool, PRIVKEY);
      expect(fetched).not.toBeNull();
      const { ciphertext } = parseEncryptedFile(fetched!.encrypted);
      const plain = await decryptV3(key, ciphertext);
      expect(bytesToHex(sha256(plain))).toBe(vaultV3Payload.plaintext_sha256);
    } finally {
      await wrapPool.close();
      await wrapRelay.stop();
    }
  });

  it("rejects snapshots whose chunks fail hash verification", async () => {
    // Corrupt every stored chunk's content in the relay
    for (const ev of relay.events) {
      if (ev.kind === 30071) ev.content = base64.encode(utf8("corrupted"));
    }
    const fetched = await fetchLatestSnapshot(pool, PRIVKEY);
    expect(fetched).toBeNull();
  });
});
