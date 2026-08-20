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
  prepareSnapshot,
  newManifestId,
  signEvent,
  buildChunkEvent,
  buildManifestEvent,
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

  /**
   * Two snapshots in the same second used to be ordered by event id, which is
   * stable but arbitrary with respect to time — so `nostr restore` returned
   * the OLDER vault roughly half the time, and entries created between the
   * two syncs disappeared with no warning. It surfaced only as an
   * intermittent test failure, because whether the newer snapshot won came
   * down to a hash comparison.
   *
   * The loop makes it deterministic: over this many distinct payloads, an
   * id-ordered restore is overwhelmingly likely to pick the older snapshot at
   * least once (p ≈ 1 - 2^-12 per run). A single pair would reproduce the bug
   * only half the time, which is how it stayed a "flake" for so long.
   */
  it("returns the newer of two snapshots published in the same second", async () => {
    const key = deriveIndexKeyBytes(MNEMONIC);
    const keyIndex = deriveKeyIndex(MNEMONIC);
    const SAME_SECOND = 1700001234;

    for (let round = 0; round < 12; round++) {
      const roundRelay = new MockRelay();
      await roundRelay.start();
      const roundPool = new RelayPool([roundRelay.url], { timeoutMs: 3000 });
      try {
        const payload = async (label: string) =>
          encryptV3(
            key,
            utf8(
              JSON.stringify({
                schema_version: 4,
                entries: {
                  "1": {
                    type: "password", kind: "password", label,
                    length: 16, archived: false, notes: "", tags: [],
                    modified_ts: SAME_SECOND,
                  },
                },
              }),
            ),
          );

        // Same created_at second, older published first — exactly what a
        // scripted or automated double-sync produces.
        await publishSnapshot(roundPool, PRIVKEY, keyIndex, await payload(`older-${round}`), {
          limit: 50_000, createdAt: SAME_SECOND, publishedMs: SAME_SECOND * 1000 + 100,
        });
        await publishSnapshot(roundPool, PRIVKEY, keyIndex, await payload(`newer-${round}`), {
          limit: 50_000, createdAt: SAME_SECOND, publishedMs: SAME_SECOND * 1000 + 900,
        });

        const fetched = await fetchLatestSnapshot(roundPool, PRIVKEY);
        const state = JSON.parse(
          new TextDecoder().decode(await decryptV3(key, fetched!.encrypted)),
        ) as { entries: Record<string, { label: string }> };
        expect(state.entries["1"]!.label).toBe(`newer-${round}`);
      } finally {
        await roundPool.close();
        await roundRelay.stop();
      }
    }
  });

  it("orders a manifest with no published_ms by its created_at second", async () => {
    // Manifests written before published_ms existed must still restore, and
    // must not outrank a newer one published in the same second. Ordering the
    // unknown one last instead would let a pre-upgrade snapshot beat every
    // post-upgrade one for that second — the bug, reintroduced from the other
    // direction.
    const legacyRelay = new MockRelay();
    await legacyRelay.start();
    const legacyPool = new RelayPool([legacyRelay.url], { timeoutMs: 3000 });
    try {
      const key = deriveIndexKeyBytes(MNEMONIC);
      const keyIndex = deriveKeyIndex(MNEMONIC);
      const AT = 1700002222;
      const payload = async (label: string) =>
        encryptV3(
          key,
          utf8(
            JSON.stringify({
              schema_version: 4,
              entries: {
                "1": {
                  type: "password", kind: "password", label, length: 16,
                  archived: false, notes: "", tags: [], modified_ts: AT,
                },
              },
            }),
          ),
        );

      // A genuinely old-format manifest: published the way a pre-upgrade
      // client did, with no published_ms key in the JSON at all. Built by
      // hand rather than by asking publishSnapshot to omit it, so the test
      // exercises the real legacy shape instead of a flag.
      {
        const legacyBytes = await payload("legacy");
        const { manifest, chunks } = await prepareSnapshot(legacyBytes, 50_000);
        for (let i = 0; i < chunks.length; i++) {
          const meta = manifest.chunks[i]!;
          const ev = signEvent(
            PRIVKEY,
            buildChunkEvent(meta.id, base64.encode(chunks[i]!), AT - 60),
          );
          await legacyPool.publish(ev);
          meta.event_id = ev.id;
        }
        const { id, nonce } = newManifestId(keyIndex);
        const legacyJson = JSON.stringify({
          ver: manifest.ver,
          algo: manifest.algo,
          chunks: manifest.chunks,
          delta_since: AT - 60,
          nonce: base64.encode(nonce),
          index0: null,
        });
        expect(legacyJson).not.toContain("published_ms");
        await legacyPool.publish(
          signEvent(PRIVKEY, buildManifestEvent(id, legacyJson, AT - 60)),
        );
      }
      await publishSnapshot(legacyPool, PRIVKEY, keyIndex, await payload("current"), {
        limit: 50_000, createdAt: AT, publishedMs: AT * 1000 + 5,
      });

      const fetched = await fetchLatestSnapshot(legacyPool, PRIVKEY);
      const state = JSON.parse(
        new TextDecoder().decode(await decryptV3(key, fetched!.encrypted)),
      ) as { entries: Record<string, { label: string }> };
      expect(state.entries["1"]!.label).toBe("current");
    } finally {
      await legacyPool.close();
      await legacyRelay.stop();
    }
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
