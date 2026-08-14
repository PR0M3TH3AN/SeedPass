/**
 * Nostr event layer parity: NIP-01 id computation must match rust-nostr
 * (via the Python-side nostr_sdk fixtures), signatures must verify, and
 * TS-built/signed events must be accepted by TS verification.
 */

import { describe, expect, it } from "vitest";
import { nostrEvents, nostrSnapshot, deltaReplay, nostrKeyCases } from "@seedpass/test-vectors";
import {
  computeEventId,
  signEvent,
  verifyEvent,
  signerPublicKeyHex,
  buildChunkEvent,
  buildManifestEvent,
  buildDeltaEvent,
  reqMessage,
  parseRelayMessage,
  eventMessage,
  type NostrEvent,
} from "@seedpass/core";

describe("NIP-01 event ids (cross-implementation)", () => {
  it.each(nostrEvents.events)("$name id matches rust-nostr", ({ event }) => {
    expect(
      computeEventId(event.pubkey, event.created_at, event.kind, event.tags, event.content),
    ).toBe(event.id);
  });

  it("signer identity matches the app-1237 fixture key", () => {
    const fixtureKey = nostrKeyCases.find(
      (c) => c.mnemonic_id === "abandon12" && c.account_index === 0,
    )!;
    expect(nostrEvents.signer_private_key_hex).toBe(fixtureKey.private_key_hex);
    expect(signerPublicKeyHex(fixtureKey.private_key_hex)).toBe(
      nostrEvents.signer_public_key_hex,
    );
  });
});

describe("BIP-340 signature verification", () => {
  it.each(nostrEvents.events)("$name verifies", ({ event }) => {
    expect(verifyEvent(event as NostrEvent)).toBe(true);
  });

  it("rejects a tampered event", () => {
    const event = { ...(nostrEvents.events[0]!.event as NostrEvent) };
    event.content = event.content + "x";
    expect(verifyEvent(event)).toBe(false);
  });
});

describe("event builders match the Python event shapes", () => {
  const byName = (name: string) =>
    nostrEvents.events.find((e) => e.name === name)!.event as NostrEvent;

  it("chunk event", () => {
    const py = byName("chunk-0");
    const unsigned = buildChunkEvent(
      nostrSnapshot.chunk_metas[0]!.id,
      nostrSnapshot.chunks_b64[0]!,
      py.created_at,
    );
    expect(computeEventId(py.pubkey, unsigned.created_at, unsigned.kind, unsigned.tags, unsigned.content)).toBe(py.id);
  });

  it("manifest event", () => {
    const py = byName("manifest");
    const unsigned = buildManifestEvent(
      nostrSnapshot.manifest_id,
      nostrSnapshot.manifest_json,
      py.created_at,
    );
    expect(computeEventId(py.pubkey, unsigned.created_at, unsigned.kind, unsigned.tags, unsigned.content)).toBe(py.id);
  });

  it("delta event", () => {
    const py = byName("delta-1");
    const unsigned = buildDeltaEvent(
      nostrSnapshot.manifest_id,
      deltaReplay.delta_payloads_b64[0]!,
      py.created_at,
    );
    expect(computeEventId(py.pubkey, unsigned.created_at, unsigned.kind, unsigned.tags, unsigned.content)).toBe(py.id);
  });

  it("TS signing produces the same ids and a valid signature", () => {
    const py = byName("manifest");
    const signed = signEvent(
      nostrEvents.signer_private_key_hex,
      buildManifestEvent(nostrSnapshot.manifest_id, nostrSnapshot.manifest_json, py.created_at),
    );
    expect(signed.id).toBe(py.id);
    expect(signed.pubkey).toBe(py.pubkey);
    expect(verifyEvent(signed)).toBe(true);
  });
});

describe("NIP-01 message framing", () => {
  it("REQ round-trips filters", () => {
    const raw = reqMessage("sub1", {
      authors: [nostrEvents.signer_public_key_hex],
      kinds: [30070],
      "#d": [nostrSnapshot.manifest_id],
      limit: 1,
    });
    const arr = JSON.parse(raw);
    expect(arr[0]).toBe("REQ");
    expect(arr[2].kinds).toEqual([30070]);
  });

  it("parses EVENT/EOSE/OK/NOTICE/CLOSED", () => {
    const ev = nostrEvents.events[0]!.event;
    expect(parseRelayMessage(JSON.stringify(["EVENT", "sub1", ev]))).toEqual({
      type: "EVENT",
      subscriptionId: "sub1",
      event: ev,
    });
    expect(parseRelayMessage('["EOSE","sub1"]')).toEqual({ type: "EOSE", subscriptionId: "sub1" });
    expect(parseRelayMessage(`["OK","${ev.id}",true,""]`)).toEqual({
      type: "OK",
      eventId: ev.id,
      accepted: true,
      message: "",
    });
    expect(parseRelayMessage('["NOTICE","hi"]')).toEqual({ type: "NOTICE", message: "hi" });
    expect(parseRelayMessage('["CLOSED","sub1","reason"]')).toEqual({
      type: "CLOSED",
      subscriptionId: "sub1",
      message: "reason",
    });
    const msg = eventMessage(ev as NostrEvent);
    expect(JSON.parse(msg)[1].id).toBe(ev.id);
  });
});
