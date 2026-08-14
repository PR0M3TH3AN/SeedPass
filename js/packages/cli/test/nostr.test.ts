/**
 * End-to-end CLI relay sync: create a profile, add entries, sync to an
 * in-process relay, destroy the local vault, restore it from the relay.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { mnemonics, nostrKeyCases } from "@seedpass/test-vectors";
import { generateFingerprint } from "@seedpass/core";
import { buildProgram, type ProgramIo } from "../src/index.js";
import { MockRelay } from "../../core/test/mockRelay.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);

let appDir: string;
let relay: MockRelay;

async function run(...argv: string[]): Promise<{ stdout: string; error?: unknown }> {
  const out: string[] = [];
  const io: ProgramIo = { out: (l: string) => out.push(l), err: () => {} };
  let error: unknown;
  try {
    await buildProgram(io).parseAsync(["node", "seedpass-js", "--app-dir", appDir, ...argv]);
  } catch (e) {
    error = e;
  }
  return { stdout: out.join("\n"), error };
}

beforeAll(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-nostr-"));
  process.env["SEEDPASS_MNEMONIC"] = MNEMONIC;
  process.env["SEEDPASS_PASSWORD"] = "nostr-test-pw";
  relay = new MockRelay();
  await relay.start();
  await run("fingerprint", "add", "--name", "sync-test");
});

afterAll(async () => {
  await relay.stop();
  delete process.env["SEEDPASS_PASSWORD"];
});

describe("nostr CLI", () => {
  it("get-pubkey matches the app-1237 fixture npub", async () => {
    const fixture = nostrKeyCases.find(
      (c) => c.mnemonic_id === "abandon12" && c.account_index === 0,
    )!;
    const r = await run("nostr", "get-pubkey");
    expect(r.stdout).toBe(fixture.npub);
  });

  it("manages the relay list in config", async () => {
    await run("nostr", "add-relay", relay.url);
    const list = JSON.parse((await run("nostr", "list-relays")).stdout) as string[];
    expect(list).toContain(relay.url);

    // Keep only the mock relay so sync never touches the network
    while (true) {
      const current = JSON.parse((await run("nostr", "list-relays")).stdout) as string[];
      const removable = current.findIndex((u) => u !== relay.url);
      if (removable === -1) break;
      await run("nostr", "remove-relay", String(removable + 1));
    }
    const final = JSON.parse((await run("nostr", "list-relays")).stdout) as string[];
    expect(final).toEqual([relay.url]);

    const bad = await run("nostr", "add-relay", "https://not-a-relay");
    expect(String((bad.error as Error).message)).toContain("ws://");
  });

  it("syncs the vault to the relay and restores after local destruction", async () => {
    await run("entry", "add", "key-value", "synced-secret", "k", "value-roundtrip");
    await run("entry", "add", "password", "synced-site", "--length", "20");

    const sync = await run("nostr", "sync", "--chunk-limit", "300");
    const syncRow = JSON.parse(sync.stdout);
    expect(syncRow.manifest_id).toMatch(/^[0-9a-f]{64}$/);
    expect(syncRow.chunk_event_ids.length).toBeGreaterThan(0);
    expect(relay.events.some((e) => e.kind === 30070)).toBe(true);

    // Destroy the local vault
    const vaultPath = join(appDir, FINGERPRINT, "seedpass_entries_db.json.enc");
    await writeFile(vaultPath, "garbage");
    const broken = await run("entry", "list");
    expect(broken.error).toBeTruthy();

    // Restore from the relay alone
    const restore = await run("nostr", "restore");
    const restored = JSON.parse(restore.stdout);
    expect(restored.entry_count).toBe(2);
    expect(restored.deltas_applied).toBe(0);

    const list = JSON.parse((await run("entry", "list")).stdout) as { label: string }[];
    expect(list.map((e) => e.label).sort()).toEqual(["synced-secret", "synced-site"]);
    const reveal = await run("entry", "reveal", "synced-secret");
    expect(reveal.stdout).toBe("value-roundtrip");
  });
});
