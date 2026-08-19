/**
 * The HTTP API.
 *
 * This process holds an unlocked parent seed and binds a TCP port, which is a
 * strictly larger attack surface than the agent's 0600 unix socket. Most of
 * this file is therefore about what the API REFUSES: unauthenticated calls,
 * secret reads on a bearer token alone, path traversal, non-loopback binds,
 * and unbounded unlock guessing. The happy paths matter too, but they are not
 * what makes opening a port defensible.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, readFile, writeFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { mnemonics } from "@seedpass/test-vectors";
import {
  generateFingerprint,
  deriveIndexKeyBytes,
  encryptV3,
  utf8,
  addPasswordEntry,
  addKeyValueEntry,
  addTotpDeterministic,
  type VaultIndex,
} from "@seedpass/core";
import {
  ApiServer,
  registerRoutes,
  buildContext,
  resolveBind,
  AppDir,
  INDEX_FILENAME,
} from "../src/index.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);
const PASSWORD = "api-test-password";
const TOKEN = "test-token-not-random-on-purpose";

let appDir: string;
let app: AppDir;
let server: ApiServer;
let base: string;
let ctx: ReturnType<typeof buildContext>;

interface Res {
  status: number;
  json: any;
  text: string;
  headers: Headers;
}

async function call(
  method: string,
  path: string,
  opts: {
    token?: string | null;
    password?: string;
    body?: unknown;
    raw?: string;
    headers?: Record<string, string>;
  } = {},
): Promise<Res> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  const token = opts.token === undefined ? TOKEN : opts.token;
  if (token !== null) headers["authorization"] = `Bearer ${token}`;
  if (opts.password !== undefined) headers["x-seedpass-password"] = opts.password;
  let body: string | undefined;
  if (opts.raw !== undefined) {
    body = opts.raw;
  } else if (opts.body !== undefined) {
    body = JSON.stringify(opts.body);
    headers["content-type"] = "application/json";
  }
  const res = await fetch(`${base}${path}`, { method, headers, ...(body !== undefined && { body }) });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: res.status, json, text, headers: res.headers };
}

beforeAll(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-api-"));
  app = new AppDir(appDir);
  await app.mutateFingerprints((data) => {
    data.fingerprints.push(FINGERPRINT);
    data.names[FINGERPRINT] = "api";
    data.last_used = FINGERPRINT;
  });
  const dir = app.profileDir(FINGERPRINT);
  await mkdir(dir, { recursive: true });
  await app.writeParentSeed(FINGERPRINT, MNEMONIC, PASSWORD);

  const index = { schema_version: 4, entries: {} } as VaultIndex;
  addPasswordEntry(index, "bank.example", 16, { username: "alice", tags: ["money"] });
  addKeyValueEntry(index, "api-token", "TOKEN", "kv-secret-value");
  addTotpDeterministic(index, "email-2fa", MNEMONIC);
  await writeFile(
    join(dir, INDEX_FILENAME),
    await encryptV3(deriveIndexKeyBytes(MNEMONIC), utf8(JSON.stringify(index))),
  );

  server = new ApiServer({ host: "127.0.0.1", port: 0, token: TOKEN });
  ctx = buildContext({ app, fingerprint: FINGERPRINT, mnemonic: MNEMONIC });
  registerRoutes(server, ctx);
  const bound = await server.listen();
  base = `http://${bound.host}:${bound.port}`;
});

afterAll(async () => {
  await server.close();
});

describe("what the API refuses", () => {
  it("rejects every request without a valid bearer token", async () => {
    for (const [method, path] of [
      ["GET", "/api/v1/entry"],
      ["GET", "/api/v1/stats"],
      ["POST", "/api/v1/entry"],
      ["GET", "/api/v1/nostr/pubkey"],
    ] as const) {
      expect((await call(method, path, { token: null })).status).toBe(401);
      expect((await call(method, path, { token: "wrong-token" })).status).toBe(401);
    }
  });

  it("does not hand over plaintext on a bearer token alone", async () => {
    // The whole point of the second factor: a token lifted from a script or a
    // process list must not be enough to read the vault.
    const noPassword = await call("GET", "/api/v1/entry/1/secret");
    expect(noPassword.status).toBe(401);
    expect(noPassword.text).not.toContain("kv-secret-value");

    const wrongPassword = await call("GET", "/api/v1/entry/1/secret", {
      password: "not-the-password",
    });
    expect(wrongPassword.status).toBe(401);
    expect(wrongPassword.text).not.toContain("kv-secret-value");

    const right = await call("GET", "/api/v1/entry/1/secret", { password: PASSWORD });
    expect(right.status).toBe(200);
    expect(right.json.value).toBe("kv-secret-value");
  });

  it("keeps secret values out of listings", async () => {
    const res = await call("GET", "/api/v1/entry");
    expect(res.status).toBe(200);
    expect(res.json).toHaveLength(3);
    // Reference-first, like every other surface.
    expect(res.text).not.toContain("kv-secret-value");
    for (const row of res.json) expect(row.ref).toMatch(/^sp:\/\/entry\//);
  });

  it("refuses to read or write outside the profile directory", async () => {
    for (const path of ["../../../etc/passwd", "/etc/passwd", "a/../../../outside"]) {
      const res = await call("POST", "/api/v1/entry/0/document/export", {
        password: PASSWORD,
        body: { path },
      });
      expect(res.status).toBe(400);
      expect(res.json.detail).toContain("inside the profile directory");
    }
  });

  it("refuses a non-loopback bind unless explicitly allowed", () => {
    expect(() => resolveBind({ host: "0.0.0.0" })).toThrow(/refusing to bind/);
    expect(() => resolveBind({ host: "192.168.1.10" })).toThrow(/refusing to bind/);
    // Explicit acknowledgement is the only way through.
    expect(resolveBind({ host: "0.0.0.0", allowRemote: true }).host).toBe("0.0.0.0");
    // Loopback in its various spellings needs no flag.
    for (const host of ["127.0.0.1", "localhost", "::1"]) {
      expect(resolveBind({ host }).host).toBe(host);
    }
  });

  it("never returns the password or pin verifier through config", async () => {
    for (const key of ["password_hash", "pin_hash"]) {
      const got = await call("GET", `/api/v1/config/${key}`);
      expect(got.json.value).toBe("<redacted>");
      // And it cannot be set either — nothing legitimate needs to.
      const set = await call("PUT", `/api/v1/config/${key}`, { body: { value: "x" } });
      expect(set.status).toBe(400);
    }
  });

  it("caps the request body rather than buffering whatever arrives", async () => {
    const small = new ApiServer({ host: "127.0.0.1", port: 0, token: TOKEN, maxBodyBytes: 64 });
    const smallCtx = buildContext({ app, fingerprint: FINGERPRINT, mnemonic: MNEMONIC });
    registerRoutes(small, smallCtx);
    const bound = await small.listen();
    try {
      const res = await fetch(`http://${bound.host}:${bound.port}/api/v1/entry`, {
        method: "POST",
        headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ kind: "password", label: "x".repeat(500) }),
      });
      expect(res.status).toBe(413);
    } finally {
      await small.close();
    }
  });

  it("limits failed unlock attempts far more tightly than ordinary requests", async () => {
    const locked = new ApiServer({
      host: "127.0.0.1",
      port: 0,
      token: TOKEN,
      unlockAttemptLimit: 3,
    });
    const lockedCtx = buildContext({ app, fingerprint: FINGERPRINT, mnemonic: null });
    registerRoutes(locked, lockedCtx);
    const bound = await locked.listen();
    const url = `http://${bound.host}:${bound.port}/api/v1/vault/unlock`;
    try {
      const attempt = (password: string) =>
        fetch(url, {
          method: "POST",
          headers: { authorization: `Bearer ${TOKEN}`, "x-seedpass-password": password },
        });
      // Wrong passwords are counted...
      expect((await attempt("wrong-1")).status).toBe(401);
      expect((await attempt("wrong-2")).status).toBe(401);
      expect((await attempt("wrong-3")).status).toBe(401);
      // ...and the budget is then spent, even for the RIGHT password. An
      // attacker must not be able to distinguish "locked out" from "wrong".
      expect((await attempt(PASSWORD)).status).toBe(429);
    } finally {
      await locked.close();
    }
  });

  it("reports a locked vault as 423 rather than failing obscurely", async () => {
    const locked = new ApiServer({ host: "127.0.0.1", port: 0, token: TOKEN });
    const lockedCtx = buildContext({ app, fingerprint: FINGERPRINT, mnemonic: null });
    registerRoutes(locked, lockedCtx);
    const bound = await locked.listen();
    try {
      const res = await fetch(`http://${bound.host}:${bound.port}/api/v1/entry`, {
        headers: { authorization: `Bearer ${TOKEN}` },
      });
      expect(res.status).toBe(423);

      // And unlocking with the right password opens it.
      const unlocked = await fetch(`http://${bound.host}:${bound.port}/api/v1/vault/unlock`, {
        method: "POST",
        headers: { authorization: `Bearer ${TOKEN}`, "x-seedpass-password": PASSWORD },
      });
      expect(unlocked.status).toBe(200);
      expect((await unlocked.json()).status).toBe("unlocked");
      expect(lockedCtx.mnemonic).toBe(MNEMONIC);
    } finally {
      await locked.close();
    }
  });

  it("sends no CORS headers unless the origin was allowlisted", async () => {
    const res = await call("GET", "/api/v1/entry", { headers: { origin: "https://evil.example" } });
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });
});

describe("entries", () => {
  it("creates an entry and returns a reference, never the secret", async () => {
    const res = await call("POST", "/api/v1/entry", {
      body: { kind: "password", label: "created.example", length: 20 },
    });
    expect(res.status).toBe(201);
    expect(res.json.ref).toMatch(/^sp:\/\/entry\//);
    // Provision-blind: creating an entry must not disclose what it derives.
    expect(res.text).not.toMatch(/"(password|value|secret)"\s*:/);

    const id = String(res.json.id);
    const fetched = await call("GET", `/api/v1/entry/${id}`, { password: PASSWORD });
    expect(fetched.json.label).toBe("created.example");
    expect(fetched.json.length).toBe(20);
  });

  it("derives the same password the CLI would, honouring the config policy", async () => {
    // The API must not become a second derivation implementation. This pins
    // it to the shared one: a non-default config policy has to reach it.
    await call("PUT", "/api/v1/config/min_uppercase", { body: { value: 5 } });
    await call("PUT", "/api/v1/config/exclude_ambiguous", { body: { value: true } });
    const res = await call("GET", "/api/v1/entry/0/secret", { password: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.json.value).not.toMatch(/[O0Il1]/);
    const uppers = (res.json.value.match(/[A-Z]/g) ?? []).length;
    expect(uppers).toBeGreaterThanOrEqual(5);
    // Put it back so later assertions are not reading a tuned vault.
    await call("PUT", "/api/v1/config/min_uppercase", { body: { value: 2 } });
    await call("PUT", "/api/v1/config/exclude_ambiguous", { body: { value: false } });
  });

  it("modifies, archives and unarchives", async () => {
    expect((await call("PUT", "/api/v1/entry/0", { body: { notes: "edited" } })).status).toBe(200);
    const after = await call("GET", "/api/v1/entry/0", { password: PASSWORD });
    expect(after.json.notes).toBe("edited");

    expect((await call("POST", "/api/v1/entry/0/archive")).json.status).toBe("archived");
    const hidden = await call("GET", "/api/v1/entry");
    expect(hidden.json.map((r: any) => r.id)).not.toContain("0");
    const shown = await call("GET", "/api/v1/entry?archived=true");
    expect(shown.json.map((r: any) => r.id)).toContain("0");

    expect((await call("POST", "/api/v1/entry/0/unarchive")).json.status).toBe("active");
  });

  it("searches by label, username, tag and kind", async () => {
    expect((await call("GET", "/api/v1/entry?query=bank")).json).toHaveLength(1);
    expect((await call("GET", "/api/v1/entry?query=alice")).json).toHaveLength(1);
    expect((await call("GET", "/api/v1/entry?query=money")).json).toHaveLength(1);
    const kv = await call("GET", "/api/v1/entry?kind=key_value");
    expect(kv.json.every((r: any) => r.kind === "key_value")).toBe(true);
  });

  it("manages typed links between entries", async () => {
    const added = await call("POST", "/api/v1/entry/0/links", {
      body: { target: 1, relation: "depends_on" },
    });
    expect(added.status).toBe(200);
    expect(added.json.links).toHaveLength(1);
    expect(added.json.links[0].relation).toBe("depends_on");

    expect((await call("GET", "/api/v1/entry/0/links")).json.links).toHaveLength(1);
    const removed = await call("DELETE", "/api/v1/entry/0/links?target=1");
    expect(removed.json.links).toHaveLength(0);
  });

  it("returns 404 for an entry that does not exist and 400 for a nonsense id", async () => {
    expect((await call("GET", "/api/v1/entry/9999", { password: PASSWORD })).status).toBe(404);
    expect((await call("GET", "/api/v1/entry/not-a-number", { password: PASSWORD })).status).toBe(400);
  });
});

describe("totp, config, relays, stats", () => {
  it("returns live TOTP codes with the time remaining", async () => {
    const res = await call("GET", "/api/v1/totp");
    expect(res.status).toBe(200);
    expect(res.json.codes).toHaveLength(1);
    expect(res.json.codes[0].code).toMatch(/^\d{6}$/);
    expect(res.json.codes[0].seconds_remaining).toBeGreaterThan(0);
  });

  it("gates the full 2FA export behind the master password", async () => {
    // This is every TOTP secret in the vault, in plaintext.
    expect((await call("GET", "/api/v1/totp/export")).status).toBe(401);
    const res = await call("GET", "/api/v1/totp/export", { password: PASSWORD });
    expect(res.status).toBe(200);
    // The base32 SECRET, not the current code — an authenticator cannot be
    // seeded from a 6-digit code, and an export that returned one would look
    // correct while being useless.
    expect(res.json.entries[0].secret).toMatch(/^[A-Z2-7]+$/);
    expect(res.json.entries[0].secret).not.toMatch(/^\d{6}$/);
    expect(res.json.entries[0].uri).toContain("otpauth://totp/");
  });

  it("reads and writes config", async () => {
    expect((await call("PUT", "/api/v1/config/inactivity_timeout", { body: { value: 42 } })).status).toBe(200);
    expect((await call("GET", "/api/v1/config/inactivity_timeout")).json.value).toBe(42);
  });

  it("manages the relay list", async () => {
    const added = await call("POST", "/api/v1/relays", { body: { url: "wss://relay.example" } });
    expect(added.json.relays).toContain("wss://relay.example");
    expect((await call("POST", "/api/v1/relays", { body: { url: "http://nope" } })).status).toBe(400);
    const reset = await call("POST", "/api/v1/relays/reset");
    expect(reset.json.relays).not.toContain("wss://relay.example");
  });

  it("reports profile statistics", async () => {
    const res = await call("GET", "/api/v1/stats");
    expect(res.json.fingerprint).toBe(FINGERPRINT);
    expect(res.json.total_entries).toBeGreaterThanOrEqual(3);
    expect(res.json.by_kind.password).toBeGreaterThanOrEqual(1);
  });

  it("exposes the sync identity's npub", async () => {
    const res = await call("GET", "/api/v1/nostr/pubkey");
    expect(res.json.npub).toMatch(/^npub1/);
  });

  it("drains notifications once", async () => {
    ctx.notifications.push({ level: "warning", message: "something happened" });
    expect((await call("GET", "/api/v1/notifications")).json).toHaveLength(1);
    expect((await call("GET", "/api/v1/notifications")).json).toHaveLength(0);
  });

  it("reports derivation collisions on the served vault", async () => {
    const res = await call("GET", "/api/v1/check-derivation");
    expect(res.status).toBe(200);
    expect(res.json.collisions).toEqual([]);
  });
});

describe("vault export and import", () => {
  it("exports a backup and refuses to import one from another seed", async () => {
    const exported = await call("POST", "/api/v1/vault/export", {
      password: PASSWORD,
      body: { plaintext: true },
    });
    expect(exported.status).toBe(200);
    expect(exported.headers.get("content-disposition")).toContain(".seedpass");

    const wrapper = JSON.parse(exported.text);
    expect(wrapper.fingerprint).toBe(FINGERPRINT);

    // Re-importing our own backup is fine.
    const ok = await call("POST", "/api/v1/vault/import", {
      password: PASSWORD,
      raw: exported.text,
      headers: { "content-type": "application/json" },
    });
    expect(ok.status).toBe(200);

    // One from a different seed is refused, because importing it would
    // re-derive every secret from THIS seed and silently change them.
    const foreign = { ...wrapper, fingerprint: "0123456789ABCDEF" };
    const refused = await call("POST", "/api/v1/vault/import", {
      password: PASSWORD,
      raw: JSON.stringify(foreign),
      headers: { "content-type": "application/json" },
    });
    expect(refused.status).toBe(409);
    expect(refused.json.detail).toContain("belongs to profile");
  });
});

describe("semantic index", () => {
  it("builds, reports status, and ranks by metadata", async () => {
    const built = await call("POST", "/api/v1/semantic/build");
    expect(built.status).toBe(200);
    expect(built.json.records).toBeGreaterThan(0);

    const status = await call("GET", "/api/v1/semantic/status");
    expect(status.json.built).toBe(true);
    expect(status.json.model_id).toBe("seedpass-token-overlap-v2");

    const hits = await call("POST", "/api/v1/semantic/search", { body: { query: "bank" } });
    expect(hits.json.results.length).toBeGreaterThan(0);
    expect(hits.json.results[0].ref).toMatch(/^sp:\/\/entry\//);
  });

  it("never writes a stored secret into the plaintext index", async () => {
    await call("POST", "/api/v1/semantic/build");
    // The vault holds a key_value entry whose value is this string. The
    // index file sits unencrypted next to the vault, so the value must not
    // reach it — nor a tokenized form of it.
    const raw = await readFile(
      join(app.profileDir(FINGERPRINT), "semantic_index", "records.json"),
      "utf8",
    );
    expect(raw).not.toContain("kv-secret-value");
    expect(raw.toLowerCase()).not.toContain("kv-secret-value".toLowerCase());
    // But the entry is still findable by its name.
    const hits = await call("POST", "/api/v1/semantic/search", { body: { query: "api-token" } });
    expect(hits.json.results.map((r: any) => r.label)).toContain("api-token");
  });

  it("writes the index at 0600, not the process umask", async () => {
    await call("POST", "/api/v1/semantic/build");
    const path = join(app.profileDir(FINGERPRINT), "semantic_index", "records.json");
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("deletes an index built before secrets stopped being indexed", async () => {
    // Such a file holds stored secrets in the clear, and fixing the writer
    // does not rewrite what is already on disk. Leaving it and reporting a
    // version string in a status field is not a remedy.
    await call("POST", "/api/v1/semantic/build");
    const dir = join(app.profileDir(FINGERPRINT), "semantic_index");
    const manifestPath = join(dir, "manifest.json");
    const recordsPath = join(dir, "records.json");

    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.model_id = "seedpass-token-overlap-v1";
    await writeFile(manifestPath, JSON.stringify(manifest));
    await writeFile(
      recordsPath,
      JSON.stringify([
        { entry_id: 1, kind: "key_value", label: "x", text: "LEAKED-SECRET", tokens: ["leaked"] },
      ]),
    );

    // Touching it at all removes it, and the leaked content never comes back
    // out through search.
    const status = await call("GET", "/api/v1/semantic/status");
    expect(status.json.built).toBe(false);
    expect(existsSync(recordsPath)).toBe(false);

    const hits = await call("POST", "/api/v1/semantic/search", { body: { query: "leaked" } });
    expect(hits.status).toBe(409);
  });

  it("keeps a current index rather than deleting anything it cannot identify", async () => {
    // "Cannot tell" must not mean "delete it": that would throw away a good
    // index on every corrupt-manifest read.
    await call("POST", "/api/v1/semantic/build");
    const dir = join(app.profileDir(FINGERPRINT), "semantic_index");
    await writeFile(join(dir, "manifest.json"), "{ not json");
    const status = await call("GET", "/api/v1/semantic/status");
    expect(status.status).toBe(200);
    expect(existsSync(join(dir, "records.json"))).toBe(true);
    // Put it back for any later test.
    await call("POST", "/api/v1/semantic/build");
  });

  it("says so rather than returning nothing when no index exists", async () => {
    const fresh = new ApiServer({ host: "127.0.0.1", port: 0, token: TOKEN });
    const other = await mkdtemp(join(tmpdir(), "seedpass-nosem-"));
    const otherApp = new AppDir(other);
    await otherApp.mutateFingerprints((d) => {
      d.fingerprints.push(FINGERPRINT);
      d.last_used = FINGERPRINT;
    });
    await mkdir(otherApp.profileDir(FINGERPRINT), { recursive: true });
    await writeFile(
      join(otherApp.profileDir(FINGERPRINT), INDEX_FILENAME),
      await encryptV3(deriveIndexKeyBytes(MNEMONIC), utf8(JSON.stringify({ schema_version: 4, entries: {} }))),
    );
    registerRoutes(fresh, buildContext({ app: otherApp, fingerprint: FINGERPRINT, mnemonic: MNEMONIC }));
    const bound = await fresh.listen();
    try {
      const res = await fetch(`http://${bound.host}:${bound.port}/api/v1/semantic/search`, {
        method: "POST",
        headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ query: "anything" }),
      });
      expect(res.status).toBe(409);
    } finally {
      await fresh.close();
    }
  });
});

describe("the unported surface answers honestly", () => {
  it("returns 501 with the reason, not 404", async () => {
    for (const [method, path, feature] of [
      ["GET", "/api/v1/high-risk/status", "high-risk partitions"],
      ["GET", "/api/v1/agent/job-profiles", "agent job profiles"],
      ["POST", "/api/v1/agent/recovery/split", "agent recovery split"],
    ] as const) {
      const res = await call(method, path);
      // 404 would read as "you typed the path wrong" and send an integrator
      // hunting for a spelling mistake that is not there.
      expect(res.status).toBe(501);
      expect(res.json.detail).toContain(feature);
    }
  });

  it("still returns 404 for a genuinely unknown path", async () => {
    expect((await call("GET", "/api/v1/no-such-thing")).status).toBe(404);
  });

  it("distinguishes a wrong method from a wrong path", async () => {
    expect((await call("DELETE", "/api/v1/stats")).status).toBe(405);
  });
});
