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
import { fileURLToPath } from "node:url";
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
import { setFactor, tagForFactor } from "../src/highRisk.js";
import {
  UNPORTED_PREFIXES,
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
// The fixture's entries, so tests can assert against what was actually seeded
// instead of a hand-counted literal that has to be chased every time the
// fixture grows.
const FIXTURE_TOTP_LABELS = ["blank-secret-2fa", "email-2fa"];
const FIXTURE_LABELS = ["api-token", "bank.example", ...FIXTURE_TOTP_LABELS].sort();

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
  // A deterministic entry that also carries a BLANK `secret` field. Python
  // and older indexes can produce this shape, and the export has to read it
  // as "no stored secret, derive one" rather than exporting the empty string
  // as if it were the key. Built here because the API refuses to create it.
  addTotpDeterministic(index, "blank-secret-2fa", MNEMONIC);
  for (const entry of Object.values(index.entries) as Record<string, unknown>[]) {
    if (entry["label"] === "blank-secret-2fa") entry["secret"] = "";
  }
  await writeFile(
    join(dir, INDEX_FILENAME),
    await encryptV3(deriveIndexKeyBytes(MNEMONIC), utf8(JSON.stringify(index))),
  );

  // Generous on purpose. The default budget is 100 requests a minute, and
  // this file passed it as it grew — which made unrelated tests fail with
  // 429 depending on how many requests ran before them. Rate limiting has
  // its own tests below, each on a server with a budget it sets explicitly,
  // so the shared fixture should not be enforcing one at all.
  server = new ApiServer({ host: "127.0.0.1", port: 0, token: TOKEN, rateLimit: 100_000 });
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
    // Every fixture entry is listed — asserted against the fixture rather
    // than a literal, so adding one does not silently weaken the check below
    // into "no secrets in an empty list".
    expect(res.json.length).toBeGreaterThan(0);
    expect(res.json.map((r: { label: string }) => r.label).sort()).toEqual(
      FIXTURE_LABELS,
    );
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
      // And it cannot be set either — nothing legitimate needs to. 403, not
      // 400: the key is real and the refusal is about authority, which is
      // also the status Python answers.
      const set = await call("PUT", `/api/v1/config/${key}`, { body: { value: "x" } });
      expect(set.status).toBe(403);
    }
  });

  it("refuses a config key it does not know, instead of storing it forever", async () => {
    // This route used to take the key from the URL and the value from the
    // body with no validation at all, so `inactivity_timout` was accepted,
    // written into the encrypted config permanently, and reported as ok —
    // while the setting it was meant to change never moved. Nothing reads an
    // unknown key, so the failure could only ever be silent.
    const typo = await call("PUT", "/api/v1/config/inactivity_timout", {
      body: { value: 60 },
    });
    expect(typo.status).toBe(400);
    expect(typo.json.detail).toContain("Unknown key");
    expect((await call("GET", "/api/v1/config/inactivity_timout")).json.value).toBeNull();

    // Nor a key that only LOOKS like an object property.
    expect(
      (await call("PUT", "/api/v1/config/__proto__", { body: { value: {} } })).status,
    ).toBe(400);
    expect(
      (await call("PUT", "/api/v1/config/constructor", { body: { value: 1 } })).status,
    ).toBe(400);
  });

  it("refuses a value of the wrong type for a key it does know", async () => {
    // The allowlist alone is not enough: `inactivity_timeout: "soon"` used to
    // be stored verbatim and turn every later comparison into NaN, which
    // compares false — so the vault would simply never time out.
    for (const [key, value] of [
      ["inactivity_timeout", "soon"],
      ["inactivity_timeout", 0],
      ["clipboard_clear_delay", -1],
      ["relays", "wss://one.example"],
      ["relays", []],
      ["min_uppercase", "lots"],
      // Values that LOOK numeric to Number() and are not numbers. Number(true)
      // is 1, Number(null) and Number("") are both 0, so without an explicit
      // check `inactivity_timeout: true` becomes a one-second timeout and
      // `clipboard_clear_delay: null` becomes zero — a setting silently
      // changed to something the caller never asked for.
      ["inactivity_timeout", true],
      ["clipboard_clear_delay", null],
      ["min_uppercase", ""],
      ["nostr_retry_delay", false],
      // Zero KDF iterations is not a slow KDF, it is no KDF — and it would be
      // written into the config of a vault whose master password protects
      // everything else.
      ["kdf_iterations", 0],
      ["kdf_iterations", -1],
    ] as const) {
      const res = await call("PUT", `/api/v1/config/${key}`, { body: { value } });
      expect(res.status).toBe(400);
    }

    // Zero is not negative, and the two must not be conflated: a
    // clipboard delay of 0 is a real choice (clear on the next tick), while
    // a negative one is nonsense.
    expect(
      (await call("PUT", "/api/v1/config/clipboard_clear_delay", { body: { value: 0 } }))
        .status,
    ).toBe(200);
    expect((await call("GET", "/api/v1/config/clipboard_clear_delay")).json.value).toBe(0);
    // One iteration is pointless but it is a number the caller may legitimately
    // choose; the floor is where nonsense starts, not where good advice does.
    expect(
      (await call("PUT", "/api/v1/config/kdf_iterations", { body: { value: 1 } })).status,
    ).toBe(200);
    await call("PUT", "/api/v1/config/kdf_iterations", { body: { value: 200000 } });

    // And the well-typed versions still go through, so the check is
    // rejecting the value rather than the key.
    expect(
      (await call("PUT", "/api/v1/config/inactivity_timeout", { body: { value: 120 } }))
        .status,
    ).toBe(200);
    expect((await call("GET", "/api/v1/config/inactivity_timeout")).json.value).toBe(120);
    expect(
      (await call("PUT", "/api/v1/config/relays", {
        body: { value: ["wss://one.example"] },
      })).status,
    ).toBe(200);
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

  it("actually enforces the ordinary rate limit", async () => {
    // Mutation testing found this: disabling the rate-limit check entirely
    // left every test passing. A limiter nothing exercises is a limiter that
    // can be removed by accident.
    const limited = new ApiServer({
      host: "127.0.0.1",
      port: 0,
      token: TOKEN,
      rateLimit: 3,
      rateWindowSeconds: 60,
    });
    registerRoutes(limited, buildContext({ app, fingerprint: FINGERPRINT, mnemonic: MNEMONIC }));
    const bound = await limited.listen();
    const url = `http://${bound.host}:${bound.port}/api/v1/entry`;
    try {
      const hit = () => fetch(url, { headers: { authorization: `Bearer ${TOKEN}` } });
      expect((await hit()).status).toBe(200);
      expect((await hit()).status).toBe(200);
      expect((await hit()).status).toBe(200);
      // Fourth request in the window is refused.
      const blocked = await hit();
      expect(blocked.status).toBe(429);
      expect((await blocked.json()).detail).toContain("Rate limit");
    } finally {
      await limited.close();
    }
  });

  it("rate-limits before authenticating, so a flood cannot hammer the token check", async () => {
    const limited = new ApiServer({
      host: "127.0.0.1",
      port: 0,
      token: TOKEN,
      rateLimit: 2,
      rateWindowSeconds: 60,
    });
    registerRoutes(limited, buildContext({ app, fingerprint: FINGERPRINT, mnemonic: MNEMONIC }));
    const bound = await limited.listen();
    const url = `http://${bound.host}:${bound.port}/api/v1/entry`;
    try {
      // Unauthenticated requests consume the budget too — otherwise the limit
      // is trivially bypassed by simply not sending a token.
      await fetch(url);
      await fetch(url);
      expect((await fetch(url)).status).toBe(429);
    } finally {
      await limited.close();
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

describe("profiles and vault state", () => {
  // Everything here was reachable and unasserted: mutation testing disabled
  // the delete guard, inverted the "current" flag and inverted the locked
  // flag, and the suite stayed green through all three.
  const OTHER = generateFingerprint(mnemonics["legal12"]!);

  it("marks exactly the served profile as current", async () => {
    await app.mutateFingerprints((data) => {
      if (!data.fingerprints.includes(OTHER)) data.fingerprints.push(OTHER);
      data.names[OTHER] = "other";
    });
    const res = await call("GET", "/api/v1/fingerprint");
    expect(res.status).toBe(200);
    const current = res.json.filter((f: { current: boolean }) => f.current);
    // Assert the PAIRING, not that some entry is current: inverted, every
    // profile except the served one is flagged, and "at least one is current"
    // still holds. This is what a profile switcher shows the user.
    expect(current).toHaveLength(1);
    expect(current[0].fingerprint).toBe(FINGERPRINT);
    expect(
      res.json.find((f: { fingerprint: string }) => f.fingerprint === OTHER).current,
    ).toBe(false);
  });

  it("refuses to delete the profile it is serving, but deletes another", async () => {
    // Destructive and unrecoverable: without the guard the server removes the
    // vault it is holding open, and keeps answering requests about it. Paired
    // with a successful delete so the test cannot pass by refusing everything.
    const refused = await call("DELETE", `/api/v1/fingerprint/${FINGERPRINT}`, {
      password: PASSWORD,
    });
    expect(refused.status).toBe(400);
    expect(existsSync(app.profileDir(FINGERPRINT))).toBe(true);

    await mkdir(app.profileDir(OTHER), { recursive: true });
    const deleted = await call("DELETE", `/api/v1/fingerprint/${OTHER}`, {
      password: PASSWORD,
    });
    expect(deleted.status).toBe(200);
    expect(existsSync(app.profileDir(OTHER))).toBe(false);
  });

  it("refuses to select a profile that does not exist", async () => {
    // Without this the caller's string becomes ctx.fingerprint, which every
    // later request joins onto a path — so the refusal is what keeps
    // "../../etc" out of the profile directory. Asserted on the shared
    // server precisely because a refusal must leave its state untouched.
    const before = ctx.fingerprint;
    for (const bogus of [generateFingerprint(mnemonics["zoo24"]!), "../../etc"]) {
      const res = await call("POST", "/api/v1/fingerprint/select", {
        body: { fingerprint: bogus },
      });
      // 404 specifically. AppDir.switchProfile repeats both checks, so
      // dropping this one still refuses — as a raw 500 from an unhandled
      // error, telling a caller the server broke when it simply named a
      // profile that is not there.
      expect(res.status).toBe(404);
      expect(ctx.fingerprint).toBe(before);
    }
  });

  it("selects a real profile, dropping the seed on the way", async () => {
    // The positive half, on its own context so the shared server keeps
    // serving the profile the rest of this file expects.
    const second = generateFingerprint(mnemonics["zoo24"]!);
    await app.mutateFingerprints((data) => {
      if (!data.fingerprints.includes(second)) data.fingerprints.push(second);
    });
    await mkdir(app.profileDir(second), { recursive: true });

    const srv = new ApiServer({ host: "127.0.0.1", port: 0, token: TOKEN });
    const ctx2 = buildContext({ app, fingerprint: FINGERPRINT, mnemonic: MNEMONIC });
    registerRoutes(srv, ctx2);
    const bound = await srv.listen();
    try {
      const res = await fetch(
        `http://${bound.host}:${bound.port}/api/v1/fingerprint/select`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${TOKEN}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ fingerprint: second }),
        },
      );
      expect(res.status).toBe(200);
      expect(ctx2.fingerprint).toBe(second);
      // The held seed belongs to the profile being left; carrying it across
      // would read one vault while the caller believed they selected another.
      expect(ctx2.mnemonic).toBeNull();
    } finally {
      await srv.close();
    }
  });

  it("reports lock state that follows the actual seed", async () => {
    expect((await call("GET", "/api/v1/vault/status")).json.locked).toBe(false);

    expect((await call("POST", "/api/v1/vault/lock")).status).toBe(200);
    expect((await call("GET", "/api/v1/vault/status")).json.locked).toBe(true);
    // And the flag is not decorative — a locked vault refuses secrets.
    expect((await call("GET", "/api/v1/entry/1/secret", { password: PASSWORD })).status)
      .not.toBe(200);

    const unlocked = await call("POST", "/api/v1/vault/unlock", { password: PASSWORD });
    expect(unlocked.status).toBe(200);
    expect((await call("GET", "/api/v1/vault/status")).json.locked).toBe(false);
  });
});

describe("the high-risk status the API reports", () => {
  // Nothing asserted this route, so mutation testing walked straight through
  // it: `>` to `>=`, `&&` to `||`, and the expires_at null check inverted all
  // survived. It is the only thing telling a caller whether the second factor
  // is currently open, so every one of those is a lie about the vault's
  // state. Built on its own context because it needs a clock it controls.
  const AT_SECONDS = 1_800_000_000;

  async function frozen(): Promise<{
    ctx2: ReturnType<typeof buildContext>;
    status: () => Promise<any>;
    close: () => Promise<void>;
    setClock: (seconds: number) => void;
  }> {
    let ms = AT_SECONDS * 1000;
    const srv = new ApiServer({ host: "127.0.0.1", port: 0, token: TOKEN });
    const ctx2 = buildContext({
      app,
      fingerprint: FINGERPRINT,
      mnemonic: MNEMONIC,
      now: () => ms,
    });
    registerRoutes(srv, ctx2);
    const bound = await srv.listen();
    const url = `http://${bound.host}:${bound.port}/api/v1/high-risk/status`;
    return {
      ctx2,
      setClock: (seconds: number) => {
        ms = seconds * 1000;
      },
      status: async () =>
        (await fetch(url, { headers: { authorization: `Bearer ${TOKEN}` } })).json(),
      close: () => srv.close(),
    };
  }

  it("reports unlocked only while a tag is held AND unexpired", async () => {
    const { ctx2, status, setClock, close } = await frozen();
    try {
      // No tag at all.
      expect((await status()).unlocked).toBe(false);
      expect((await status()).expires_at).toBeNull();

      ctx2.highRiskTag = "a".repeat(64);
      ctx2.highRiskExpiresAt = AT_SECONDS + 60;
      expect(await status()).toMatchObject({
        unlocked: true,
        expires_at: AT_SECONDS + 60,
      });

      // One second short of expiry: still open.
      setClock(AT_SECONDS + 59);
      expect((await status()).unlocked).toBe(true);

      // EXACTLY at expiry: closed. `>=` would report one more second of a
      // second factor that has lapsed.
      setClock(AT_SECONDS + 60);
      expect((await status()).unlocked).toBe(false);

      // A future expiry with no tag is not an unlock — that is the `&&`.
      // Without it, an expiry left behind by a previous session reads as open.
      setClock(AT_SECONDS);
      ctx2.highRiskTag = null;
      ctx2.highRiskExpiresAt = AT_SECONDS + 600;
      expect(await status()).toMatchObject({ unlocked: false, expires_at: null });
    } finally {
      await close();
    }
  });
});

describe("totp, config, relays, stats", () => {
  it("requires the master password for live TOTP codes", async () => {
    // A live code authenticates, so a leaked bearer token must not produce
    // one. Python gates this the same way; this port did not until the
    // route-table invariant test caught it.
    const noPassword = await call("GET", "/api/v1/totp");
    expect(noPassword.status).toBe(401);
    expect(noPassword.text).not.toMatch(/\d{6}/);
  });

  it("returns live TOTP codes with the time remaining", async () => {
    const res = await call("GET", "/api/v1/totp", { password: PASSWORD });
    expect(res.status).toBe(200);
    // One per TOTP entry in the fixture, and every one a real code.
    expect(res.json.codes).toHaveLength(FIXTURE_TOTP_LABELS.length);
    expect(res.json.codes.map((c: { label: string }) => c.label).sort()).toEqual(
      FIXTURE_TOTP_LABELS,
    );
    for (const c of res.json.codes) {
      expect(c.code).toMatch(/^\d{6}$/);
      expect(c.seconds_remaining).toBeGreaterThan(0);
    }
  });

  it("derives past a blank stored secret rather than exporting the blank", async () => {
    // `typeof secret === "string" && secret` — the second half is the part
    // that matters. Loosened to `||`, an entry whose `secret` is present but
    // empty exports as an empty secret: an authenticator entry that silently
    // produces nothing, from an export that looked like it worked.
    const exported = await call("GET", "/api/v1/totp/export", { password: PASSWORD });
    const entries = exported.json.entries as { label: string; secret: string }[];
    const blank = entries.find((e) => e.label === "blank-secret-2fa");
    expect(blank).toBeDefined();
    expect(blank!.secret).toMatch(/^[A-Z2-7]{16,}$/);
  });

  it("exports an imported secret as imported, not re-derived from the seed", async () => {
    // The export picks per entry: stored secret if it has one, derived
    // otherwise. Invert that choice and every exported secret is still
    // well-formed base32 — so shape assertions pass while the codes the user
    // loads into their authenticator are for a different account entirely.
    const IMPORTED = "JBSWY3DPEHPK3PXP";
    const created = await call("POST", "/api/v1/entry", {
      password: PASSWORD,
      body: { kind: "totp", label: "imported-2fa", secret: IMPORTED },
    });
    expect(created.status).toBe(201);

    const exported = await call("GET", "/api/v1/totp/export", { password: PASSWORD });
    const entries = exported.json.entries as { label: string; secret: string }[];
    const mine = entries.find((e) => e.label === "imported-2fa");
    expect(mine?.secret).toBe(IMPORTED);
    // And the derived entries in the same export are NOT the imported one:
    // the branch has to be taken per entry, not once for the whole export.
    for (const other of entries.filter((e) => e.label !== "imported-2fa")) {
      expect(other.secret).not.toBe(IMPORTED);
    }
  });

  it("derives a TOTP secret when none is supplied, rather than importing nothing", async () => {
    // `secret.length > 0` decides between importing the caller's secret and
    // deriving one from the seed. Relaxed to `>= 0`, an omitted-but-present
    // empty secret would be IMPORTED -- an entry that looks like a second
    // factor and is keyed on nothing. Nothing tested the empty case, so the
    // relaxation went unnoticed.
    const created = await call("POST", "/api/v1/entry", {
      password: PASSWORD,
      body: { kind: "totp", label: "derived-2fa", secret: "" },
    });
    expect(created.status).toBe(201);

    const exported = await call("GET", "/api/v1/totp/export", { password: PASSWORD });
    const entry = exported.json.entries.find(
      (e: { label: string }) => e.label === "derived-2fa",
    );
    expect(entry).toBeDefined();
    // A derived secret is real base32 of the usual length; an imported empty
    // one could only be empty.
    expect(entry.secret).toMatch(/^[A-Z2-7]{16,}$/);
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

describe("high-risk partition over the API", () => {
  it("reports the factor as unconfigured before it is set", async () => {
    const res = await call("GET", "/api/v1/high-risk/status");
    expect(res.status).toBe(200);
    expect(res.json.configured).toBe(false);
    expect(res.json.unlocked).toBe(false);

    // And unlocking says so, rather than blaming the factor. Without this
    // check the request falls through to tagForFactor, which fails and
    // reports "high_risk_factor_invalid" — telling someone who has never set
    // a factor that the factor they just chose is wrong, permanently. Both
    // refuse, so only the distinction is testable, and the distinction is
    // the whole value.
    const unconfigured = await call("POST", "/api/v1/high-risk/unlock", {
      password: PASSWORD,
      headers: { "x-seedpass-high-risk-factor": "anything-at-all" },
    });
    expect(unconfigured.status).toBe(409);
    expect(unconfigured.json.detail).toContain("not_configured");
  });

  it("needs the master password AND the factor to unlock", async () => {
    await setFactor(appDir, "api-second-factor");

    // Bearer token alone: no.
    expect((await call("POST", "/api/v1/high-risk/unlock")).status).toBe(401);
    // Password but no factor: still no. The whole point of the partition is
    // that the master password is not enough for these kinds.
    const noFactor = await call("POST", "/api/v1/high-risk/unlock", { password: PASSWORD });
    expect(noFactor.status).toBe(401);
    expect(noFactor.json.detail).toContain("High-Risk-Factor");
    // Wrong factor: one reason, so probing cannot distinguish failures.
    const wrong = await call("POST", "/api/v1/high-risk/unlock", {
      password: PASSWORD,
      headers: { "x-seedpass-high-risk-factor": "not-it" },
    });
    expect(wrong.status).toBe(401);
    expect(wrong.json.detail).toBe("high_risk_factor_invalid");

    const ok = await call("POST", "/api/v1/high-risk/unlock", {
      password: PASSWORD,
      headers: { "x-seedpass-high-risk-factor": "api-second-factor" },
      body: { ttl: 60 },
    });
    expect(ok.status).toBe(200);
    expect(ok.json.status).toBe("unlocked");
  });

  it("never returns the partition key tag over the wire", async () => {
    const tag = await tagForFactor(appDir, "api-second-factor");
    // The tag IS the partition's encryption key. No response may carry it.
    for (const [method, path] of [
      ["GET", "/api/v1/high-risk/status"],
      ["POST", "/api/v1/high-risk/lock"],
    ] as const) {
      const res = await call(method, path);
      expect(res.text).not.toContain(tag);
    }
  });

  it("locks on request", async () => {
    await call("POST", "/api/v1/high-risk/unlock", {
      password: PASSWORD,
      headers: { "x-seedpass-high-risk-factor": "api-second-factor" },
    });
    expect((await call("GET", "/api/v1/high-risk/status")).json.unlocked).toBe(true);
    expect((await call("POST", "/api/v1/high-risk/lock")).json.locked).toBe(true);
    expect((await call("GET", "/api/v1/high-risk/status")).json.unlocked).toBe(false);
  });
});

describe("path handling", () => {
  it("returns 404 for a genuinely unknown path", async () => {
    expect((await call("GET", "/api/v1/no-such-thing")).status).toBe(404);
  });

  it("distinguishes a wrong method from a wrong path", async () => {
    expect((await call("DELETE", "/api/v1/stats")).status).toBe(405);
  });

  it("has no remaining 501 surface", async () => {
    // Every Python endpoint now has an equivalent here. If a subsystem is
    // ever dropped again it should answer 501 naming the feature rather than
    // 404, which is why the mechanism stays.
    expect(UNPORTED_PREFIXES).toEqual([]);
  });
});

describe("structural invariants of the route table", () => {
  /**
   * Mutation testing showed the route-level `requiresPassword` flag is
   * redundant: every route that sets it also calls `requirePassword` in its
   * handler, so disabling the flag changes nothing. That redundancy is
   * defense in depth and worth keeping — but nothing ENFORCED the pairing,
   * which meant a future route could set one and forget the other, and the
   * suite would be silent either way.
   *
   * This reads the source rather than exercising behaviour, which is unusual
   * for a test and justified here: the property is about how routes are
   * DECLARED, and it is exactly the property a new route would break.
   */
  it("pairs the requiresPassword flag with an actual requirePassword call", async () => {
    const source = await readFile(
      fileURLToPath(new URL("../src/api/routes.ts", import.meta.url)),
      "utf8",
    );
    const blocks = source
      .split(/(?=\n  server\.route\()/)
      // Drop the file preamble: it holds the requirePassword DEFINITION, not
      // a route, and would otherwise read as a route that calls it.
      .filter((block) => /\n?\s*server\.route\(/.test(block));
    const mismatched: string[] = [];
    for (const block of blocks) {
      const flagged = block.includes("requiresPassword: true");
      const called = block.includes("requirePassword(ctx");
      if (flagged === called) continue;
      const name = /server\.route\(\s*"(\w+)",\s*"([^"]+)"/.exec(block);
      mismatched.push(
        `${name ? `${name[1]} ${name[2]}` : "(unparsed)"}: ` +
          `flag=${flagged} call=${called}`,
      );
    }
    expect(mismatched).toEqual([]);
  });

  it("refuses a flagged route whose handler forgot to check", async () => {
    // The behavioural half of the pairing test above. The flag is redundant
    // for every route that exists today, which is why disabling the server's
    // check changed nothing — but its entire purpose is the route that does
    // NOT exist yet, written by someone who set the flag and skipped the
    // call. So register exactly that route and confirm the server layer
    // stops it before the handler ever runs.
    const srv = new ApiServer({ host: "127.0.0.1", port: 0, token: TOKEN });
    let handlerRan = false;
    srv.route(
      "GET",
      "/api/v1/test-forgot-to-check",
      async () => {
        handlerRan = true;
        return { json: { secret: "leaked-plaintext" } };
      },
      { requiresPassword: true },
    );
    const bound = await srv.listen();
    try {
      const url = `http://${bound.host}:${bound.port}/api/v1/test-forgot-to-check`;
      const res = await fetch(url, { headers: { authorization: `Bearer ${TOKEN}` } });
      expect(res.status).toBe(401);
      expect(await res.text()).not.toContain("leaked-plaintext");
      // Not merely refused after the fact — never invoked.
      expect(handlerRan).toBe(false);

      // With the password it goes through, so the test cannot pass by the
      // route being broken.
      const ok = await fetch(url, {
        headers: {
          authorization: `Bearer ${TOKEN}`,
          "x-seedpass-password": PASSWORD,
        },
      });
      expect(ok.status).toBe(200);
      expect(handlerRan).toBe(true);
    } finally {
      await srv.close();
    }
  });

  it("password-gates every route that can return plaintext", async () => {
    // The failure this guards against is a NEW secret-returning route with
    // neither the flag nor the call — which the pairing test above cannot
    // see, because it only checks consistency, not coverage.
    const source = await readFile(
      fileURLToPath(new URL("../src/api/routes.ts", import.meta.url)),
      "utf8",
    );
    const blocks = source
      .split(/(?=\n  server\.route\()/)
      .filter((block) => /\n?\s*server\.route\(/.test(block));
    const ungated: string[] = [];
    for (const block of blocks) {
      // A handler that materializes a secret, reads the partition, or hands
      // back the parent seed must be password-gated.
      const producesPlaintext =
        block.includes("materializeSecret(") ||
        block.includes("deriveTotpSecret(") ||
        block.includes("readPartition(") ||
        block.includes("requireUnlocked(ctx)") && block.includes("mnemonic + ");
      if (!producesPlaintext) continue;
      if (block.includes("requirePassword(ctx")) continue;
      const name = /server\.route\(\s*"(\w+)",\s*"([^"]+)"/.exec(block);
      ungated.push(name ? `${name[1]} ${name[2]}` : "(unparsed)");
    }
    expect(ungated).toEqual([]);
  });
});
