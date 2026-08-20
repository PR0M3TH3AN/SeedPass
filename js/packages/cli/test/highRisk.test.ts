/**
 * High-risk partition and approval gates, end to end.
 *
 * The partition exists so that a handful of entry kinds need a SECOND factor
 * beyond the master password. Most of this file is therefore about the ways
 * that guarantee could be lost: the tag reaching disk, a locked partition
 * still yielding secrets, a stub deriving a plausible-but-wrong value, or a
 * scoped token reaching the unlock op.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, readFile, writeFile, readdir, stat } from "node:fs/promises";
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
  addSshKeyEntry,
  addPasswordEntry,
  partitionKeyTag,
  type VaultIndex,
} from "@seedpass/core";
import {
  buildProgram,
  AgentDaemon,
  AgentClient,
  agentSocketPath,
  AppDir,
  INDEX_FILENAME,
  type ProgramIo,
} from "../src/index.js";
import {
  setFactor,
  tagForFactor,
  factorConfigured,
  partitionPath,
  envelopePath,
} from "../src/highRisk.js";
import {
  issueApproval,
  listApprovals,
  revokeApproval,
  consumeApproval,
  approvalRequired,
} from "../src/approvals.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);
const PASSWORD = "high-risk-test-pw";
const FACTOR = "the-second-factor";

let appDir: string;
let app: AppDir;
let daemon: AgentDaemon;

async function run(
  env: Record<string, string | undefined>,
  ...argv: string[]
): Promise<{ stdout: string; stderr: string; error?: unknown }> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  const out: string[] = [];
  const err: string[] = [];
  const io: ProgramIo = { out: (l) => out.push(l), err: (l) => err.push(l) };
  let error: unknown;
  try {
    await buildProgram(io).parseAsync(["node", "seedpass-js", "--app-dir", appDir, ...argv]);
  } catch (e) {
    error = e;
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  return { stdout: out.join("\n"), stderr: err.join("\n"), error };
}

const asOwner = { SEEDPASS_MNEMONIC: MNEMONIC };
const withFactor = { ...asOwner, SEEDPASS_HIGH_RISK_FACTOR: FACTOR };
/** `vault unlock` decrypts the parent seed, so it needs the master password. */
const toUnlock = { ...asOwner, SEEDPASS_PASSWORD: PASSWORD };

beforeAll(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-hr-"));
  app = new AppDir(appDir);
  process.env["SEEDPASS_AGENT_SOCK"] = join(appDir, "agent.sock");
  daemon = new AgentDaemon(agentSocketPath(appDir), 900, appDir);
  await daemon.start();

  await app.mutateFingerprints((d) => {
    d.fingerprints.push(FINGERPRINT);
    d.names[FINGERPRINT] = "hr";
    d.last_used = FINGERPRINT;
  });
  await mkdir(app.profileDir(FINGERPRINT), { recursive: true });
  await app.writeParentSeed(FINGERPRINT, MNEMONIC, PASSWORD);
});

afterAll(async () => {
  await daemon.stop();
  delete process.env["SEEDPASS_AGENT_SOCK"];
});

beforeEach(async () => {
  // Fresh vault each test: migration is destructive to the index by design.
  const index = { schema_version: 4, entries: {} } as VaultIndex;
  addPasswordEntry(index, "ordinary.example", 16, {});
  addSshKeyEntry(index, "prod-server", { notes: "deployment key" });
  await writeFile(
    join(app.profileDir(FINGERPRINT), INDEX_FILENAME),
    await encryptV3(deriveIndexKeyBytes(MNEMONIC), utf8(JSON.stringify(index))),
  );
});

describe("the factor", () => {
  it("is configured once and refuses to be silently replaced", async () => {
    const first = await run(withFactor, "agent", "high-risk", "factor-set");
    expect(JSON.parse(first.stdout).configured).toBe(true);
    expect(factorConfigured(appDir)).toBe(true);

    // Replacing it mints a new partition key, which would make an existing
    // partition permanently unreadable. Losing a partition is losing secrets.
    const second = await run(
      { ...asOwner, SEEDPASS_HIGH_RISK_FACTOR: "different" },
      "agent", "high-risk", "factor-set",
    );
    expect(String((second.error as Error).message)).toContain("already configured");
  });

  it("cannot be empty, and leaves nothing behind when refused", async () => {
    // An empty factor would wrap the partition key under nothing: the
    // envelope unwraps for anyone who supplies "", while `configured` still
    // reports true. So the vault would show a second factor that is not one.
    // Python raises on the same falsy check, so this is parity as well.
    const fresh = await mkdtemp(join(tmpdir(), "seedpass-empty-factor-"));
    await expect(setFactor(fresh, "")).rejects.toThrow(/cannot be empty/);
    // Refused BEFORE the envelope is written — a half-configured factor would
    // be worse than none, because factorConfigured() would start saying yes.
    expect(factorConfigured(fresh)).toBe(false);
    // And a real factor still works in the same directory, so the guard is
    // rejecting the empty string rather than the directory.
    await expect(setFactor(fresh, "a-real-factor")).resolves.toMatch(/^[0-9a-f]{64}$/);
  });

  it("is never read from the command line", async () => {
    const r = await run({ ...asOwner, SEEDPASS_HIGH_RISK_FACTOR: undefined },
      "agent", "high-risk", "unlock");
    expect(String((r.error as Error).message)).toContain("SEEDPASS_HIGH_RISK_FACTOR");
  });

  it("says NOT CONFIGURED rather than blaming the envelope", async () => {
    // Without the existsSync guard, readFile's ENOENT is caught by the same
    // handler that catches malformed JSON, so a profile that never set a
    // factor is told its partition envelope is invalid. Both refuse, so only
    // the reason is observable — and the reason is the whole difference
    // between "set one up" and "yours is corrupt, restore a backup".
    const fresh = await mkdtemp(join(tmpdir(), "seedpass-no-envelope-"));
    await expect(tagForFactor(fresh, "anything")).rejects.toMatchObject({
      reason: "high_risk_partition_not_configured",
    });

    // A file that exists but is not JSON is the case that reason belongs to.
    await setFactor(fresh, "a-real-factor");
    await writeFile(envelopePath(fresh), "{not json");
    await expect(tagForFactor(fresh, "a-real-factor")).rejects.toMatchObject({
      reason: "invalid_partition_envelope",
    });
  });

  it("verifies correctly and rejects a wrong one", async () => {
    expect(await tagForFactor(appDir, FACTOR)).toMatch(/^[0-9a-f]{64}$/);
    await expect(tagForFactor(appDir, "wrong")).rejects.toMatchObject({
      reason: "high_risk_factor_invalid",
    });
  });
});

describe("migration and access", () => {
  it("moves high-risk entries out of the index and leaves only a stub", async () => {
    await run(toUnlock, "vault", "unlock");
    const migrated = await run(withFactor, "agent", "high-risk", "migrate");
    expect(JSON.parse(migrated.stdout).moved_count).toBe(1);

    // The index no longer holds the entry's substance.
    const raw = await readFile(join(app.profileDir(FINGERPRINT), INDEX_FILENAME));
    const listed = JSON.parse((await run(asOwner, "entry", "list")).stdout);
    const stub = listed.find((r: any) => r.label === "prod-server");
    expect(stub).toBeTruthy();
    expect(JSON.stringify(listed)).not.toContain("deployment key");
    void raw;

    // The partition file exists and is 0600 — it is the whole secret.
    const path = partitionPath(app.profileDir(FINGERPRINT));
    expect(existsSync(path)).toBe(true);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("refuses to reveal a partitioned entry while the partition is locked", async () => {
    await run(toUnlock, "vault", "unlock");
    await run(withFactor, "agent", "high-risk", "migrate");
    await run(asOwner, "agent", "high-risk", "lock");

    const r = await run(asOwner, "entry", "reveal", "prod-server");
    expect(String((r.error as Error).message)).toContain("high-risk partition");
    expect(r.stdout).toBe("");
  });

  it("reveals it again once unlocked, and matches the pre-migration secret", async () => {
    await run(toUnlock, "vault", "unlock");
    // Capture the secret BEFORE migrating, so this proves the round trip
    // rather than merely that something came back.
    const before = (await run(asOwner, "entry", "reveal", "prod-server")).stdout;
    expect(before.length).toBeGreaterThan(0);

    await run(withFactor, "agent", "high-risk", "migrate");
    await run(withFactor, "agent", "high-risk", "unlock", "--ttl", "60");
    const after = (await run(asOwner, "entry", "reveal", "prod-server")).stdout;
    expect(after).toBe(before);
  });

  it("leaves ordinary entries alone", async () => {
    await run(toUnlock, "vault", "unlock");
    const before = (await run(asOwner, "entry", "reveal", "ordinary.example")).stdout;
    await run(withFactor, "agent", "high-risk", "migrate");
    // No unlock: a password entry must still work with the master password.
    const after = (await run(asOwner, "entry", "reveal", "ordinary.example")).stdout;
    expect(after).toBe(before);
  });

  it("is idempotent — a second migration moves nothing", async () => {
    await run(toUnlock, "vault", "unlock");
    await run(withFactor, "agent", "high-risk", "migrate");
    const again = await run(withFactor, "agent", "high-risk", "migrate");
    expect(JSON.parse(again.stdout).moved_count).toBe(0);
  });
});

describe("the unlock never reaches disk", () => {
  it("writes no file containing the partition key tag", async () => {
    await run(toUnlock, "vault", "unlock");
    await run(withFactor, "agent", "high-risk", "migrate");
    await run(withFactor, "agent", "high-risk", "unlock", "--ttl", "300");

    const tag = await tagForFactor(appDir, FACTOR);
    expect(tag).toMatch(/^[0-9a-f]{64}$/);

    // The tag IS the partition's encryption key. Python records it in
    // agent_high_risk_unlock.json for the life of a session, which lets
    // anything that can read the app directory open the partition with no
    // factor at all — voiding the second factor the partition exists for.
    // Nothing here may contain it.
    for (const name of await readdir(appDir)) {
      const path = join(appDir, name);
      if (!(await stat(path)).isFile()) continue;
      const contents = await readFile(path, "utf8").catch(() => "");
      expect(contents).not.toContain(tag);
    }
    // And specifically: no session file exists at all.
    expect(existsSync(join(appDir, "agent_high_risk_unlock.json"))).toBe(false);
  });

  it("drops the unlock when the vault is locked", async () => {
    await run(toUnlock, "vault", "unlock");
    await run(withFactor, "agent", "high-risk", "migrate");
    await run(withFactor, "agent", "high-risk", "unlock", "--ttl", "300");

    const client = new AgentClient(agentSocketPath(appDir));
    expect((await client.highRiskStatus(FINGERPRINT)).unlocked).toBe(true);
    // Locking the vault must not leave the stronger grant standing.
    await client.lock(FINGERPRINT);
    expect((await client.highRiskStatus(FINGERPRINT)).unlocked).toBe(false);
  });

  it("expires on its own clock", async () => {
    await run(toUnlock, "vault", "unlock");
    const client = new AgentClient(agentSocketPath(appDir));
    const tag = await tagForFactor(appDir, FACTOR);
    const expiresAt = await client.highRiskUnlock(FINGERPRINT, tag, 1);
    expect(expiresAt).toBeGreaterThan(0);
    await new Promise((r) => setTimeout(r, 1300));
    expect((await client.highRiskStatus(FINGERPRINT)).unlocked).toBe(false);
    expect(await client.highRiskTag(FINGERPRINT)).toBeNull();
  });

  it("refuses an unlock for a profile whose vault is locked", async () => {
    const client = new AgentClient(agentSocketPath(appDir));
    await client.lock(FINGERPRINT);
    const tag = await tagForFactor(appDir, FACTOR);
    // A high-risk grant over a locked vault protects nothing and would
    // outlive the thing it applies to.
    await expect(client.highRiskUnlock(FINGERPRINT, tag, 60)).rejects.toThrow(/not unlocked/);
  });

  it("rejects a malformed tag rather than storing it", async () => {
    await run(toUnlock, "vault", "unlock");
    const client = new AgentClient(agentSocketPath(appDir));
    for (const bad of ["", "short", "z".repeat(64), "../../etc"]) {
      await expect(client.highRiskUnlock(FINGERPRINT, bad, 60)).rejects.toThrow();
    }
  });

  it("keeps the tag out of the audit log", async () => {
    await run(toUnlock, "vault", "unlock");
    await run(withFactor, "agent", "high-risk", "unlock", "--ttl", "60");
    const tag = await tagForFactor(appDir, FACTOR);
    const audit = await readFile(join(app.profileDir(FINGERPRINT), "audit.log"), "utf8");
    // The audit records THAT the partition was unlocked; recording the tag
    // would put the key on disk by another route.
    expect(audit).toContain("high_risk_unlocked");
    expect(audit).not.toContain(tag);
  });
});

describe("approval gates", () => {
  it("issues, lists, consumes and exhausts", async () => {
    const issued = JSON.parse(
      (await run(asOwner, "agent", "approval", "issue", "--action", "export", "--uses", "2"))
        .stdout,
    );
    expect(issued.action).toBe("export");
    expect(issued.uses_remaining).toBe(2);
    expect(issued.id).toHaveLength(24); // 18 random bytes, base64url

    expect(await listApprovals(appDir)).toHaveLength(1);

    expect(await consumeApproval(appDir, { approvalId: issued.id, action: "export" })).toEqual({
      ok: true,
      reason: "approval_consumed",
    });
    expect(await consumeApproval(appDir, { approvalId: issued.id, action: "export" })).toEqual({
      ok: true,
      reason: "approval_consumed",
    });
    // Third use: the budget is spent.
    expect(await consumeApproval(appDir, { approvalId: issued.id, action: "export" })).toEqual({
      ok: false,
      reason: "approval_exhausted",
    });
  });

  it("distinguishes every way a consume can fail", async () => {
    const issued = await issueApproval(appDir, {
      action: "export",
      resource: "vault-a",
      ttlSeconds: 300,
      uses: 1,
    });

    expect(
      await consumeApproval(appDir, { approvalId: "no-such-id", action: "export" }),
    ).toEqual({ ok: false, reason: "approval_not_found" });

    expect(
      await consumeApproval(appDir, { approvalId: issued.id, action: "reveal_parent_seed" }),
    ).toEqual({ ok: false, reason: "approval_action_mismatch" });

    expect(
      await consumeApproval(appDir, {
        approvalId: issued.id,
        action: "export",
        resource: "vault-b",
      }),
    ).toEqual({ ok: false, reason: "approval_resource_mismatch" });

    // Still unconsumed after all those failures.
    expect((await listApprovals(appDir)).find((a) => a.id === issued.id)!.uses_remaining).toBe(1);
  });

  it("honours resource scoping in both directions", async () => {
    // Only the FAILING side of resource scoping was tested, and the check is
    // `record !== "*" && record !== requested` — for a scoped record and a
    // different resource both halves are true, so `&&` and `||` agree and a
    // mutation there was invisible. These are the two cases where they
    // differ, and they are the cases that make scoping useful rather than
    // merely restrictive.
    const scoped = await issueApproval(appDir, {
      action: "export",
      resource: "vault-a",
      ttlSeconds: 300,
      uses: 1,
    });
    // A scoped approval works for the resource it names.
    expect(
      await consumeApproval(appDir, {
        approvalId: scoped.id,
        action: "export",
        resource: "vault-a",
      }),
    ).toEqual({ ok: true, reason: "approval_consumed" });

    // A wildcard approval works for any resource — that is what "*" is for.
    const wildcard = await issueApproval(appDir, {
      action: "export",
      resource: "*",
      ttlSeconds: 300,
      uses: 1,
    });
    expect(
      await consumeApproval(appDir, {
        approvalId: wildcard.id,
        action: "export",
        resource: "some-specific-vault",
      }),
    ).toEqual({ ok: true, reason: "approval_consumed" });
  });

  it("refuses an expired approval", async () => {
    const issued = await issueApproval(appDir, {
      action: "export",
      ttlSeconds: 1,
      uses: 1,
      now: Date.now() - 10_000,
    });
    expect(await consumeApproval(appDir, { approvalId: issued.id, action: "export" })).toEqual({
      ok: false,
      reason: "approval_expired",
    });
  });

  it("refuses a revoked approval and hides it from the default listing", async () => {
    const issued = await issueApproval(appDir, { action: "export", ttlSeconds: 300, uses: 5 });
    expect(await revokeApproval(appDir, issued.id)).toBe(true);
    // Revoking twice is not an error but changes nothing.
    expect(await revokeApproval(appDir, issued.id)).toBe(false);

    expect(await consumeApproval(appDir, { approvalId: issued.id, action: "export" })).toEqual({
      ok: false,
      reason: "approval_revoked",
    });
    expect((await listApprovals(appDir)).map((a) => a.id)).not.toContain(issued.id);
    expect((await listApprovals(appDir, { includeRevoked: true })).map((a) => a.id)).toContain(
      issued.id,
    );
  });

  it("refuses a ttl or use count that would make the approval meaningless", async () => {
    // Mutation testing found these unguarded by any test. An approval issued
    // with ttl 0 is expired the instant it exists; one with uses 0 can never
    // be consumed. Both would look like a granted authorization to whoever
    // requested it and silently authorize nothing — the confusing failure,
    // not the safe one.
    for (const ttl of [0, -1, 1.5, Number.NaN]) {
      await expect(
        issueApproval(appDir, { action: "export", ttlSeconds: ttl, uses: 1 }),
      ).rejects.toThrow(/ttl must be a positive integer/);
    }
    for (const uses of [0, -1, 2.5, Number.NaN]) {
      await expect(
        issueApproval(appDir, { action: "export", ttlSeconds: 60, uses }),
      ).rejects.toThrow(/uses must be a positive integer/);
    }
  });

  it("treats an approval expiring exactly now as expired", async () => {
    // The boundary, which no test previously pinned: `<=` refuses at the
    // instant of expiry, `<` would allow one last use. Python uses `<=`, so
    // this is parity as well as the safer direction.
    const now = Date.now();
    const issued = await issueApproval(appDir, {
      action: "export",
      ttlSeconds: 60,
      uses: 1,
      now: now - 60_000,
    });
    expect(Date.parse(issued.expires_at_utc)).toBe(now);
    expect(
      await consumeApproval(appDir, { approvalId: issued.id, action: "export", now }),
    ).toEqual({ ok: false, reason: "approval_expired" });
    // And one millisecond earlier it is still usable, so the boundary is
    // exactly where it claims to be rather than approximately.
    const still = await issueApproval(appDir, {
      action: "export",
      ttlSeconds: 60,
      uses: 1,
      now: now - 60_000 + 1,
    });
    expect(
      await consumeApproval(appDir, { approvalId: still.id, action: "export", now }),
    ).toEqual({ ok: true, reason: "approval_consumed" });
  });

  it("refuses to issue an approval for an action it does not know", async () => {
    // An unknown action would produce an approval that gates nothing while
    // looking like it gates something.
    await expect(
      issueApproval(appDir, { action: "delete_everything", ttlSeconds: 60, uses: 1 }),
    ).rejects.toThrow(/unknown approval action/);
  });

  it("reads require_for out of a policy", () => {
    const policy = { approvals: { require_for: ["Export", "reveal_parent_seed"] } };
    expect(approvalRequired(policy, "export")).toBe(true);
    expect(approvalRequired(policy, "REVEAL_PARENT_SEED")).toBe(true);
    expect(approvalRequired(policy, "private_key_retrieval")).toBe(false);
    // A malformed policy must not accidentally mean "nothing needs approval"
    // in a way that differs from Python — both treat it as no requirement.
    expect(approvalRequired({}, "export")).toBe(false);
    expect(approvalRequired({ approvals: "yes" }, "export")).toBe(false);
  });

  it("stores approvals at 0600", async () => {
    await issueApproval(appDir, { action: "export", ttlSeconds: 60, uses: 1 });
    const mode = (await stat(join(appDir, "agent_approvals.json"))).mode & 0o777;
    expect(mode).toBe(0o600);
  });
});
