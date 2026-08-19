/**
 * Job profiles and recovery drills.
 *
 * Both are records rather than credentials, so the interesting properties are
 * about honesty: a job profile must show when the policy it was created under
 * has changed, and a drill log must be unable to be edited quietly — a
 * tamper-evident history you can rewrite records nothing at all.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, readFile, writeFile, stat, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createJobProfile,
  listJobProfiles,
  getJobProfile,
  revokeJobProfile,
  checkJobProfiles,
  currentPolicyStamp,
  policyPath,
} from "../src/jobProfiles.js";
import {
  recordRecoveryDrill,
  listRecoveryDrills,
  verifyRecoveryDrills,
  drillLogPath,
  drillKeyPath,
} from "../src/recoveryDrills.js";

let appDir: string;

beforeAll(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-jobs-"));
});

afterAll(() => {});

describe("job profiles", () => {
  it("creates, reads back and revokes", async () => {
    const record = await createJobProfile(appDir, {
      jobId: "nightly-deploy",
      fingerprint: "ABCDEF0123456789",
      query: "sp://entry/3",
      schedule: "0 2 * * *",
      description: "deploy key for CI",
    });
    expect(record.id).toBe("nightly-deploy");
    expect(record.revoked_at_utc).toBeNull();
    // Defaults match Python's, including broker_command being null rather
    // than an empty string.
    expect(record.auth_broker).toBe("env");
    expect(record.broker_command).toBeNull();
    expect(record.policy_binding).toBe("default");

    expect(await getJobProfile(appDir, "nightly-deploy")).toEqual(record);
    expect(await listJobProfiles(appDir)).toHaveLength(1);

    expect(await revokeJobProfile(appDir, "nightly-deploy")).toBe(true);
    // Revoking twice is not an error but changes nothing.
    expect(await revokeJobProfile(appDir, "nightly-deploy")).toBe(false);
    expect(await listJobProfiles(appDir)).toHaveLength(0);
    expect(await listJobProfiles(appDir, { includeRevoked: true })).toHaveLength(1);
  });

  it("refuses a duplicate id", async () => {
    await createJobProfile(appDir, { jobId: "dup", fingerprint: "A".repeat(16), query: "x" });
    // Silently replacing would let a second, different job inherit the
    // first's identity and audit history.
    await expect(
      createJobProfile(appDir, { jobId: "dup", fingerprint: "A".repeat(16), query: "y" }),
    ).rejects.toThrow(/job_exists/);
  });

  it("refuses an empty id", async () => {
    await expect(
      createJobProfile(appDir, { jobId: "   ", fingerprint: "A".repeat(16), query: "x" }),
    ).rejects.toThrow(/job_id_required/);
  });

  it("stores the file at 0600", async () => {
    expect((await stat(join(appDir, "agent_jobs.json"))).mode & 0o777).toBe(0o600);
  });
});

describe("policy binding", () => {
  it("flags a profile whose policy changed after it was created", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-policy-"));
    await writeFile(policyPath(dir), JSON.stringify({ approvals: { require_for: [] } }));

    const stampBefore = await currentPolicyStamp(dir);
    await createJobProfile(dir, {
      jobId: "bound",
      fingerprint: "A".repeat(16),
      query: "x",
      policyStamp: stampBefore,
    });
    expect((await checkJobProfiles(dir, await currentPolicyStamp(dir)))[0]!.policy_current).toBe(
      true,
    );

    // Tighten the policy. The job is now running under rules it was never
    // reviewed against, which is precisely what the stamp exists to surface.
    await writeFile(
      policyPath(dir),
      JSON.stringify({ approvals: { require_for: ["export"] } }),
    );
    const checks = await checkJobProfiles(dir, await currentPolicyStamp(dir));
    expect(checks[0]!.policy_current).toBe(false);
    expect(checks[0]!.stored_policy_stamp).toBe(stampBefore);
  });

  it("treats an unreadable policy as its own state, not as no policy", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-badpolicy-"));
    const empty = await currentPolicyStamp(dir);
    await writeFile(policyPath(dir), "{ not json");
    const broken = await currentPolicyStamp(dir);
    // If a corrupt file hashed as `{}` every job would read as current while
    // the real policy was unknown.
    expect(broken).not.toBe(empty);
  });

  it("excludes revoked profiles from the check", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-revoked-"));
    await createJobProfile(dir, {
      jobId: "gone",
      fingerprint: "A".repeat(16),
      query: "x",
      policyStamp: "stale",
    });
    await revokeJobProfile(dir, "gone");
    // A revoked job is not running, so a stale binding on it is not a finding.
    expect(await checkJobProfiles(dir, await currentPolicyStamp(dir))).toEqual([]);
  });
});

describe("recovery drills", () => {
  it("records a present backup as ok and a missing one as a warning", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-drill-"));
    const backup = join(dir, "vault.seedpass");
    await writeFile(backup, "backup contents");

    const ok = await recordRecoveryDrill(dir, {
      fingerprint: "A".repeat(16),
      backupPath: backup,
      simulated: false,
    });
    expect(ok.status).toBe("ok");
    expect(ok.backup_exists).toBe(true);
    expect(ok.backup_size).toBe("backup contents".length);

    // A missing backup is the FINDING, not an error — that is what a drill is
    // for, so it records rather than throws.
    const missing = await recordRecoveryDrill(dir, {
      fingerprint: "A".repeat(16),
      backupPath: join(dir, "not-there"),
      simulated: false,
    });
    expect(missing.status).toBe("warning");
    expect(missing.backup_exists).toBe(false);
    expect(missing.backup_age_days).toBeNull();
  });

  it("flags a backup older than the expected maximum age", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-stale-"));
    const backup = join(dir, "old.seedpass");
    await writeFile(backup, "x");
    // Ask as if it were 40 days later.
    const record = await recordRecoveryDrill(dir, {
      fingerprint: "A".repeat(16),
      backupPath: backup,
      simulated: false,
      expectedMaxAgeDays: 30,
      // Half a day past the boundary, so flooring is unambiguous: the file
      // was written a few milliseconds before `now` was computed, and an
      // exact multiple would floor to 39.
      now: Date.now() + 40 * 86_400_000 + 43_200_000,
    });
    expect(record.backup_age_days).toBe(40);
    expect(record.stale).toBe(true);
    expect(record.status).toBe("warning");
  });

  it("chains records so the log cannot be edited quietly", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-chain-"));
    const backup = join(dir, "b");
    await writeFile(backup, "x");
    for (let i = 0; i < 4; i++) {
      await recordRecoveryDrill(dir, {
        fingerprint: "A".repeat(16),
        backupPath: backup,
        simulated: true,
      });
    }
    expect(await verifyRecoveryDrills(dir)).toEqual({ valid: true, checked: 4, errors: [] });
    expect(await listRecoveryDrills(dir)).toHaveLength(4);

    // Edit one record in place, keeping its signature.
    const lines = (await readFile(drillLogPath(dir), "utf8")).trim().split("\n");
    const tampered = JSON.parse(lines[1]!);
    // Change something that genuinely differs from what was signed. All four
    // records are otherwise identical, so flipping `status` to the value it
    // already held would "tamper" with nothing and prove nothing.
    expect(tampered.simulated).toBe(true);
    tampered.simulated = false;
    lines[1] = JSON.stringify(tampered);
    await writeFile(drillLogPath(dir), lines.join("\n") + "\n");

    const verified = await verifyRecoveryDrills(dir);
    expect(verified.valid).toBe(false);
    expect(verified.errors).toContain("sig_mismatch_line:1");
  });

  it("detects a removed record, not just an altered one", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-drop-"));
    const backup = join(dir, "b");
    await writeFile(backup, "x");
    for (let i = 0; i < 3; i++) {
      await recordRecoveryDrill(dir, {
        fingerprint: "A".repeat(16),
        backupPath: backup,
        simulated: true,
      });
    }
    const lines = (await readFile(drillLogPath(dir), "utf8")).trim().split("\n");
    // Drop the middle record. Each signature covers the previous one, so the
    // survivor after the gap no longer verifies.
    await writeFile(drillLogPath(dir), [lines[0], lines[2]].join("\n") + "\n");
    expect((await verifyRecoveryDrills(dir)).valid).toBe(false);
  });

  it("reports an appended record that was never signed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-append-"));
    const backup = join(dir, "b");
    await writeFile(backup, "x");
    await recordRecoveryDrill(dir, {
      fingerprint: "A".repeat(16),
      backupPath: backup,
      simulated: true,
    });
    await appendFile(drillLogPath(dir), JSON.stringify({ status: "ok" }) + "\n");
    const verified = await verifyRecoveryDrills(dir);
    expect(verified.valid).toBe(false);
    expect(verified.errors).toContain("missing_sig_line:1");
  });

  it("verifies an absent log as trivially valid", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-nolog-"));
    expect(await verifyRecoveryDrills(dir)).toEqual({ valid: true, checked: 0, errors: [] });
  });

  it("keeps the key and log at 0600", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-modes-"));
    const backup = join(dir, "b");
    await writeFile(backup, "x");
    await recordRecoveryDrill(dir, {
      fingerprint: "A".repeat(16),
      backupPath: backup,
      simulated: true,
    });
    expect((await stat(drillKeyPath(dir))).mode & 0o777).toBe(0o600);
    expect((await stat(drillLogPath(dir))).mode & 0o777).toBe(0o600);
  });
});
