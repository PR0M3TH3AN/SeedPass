/**
 * Password policy layering: profile config is the BASE, the entry's own
 * `policy` block overrides it per field.
 *
 * This is the case the parity fixture suite could not catch. Those fixtures
 * call generatePassword with one already-resolved policy, so they prove the
 * algorithm and say nothing about where the policy came from. The port read
 * the entry's block over hardcoded defaults and never read the profile
 * config at all, so every entry in a profile with a non-default policy
 * derived a different password than Python — presenting to the user as a
 * wrong password, i.e. as data loss, with nothing failing anywhere.
 *
 * The expected values below are ground truth computed by the Python
 * implementation, not by this one:
 *
 *   pg = PasswordGenerator(_SeedDeriver(), MNEMONIC, bip85, policy=<policy>)
 *   pg.generate_password(length=20, index=<i>, gen_version=<v>)
 *
 * with <policy> = PasswordPolicy(**CONFIG_POLICY) for an entry carrying no
 * block, and dataclasses.replace(base, **entry_block) for one that does —
 * mirroring manager.py's _generate_password_for_entry.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { mnemonics } from "@seedpass/test-vectors";
import {
  deriveIndexKeyBytes,
  encryptV3,
  generateFingerprint,
  utf8,
} from "@seedpass/core";
import { buildProgram, type ProgramIo } from "../src/index.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);
const PASSWORD = "policy-test-password";

/** A deliberately non-default profile policy — every field differs. */
const CONFIG_POLICY = {
  min_uppercase: 5,
  min_lowercase: 1,
  min_digits: 4,
  min_special: 0,
  exclude_ambiguous: true,
};

/** Python, policy = the config above, entry carries no policy block. */
const PY_CONFIG_ONLY_V2 = "27osg$|$$,W*}UFyPL85";
/** Same config policy, entry id 2, gen_version 1. */
const PY_CONFIG_ONLY_V1 = "WL2c'A&\"G62sm:Pg*47d";
/** Python, policy = config with min_digits overridden to 1 by the entry. */
const PY_ENTRY_OVERRIDE_V2 = "!@`\\8Tfn`]]H$SH2cx7V";

/**
 * What the port produced before the fix: the same entries derived against
 * built-in defaults instead of the profile config. Asserted as inequality so
 * a regression that quietly drops the config base fails loudly rather than
 * needing someone to notice a changed constant.
 */
const DEFAULTS_ONLY_V2 = "SXnmg8]83'O9?RExHE3V";
const DEFAULTS_PLUS_ENTRY_V2 = "3r/G3G\\[<5~/hK},cf2N";
const DEFAULTS_ONLY_V1 = "+y:2Acu06&?K[j9aCG8K";

let appDir: string;

interface RunResult {
  stdout: string;
  error?: unknown;
}

async function run(
  env: Record<string, string | undefined>,
  ...argv: string[]
): Promise<RunResult> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  const out: string[] = [];
  const io: ProgramIo = { out: (l: string) => out.push(l), err: () => {} };
  let error: unknown;
  try {
    await buildProgram(io).parseAsync([
      "node", "seedpass-js", "--app-dir", appDir, ...argv,
    ]);
  } catch (e) {
    error = e;
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  return { stdout: out.join("\n"), error };
}

function passwordEntry(
  label: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    kind: "password",
    type: "password",
    label,
    length: 20,
    username: "",
    url: "",
    notes: "",
    tags: [],
    links: [],
    custom_fields: [],
    archived: false,
    date_added: "2023-11-14T22:13:20+00:00",
    date_modified: "2023-11-14T22:13:20+00:00",
    modified_ts: 1700000000,
    gen_version: 2,
    ...extra,
  };
}

beforeAll(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-policy-"));

  // Real profile, created the way a user creates one.
  await run(
    { SEEDPASS_MNEMONIC: MNEMONIC, SEEDPASS_PASSWORD: PASSWORD },
    "fingerprint", "add", "--name", "policy",
  );

  // Set the policy through the real config command, so the test covers the
  // path a user actually takes rather than a hand-written config file.
  for (const [key, value] of Object.entries(CONFIG_POLICY)) {
    await run({ SEEDPASS_MNEMONIC: MNEMONIC }, "config", "set", key, String(value));
  }

  const index = {
    schema_version: 4,
    _sync_meta: { next_index: 3 },
    entries: {
      // 0: no policy block at all -> derives purely from the config policy.
      "0": passwordEntry("config-base.example"),
      // 1: overrides exactly one field; the other four must still come from
      //    the config, which is what distinguishes layering from replacement.
      "1": passwordEntry("entry-override.example", { policy: { min_digits: 1 } }),
      // 2: same as 0 but frozen v1 -- the legacy algorithm reads the same
      //    resolved policy, so the config base must reach it too.
      "2": passwordEntry("legacy-v1.example", { gen_version: 1 }),
    },
  };
  const key = deriveIndexKeyBytes(MNEMONIC);
  await writeFile(
    join(appDir, FINGERPRINT, "seedpass_entries_db.json.enc"),
    await encryptV3(key, utf8(JSON.stringify(index))),
  );
});

afterAll(() => {
  delete process.env["SEEDPASS_MNEMONIC"];
});

describe("profile config is the base password policy", () => {
  it("derives an unblocked entry from the config policy, matching Python", async () => {
    const r = await run({ SEEDPASS_MNEMONIC: MNEMONIC }, "entry", "reveal", "config-base.example");
    expect(r.error).toBeUndefined();
    expect(r.stdout).toBe(PY_CONFIG_ONLY_V2);
    expect(r.stdout).not.toBe(DEFAULTS_ONLY_V2);
  });

  it("layers the entry's policy block over the config rather than replacing it", async () => {
    const r = await run(
      { SEEDPASS_MNEMONIC: MNEMONIC }, "entry", "reveal", "entry-override.example",
    );
    expect(r.error).toBeUndefined();
    expect(r.stdout).toBe(PY_ENTRY_OVERRIDE_V2);
    // Would be the answer if the entry block replaced the config base instead
    // of merging over it.
    expect(r.stdout).not.toBe(DEFAULTS_PLUS_ENTRY_V2);
  });

  it("applies the config base to frozen v1 entries too", async () => {
    const r = await run({ SEEDPASS_MNEMONIC: MNEMONIC }, "entry", "reveal", "legacy-v1.example");
    expect(r.error).toBeUndefined();
    expect(r.stdout).toBe(PY_CONFIG_ONLY_V1);
    expect(r.stdout).not.toBe(DEFAULTS_ONLY_V1);
  });

  it("honours exclude_ambiguous from the config", async () => {
    const r = await run({ SEEDPASS_MNEMONIC: MNEMONIC }, "entry", "reveal", "config-base.example");
    expect(r.stdout).not.toMatch(/[O0Il1]/);
  });
});
