/**
 * CLI behavior tests against a fixture vault.
 *
 * The load-bearing assertions are the agent-blind properties from plan
 * section 9.3: default output never contains secret values; `reveal` is the
 * only command that prints one; sinks deliver without printing.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import {
  entriesIndex,
  entrySecrets,
  passwordV1Cases,
  passwordV2Cases,
  totpCases,
  mnemonics,
} from "@seedpass/test-vectors";
import { deriveIndexKeyBytes, encryptV3, utf8 } from "@seedpass/core";
import { buildProgram, type ProgramIo } from "../src/index.js";

const MNEMONIC = mnemonics["abandon12"]!;
let vaultPath: string;

interface RunResult {
  stdout: string;
  stderr: string;
  error?: unknown;
}

async function run(...argv: string[]): Promise<RunResult> {
  const out: string[] = [];
  const err: string[] = [];
  const io: ProgramIo = {
    out: (l: string) => out.push(l),
    err: (l: string) => err.push(l),
  };
  const program = buildProgram(io);
  let error: unknown;
  try {
    await program.parseAsync(["node", "seedpass-js", ...argv]);
  } catch (e) {
    error = e;
  }
  return { stdout: out.join("\n"), stderr: err.join("\n"), error };
}

beforeAll(async () => {
  process.env["SEEDPASS_MNEMONIC"] = MNEMONIC;
  // Hermetic app dir: without this, any code path that touches the DEFAULT
  // profile directory silently depends on the developer's real ~/.seedpass —
  // which is exactly how a "vault import --vault x needs a default profile"
  // bug passed locally for months while failing in CI, where no ~/.seedpass
  // exists. Tests must fail the way CI fails.
  process.env["SEEDPASS_APP_DIR"] = await mkdtemp(join(tmpdir(), "seedpass-cli-appdir-"));
  const dir = await mkdtemp(join(tmpdir(), "seedpass-cli-"));
  vaultPath = join(dir, "vault.enc");
  const key = deriveIndexKeyBytes(MNEMONIC);
  const payload = await encryptV3(key, utf8(JSON.stringify(entriesIndex.entries)));
  await writeFile(vaultPath, payload);
});

describe("capabilities", () => {
  it("reports the agent surface", async () => {
    const r = await run("capabilities");
    const caps = JSON.parse(r.stdout);
    expect(caps.agent_surface.reference_first_output).toBe(true);
    expect(caps.protocol.entry_schema_version).toBe(4);
  });
});

describe("reference-first output (agent-blind default)", () => {
  it("entry list returns refs and metadata for all entries, no secret values", async () => {
    const r = await run("--vault", vaultPath, "entry", "list");
    const rows = JSON.parse(r.stdout) as Record<string, unknown>[];
    expect(rows).toHaveLength(10);
    for (const row of rows) {
      expect(String(row["ref"])).toMatch(/^sp:\/\/entry\/\d+$/);
      expect(row).not.toHaveProperty("secret");
      expect(row).not.toHaveProperty("value");
      expect(row).not.toHaveProperty("content");
    }
    // The imported TOTP secret must not appear anywhere in the output
    expect(r.stdout).not.toContain("JBSWY3DPEHPK3PXP");
    // ...but its presence is flagged
    const importedTotp = rows.find((row) => row["label"] === "imported-totp")!;
    expect(importedTotp["has_secret"]).toBe(true);
  });

  it("entry get resolves by label, id, and ref identically", async () => {
    const byLabel = await run("--vault", vaultPath, "entry", "get", "example.com");
    const byId = await run("--vault", vaultPath, "entry", "get", "0");
    const byRef = await run("--vault", vaultPath, "entry", "get", "sp://entry/0");
    expect(byLabel.stdout).toBe(byId.stdout);
    expect(byId.stdout).toBe(byRef.stdout);
    const row = JSON.parse(byRef.stdout);
    expect(row.label).toBe("example.com");
    expect(row.kind).toBe("password");
  });

  it("entry search matches tags and never leaks values", async () => {
    const r = await run("--vault", vaultPath, "entry", "search", "api");
    const rows = JSON.parse(r.stdout) as Record<string, unknown>[];
    expect(rows.map((x) => x["label"])).toEqual(["api-token"]);
    expect(r.stdout).not.toContain("abc123");
  });
});

describe("plaintext egress is explicit and correct", () => {
  it("reveal derives the same password as the Python fixture", async () => {
    // Vault entry 0: example.com, length 16, gen_version 2, derivation index 0
    const expected = passwordV2Cases.find(
      (c) => c.policy === "default" && c.length === 16 && c.index === 0,
    )!.password;
    const r = await run("--vault", vaultPath, "entry", "reveal", "example.com");
    expect(r.stdout).toBe(expected);
  });

  it("reveal computes deterministic TOTP codes at a pinned time", async () => {
    const fixture = totpCases.find((c) => c.mnemonic_id === "abandon12" && c.index === 0)!;
    const r = await run(
      "--vault", vaultPath, "entry", "reveal", "example-totp", "--at", "1700000000",
    );
    expect(r.stdout).toBe(fixture.codes_at["1700000000"]);
  });

  it("reveal prints an imported key_value secret", async () => {
    const r = await run("--vault", vaultPath, "entry", "reveal", "api-token");
    expect(r.stdout).toBe("abc123");
  });

  it("reveal matches every Python-computed entry secret", async () => {
    expect((await run("--vault", vaultPath, "entry", "reveal", "example.com")).stdout).toBe(
      entrySecrets.password_entry_0,
    );
    expect(
      (await run("--vault", vaultPath, "entry", "reveal", "example-totp", "--at", "1700000000"))
        .stdout,
    ).toBe(entrySecrets.totp_entry_1_code_at["1700000000"]);
    // Nostr entries use BIP-85 app 39 (not the sync client's app 1237)
    expect((await run("--vault", vaultPath, "entry", "reveal", "example-nostr")).stdout).toBe(
      entrySecrets.nostr_entry_4.nsec,
    );
    expect((await run("--vault", vaultPath, "entry", "reveal", "example-seed")).stdout).toBe(
      entrySecrets.seed_entry_7_mnemonic,
    );
    expect((await run("--vault", vaultPath, "entry", "reveal", "example-managed")).stdout).toBe(
      entrySecrets.managed_entry_8_mnemonic,
    );
  });
});

describe("provisioning is agent-blind", () => {
  let writablePath: string;

  beforeAll(async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-provision-"));
    writablePath = join(dir, "vault.enc");
    await writeFile(writablePath, await readFile(vaultPath));
  });

  it("entry add password returns a reference, never the derived password", async () => {
    const r = await run(
      "--vault", writablePath, "entry", "add", "password", "new-site.example",
      "--length", "16", "--username", "bob",
    );
    const row = JSON.parse(r.stdout);
    expect(row.ref).toBe("sp://entry/10");
    expect(row.kind).toBe("password");
    expect(row.gen_version).toBe(2);

    // The derived password exists and reveals correctly, but appeared
    // nowhere in the provisioning output.
    const reveal = await run("--vault", writablePath, "entry", "reveal", "sp://entry/10");
    expect(reveal.stdout).toHaveLength(16);
    expect(r.stdout).not.toContain(reveal.stdout);
  });

  it("entry add totp --secret stores but never echoes the imported secret", async () => {
    const secret = "GEZDGNBVGY3TQOJQ";
    const r = await run(
      "--vault", writablePath, "entry", "add", "totp", "imported-2", "--secret", secret,
    );
    const row = JSON.parse(r.stdout);
    expect(row.has_secret).toBe(true);
    expect(r.stdout).not.toContain(secret);
  });

  it("entry add key-value persists across reopen", async () => {
    await run(
      "--vault", writablePath, "entry", "add", "key-value", "deploy-token", "token", "s3cr3t-value",
    );
    const list = await run("--vault", writablePath, "entry", "list");
    const rows = JSON.parse(list.stdout) as { label: string }[];
    expect(rows.map((x) => x.label)).toContain("deploy-token");
    expect(list.stdout).not.toContain("s3cr3t-value");
    const reveal = await run("--vault", writablePath, "entry", "reveal", "deploy-token");
    expect(reveal.stdout).toBe("s3cr3t-value");
  });

  it("entry add managed-account records the child fingerprint only", async () => {
    const r = await run("--vault", writablePath, "entry", "add", "managed-account", "child-acct");
    const row = JSON.parse(r.stdout);
    expect(row.fingerprint).toMatch(/^[0-9A-F]{16}$/);
    expect(row.word_count).toBe(12);
    // The child mnemonic is derivable but was never printed
    const reveal = await run("--vault", writablePath, "entry", "reveal", "child-acct");
    expect(reveal.stdout.split(" ")).toHaveLength(12);
    expect(r.stdout).not.toContain(reveal.stdout);
  });
});

describe("sink delivery keeps secrets out of CLI output", () => {
  it("use --exec injects SEEDPASS_SECRET into the child env only", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-sink-"));
    const capture = join(dir, "captured.txt");
    const script = join(dir, "cap.sh");
    await writeFile(script, `#!/bin/sh\nprintf '%s' "$SEEDPASS_SECRET" > "${capture}"\n`, {
      mode: 0o755,
    });

    const r = await run("--vault", vaultPath, "use", "api-token", "--exec", script);
    const delivered = JSON.parse(r.stdout);
    expect(delivered.sink).toBe("exec");
    expect(delivered.exitCode).toBe(0);
    expect(delivered.ref).toBe("sp://entry/5");
    // The secret reached the child...
    expect(await readFile(capture, "utf8")).toBe("abc123");
    // ...and never appeared in the CLI's own output
    expect(r.stdout).not.toContain("abc123");
    expect(r.stderr).not.toContain("abc123");
  });

  it("use --stdin-to pipes the secret to the command's stdin", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-sink-"));
    const capture = join(dir, "captured.txt");
    const script = join(dir, "cap.sh");
    await writeFile(script, `#!/bin/sh\ncat > "${capture}"\n`, { mode: 0o755 });

    const r = await run("--vault", vaultPath, "use", "api-token", "--stdin-to", script);
    expect(JSON.parse(r.stdout).sink).toBe("stdin");
    expect(await readFile(capture, "utf8")).toBe("abc123");
    expect(r.stdout).not.toContain("abc123");
  });

  it("accepts a quoted command spec so flags survive option parsing", async () => {
    // Regression: commander's variadic options stop at the next "-token",
    // so `--stdin-to wc -c` lost the flag. A quoted spec is the documented
    // way to include flags.
    const dir = await mkdtemp(join(tmpdir(), "seedpass-spec-"));
    const capture = join(dir, "captured.txt");
    const script = join(dir, "cap.sh");
    await writeFile(script, `#!/bin/sh\nprintf '%s %s' "$1" "$(cat)" > "${capture}"\n`, {
      mode: 0o755,
    });
    const r = await run(
      "--vault", vaultPath, "use", "api-token", "--stdin-to", `${script} -flagged`,
    );
    expect(JSON.parse(r.stdout).sink).toBe("stdin");
    expect(await readFile(capture, "utf8")).toBe("-flagged abc123");
  });

  it("use refuses ambiguous sink selection", async () => {
    const r = await run(
      "--vault", vaultPath, "use", "api-token", "--clipboard", "--stdin-to", "cat",
    );
    expect(String((r.error as Error).message)).toContain("exactly one sink");
  });
});

describe("modification commands", () => {
  let modPath: string;

  beforeAll(async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-mod-"));
    modPath = join(dir, "vault.enc");
    await writeFile(modPath, await readFile(vaultPath));
  });

  it("entry modify updates fields and bumps timestamps", async () => {
    const before = JSON.parse(
      (await run("--vault", modPath, "entry", "get", "example.com")).stdout,
    );
    const r = await run(
      "--vault", modPath, "entry", "modify", "example.com",
      "--username", "carol", "--tags", "web", "staging",
    );
    const row = JSON.parse(r.stdout);
    expect(row.username).toBe("carol");
    expect(row.tags).toEqual(["web", "staging"]);
    expect(row.modified_ts).toBeGreaterThan(before.modified_ts);
  });

  it("entry modify rejects fields the kind does not allow", async () => {
    const r = await run(
      "--vault", modPath, "entry", "modify", "example-totp", "--username", "x",
    );
    expect(String((r.error as Error).message)).toContain("does not support fields");
  });

  it("archive hides from totp-codes; unarchive restores", async () => {
    await run("--vault", modPath, "entry", "archive", "example-totp");
    const archived = JSON.parse(
      (await run("--vault", modPath, "entry", "totp-codes", "--at", "1700000000")).stdout,
    ) as { label: string }[];
    expect(archived.map((x) => x.label)).not.toContain("example-totp");

    await run("--vault", modPath, "entry", "unarchive", "example-totp");
    const restored = JSON.parse(
      (await run("--vault", modPath, "entry", "totp-codes", "--at", "1700000000")).stdout,
    ) as { label: string; code: string }[];
    const det = restored.find((x) => x.label === "example-totp")!;
    expect(det.code).toBe(entrySecrets.totp_entry_1_code_at["1700000000"]);
  });

  it("link-add/links/link-remove round-trip with resolved targets", async () => {
    await run(
      "--vault", modPath, "entry", "link-add", "example.com", "example-totp",
      "--relation", "totp", "--note", "2fa",
    );
    const links = JSON.parse(
      (await run("--vault", modPath, "entry", "links", "example.com")).stdout,
    );
    expect(links).toEqual([
      { target_id: 1, relation: "totp", note: "2fa", target_label: "example-totp", target_kind: "totp" },
    ]);
    const after = await run(
      "--vault", modPath, "entry", "link-remove", "example.com", "example-totp",
    );
    expect(JSON.parse(after.stdout).links).toEqual([]);
  });
});

describe("util generate-password", () => {
  it("matches the v1 fixture at default index/version", async () => {
    const expected = passwordV1Cases.find(
      (c) => c.policy === "default" && c.length === 16 && c.index === 0,
    )!.password;
    const r = await run("util", "generate-password", "--length", "16");
    expect(r.stdout).toBe(expected);
  });

  it("matches v2 and policy fixtures", async () => {
    const v2 = passwordV2Cases.find(
      (c) => c.policy === "safe_special" && c.length === 40 && c.index === 2,
    )!.password;
    const r = await run(
      "util", "generate-password", "--length", "40", "--index", "2",
      "--gen-version", "2", "--special-mode", "safe",
    );
    expect(r.stdout).toBe(v2);
  });
});

describe("vault export/import", () => {
  it("exports an encrypted portable backup and inspects it without writing", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-export-"));
    const dest = join(dir, "backup.json");
    const exportResult = await run("--vault", vaultPath, "vault", "export", dest);
    expect(JSON.parse(exportResult.stdout).encrypted).toBe(true);

    const importResult = await run("vault", "import", dest, "--inspect");
    const summary = JSON.parse(importResult.stdout);
    expect(summary.schema_version).toBe(4);
    expect(summary.entry_count).toBe(10);
    expect(summary.written).toBe(false);
  });

  it("import actually restores into a vault and guards non-empty targets", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-import-"));
    const backup = join(dir, "backup.json");
    await run("--vault", vaultPath, "vault", "export", backup);

    // Fresh empty vault: import writes without --yes
    const target = join(dir, "target.enc");
    await writeFile(
      target,
      await encryptV3(deriveIndexKeyBytes(MNEMONIC), utf8(JSON.stringify({ schema_version: 4, entries: {} }))),
    );
    const first = await run("--vault", target, "vault", "import", backup);
    expect(JSON.parse(first.stdout).entry_count).toBe(10);
    const listed = JSON.parse((await run("--vault", target, "entry", "list")).stdout);
    expect(listed).toHaveLength(10);

    // Now non-empty: refuses without --yes, proceeds with it
    const guarded = await run("--vault", target, "vault", "import", backup);
    expect(String((guarded.error as Error).message)).toContain("--yes");
    const forced = await run("--vault", target, "vault", "import", backup, "--yes");
    expect(JSON.parse(forced.stdout).entry_count).toBe(10);
  });
});

describe("document import/export", () => {
  it("imports a file and exports it back, matching Python's naming rules", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-doc-"));
    const src = join(dir, "meeting notes.md");
    const body = "# Notes\n\nrecovery phrase is NOT here\n";
    await writeFile(src, body);

    const vaultCopy = join(dir, "vault.enc");
    await writeFile(vaultCopy, await readFile(vaultPath));

    const imported = JSON.parse(
      (await run("--vault", vaultCopy, "entry", "import-document", src)).stdout,
    );
    expect(imported.kind).toBe("document");
    expect(imported.label).toBe("meeting notes");
    expect(imported.file_type).toBe("md");
    // The body is a secret: it must not appear in provisioning output
    expect(imported).not.toHaveProperty("content");

    const outDir = join(dir, "out");
    const exported = JSON.parse(
      (await run(
        "--vault", vaultCopy, "entry", "export-document", "meeting notes", "--out", outDir,
      )).stdout,
    );
    // Spaces collapse to "_" exactly as Python sanitizes them
    expect(exported.exported).toBe(join(outDir, "meeting_notes.md"));
    expect(await readFile(exported.exported, "utf8")).toBe(body);

    const again = await run(
      "--vault", vaultCopy, "entry", "export-document", "meeting notes", "--out", outDir,
    );
    expect(String((again.error as Error).message)).toContain("already exists");

    const forced = await run(
      "--vault", vaultCopy, "entry", "export-document", "meeting notes",
      "--out", outDir, "--overwrite",
    );
    expect(JSON.parse(forced.stdout).exported).toBe(join(outDir, "meeting_notes.md"));
  });

  it("refuses to export a non-document entry", async () => {
    const r = await run("--vault", vaultPath, "entry", "export-document", "example.com");
    expect(String((r.error as Error).message)).toContain("not a document entry");
  });
});

describe("exit behaviour", () => {
  it("prints help without reporting it as an error when stdout is not a terminal", async () => {
    // Bare invocation launches the interactive mode on a terminal, but there
    // is no terminal to drive here, so it falls back to the help. Two bugs
    // met on this path: exitOverride() makes commander throw when it prints
    // help, and the handler reported that throw as "error: (outputHelp)".
    const out: string[] = [];
    const err: string[] = [];
    const io: ProgramIo = { out: (l) => out.push(l), err: (l) => err.push(l) };
    const previous = process.exitCode;
    let thrown: unknown;
    try {
      await buildProgram(io).parseAsync(["node", "seedpass-js"]);
    } catch (e) {
      thrown = e;
    }
    const printed = [...out, ...err].join("\n");
    expect(thrown).toBeUndefined();
    expect(printed).toContain("Usage: seedpass-js");
    expect(printed).not.toContain("outputHelp");
    expect(process.exitCode).toBe(1);
    process.exitCode = previous;
  });
});

describe("error messages", () => {
  it("explains a corrupt or foreign vault file instead of leaking a codec error", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-corrupt-"));
    const broken = join(dir, "broken.enc");
    await writeFile(broken, "not a seedpass vault");
    const r = await run("--vault", broken, "entry", "list");
    const msg = String((r.error as Error).message);
    expect(msg).toContain("could not decrypt vault");
    expect(msg).toContain("different seed");
  });
});

describe("unknown entry kinds at the CLI surface", () => {
  let foreignVault: string;
  const FOREIGN = {
    kind: "bitlogin_org",
    type: "bitlogin_org",
    label: "Acme Corporation",
    modified_ts: 1700000123,
    bitlogin: { admins: ["npub1aaaa"], api_token: "sk-live-visible-if-leaked" },
  };

  beforeAll(async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-cli-foreign-"));
    foreignVault = join(dir, "vault.enc");
    const key = deriveIndexKeyBytes(MNEMONIC);
    const index = {
      schema_version: 4,
      entries: {
        "0": {
          type: "key_value", kind: "key_value", label: "api", key: "k", value: "v",
          archived: false, notes: "", tags: [], links: [],
        },
        "1": FOREIGN,
      },
    };
    await writeFile(foreignVault, await encryptV3(key, utf8(JSON.stringify(index))));
  });

  it("lists a vault containing a foreign record, values redacted", async () => {
    const r = await run("--vault", foreignVault, "entry", "list");
    expect(r.error).toBeUndefined();
    const rows = JSON.parse(r.stdout) as Record<string, unknown>[];
    const foreign = rows.find((row) => row["kind"] === "bitlogin_org")!;
    expect(foreign).toBeDefined();
    expect(foreign["label"]).toBe("Acme Corporation");
    // Fields this build does not recognize are reported as present, never
    // dumped: another application's data is not ours to hand out.
    expect(foreign["has_bitlogin"]).toBe(true);
    expect(r.stdout).not.toContain("sk-live-visible-if-leaked");
    expect(r.stdout).not.toContain("npub1aaaa");
  });

  it("refuses to reveal a foreign record instead of guessing", async () => {
    const r = await run("--vault", foreignVault, "entry", "reveal", "sp://entry/1");
    expect(String((r.error as Error)?.message ?? r.stderr)).toMatch(/unsupported entry kind/);
    expect(r.stdout).not.toContain("sk-live");
  });

  it("mutating a neighbour entry does not disturb the foreign record", async () => {
    const r = await run("--vault", foreignVault, "entry", "add", "password", "new-site", "--length", "20");
    expect(r.error).toBeUndefined();
    const list = await run("--vault", foreignVault, "entry", "list");
    const rows = JSON.parse(list.stdout) as Record<string, unknown>[];
    // Allocation skipped past the foreign record's id.
    expect(rows.map((row) => row["id"])).toContain("2");
    expect(rows.find((row) => row["kind"] === "bitlogin_org")).toBeDefined();
  });
});

describe(".seedpass export naming", () => {
  it("a directory target gets the generated seedpass-<fp>-<date>.seedpass name", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-name-"));
    const r = await run("--vault", vaultPath, "vault", "export", dir);
    expect(r.error).toBeUndefined();
    const dest = String(JSON.parse(r.stdout).exported);
    expect(dest.startsWith(dir)).toBe(true);
    expect(dest).toMatch(/seedpass-[0-9A-F]{16}-\d{8}\.seedpass$/);
    // And the file restores like any other backup: same wrapper shape.
    const wrapper = JSON.parse(await readFile(dest, "utf8"));
    expect(wrapper.format_version).toBe(1);
  });

  it("an explicit file path is used exactly as typed (scripts depend on it)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-name-"));
    const exact = join(dir, "my-backup.json");
    const r = await run("--vault", vaultPath, "vault", "export", exact);
    expect(String(JSON.parse(r.stdout).exported)).toBe(exact);
  });

  it("an extensionless explicit path is also used exactly as typed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-name-"));
    const bare = join(dir, "backup");
    const r = await run("--vault", vaultPath, "vault", "export", bare);
    expect(String(JSON.parse(r.stdout).exported)).toBe(bare);
  });
});
