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

  it("use refuses ambiguous sink selection", async () => {
    const r = await run(
      "--vault", vaultPath, "use", "api-token", "--clipboard", "--stdin-to", "cat",
    );
    expect(String((r.error as Error).message)).toContain("exactly one sink");
  });
});

describe("vault export/import", () => {
  it("exports an encrypted portable backup the importer accepts", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-export-"));
    const dest = join(dir, "backup.json");
    const exportResult = await run("--vault", vaultPath, "vault", "export", dest);
    expect(JSON.parse(exportResult.stdout).encrypted).toBe(true);

    const importResult = await run("vault", "import", dest);
    const summary = JSON.parse(importResult.stdout);
    expect(summary.schema_version).toBe(4);
    expect(summary.entry_count).toBe(10);
  });
});
