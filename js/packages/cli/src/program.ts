/**
 * seedpass-js command surface.
 *
 * Design constraint (plan section 9.3): default output is reference-first —
 * entry ids, labels, and metadata, never secret values. Plaintext egress
 * exists only as the distinct `entry reveal` command; `use` delivers secrets
 * to sinks (clipboard, child-process env, stdin) without printing them.
 */

import { Command } from "commander";
import process from "node:process";
import { entryMetadata, resolveEntry } from "./refs.js";
import { materializeSecret } from "./secrets.js";
import { clipboardSink, execSink, stdinSink } from "./sinks.js";
import { capabilities } from "./capabilities.js";
import { openVault, saveVault, type OpenedVault } from "./vaultFile.js";
import {
  importBackup,
  exportBackup,
  generateFingerprint,
  addPasswordEntry,
  addTotpDeterministic,
  addTotpImported,
  addKeyValueEntry,
  addDocumentEntry,
  addSeedEntry,
  addManagedAccountEntry,
  addNostrKeyEntry,
} from "@seedpass/core";
import { readFile, writeFile } from "node:fs/promises";

export interface ProgramIo {
  out(line: string): void;
  err(line: string): void;
}

const defaultIo: ProgramIo = {
  out: (line) => process.stdout.write(line + "\n"),
  err: (line) => process.stderr.write(line + "\n"),
};

function requireMnemonic(): string {
  const m = process.env["SEEDPASS_MNEMONIC"];
  if (!m) {
    throw new Error(
      "SEEDPASS_MNEMONIC is not set. Export the parent seed mnemonic into the " +
        "environment of this process (never pass it on the command line).",
    );
  }
  return m;
}

async function openFromOptions(opts: { vault?: string }): Promise<OpenedVault> {
  if (!opts.vault) throw new Error("--vault <file> is required");
  return openVault(opts.vault, requireMnemonic());
}

export function buildProgram(io: ProgramIo = defaultIo): Command {
  const program = new Command();
  program
    .name("seedpass-js")
    .description("SeedPass (TypeScript port) — reference-first CLI")
    .option("--vault <file>", "encrypted vault index file")
    .configureOutput({
      writeOut: (s) => io.out(s.replace(/\n$/, "")),
      writeErr: (s) => io.err(s.replace(/\n$/, "")),
    })
    .exitOverride();

  program
    .command("capabilities")
    .description("machine-readable capability map")
    .action(() => {
      io.out(JSON.stringify(capabilities(), null, 2));
    });

  const entry = program.command("entry").description("entry operations (reference-first)");

  entry
    .command("list")
    .description("list entries as references + metadata (no secrets)")
    .action(async () => {
      const vault = await openFromOptions(program.opts());
      const rows = Object.entries(vault.index.entries).map(([id, e]) =>
        entryMetadata(id, e),
      );
      io.out(JSON.stringify(rows, null, 2));
    });

  entry
    .command("get <refOrQuery>")
    .description("show one entry's reference + metadata (no secrets)")
    .action(async (refOrQuery: string) => {
      const vault = await openFromOptions(program.opts());
      const hit = resolveEntry(vault.index, refOrQuery);
      io.out(JSON.stringify(entryMetadata(hit.id, hit.entry), null, 2));
    });

  entry
    .command("search <text>")
    .description("substring search over labels/tags/notes (no secrets)")
    .action(async (text: string) => {
      const vault = await openFromOptions(program.opts());
      const needle = text.toLowerCase();
      const rows = Object.entries(vault.index.entries)
        .filter(([, e]) => {
          const hay = [e.label, e.notes ?? "", ...(e.tags ?? [])].join("\n").toLowerCase();
          return hay.includes(needle);
        })
        .map(([id, e]) => entryMetadata(id, e));
      io.out(JSON.stringify(rows, null, 2));
    });

  // Provisioning (plan section 9.3): create entries, get back a reference
  // and metadata — never the secret the entry represents. Deterministic
  // artifacts are recoverable from the seed; nothing extra to back up.
  const add = entry.command("add").description("create entries (returns references, not secrets)");

  const commonAddOptions = <T extends Command>(cmd: T): T => {
    cmd
      .option("--notes <text>", "notes", "")
      .option("--tags <tag...>", "tags")
      .option("--archived", "create archived");
    return cmd;
  };

  async function finishAdd(vault: OpenedVault, id: string): Promise<void> {
    await saveVault(vault);
    const e = vault.index.entries[id]!;
    io.out(JSON.stringify(entryMetadata(id, e), null, 2));
  }

  const commonOpts = (o: { notes?: string; tags?: string[]; archived?: boolean }) => ({
    notes: o.notes ?? "",
    ...(o.tags !== undefined && { tags: o.tags }),
    ...(o.archived !== undefined && { archived: o.archived }),
  });

  commonAddOptions(
    add
      .command("password <label>")
      .description("deterministic password entry (derives on demand; value never shown here)")
      .option("--length <n>", "password length", "16")
      .option("--username <name>", "username")
      .option("--url <url>", "site URL"),
  ).action(
    async (
      label: string,
      o: { length: string; username?: string; url?: string; notes?: string; tags?: string[]; archived?: boolean },
    ) => {
      const vault = await openFromOptions(program.opts());
      const id = addPasswordEntry(vault.index, label, Number(o.length), {
        ...commonOpts(o),
        ...(o.username !== undefined && { username: o.username }),
        ...(o.url !== undefined && { url: o.url }),
      });
      await finishAdd(vault, id);
    },
  );

  commonAddOptions(
    add
      .command("totp <label>")
      .description("TOTP entry: deterministic by default, or --secret to import")
      .option("--secret <b32>", "import an existing base32 secret")
      .option("--period <s>", "period seconds", "30")
      .option("--digits <n>", "code digits", "6"),
  ).action(
    async (
      label: string,
      o: { secret?: string; period: string; digits: string; notes?: string; tags?: string[]; archived?: boolean },
    ) => {
      const vault = await openFromOptions(program.opts());
      const opts = {
        ...commonOpts(o),
        period: Number(o.period),
        digits: Number(o.digits),
      };
      const id = o.secret
        ? addTotpImported(vault.index, label, o.secret, opts)
        : addTotpDeterministic(vault.index, label, vault.mnemonic, opts);
      await finishAdd(vault, id);
    },
  );

  commonAddOptions(
    add
      .command("key-value <label> <key> <value>")
      .description("store an arbitrary secret value"),
  ).action(
    async (
      label: string,
      key: string,
      value: string,
      o: { notes?: string; tags?: string[]; archived?: boolean },
    ) => {
      const vault = await openFromOptions(program.opts());
      const id = addKeyValueEntry(vault.index, label, key, value, commonOpts(o));
      await finishAdd(vault, id);
    },
  );

  commonAddOptions(
    add
      .command("document <label> <content>")
      .description("store a text document")
      .option("--file-type <ext>", "file type", "txt"),
  ).action(
    async (
      label: string,
      content: string,
      o: { fileType: string; notes?: string; tags?: string[]; archived?: boolean },
    ) => {
      const vault = await openFromOptions(program.opts());
      const id = addDocumentEntry(vault.index, label, content, {
        ...commonOpts(o),
        fileType: o.fileType,
      });
      await finishAdd(vault, id);
    },
  );

  commonAddOptions(
    add
      .command("seed <label>")
      .description("derived seed phrase entry (12/18/24 words)")
      .option("--words <n>", "word count", "24"),
  ).action(
    async (label: string, o: { words: string; notes?: string; tags?: string[]; archived?: boolean }) => {
      const vault = await openFromOptions(program.opts());
      const words = Number(o.words);
      if (words !== 12 && words !== 18 && words !== 24) {
        throw new Error("--words must be 12, 18 or 24");
      }
      const id = addSeedEntry(vault.index, label, {
        ...commonOpts(o),
        wordCount: words as 12 | 18 | 24,
      });
      await finishAdd(vault, id);
    },
  );

  commonAddOptions(
    add.command("managed-account <label>").description("BIP-85 managed account (12-word child seed)"),
  ).action(async (label: string, o: { notes?: string; tags?: string[]; archived?: boolean }) => {
    const vault = await openFromOptions(program.opts());
    const id = addManagedAccountEntry(vault.index, label, vault.mnemonic, commonOpts(o));
    await finishAdd(vault, id);
  });

  commonAddOptions(
    add.command("nostr <label>").description("derived Nostr key entry"),
  ).action(async (label: string, o: { notes?: string; tags?: string[]; archived?: boolean }) => {
    const vault = await openFromOptions(program.opts());
    const id = addNostrKeyEntry(vault.index, label, commonOpts(o));
    await finishAdd(vault, id);
  });

  entry
    .command("reveal <refOrQuery>")
    .description("PLAINTEXT EGRESS: print the secret to stdout")
    .option("--at <timestamp>", "TOTP: unix time to compute the code at")
    .action(async (refOrQuery: string, cmdOpts: { at?: string }) => {
      const vault = await openFromOptions(program.opts());
      const hit = resolveEntry(vault.index, refOrQuery);
      const secret = materializeSecret(vault.index, hit.id, hit.entry, vault.mnemonic, {
        ...(cmdOpts.at !== undefined && { timestamp: Number(cmdOpts.at) }),
      });
      io.out(secret.value);
    });

  program
    .command("use <refOrQuery>")
    .description("deliver a secret to a sink without printing it")
    .option("--clipboard", "copy to the system clipboard")
    .option("--exec <cmd...>", "run a command with SEEDPASS_SECRET in its env")
    .option("--stdin-to <cmd...>", "pipe the secret to a command's stdin")
    .option("--at <timestamp>", "TOTP: unix time to compute the code at")
    .action(
      async (
        refOrQuery: string,
        cmdOpts: { clipboard?: boolean; exec?: string[]; stdinTo?: string[]; at?: string },
      ) => {
        const chosen = [cmdOpts.clipboard, cmdOpts.exec, cmdOpts.stdinTo].filter(
          (v) => v !== undefined,
        ).length;
        if (chosen !== 1) {
          throw new Error("choose exactly one sink: --clipboard, --exec, or --stdin-to");
        }
        const vault = await openFromOptions(program.opts());
        const hit = resolveEntry(vault.index, refOrQuery);
        const secret = materializeSecret(vault.index, hit.id, hit.entry, vault.mnemonic, {
          ...(cmdOpts.at !== undefined && { timestamp: Number(cmdOpts.at) }),
        });

        let result;
        if (cmdOpts.clipboard) {
          result = await clipboardSink(secret.value);
        } else if (cmdOpts.exec) {
          const [cmd, ...args] = cmdOpts.exec;
          result = await execSink(secret.value, cmd!, args);
        } else {
          const [cmd, ...args] = cmdOpts.stdinTo!;
          result = await stdinSink(secret.value, cmd!, args);
        }
        io.out(
          JSON.stringify({
            delivered: secret.descriptor,
            ref: hit.ref,
            ...result,
          }),
        );
      },
    );

  const vaultCmd = program.command("vault").description("vault import/export");

  vaultCmd
    .command("export <destFile>")
    .description("write a portable backup (encrypted by default)")
    .option("--plaintext", "HIGH RISK: export without encryption")
    .action(async (destFile: string, cmdOpts: { plaintext?: boolean }) => {
      const vault = await openFromOptions(program.opts());
      const wrapper = await exportBackup(vault.index as Record<string, unknown>, {
        mnemonic: vault.mnemonic,
        fingerprint: generateFingerprint(vault.mnemonic),
        encrypt: !cmdOpts.plaintext,
      });
      await writeFile(destFile, JSON.stringify(wrapper, null, 2) + "\n", { mode: 0o600 });
      io.out(
        JSON.stringify({
          exported: destFile,
          encrypted: !cmdOpts.plaintext,
          checksum: wrapper.checksum,
        }),
      );
    });

  vaultCmd
    .command("import <srcFile>")
    .description("read a portable backup and print its reference summary")
    .action(async (srcFile: string) => {
      const raw = await readFile(srcFile);
      const mnemonic = process.env["SEEDPASS_MNEMONIC"];
      const index = await importBackup(new Uint8Array(raw), {
        ...(mnemonic && { mnemonic }),
      });
      const entries = (index["entries"] ?? {}) as Record<string, { label?: string }>;
      io.out(
        JSON.stringify({
          imported: srcFile,
          schema_version: index["schema_version"],
          entry_count: Object.keys(entries).length,
        }),
      );
    });

  return program;
}
