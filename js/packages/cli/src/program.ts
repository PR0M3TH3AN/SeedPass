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
import { entryMetadata, parseRef, resolveEntry } from "./refs.js";
import { materializeSecret } from "./secrets.js";
import { clipboardSink, execSink, parseCommandSpec, stdinSink } from "./sinks.js";
import { capabilities } from "./capabilities.js";
import {
  openVault,
  saveVault,
  saveVaultHoldingLock,
  withVaultLock,
  atomicWrite,
  type OpenedVault,
} from "./vaultFile.js";
import {
  importBackup,
  exportBackup,
  generateFingerprint,
  assertValidMnemonic,
  modifyEntry,
  archiveEntry,
  restoreEntry,
  addLink,
  removeLink,
  getLinks,
  generatePassword,
  Bip85,
  totpCodeAt,
  deriveTotpSecret,
  deriveNostrKeys,
  deriveKeyIndex,
  deriveIndexKeyBytes,
  RelayPool,
  publishSnapshot,
  fetchLatestSnapshot,
  fetchDeltasSince,
  decryptPayload,
  parseEncryptedFile,
  mergeIndexPayloads,
  parseVaultIndex,
  sha256Hex,
  type ModifyChanges,
  type PasswordPolicy,
  addPasswordEntry,
  addTotpDeterministic,
  addTotpImported,
  addKeyValueEntry,
  addDocumentEntry,
  addSeedEntry,
  addManagedAccountEntry,
  addNostrKeyEntry,
  addSshKeyEntry,
  addPgpKeyEntry,
  deriveSshKeyPair,
  derivePgpKey,
  sshPublicKeyOpenSsh,
} from "@seedpass/core";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { basename, dirname, extname, join } from "node:path";
import { homedir } from "node:os";

/**
 * Parse a numeric option, refusing anything that would poison the vault.
 *
 * `Number("not-a-number")` is NaN, which JSON.stringify writes as null; a
 * single bad --length once persisted an unreadable entry that failed schema
 * validation on every subsequent open. Validate before anything is stored.
 */
function parseIntOption(raw: string, name: string, opts: { min?: number; max?: number } = {}): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || !Number.isInteger(value)) {
    throw new Error(`${name} must be a whole number (got ${JSON.stringify(raw)})`);
  }
  if (opts.min !== undefined && value < opts.min) {
    throw new Error(`${name} must be at least ${opts.min} (got ${value})`);
  }
  if (opts.max !== undefined && value > opts.max) {
    throw new Error(`${name} must be at most ${opts.max} (got ${value})`);
  }
  return value;
}

/** Unix timestamps may be large but must still be real integers. */
function parseUnixTime(raw: string): number {
  return parseIntOption(raw, "--at", { min: 0 });
}

/** Expand a leading ~ the way Python's Path.expanduser does. */
function resolveHome(p: string): string {
  return p.startsWith("~") ? join(homedir(), p.slice(1)) : p;
}
import { AppDir, resolveAppDir, INDEX_FILENAME } from "./appDir.js";
import { loadConfig, saveConfig } from "./configFile.js";
import { AgentClient, AgentDaemon, agentSocketPath, DEFAULT_TTL_SECONDS } from "./agent.js";
import { AuditLog } from "./audit.js";

export interface ProgramIo {
  out(line: string): void;
  err(line: string): void;
}

const defaultIo: ProgramIo = {
  out: (line) => process.stdout.write(line + "\n"),
  err: (line) => process.stderr.write(line + "\n"),
};

interface GlobalOpts {
  vault?: string;
  appDir?: string;
  fingerprint?: string;
}

async function currentFingerprint(app: AppDir, opts: GlobalOpts): Promise<string> {
  if (opts.fingerprint) return opts.fingerprint;
  const data = await app.readFingerprints();
  if (!data.last_used) throw new Error("no profile selected; run 'fingerprint add' first");
  return data.last_used;
}

/**
 * Seed resolution order: SEEDPASS_MNEMONIC env -> session agent -> error.
 * The mnemonic never comes from argv.
 */
async function resolveMnemonic(app: AppDir, opts: GlobalOpts): Promise<string> {
  const env = process.env["SEEDPASS_MNEMONIC"];
  if (env) {
    // Catch a typo'd phrase at the boundary rather than deriving a silently
    // different vault from it.
    assertValidMnemonic(env, "SEEDPASS_MNEMONIC");
    return env;
  }
  // A process that authenticates with a scoped token has declared itself a
  // constrained principal: it must never escalate to owner access by
  // pulling the mnemonic from the unlocked agent.
  if (process.env["SEEDPASS_TOKEN"]) {
    throw new Error(
      "token mode: this operation requires owner access (unset SEEDPASS_TOKEN " +
        "and unlock as the owner)",
    );
  }
  try {
    const fp = await currentFingerprint(app, opts);
    const client = new AgentClient(agentSocketPath(app.root));
    const held = await client.ownerMnemonic(fp);
    if (held) return held;
  } catch {
    // fall through to the error below
  }
  throw new Error(
    "vault is locked: set SEEDPASS_MNEMONIC, or run 'seedpass-js vault unlock' " +
      "with the session agent running ('seedpass-js agent start')",
  );
}

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

async function openFromOptions(opts: GlobalOpts): Promise<OpenedVault> {
  const app = new AppDir(resolveAppDir(opts.appDir));
  if (opts.vault) {
    return openVault(opts.vault, await resolveMnemonic(app, opts));
  }
  const fp = await currentFingerprint(app, opts);
  const path = join(app.profileDir(fp), INDEX_FILENAME);
  return openVault(path, await resolveMnemonic(app, opts));
}

/**
 * Run a mutation under the vault lock, holding it for the whole
 * read-modify-write cycle.
 *
 * Locking only the write still loses changes: two commands can each read the
 * same index, mutate their copy, and write in turn. Everything that changes
 * the vault must go through here.
 */
async function mutateVault<T>(
  opts: GlobalOpts,
  fn: (vault: OpenedVault) => Promise<T> | T,
): Promise<T> {
  const app = new AppDir(resolveAppDir(opts.appDir));
  const path =
    opts.vault ?? join(app.profileDir(await currentFingerprint(app, opts)), INDEX_FILENAME);
  const mnemonic = await resolveMnemonic(app, opts);
  return withVaultLock(path, async () => {
    const vault = await openVault(path, mnemonic);
    const result = await fn(vault);
    await saveVaultHoldingLock(vault);
    return result;
  });
}

/**
 * Read/secret access that works in two modes:
 *  - owner mode (mnemonic via env or agent): full local access
 *  - token mode (SEEDPASS_TOKEN set, no mnemonic): every read and secret
 *    goes through the agent, which enforces the token's scopes/kinds/label
 *    constraints and writes the audit trail. The mnemonic never reaches
 *    this process.
 */
interface ReadAccess {
  /** Redacted metadata rows, already filtered to what the caller may see. */
  rows(): Promise<Array<Record<string, unknown>>>;
  /** Resolve a ref/label/id to an entry id, using visible metadata only. */
  resolveId(refOrQuery: string): Promise<{ id: string; ref: string; label: string; kind: string }>;
  mode: "owner" | "token";
  /** Plaintext egress. In token mode this requires the reveal scope. */
  reveal(id: string, timestamp?: number): Promise<{ value: string; descriptor: string }>;
  /** Deliver to a sink. In token mode the agent runs the sink itself. */
  deliver(
    id: string,
    sink: "clipboard" | "exec" | "stdin",
    command: string[],
    timestamp?: number,
  ): Promise<Record<string, unknown>>;
}

function resolveFromRows(
  rows: Array<Record<string, unknown>>,
  refOrQuery: string,
): { id: string; ref: string; label: string; kind: string } {
  const asRow = (r: Record<string, unknown>) => ({
    id: String(r["id"]),
    ref: String(r["ref"]),
    label: String(r["label"] ?? ""),
    kind: String(r["kind"] ?? ""),
  });
  const refId = parseRef(refOrQuery);
  const byId = (id: string) => rows.find((r) => String(r["id"]) === id);
  if (refId !== null) {
    const hit = byId(refId);
    if (!hit) throw new Error(`no entry for reference ${refOrQuery}`);
    return asRow(hit);
  }
  if (/^\d+$/.test(refOrQuery)) {
    const hit = byId(refOrQuery);
    if (hit) return asRow(hit);
  }
  const labelHits = rows.filter((r) => String(r["label"] ?? "") === refOrQuery);
  if (labelHits.length === 1) return asRow(labelHits[0]!);
  if (labelHits.length > 1) {
    throw new Error(
      `label "${refOrQuery}" is ambiguous (${labelHits.length} entries); use an id or sp:// reference`,
    );
  }
  throw new Error(`no entry matches "${refOrQuery}"`);
}

async function openReadAccess(opts: GlobalOpts): Promise<ReadAccess> {
  const token = process.env["SEEDPASS_TOKEN"];
  const app = new AppDir(resolveAppDir(opts.appDir));
  if (token && !process.env["SEEDPASS_MNEMONIC"]) {
    const fp = await currentFingerprint(app, opts);
    const client = new AgentClient(agentSocketPath(app.root));
    let cached: Array<Record<string, unknown>> | null = null;
    const rows = async () => {
      cached ??= await client.vaultEntries(fp, token);
      return cached;
    };
    return {
      mode: "token",
      rows,
      resolveId: async (refOrQuery) => resolveFromRows(await rows(), refOrQuery),
      reveal: async (id, timestamp) =>
        client.secret({
          fingerprint: fp,
          id,
          token,
          ...(timestamp !== undefined && { timestamp }),
        }),
      deliver: async (id, sink, command, timestamp) =>
        client.useSink({
          fingerprint: fp,
          id,
          token,
          sink,
          command,
          ...(timestamp !== undefined && { timestamp }),
        }),
    };
  }
  const vault = await openFromOptions(opts);
  const localRows = async () =>
    Object.entries(vault.index.entries).map(([id, e]) => entryMetadata(id, e));
  const localSecret = (id: string, timestamp?: number) => {
    const entry = vault.index.entries[id];
    if (!entry) throw new Error(`no entry ${id}`);
    return materializeSecret(vault.index, id, entry, vault.mnemonic, {
      ...(timestamp !== undefined && { timestamp }),
    });
  };
  return {
    mode: "owner",
    rows: localRows,
    resolveId: async (refOrQuery) => {
      const hit = resolveEntry(vault.index, refOrQuery);
      return { id: hit.id, ref: hit.ref, label: hit.entry.label, kind: hit.entry.kind };
    },
    reveal: async (id, timestamp) => localSecret(id, timestamp),
    deliver: async (id, sink, command, timestamp) => {
      const secret = localSecret(id, timestamp);
      const result =
        sink === "clipboard"
          ? await clipboardSink(secret.value)
          : sink === "exec"
            ? await execSink(secret.value, ...parseCommandSpec(command))
            : await stdinSink(secret.value, ...parseCommandSpec(command));
      return { descriptor: secret.descriptor, ...result };
    },
  };
}

export function buildProgram(io: ProgramIo = defaultIo): Command {
  const program = new Command();
  program
    .name("seedpass-js")
    .description("SeedPass (TypeScript port) — reference-first CLI")
    .option("--vault <file>", "encrypted vault index file (overrides profile)")
    .option("--app-dir <dir>", "application directory (default ~/.seedpass)")
    .option("--fingerprint <fp>", "profile fingerprint (default: last used)")
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
      const access = await openReadAccess(program.opts());
      io.out(JSON.stringify(await access.rows(), null, 2));
    });

  entry
    .command("get <refOrQuery>")
    .description("show one entry's reference + metadata (no secrets)")
    .action(async (refOrQuery: string) => {
      const access = await openReadAccess(program.opts());
      const hit = await access.resolveId(refOrQuery);
      const row = (await access.rows()).find((r) => String(r["id"]) === hit.id);
      io.out(JSON.stringify(row, null, 2));
    });

  entry
    .command("search <text>")
    .description("substring search over labels/tags/notes (no secrets)")
    .action(async (text: string) => {
      const access = await openReadAccess(program.opts());
      const needle = text.toLowerCase();
      const rows = (await access.rows()).filter((r) => {
        const tags = Array.isArray(r["tags"]) ? (r["tags"] as string[]) : [];
        const hay = [String(r["label"] ?? ""), String(r["notes"] ?? ""), ...tags]
          .join("\n")
          .toLowerCase();
        return hay.includes(needle);
      });
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

  /** Create an entry under the lock and print its reference + metadata. */
  async function addEntry(
    create: (vault: OpenedVault) => string,
  ): Promise<void> {
    const row = await mutateVault(program.opts(), (vault) => {
      const id = create(vault);
      return entryMetadata(id, vault.index.entries[id]!);
    });
    io.out(JSON.stringify(row, null, 2));
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
      await addEntry((vault) => addPasswordEntry(vault.index, label, parseIntOption(o.length, "--length", { min: 8, max: 128 }), {
        ...commonOpts(o),
        ...(o.username !== undefined && { username: o.username }),
        ...(o.url !== undefined && { url: o.url }),
      }));
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
      const opts = {
        ...commonOpts(o),
        period: parseIntOption(o.period, "--period", { min: 1 }),
        digits: parseIntOption(o.digits, "--digits", { min: 6, max: 10 }),
      };
      await addEntry((vault) =>
        o.secret
          ? addTotpImported(vault.index, label, o.secret, opts)
          : addTotpDeterministic(vault.index, label, vault.mnemonic, opts),
      );
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
      await addEntry((vault) => addKeyValueEntry(vault.index, label, key, value, commonOpts(o)));
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
      await addEntry((vault) => addDocumentEntry(vault.index, label, content, {
        ...commonOpts(o),
        fileType: o.fileType,
      }));
    },
  );

  commonAddOptions(
    add
      .command("seed <label>")
      .description("derived seed phrase entry (12/18/24 words)")
      .option("--words <n>", "word count", "24"),
  ).action(
    async (label: string, o: { words: string; notes?: string; tags?: string[]; archived?: boolean }) => {
      const words = parseIntOption(o.words, "--words");
      if (words !== 12 && words !== 18 && words !== 24) {
        throw new Error("--words must be 12, 18 or 24");
      }
      await addEntry((vault) =>
        addSeedEntry(vault.index, label, {
          ...commonOpts(o),
          wordCount: words as 12 | 18 | 24,
        }),
      );
    },
  );

  commonAddOptions(
    add.command("managed-account <label>").description("BIP-85 managed account (12-word child seed)"),
  ).action(async (label: string, o: { notes?: string; tags?: string[]; archived?: boolean }) => {
    await addEntry((vault) =>
      addManagedAccountEntry(vault.index, label, vault.mnemonic, commonOpts(o)),
    );
  });

  commonAddOptions(
    add.command("nostr <label>").description("derived Nostr key entry"),
  ).action(async (label: string, o: { notes?: string; tags?: string[]; archived?: boolean }) => {
    await addEntry((vault) => addNostrKeyEntry(vault.index, label, commonOpts(o)));
  });

  commonAddOptions(
    add.command("ssh <label>").description("derived Ed25519 SSH key entry"),
  ).action(async (label: string, o: { notes?: string; tags?: string[]; archived?: boolean }) => {
    await addEntry((vault) => addSshKeyEntry(vault.index, label, commonOpts(o)));
  });

  commonAddOptions(
    add
      .command("pgp <label>")
      .description("derived Ed25519 PGP key entry")
      .option("--user-id <uid>", "PGP user id", ""),
  ).action(
    async (
      label: string,
      o: { userId: string; notes?: string; tags?: string[]; archived?: boolean },
    ) => {
      await addEntry((vault) => addPgpKeyEntry(vault.index, label, {
        ...commonOpts(o),
        userId: o.userId,
      }));
    },
  );

  entry
    .command("import-document <file>")
    .description("import a local text file as a document entry")
    .option("--label <text>", "title override (default: the file's stem)")
    .option("--notes <text>", "entry notes", "")
    .option("--tags <tag...>", "tags")
    .action(
      async (
        file: string,
        o: { label?: string; notes: string; tags?: string[] },
      ) => {
        const path = resolveHome(file);
        // Documents are stored as text, matching Python's read_text.
        const content = await readFile(path, "utf8");
        const base = basename(path);
        const ext = extname(base).replace(/^\./, "").toLowerCase();
        await addEntry((vault) =>
          addDocumentEntry(vault.index, o.label || base.replace(/\.[^.]*$/, ""), content, {
            fileType: ext || "txt",
            notes: o.notes,
            ...(o.tags !== undefined && { tags: o.tags }),
          }),
        );
      },
    );

  entry
    .command("export-document <refOrQuery>")
    .description("write a document entry to a file (plaintext egress)")
    .option("--out <path>", "output file or directory (default: cwd)")
    .option("--overwrite", "replace an existing file")
    .action(async (refOrQuery: string, o: { out?: string; overwrite?: boolean }) => {
      const vault = await openFromOptions(program.opts());
      const hit = resolveEntry(vault.index, refOrQuery);
      if (hit.entry.kind !== "document") throw new Error(`${hit.ref} is not a document entry`);
      const fileType = (hit.entry.file_type || "txt").trim().toLowerCase() || "txt";
      // Same sanitization as Python: non-portable characters collapse to "_".
      const stem =
        hit.entry.label.trim().replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+|[._]+$/g, "") ||
        `document_${hit.id}`;

      let dest: string;
      if (o.out === undefined) {
        dest = join(process.cwd(), `${stem}.${fileType}`);
      } else {
        const raw = resolveHome(o.out);
        const isDir = existsSync(raw) && statSync(raw).isDirectory();
        dest = isDir || !extname(raw) ? join(raw, `${stem}.${fileType}`) : raw;
      }
      await mkdir(dirname(dest), { recursive: true });
      if (existsSync(dest) && !o.overwrite) {
        throw new Error(`File already exists: ${dest} (use --overwrite)`);
      }
      await writeFile(dest, hit.entry.content, { mode: 0o600 });
      io.out(JSON.stringify({ exported: dest, ref: hit.ref, bytes: hit.entry.content.length }));
    });

  entry
    .command("pgp-public <refOrQuery>")
    .description("print a PGP entry's public key block (not secret material)")
    .action(async (refOrQuery: string) => {
      const vault = await openFromOptions(program.opts());
      const hit = resolveEntry(vault.index, refOrQuery);
      if (hit.entry.kind !== "pgp") throw new Error(`${hit.ref} is not a pgp entry`);
      const key = derivePgpKey(vault.mnemonic, hit.entry.index, {
        userId: hit.entry.user_id,
        keyType: hit.entry.key_type,
      });
      io.out(JSON.stringify({ fingerprint: key.fingerprint }));
      io.out(key.publicKeyArmored.trimEnd());
    });

  entry
    .command("ssh-public <refOrQuery>")
    .description("print an SSH entry's public key (not secret material)")
    .option("--format <fmt>", "pem or openssh", "openssh")
    .option("--comment <text>", "comment for the openssh format", "")
    .action(async (refOrQuery: string, o: { format: string; comment: string }) => {
      const vault = await openFromOptions(program.opts());
      const hit = resolveEntry(vault.index, refOrQuery);
      if (hit.entry.kind !== "ssh") throw new Error(`${hit.ref} is not an ssh entry`);
      const pair = deriveSshKeyPair(vault.mnemonic, hit.entry.index);
      io.out(
        o.format === "pem"
          ? pair.publicKeyPem.trimEnd()
          : sshPublicKeyOpenSsh(pair.publicKey, o.comment || hit.entry.label),
      );
    });

  entry
    .command("modify <refOrQuery>")
    .description("update entry fields (kind-checked); prints the new metadata")
    .option("--label <text>")
    .option("--username <text>")
    .option("--url <text>")
    .option("--notes <text>")
    .option("--tags <tag...>")
    .option("--period <n>")
    .option("--digits <n>")
    .option("--key <text>")
    .option("--value <text>", "new secret value (key_value/managed_account)")
    .option("--content <text>", "new document content")
    .option("--file-type <ext>")
    .action(
      async (
        refOrQuery: string,
        o: {
          label?: string; username?: string; url?: string; notes?: string;
          tags?: string[]; period?: string; digits?: string; key?: string;
          value?: string; content?: string; fileType?: string;
        },
      ) => {
        const changes: ModifyChanges = {
          ...(o.label !== undefined && { label: o.label }),
          ...(o.username !== undefined && { username: o.username }),
          ...(o.url !== undefined && { url: o.url }),
          ...(o.notes !== undefined && { notes: o.notes }),
          ...(o.tags !== undefined && { tags: o.tags }),
          ...(o.period !== undefined && { period: parseIntOption(o.period, "--period", { min: 1 }) }),
          ...(o.digits !== undefined && { digits: parseIntOption(o.digits, "--digits", { min: 6, max: 10 }) }),
          ...(o.key !== undefined && { key: o.key }),
          ...(o.value !== undefined && { value: o.value }),
          ...(o.content !== undefined && { content: o.content }),
          ...(o.fileType !== undefined && { file_type: o.fileType }),
        };
        if (Object.keys(changes).length === 0) throw new Error("no changes given");
        const row = await mutateVault(program.opts(), (vault) => {
          const hit = resolveEntry(vault.index, refOrQuery);
          modifyEntry(vault.index, hit.id, changes);
          return entryMetadata(hit.id, vault.index.entries[hit.id]!);
        });
        io.out(JSON.stringify(row, null, 2));
      },
    );

  entry
    .command("archive <refOrQuery>")
    .description("archive an entry")
    .action(async (refOrQuery: string) => {
      const ref = await mutateVault(program.opts(), (vault) => {
        const hit = resolveEntry(vault.index, refOrQuery);
        archiveEntry(vault.index, hit.id);
        return hit.ref;
      });
      io.out(JSON.stringify({ ref, archived: true }));
    });

  entry
    .command("unarchive <refOrQuery>")
    .description("restore an archived entry")
    .action(async (refOrQuery: string) => {
      const ref = await mutateVault(program.opts(), (vault) => {
        const hit = resolveEntry(vault.index, refOrQuery);
        restoreEntry(vault.index, hit.id);
        return hit.ref;
      });
      io.out(JSON.stringify({ ref, archived: false }));
    });

  entry
    .command("links <refOrQuery>")
    .description("list an entry's links with resolved targets")
    .action(async (refOrQuery: string) => {
      const vault = await openFromOptions(program.opts());
      const hit = resolveEntry(vault.index, refOrQuery);
      io.out(JSON.stringify(getLinks(vault.index, hit.id), null, 2));
    });

  entry
    .command("link-add <refOrQuery> <target>")
    .description("link an entry to another")
    .option("--relation <name>", "relation type", "related_to")
    .option("--note <text>", "link note", "")
    .action(async (refOrQuery: string, target: string, o: { relation: string; note: string }) => {
      const result = await mutateVault(program.opts(), (vault) => {
        const hit = resolveEntry(vault.index, refOrQuery);
        const targetHit = resolveEntry(vault.index, target);
        const links = addLink(vault.index, hit.id, Number(targetHit.id), {
          relation: o.relation,
          note: o.note,
        });
        return { ref: hit.ref, links };
      });
      io.out(JSON.stringify(result, null, 2));
    });

  entry
    .command("link-remove <refOrQuery> <target>")
    .description("remove links to a target entry")
    .option("--relation <name>", "only remove this relation")
    .action(async (refOrQuery: string, target: string, o: { relation?: string }) => {
      const result = await mutateVault(program.opts(), (vault) => {
        const hit = resolveEntry(vault.index, refOrQuery);
        const targetHit = resolveEntry(vault.index, target);
        const links = removeLink(vault.index, hit.id, Number(targetHit.id), {
          ...(o.relation !== undefined && { relation: o.relation }),
        });
        return { ref: hit.ref, links };
      });
      io.out(JSON.stringify(result, null, 2));
    });

  entry
    .command("totp-codes")
    .description("PLAINTEXT EGRESS: current codes for all active TOTP entries")
    .option("--at <timestamp>", "unix time to compute codes at")
    .action(async (cmdOpts: { at?: string }) => {
      const vault = await openFromOptions(program.opts());
      const ts = cmdOpts.at !== undefined ? parseUnixTime(cmdOpts.at) : Math.floor(Date.now() / 1000);
      const rows = Object.entries(vault.index.entries)
        .filter(([, e]) => e.kind === "totp" && !e.archived)
        .map(([id, e]) => {
          const totp = e as { secret?: string; index?: number; period: number; digits: number; label: string };
          const secret = totp.secret ?? deriveTotpSecret(vault.mnemonic, totp.index ?? 0);
          return {
            ref: `sp://entry/${id}`,
            label: totp.label,
            code: totpCodeAt(secret, ts, totp.period, totp.digits),
            period: totp.period,
            seconds_remaining: totp.period - (ts % totp.period),
          };
        });
      io.out(JSON.stringify(rows, null, 2));
    });

  entry
    .command("reveal <refOrQuery>")
    .description("PLAINTEXT EGRESS: print the secret to stdout")
    .option("--at <timestamp>", "TOTP: unix time to compute the code at")
    .action(async (refOrQuery: string, cmdOpts: { at?: string }) => {
      const access = await openReadAccess(program.opts());
      const hit = await access.resolveId(refOrQuery);
      const secret = await access.reveal(
        hit.id,
        cmdOpts.at !== undefined ? parseUnixTime(cmdOpts.at) : undefined,
      );
      io.out(secret.value);
    });

  program
    .command("use <refOrQuery>")
    .description("deliver a secret to a sink without printing it")
    .option("--clipboard", "copy to the system clipboard")
    .option(
      "--exec <cmd...>",
      'run a command with SEEDPASS_SECRET in its env (quote it to include flags: --exec "cmd -f")',
    )
    .option(
      "--stdin-to <cmd...>",
      'pipe the secret to a command\'s stdin (quote it to include flags: --stdin-to "wc -c")',
    )
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
        const access = await openReadAccess(program.opts());
        const hit = await access.resolveId(refOrQuery);
        const sink = cmdOpts.clipboard ? "clipboard" : cmdOpts.exec ? "exec" : "stdin";
        const command = cmdOpts.clipboard ? [] : (cmdOpts.exec ?? cmdOpts.stdinTo!);
        // In token mode the agent runs the sink: the secret is never sent
        // back to this process.
        const result = await access.deliver(
          hit.id,
          sink,
          command,
          cmdOpts.at !== undefined ? parseUnixTime(cmdOpts.at) : undefined,
        );
        io.out(
          JSON.stringify({
            delivered: result["descriptor"],
            ref: hit.ref,
            mode: access.mode,
            ...Object.fromEntries(
              Object.entries(result).filter(([k]) => k !== "descriptor"),
            ),
          }),
        );
      },
    );

  const fingerprint = program.command("fingerprint").description("profile management");

  fingerprint
    .command("list")
    .description("list profiles")
    .action(async () => {
      const app = new AppDir(resolveAppDir((program.opts() as GlobalOpts).appDir));
      const data = await app.readFingerprints();
      io.out(
        JSON.stringify(
          data.fingerprints.map((fp) => ({
            fingerprint: fp,
            name: data.names[fp] ?? null,
            current: fp === data.last_used,
          })),
          null,
          2,
        ),
      );
    });

  fingerprint
    .command("add")
    .description("create a profile from SEEDPASS_MNEMONIC + SEEDPASS_PASSWORD")
    .option("--name <name>", "human-readable profile name")
    .action(async (o: { name?: string }) => {
      const app = new AppDir(resolveAppDir((program.opts() as GlobalOpts).appDir));
      const mnemonic = requireMnemonic();
      const password = process.env["SEEDPASS_PASSWORD"];
      if (!password) throw new Error("SEEDPASS_PASSWORD is not set");
      const fp = await app.createProfile(mnemonic, password, o.name);
      io.out(JSON.stringify({ fingerprint: fp, name: o.name ?? null }));
    });

  fingerprint
    .command("switch <fp>")
    .description("set the active profile")
    .action(async (fp: string) => {
      const app = new AppDir(resolveAppDir((program.opts() as GlobalOpts).appDir));
      await app.switchProfile(fp);
      io.out(JSON.stringify({ current: fp }));
    });

  fingerprint
    .command("remove <fp>")
    .description("DESTRUCTIVE: delete a profile directory")
    .option("--yes", "confirm deletion")
    .action(async (fp: string, o: { yes?: boolean }) => {
      if (!o.yes) throw new Error("refusing to delete without --yes");
      const app = new AppDir(resolveAppDir((program.opts() as GlobalOpts).appDir));
      await app.removeProfile(fp);
      io.out(JSON.stringify({ removed: fp }));
    });

  const config = program.command("config").description("per-profile configuration");

  config
    .command("get [key]")
    .description("read config (whole object or one key); secret hashes redacted")
    .action(async (key: string | undefined) => {
      const opts = program.opts() as GlobalOpts;
      const app = new AppDir(resolveAppDir(opts.appDir));
      const fp = await currentFingerprint(app, opts);
      const cfg = await loadConfig(app.profileDir(fp), await resolveMnemonic(app, opts));
      for (const k of ["pin_hash", "password_hash"]) {
        if (cfg[k]) cfg[k] = "<redacted>";
      }
      io.out(JSON.stringify(key !== undefined ? { [key]: cfg[key] } : cfg, null, 2));
    });

  config
    .command("set <key> <value>")
    .description("set a config value (JSON-parsed when possible)")
    .action(async (key: string, value: string) => {
      const opts = program.opts() as GlobalOpts;
      const app = new AppDir(resolveAppDir(opts.appDir));
      const fp = await currentFingerprint(app, opts);
      const mnemonic = await resolveMnemonic(app, opts);
      const cfg = await loadConfig(app.profileDir(fp), mnemonic);
      let parsed: unknown = value;
      try {
        parsed = JSON.parse(value);
      } catch {
        // keep as string
      }
      cfg[key] = parsed;
      await saveConfig(app.profileDir(fp), mnemonic, cfg);
      io.out(JSON.stringify({ [key]: parsed }));
    });

  const nostr = program.command("nostr").description("Nostr relay sync");

  async function nostrContext(opts: GlobalOpts) {
    const app = new AppDir(resolveAppDir(opts.appDir));
    const fp = await currentFingerprint(app, opts);
    const mnemonic = await resolveMnemonic(app, opts);
    const cfg = await loadConfig(app.profileDir(fp), mnemonic);
    const relays = cfg["relays"] as string[];
    const keys = deriveNostrKeys(Bip85.fromMnemonic(mnemonic), 0);
    return { app, fp, mnemonic, cfg, relays, keys };
  }

  nostr
    .command("get-pubkey")
    .description("display the active profile's npub")
    .action(async () => {
      const { keys } = await nostrContext(program.opts());
      io.out(keys.npub);
    });

  nostr
    .command("list-relays")
    .description("show configured relays")
    .action(async () => {
      const { relays } = await nostrContext(program.opts());
      io.out(JSON.stringify(relays, null, 2));
    });

  nostr
    .command("add-relay <url>")
    .description("add a relay URL")
    .action(async (url: string) => {
      if (!/^wss?:\/\//.test(url)) throw new Error("relay URL must start with ws:// or wss://");
      const { app, fp, mnemonic, cfg } = await nostrContext(program.opts());
      const relays = cfg["relays"] as string[];
      if (!relays.includes(url)) relays.push(url);
      await saveConfig(app.profileDir(fp), mnemonic, cfg);
      io.out(JSON.stringify({ relays }));
    });

  nostr
    .command("remove-relay <index>")
    .description("remove a relay by 1-based index")
    .action(async (indexStr: string) => {
      const { app, fp, mnemonic, cfg } = await nostrContext(program.opts());
      const relays = cfg["relays"] as string[];
      const i = parseIntOption(indexStr, "index", { min: 1 }) - 1;
      if (!Number.isInteger(i) || i < 0 || i >= relays.length) {
        throw new Error(`index out of range 1..${relays.length}`);
      }
      if (relays.length === 1) throw new Error("at least one relay must remain");
      relays.splice(i, 1);
      await saveConfig(app.profileDir(fp), mnemonic, cfg);
      io.out(JSON.stringify({ relays }));
    });

  nostr
    .command("sync")
    .description("publish the local vault as a snapshot to the configured relays")
    .option("--chunk-limit <bytes>", "max chunk size", "50000")
    .action(async (o: { chunkLimit: string }) => {
      const opts = program.opts() as GlobalOpts;
      const { app, fp, mnemonic, relays, keys } = await nostrContext(opts);
      const vaultPath = opts.vault ?? join(app.profileDir(fp), INDEX_FILENAME);
      const encrypted = new Uint8Array(await readFile(vaultPath));
      const pool = new RelayPool(relays);
      try {
        const published = await publishSnapshot(
          pool,
          keys.privateKeyHex,
          deriveKeyIndex(mnemonic),
          encrypted,
          { limit: parseIntOption(o.chunkLimit, "--chunk-limit", { min: 64 }) },
        );
        io.out(
          JSON.stringify(
            {
              manifest_id: published.manifestId,
              manifest_event_id: published.manifestEventId,
              chunk_event_ids: published.chunkEventIds,
              relays,
            },
            null,
            2,
          ),
        );
      } finally {
        await pool.close();
      }
    });

  nostr
    .command("restore")
    .description("fetch the latest snapshot + deltas and merge them into the local vault")
    .option(
      "--replace",
      "DESTRUCTIVE: discard local state instead of merging remote into it",
    )
    .option("--yes", "confirm --replace")
    .action(async (o: { replace?: boolean; yes?: boolean }) => {
      const opts = program.opts() as GlobalOpts;
      const { app, fp, mnemonic, relays, keys } = await nostrContext(opts);
      if (o.replace && !o.yes) {
        throw new Error("--replace discards local entries; pass --yes to confirm");
      }
      const pool = new RelayPool(relays);
      try {
        const fetched = await fetchLatestSnapshot(pool, keys.privateKeyHex);
        if (!fetched) throw new Error("no snapshot found on the configured relays");
        const indexKey = deriveIndexKeyBytes(mnemonic);
        const snapshotPayload = parseEncryptedFile(fetched.encrypted).ciphertext;
        let remote = JSON.parse(
          new TextDecoder().decode(await decryptPayload(indexKey, snapshotPayload)),
        ) as Record<string, unknown>;

        let deltaCount = 0;
        if (fetched.manifest.delta_since) {
          // Bind deltas to this manifest so a relay cannot replay one from
          // another snapshot lineage into the restore.
          const deltas = await fetchDeltasSince(
            pool,
            keys.privateKeyHex,
            fetched.manifest.delta_since,
            fetched.manifestEvent.id,
          );
          for (const delta of deltas) {
            const incoming = JSON.parse(
              new TextDecoder().decode(
                await decryptPayload(indexKey, parseEncryptedFile(delta).ciphertext),
              ),
            );
            remote = mergeIndexPayloads(remote, incoming, sha256Hex(delta).slice(0, 16));
            deltaCount++;
          }
        }

        const vaultPath = opts.vault ?? join(app.profileDir(fp), INDEX_FILENAME);
        const localExists = existsSync(vaultPath);
        let local: Record<string, unknown> | null = null;
        if (localExists) {
          try {
            local = (await openVault(vaultPath, mnemonic)).index as unknown as Record<
              string,
              unknown
            >;
          } catch {
            local = null; // unreadable local vault: treat the restore as recovery
          }
        }

        // Default is a merge, not a replacement: a restore must not silently
        // discard entries created locally since the snapshot was published.
        let final: Record<string, unknown>;
        let mode: string;
        if (o.replace || local === null) {
          final = remote;
          mode = local === null ? "restored" : "replaced";
        } else {
          // Keep the local _system.index0 verbatim: it is Python-derived
          // atlas state recomputed on load, and refusing to merge it would
          // block every restore into a Python-created profile.
          final = mergeIndexPayloads(local, remote, "nostr-restore", {
            index0: "preserve-current",
          });
          mode = "merged";
        }

        // Keep a copy of whatever we are about to overwrite.
        let backupPath: string | null = null;
        if (localExists) {
          backupPath = `${vaultPath}.pre-restore-${Math.floor(Date.now() / 1000)}`;
          await atomicWrite(backupPath, new Uint8Array(await readFile(vaultPath)));
        }

        const index = parseVaultIndex(final);
        await saveVault({ index, mnemonic, path: vaultPath });
        io.out(
          JSON.stringify({
            mode,
            vault: vaultPath,
            entry_count: Object.keys(index.entries).length,
            deltas_applied: deltaCount,
            local_backup: backupPath,
          }),
        );
      } finally {
        await pool.close();
      }
    });

  const agent = program.command("agent").description("session agent (holds unlocked seeds)");

  agent
    .command("start")
    .description("run the session agent in the foreground")
    .option("--ttl <seconds>", "default unlock TTL", String(DEFAULT_TTL_SECONDS))
    .action(async (o: { ttl: string }) => {
      const app = new AppDir(resolveAppDir((program.opts() as GlobalOpts).appDir));
      const daemon = new AgentDaemon(agentSocketPath(app.root), parseIntOption(o.ttl, "--ttl", { min: 1 }), app.root);
      await daemon.start();
      io.out(JSON.stringify({ agent: "running", socket: agentSocketPath(app.root) }));
      await new Promise(() => {}); // run until killed
    });

  agent
    .command("token-issue")
    .description("issue a scoped bearer token (printed exactly once)")
    .option("--name <name>", "token name", "agent")
    .option("--scope <scope...>", "read/use/reveal (repeatable)", ["read"])
    .option("--kind <kind...>", "restrict to entry kinds (repeatable)")
    .option("--label-regex <re>", "restrict to matching labels", ".*")
    .option("--ttl <seconds>", "token lifetime", "300")
    .option("--uses <n>", "max secret deliveries", "1")
    .action(
      async (o: {
        name: string; scope: string[]; kind?: string[]; labelRegex: string;
        ttl: string; uses: string;
      }) => {
        const opts = program.opts() as GlobalOpts;
        const app = new AppDir(resolveAppDir(opts.appDir));
        const fp = await currentFingerprint(app, opts);
        const client = new AgentClient(agentSocketPath(app.root));
        const issued = await client.tokenIssue({
          fingerprint: fp,
          name: o.name,
          scopes: o.scope as ("read" | "use" | "reveal")[],
          ...(o.kind !== undefined && { kinds: o.kind }),
          labelRegex: o.labelRegex,
          ttl: parseIntOption(o.ttl, "--ttl", { min: 1 }),
          uses: parseIntOption(o.uses, "--uses", { min: 1 }),
        });
        io.out(
          JSON.stringify(
            { token: issued.token, note: "shown once — store it now", record: issued.record },
            null,
            2,
          ),
        );
      },
    );

  agent
    .command("token-list")
    .description("list issued tokens (no secrets)")
    .action(async () => {
      const opts = program.opts() as GlobalOpts;
      const app = new AppDir(resolveAppDir(opts.appDir));
      const fp = await currentFingerprint(app, opts);
      const client = new AgentClient(agentSocketPath(app.root));
      io.out(JSON.stringify(await client.tokenList(fp), null, 2));
    });

  agent
    .command("token-revoke <tokenId>")
    .description("revoke a token immediately")
    .action(async (tokenId: string) => {
      const app = new AppDir(resolveAppDir((program.opts() as GlobalOpts).appDir));
      const client = new AgentClient(agentSocketPath(app.root));
      await client.tokenRevoke(tokenId);
      io.out(JSON.stringify({ revoked: tokenId }));
    });

  agent
    .command("audit-verify")
    .description("verify the profile's HMAC-chained audit log (owner only)")
    .action(async () => {
      const opts = program.opts() as GlobalOpts;
      const app = new AppDir(resolveAppDir(opts.appDir));
      const fp = await currentFingerprint(app, opts);
      const mnemonic = await resolveMnemonic(app, opts);
      const path = join(app.profileDir(fp), "audit.log");
      const records = await AuditLog.verify(path, deriveKeyIndex(mnemonic));
      io.out(JSON.stringify({ verified: true, records: records.length, path }));
    });

  agent
    .command("audit-tail")
    .description("show the last audit records after verifying the chain (owner only)")
    .option("-n <count>", "records to show", "10")
    .action(async (o: { n: string }) => {
      const opts = program.opts() as GlobalOpts;
      const app = new AppDir(resolveAppDir(opts.appDir));
      const fp = await currentFingerprint(app, opts);
      const mnemonic = await resolveMnemonic(app, opts);
      const records = await AuditLog.verify(
        join(app.profileDir(fp), "audit.log"),
        deriveKeyIndex(mnemonic),
      );
      io.out(JSON.stringify(records.slice(-parseIntOption(o.n, "-n", { min: 1 })), null, 2));
    });

  agent
    .command("status")
    .description("show unlocked profiles and expiry times")
    .action(async () => {
      const app = new AppDir(resolveAppDir((program.opts() as GlobalOpts).appDir));
      const client = new AgentClient(agentSocketPath(app.root));
      io.out(JSON.stringify(await client.status(), null, 2));
    });

  agent
    .command("stop")
    .description("shut down the session agent (wipes held seeds)")
    .action(async () => {
      const app = new AppDir(resolveAppDir((program.opts() as GlobalOpts).appDir));
      const client = new AgentClient(agentSocketPath(app.root));
      await client.request({ op: "shutdown" });
      io.out(JSON.stringify({ agent: "stopped" }));
    });

  const util = program.command("util").description("utility commands");

  util
    .command("generate-password")
    .description("derive a password (Python parity: index 0, gen v1 by default)")
    .option("--length <n>", "password length", "24")
    .option("--index <n>", "derivation index", "0")
    .option("--gen-version <v>", "generation version (1 or 2)", "1")
    .option("--no-special", "exclude special characters")
    .option("--allowed-special-chars <set>")
    .option("--special-mode <mode>")
    .option("--exclude-ambiguous")
    .option("--min-uppercase <n>")
    .option("--min-lowercase <n>")
    .option("--min-digits <n>")
    .option("--min-special <n>")
    .action(
      (o: {
        length: string; index: string; genVersion: string; special: boolean;
        allowedSpecialChars?: string; specialMode?: string; excludeAmbiguous?: boolean;
        minUppercase?: string; minLowercase?: string; minDigits?: string; minSpecial?: string;
      }) => {
        const policy: PasswordPolicy = {
          ...(o.special === false && { includeSpecialChars: false }),
          ...(o.allowedSpecialChars !== undefined && { allowedSpecialChars: o.allowedSpecialChars }),
          ...(o.specialMode !== undefined && { specialMode: o.specialMode }),
          ...(o.excludeAmbiguous !== undefined && { excludeAmbiguous: o.excludeAmbiguous }),
          ...(o.minUppercase !== undefined && {
            minUppercase: parseIntOption(o.minUppercase, "--min-uppercase", { min: 0 }),
          }),
          ...(o.minLowercase !== undefined && {
            minLowercase: parseIntOption(o.minLowercase, "--min-lowercase", { min: 0 }),
          }),
          ...(o.minDigits !== undefined && {
            minDigits: parseIntOption(o.minDigits, "--min-digits", { min: 0 }),
          }),
          ...(o.minSpecial !== undefined && {
            minSpecial: parseIntOption(o.minSpecial, "--min-special", { min: 0 }),
          }),
        };
        const bip85 = Bip85.fromMnemonic(requireMnemonic());
        io.out(
          generatePassword(bip85, {
            length: parseIntOption(o.length, "--length", { min: 8, max: 128 }),
            index: parseIntOption(o.index, "--index", { min: 0 }),
            genVersion: parseIntOption(o.genVersion, "--gen-version", { min: 1, max: 2 }),
            policy,
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
    .command("unlock")
    .description("decrypt the parent seed with SEEDPASS_PASSWORD and hand it to the agent")
    .option("--ttl <seconds>", "how long the agent holds the seed")
    .action(async (o: { ttl?: string }) => {
      const opts = program.opts() as GlobalOpts;
      const app = new AppDir(resolveAppDir(opts.appDir));
      const fp = await currentFingerprint(app, opts);
      const password = process.env["SEEDPASS_PASSWORD"];
      if (!password) throw new Error("SEEDPASS_PASSWORD is not set");
      const mnemonic = await app.decryptParentSeed(fp, password);
      const client = new AgentClient(agentSocketPath(app.root));
      const expiresAt = await client.put(
        fp,
        mnemonic,
        o.ttl !== undefined ? parseIntOption(o.ttl, "--ttl", { min: 1 }) : undefined,
      );
      io.out(JSON.stringify({ unlocked: fp, expires_at: expiresAt }));
    });

  vaultCmd
    .command("lock")
    .description("drop the seed from the session agent")
    .option("--all", "lock every profile")
    .action(async (o: { all?: boolean }) => {
      const opts = program.opts() as GlobalOpts;
      const app = new AppDir(resolveAppDir(opts.appDir));
      const client = new AgentClient(agentSocketPath(app.root));
      const locked = o.all
        ? await client.lock()
        : await client.lock(await currentFingerprint(app, opts));
      io.out(JSON.stringify({ locked }));
    });

  vaultCmd
    .command("import <srcFile>")
    .description("restore a portable backup into the active vault")
    .option("--inspect", "verify and summarize without writing")
    .option("--yes", "confirm replacing a vault that already has entries")
    .action(async (srcFile: string, o: { inspect?: boolean; yes?: boolean }) => {
      const opts = program.opts() as GlobalOpts;
      const app = new AppDir(resolveAppDir(opts.appDir));
      const raw = await readFile(srcFile);
      // Encrypted backups need the seed; plaintext ones do not, so only
      // resolve when required (and use the agent, not just the env).
      const isEncrypted = !/"encryption_mode"\s*:\s*"none"/.test(raw.toString("utf8"));
      const mnemonic = isEncrypted ? await resolveMnemonic(app, opts) : undefined;
      const parsed = await importBackup(new Uint8Array(raw), {
        ...(mnemonic !== undefined && { mnemonic }),
      });
      const index = parseVaultIndex(parsed);
      const entryCount = Object.keys(index.entries).length;

      if (o.inspect) {
        io.out(
          JSON.stringify({
            inspected: srcFile,
            schema_version: index.schema_version,
            entry_count: entryCount,
            written: false,
          }),
        );
        return;
      }

      const targetMnemonic = mnemonic ?? (await resolveMnemonic(app, opts));
      const fp = await currentFingerprint(app, opts);
      const vaultPath = opts.vault ?? join(app.profileDir(fp), INDEX_FILENAME);
      if (existsSync(vaultPath) && !o.yes) {
        const current = await openVault(vaultPath, targetMnemonic);
        if (Object.keys(current.index.entries).length > 0) {
          throw new Error(
            "refusing to replace a non-empty vault without --yes " +
              "(use --inspect to check the backup first)",
          );
        }
      }
      await saveVault({ index, mnemonic: targetMnemonic, path: vaultPath });
      io.out(
        JSON.stringify({
          imported: srcFile,
          into: vaultPath,
          schema_version: index.schema_version,
          entry_count: entryCount,
        }),
      );
    });

  return program;
}
