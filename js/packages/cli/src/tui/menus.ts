/**
 * The interactive menus, matching Python's legacy (v1) TUI.
 *
 * Structure and numbering follow `src/main.py` deliberately: the same items
 * in the same order under the same names, so muscle memory carries over.
 * Where this build cannot do something Python can (semantic index, QR
 * rendering, PGP RSA) the item is still listed and says so, rather than
 * disappearing and leaving the numbering shifted.
 *
 * The agent-blind rule (plan section 9.3) still holds: secrets are shown only
 * by the actions whose whole purpose is to show them, and Secret Mode routes
 * those to the clipboard instead.
 */

import process from "node:process";
import { join, basename } from "node:path";
import { readFile } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import {
  addPasswordEntry,
  addTotpDeterministic,
  addTotpImported,
  addSshKeyEntry,
  addSeedEntry,
  addNostrKeyEntry,
  addPgpKeyEntry,
  addKeyValueEntry,
  addManagedAccountEntry,
  addDocumentEntry,
  modifyEntry,
  archiveEntry,
  restoreEntry,
  deriveNostrKeys,
  deriveTotpSecret,
  Bip85,
  generateMnemonic,
  exportBackup,
  importBackup,
  totpCodeAt,
  utf8,
  type Entry,
  type VaultIndex,
} from "@seedpass/core";
import { AppDir, INDEX_FILENAME, DEFAULT_PBKDF2_ITERATIONS, BACKUP_EXTENSION, defaultBackupFilename } from "../appDir.js";
import { atomicWrite, openVault, saveVaultHoldingLock, withVaultLock, type OpenedVault } from "../vaultFile.js";
import { entryMetadata, refFor } from "../refs.js";
import { materializeSecret, type MaterializedSecret } from "../secrets.js";
import { clipboardSink } from "../sinks.js";
import {
  loadConfig,
  mutateConfig,
  passwordPolicyFromConfig,
  DEFAULT_RELAYS,
} from "../configFile.js";
import {
  ansi,
  confirm,
  fail,
  header,
  menu,
  ok,
  pause,
  warn,
  type Ui,
} from "./console.js";

const ENTRY_TYPES = [
  "password",
  "totp",
  "ssh",
  "seed",
  "pgp",
  "nostr",
  "key_value",
  "managed_account",
  "document",
] as const;

/** Shared state for one interactive session. */
export interface Session {
  ui: Ui;
  app: AppDir;
  fingerprint: string;
  name: string | null;
  vault: OpenedVault;
  config: Record<string, unknown>;
  /** Re-prompt for the master password; used by Lock Vault and profile switch. */
  relock: (fingerprint: string) => Promise<string>;
  /** Milliseconds since epoch. Injectable so inactivity locking is testable. */
  clock: () => number;
}

// ---------------------------------------------------------------- utilities

/**
 * materializeSecret bound to this session's profile config.
 *
 * Every TUI path that turns an entry into a secret must go through here.
 * Password derivation takes the profile config's policy as its base and
 * merges the entry's own block over it; a call site that reaches for
 * materializeSecret directly loses the config base and silently derives a
 * different password than Python for any profile whose policy is not the
 * default.
 */
function sessionSecret(
  s: Session,
  id: string,
  entry: Entry,
  options: { timestamp?: number } = {},
): MaterializedSecret {
  return materializeSecret(s.vault.index, id, entry, s.vault.mnemonic, {
    ...options,
    basePolicy: passwordPolicyFromConfig(s.config),
  });
}

function title(s: Session, breadcrumb: string): void {
  header(s.ui, s.fingerprint, s.name, breadcrumb);
}

function kindOf(entry: Entry): string {
  const e = entry as unknown as Record<string, unknown>;
  return String(e["kind"] ?? e["type"] ?? "unknown");
}

/**
 * otpauth:// URI for a TOTP entry, for "Export 2FA codes".
 *
 * Imported entries carry their secret; deterministic ones derive it from the
 * seed at the entry's index — the same secret the code is computed from.
 */
function totpUri(entry: Entry, mnemonic: string): string {
  const e = entry as unknown as Record<string, unknown>;
  const secret =
    typeof e["secret"] === "string" && e["secret"]
      ? (e["secret"] as string)
      : deriveTotpSecret(mnemonic, Number(e["index"] ?? 0));
  const label = encodeURIComponent(String(e["label"] ?? ""));
  const period = Number(e["period"] ?? 30);
  const digits = Number(e["digits"] ?? 6);
  return `otpauth://totp/${label}?secret=${secret}&issuer=SeedPass&period=${period}&digits=${digits}`;
}

function prettyKind(kind: string): string {
  return kind
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function entriesOf(index: VaultIndex): Array<{ id: string; entry: Entry }> {
  return Object.entries(index.entries)
    .map(([id, entry]) => ({ id, entry: entry as Entry }))
    .sort((a, b) => Number(a.id) - Number(b.id));
}

function isArchived(entry: Entry): boolean {
  return Boolean(entry.archived ?? (entry as Record<string, unknown>)["blacklisted"]);
}

/** Apply a change under the vault lock, re-reading first. */
async function mutate(s: Session, fn: (vault: OpenedVault) => void): Promise<void> {
  const { path, mnemonic } = s.vault;
  await withVaultLock(path, async () => {
    const fresh = await openVault(path, mnemonic);
    fn(fresh);
    await saveVaultHoldingLock(fresh);
    s.vault = fresh;
  });
}

async function reload(s: Session): Promise<void> {
  s.vault = await openVault(s.vault.path, s.vault.mnemonic);
}

function secretModeOn(s: Session): boolean {
  return Boolean(s.config["secret_mode_enabled"]);
}

/**
 * How long a copied secret should sit on the clipboard before being wiped.
 * 0 (or a non-positive value) disables the auto-clear. Parity with Python's
 * clipboard_clear_delay.
 */
function clipboardClearSeconds(s: Session): number {
  const raw = Number(s.config["clipboard_clear_delay"] ?? 0);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : 0;
}

/** Copy a secret to the clipboard, honouring the configured auto-clear delay. */
async function copyToClipboard(s: Session, value: string): Promise<{ detail: string }> {
  return clipboardSink(value, { clearAfterSeconds: clipboardClearSeconds(s) });
}

/**
 * Write plaintext-secret output to a file the way the CLI does: an explicit
 * choice before overwriting, then a fresh 0600 inode renamed into place
 * (atomicWrite). A plain writeFile(mode) applies the mode only at creation,
 * so exporting over an existing 0644 file kept it world-readable — for the
 * 2FA export, that is every TOTP secret in the vault — and a pre-planted
 * symlink could redirect the plaintext somewhere else entirely.
 */
async function writeSecretFile(s: Session, dest: string, content: string): Promise<boolean> {
  if (existsSync(dest) && !(await confirm(s.ui, `${dest} exists. Overwrite it?`))) {
    warn(s.ui, "Nothing was written.");
    return false;
  }
  await atomicWrite(dest, utf8(content));
  return true;
}

/**
 * Smallest iteration count the KDF settings screen will store. Honour any
 * value at or above it — including one below the default, which is a downgrade
 * the user chose deliberately — and fall back to the default only for garbage,
 * so the setting is never silently ignored for a legitimate value.
 */
const MIN_KDF_ITERATIONS = 50_000;

/**
 * The PBKDF2 iteration count this profile's config asks for. Used to re-wrap
 * the parent seed on Change password and to wrap new profiles — the two places
 * the KDF-strength setting actually takes effect.
 */
function kdfIterations(s: Session): number {
  const raw = Number(s.config["kdf_iterations"] ?? DEFAULT_PBKDF2_ITERATIONS);
  if (!Number.isFinite(raw) || !Number.isInteger(raw) || raw < MIN_KDF_ITERATIONS) {
    return DEFAULT_PBKDF2_ITERATIONS;
  }
  return raw;
}

/**
 * Show a secret, honouring Secret Mode.
 *
 * Python's Secret Mode copies to the clipboard instead of printing; this
 * keeps that behaviour so the setting means the same thing in both.
 */
async function reveal(s: Session, value: string, descriptor: string): Promise<void> {
  if (secretModeOn(s)) {
    try {
      const result = await copyToClipboard(s, value);
      ok(s.ui, `${descriptor} copied to clipboard (${result.detail}).`);
    } catch (e) {
      fail(s.ui, `Clipboard unavailable: ${(e as Error).message}`);
      warn(s.ui, "Secret Mode is on, so it was not printed. Turn it off to display it.");
    }
    return;
  }
  s.ui.say(`${ansi.dim}${descriptor}:${ansi.reset}`);
  s.ui.say(`${ansi.bold}${value}${ansi.reset}`);
}

async function askIndex(s: Session, prompt: string): Promise<string | null> {
  const raw = await s.ui.ask(prompt);
  if (!raw) return null;
  const id = raw.startsWith("sp://entry/") ? raw.slice("sp://entry/".length) : raw;
  if (!/^\d+$/.test(id)) {
    fail(s.ui, "Invalid index.");
    await pause(s.ui);
    return null;
  }
  if (!s.vault.index.entries[id]) {
    fail(s.ui, `No entry ${id}.`);
    await pause(s.ui);
    return null;
  }
  return id;
}

async function askInt(
  s: Session,
  prompt: string,
  opts: { min?: number; max?: number; default?: number } = {},
): Promise<number | null> {
  const raw = await s.ui.ask(prompt);
  if (!raw) return opts.default ?? null;
  const value = Number(raw);
  // A NaN reaching the vault once made an index unreadable on every later
  // open; refuse it at the prompt.
  if (!Number.isInteger(value)) {
    fail(s.ui, "Please enter a whole number.");
    return null;
  }
  if (opts.min !== undefined && value < opts.min) {
    fail(s.ui, `Must be at least ${opts.min}.`);
    return null;
  }
  if (opts.max !== undefined && value > opts.max) {
    fail(s.ui, `Must be at most ${opts.max}.`);
    return null;
  }
  return value;
}

// ------------------------------------------------------------- main menu

/**
 * Inactivity timeout in milliseconds, from config (seconds). 0 disables it.
 * Parity with Python's inactivity_timeout, which the legacy TUI also checks
 * at the top of its main loop.
 */
function inactivityTimeoutMs(s: Session): number {
  const raw = Number(s.config["inactivity_timeout"] ?? 0);
  return Number.isFinite(raw) && raw > 0 ? raw * 1000 : 0;
}

export async function mainMenu(s: Session): Promise<number> {
  const timeoutMs = inactivityTimeoutMs(s);
  for (;;) {
    title(s, "Main Menu");
    menu(s.ui, [
      { key: "1", label: "Add Entry" },
      { key: "2", label: "Retrieve Entry" },
      { key: "3", label: "Search Entries" },
      { key: "4", label: "List Entries" },
      { key: "5", label: "Modify an Existing Entry" },
      { key: "6", label: "2FA Codes" },
      { key: "7", label: "Settings" },
      { key: "8", label: "List Archived" },
    ]);
    const promptedAt = s.clock();
    const choice = await s.ui.ask("Enter your choice (1-8) or press Enter to exit: ");
    // If the user was away from the main menu longer than the timeout, lock
    // the vault and require the password again before acting on their input.
    // The seed is dropped and re-derived; the keystroke that arrived after the
    // timeout is discarded rather than obeyed on a stale, unlocked screen.
    if (timeoutMs > 0 && s.clock() - promptedAt > timeoutMs) {
      warn(s.ui, "Session timed out. Vault locked.");
      try {
        const mnemonic = await s.relock(s.fingerprint);
        s.vault = await openVault(s.vault.path, mnemonic);
      } catch (e) {
        fail(s.ui, `Vault remains locked: ${(e as Error).message}`);
        return 1;
      }
      continue;
    }
    if (!choice) return 0;
    try {
      switch (choice) {
        case "1":
          await addEntryMenu(s);
          break;
        case "2":
          await retrieveEntry(s);
          break;
        case "3":
          await searchEntries(s);
          break;
        case "4":
          await listEntriesMenu(s);
          break;
        case "5":
          await modifyEntryFlow(s);
          break;
        case "6":
          await totpCodes(s);
          break;
        case "7":
          await settingsMenu(s);
          break;
        case "8":
          await listArchived(s);
          break;
        default:
          fail(s.ui, "Invalid choice. Please select a valid option.");
          await pause(s.ui);
      }
    } catch (e) {
      fail(s.ui, `Action failed: ${(e as Error).message}`);
      await pause(s.ui);
    }
  }
}

// -------------------------------------------------------------- add entry

async function addEntryMenu(s: Session): Promise<void> {
  for (;;) {
    title(s, "Main Menu > Add Entry");
    menu(s.ui, [
      { key: "1", label: "Password" },
      { key: "2", label: "2FA (TOTP)" },
      { key: "3", label: "SSH Key" },
      { key: "4", label: "Seed Phrase" },
      { key: "5", label: "Nostr Key Pair" },
      { key: "6", label: "PGP Key" },
      { key: "7", label: "Key/Value" },
      { key: "8", label: "Managed Account" },
      { key: "9", label: "Document" },
    ]);
    const choice = await s.ui.ask("Select entry type or press Enter to go back: ");
    if (!choice) return;
    const handlers: Record<string, () => Promise<boolean>> = {
      "1": () => addPassword(s),
      "2": () => addTotp(s),
      "3": () => addSimple(s, "SSH Key", (index, label) => addSshKeyEntry(index, label)),
      "4": () => addSeed(s),
      "5": () => addSimple(s, "Nostr Key Pair", (index, label) => addNostrKeyEntry(index, label)),
      "6": () => addPgp(s),
      "7": () => addKeyValue(s),
      "8": () =>
        addSimple(s, "Managed Account", (index, label) =>
          addManagedAccountEntry(index, label, s.vault.mnemonic),
        ),
      "9": () => addDocument(s),
    };
    const handler = handlers[choice];
    if (!handler) {
      fail(s.ui, "Invalid choice.");
      await pause(s.ui);
      continue;
    }
    if (await handler()) return;
  }
}

async function commonFields(
  s: Session,
): Promise<{ notes: string; tags: string[] }> {
  const notes = await s.ui.ask("Notes (optional): ");
  const tagsRaw = await s.ui.ask("Tags, comma separated (optional): ");
  const tags = tagsRaw
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  return { notes, tags };
}

async function announce(s: Session, id: string, what: string): Promise<void> {
  ok(s.ui, `[+] ${what} added at index ${id} (${refFor(id)}).`);
  await pause(s.ui);
}

async function addPassword(s: Session): Promise<boolean> {
  const label = await s.ui.ask("Label: ");
  if (!label) return false;
  const length = await askInt(s, "Length (default 20): ", { min: 8, max: 128, default: 20 });
  if (length === null) {
    await pause(s.ui);
    return false;
  }
  const username = await s.ui.ask("Username (optional): ");
  const url = await s.ui.ask("URL (optional): ");
  const { notes, tags } = await commonFields(s);
  let id = "";
  await mutate(s, (v) => {
    id = addPasswordEntry(v.index, label, length, { username, url, notes, tags });
  });
  // Derived, not stored: show it once here the way Python does.
  const entry = s.vault.index.entries[id] as Entry;
  const secret = sessionSecret(s, id, entry);
  await reveal(s, secret.value, `Password for ${label}`);
  await announce(s, id, "Password");
  return true;
}

async function addTotp(s: Session): Promise<boolean> {
  const label = await s.ui.ask("Label: ");
  if (!label) return false;
  const imported = await s.ui.ask("Import an existing secret? (y/N): ");
  let id = "";
  if (imported.toLowerCase().startsWith("y")) {
    const secret = await s.ui.askHidden("Base32 secret: ");
    if (!secret) return false;
    const period = await askInt(s, "Period seconds (default 30): ", { min: 1, default: 30 });
    const digits = await askInt(s, "Digits (default 6): ", { min: 4, max: 10, default: 6 });
    await mutate(s, (v) => {
      id = addTotpImported(v.index, label, secret, {
        ...(period !== null && { period }),
        ...(digits !== null && { digits }),
      });
    });
  } else {
    await mutate(s, (v) => {
      id = addTotpDeterministic(v.index, label, v.mnemonic);
    });
  }
  const entry = s.vault.index.entries[id] as Entry;
  try {
    await reveal(s, totpUri(entry, s.vault.mnemonic), `otpauth URI for ${label}`);
  } catch {
    // Not fatal: the entry exists either way.
  }
  await announce(s, id, "2FA entry");
  return true;
}

async function addSimple(
  s: Session,
  what: string,
  add: (index: VaultIndex, label: string) => string,
): Promise<boolean> {
  const label = await s.ui.ask("Label: ");
  if (!label) return false;
  let id = "";
  await mutate(s, (v) => {
    id = add(v.index, label);
  });
  await announce(s, id, what);
  return true;
}

async function addSeed(s: Session): Promise<boolean> {
  const label = await s.ui.ask("Label: ");
  if (!label) return false;
  const words = await askInt(s, "Word count 12 or 24 (default 24): ", { default: 24 });
  if (words !== 12 && words !== 24) {
    fail(s.ui, "Word count must be 12 or 24.");
    await pause(s.ui);
    return false;
  }
  let id = "";
  await mutate(s, (v) => {
    id = addSeedEntry(v.index, label, { wordCount: words });
  });
  await announce(s, id, "Seed Phrase");
  return true;
}

async function addPgp(s: Session): Promise<boolean> {
  const label = await s.ui.ask("Label: ");
  if (!label) return false;
  const userId = await s.ui.ask("User ID (e.g. name <email>): ");
  let id = "";
  await mutate(s, (v) => {
    id = addPgpKeyEntry(v.index, label, { ...(userId && { userId }) });
  });
  await announce(s, id, "PGP Key");
  return true;
}

async function addKeyValue(s: Session): Promise<boolean> {
  const label = await s.ui.ask("Label: ");
  if (!label) return false;
  const key = await s.ui.ask("Key: ");
  if (!key) {
    fail(s.ui, "Key is required.");
    await pause(s.ui);
    return false;
  }
  // Hidden: this is a stored secret, and it should not sit in the scrollback
  // of the terminal it was typed into.
  const value = await s.ui.askHidden("Value (hidden): ");
  let id = "";
  await mutate(s, (v) => {
    id = addKeyValueEntry(v.index, label, key, value);
  });
  await announce(s, id, "Key/Value");
  return true;
}

async function addDocument(s: Session): Promise<boolean> {
  const label = await s.ui.ask("Label: ");
  if (!label) return false;
  const path = await s.ui.ask("Path to file (blank to type the content): ");
  let content: string;
  let fileType = "";
  if (path) {
    try {
      content = await readFile(path, "utf8");
    } catch (e) {
      fail(s.ui, `Could not read ${path}: ${(e as Error).message}`);
      await pause(s.ui);
      return false;
    }
    const dot = basename(path).lastIndexOf(".");
    if (dot > 0) fileType = basename(path).slice(dot + 1);
  } else {
    content = await s.ui.ask("Content: ");
    fileType = await s.ui.ask("File type (optional): ");
  }
  let id = "";
  await mutate(s, (v) => {
    id = addDocumentEntry(v.index, label, content, { ...(fileType && { fileType }) });
  });
  await announce(s, id, "Document");
  return true;
}

// --------------------------------------------------------- retrieve/search

async function retrieveEntry(s: Session): Promise<void> {
  title(s, "Main Menu > Retrieve Entry");
  const query = await s.ui.ask("Enter index, sp:// reference, or label: ");
  if (!query) return;
  const id = await resolveQuery(s, query);
  if (id === null) return;
  await entryDetails(s, id);
}

async function resolveQuery(s: Session, query: string): Promise<string | null> {
  const bare = query.startsWith("sp://entry/") ? query.slice("sp://entry/".length) : query;
  if (/^\d+$/.test(bare) && s.vault.index.entries[bare]) return bare;
  const matches = entriesOf(s.vault.index).filter(({ entry }) =>
    String(entry.label ?? "").toLowerCase().includes(query.toLowerCase()),
  );
  if (matches.length === 0) {
    warn(s.ui, "No matching entries found.");
    await pause(s.ui);
    return null;
  }
  if (matches.length === 1) return matches[0]!.id;
  s.ui.say();
  for (const { id, entry } of matches) {
    s.ui.say(`  ${ansi.cyan}${id}.${ansi.reset} ${prettyKind(kindOf(entry))} - ${entry.label}`);
  }
  s.ui.say();
  return askIndex(s, "Enter index or press Enter to go back: ");
}

async function searchEntries(s: Session): Promise<void> {
  title(s, "Main Menu > Search Entries");
  const query = (await s.ui.ask("Search: ")).toLowerCase();
  if (!query) return;
  const matches = entriesOf(s.vault.index).filter(({ entry }) => {
    const tags = Array.isArray(entry.tags) ? (entry.tags as string[]).join(" ") : "";
    return `${entry.label ?? ""} ${kindOf(entry)} ${tags} ${entry.username ?? ""} ${entry.notes ?? ""}`
      .toLowerCase()
      .includes(query);
  });
  if (matches.length === 0) {
    warn(s.ui, "No matching entries found.");
    await pause(s.ui);
    return;
  }
  s.ui.say(`\n${ansi.green}[+] Matches:${ansi.reset}\n`);
  for (const { id, entry } of matches) {
    const archived = isArchived(entry) ? `${ansi.dim} (archived)${ansi.reset}` : "";
    s.ui.say(
      `  ${ansi.cyan}${id}.${ansi.reset} ${prettyKind(kindOf(entry))} - ${entry.label}${archived}`,
    );
  }
  s.ui.say();
  const id = await askIndex(s, "Enter index to view details or press Enter to go back: ");
  if (id !== null) await entryDetails(s, id);
}

// ------------------------------------------------------------ list entries

async function listEntriesMenu(s: Session): Promise<void> {
  for (;;) {
    title(s, "Main Menu > List Entries");
    const options = [{ key: "1", label: "All" }];
    const optionMap: Record<string, string> = {};
    ENTRY_TYPES.forEach((t, i) => {
      const key = String(i + 2);
      options.push({ key, label: prettyKind(t) });
      optionMap[key] = t;
    });
    menu(s.ui, options);
    const choice = await s.ui.ask("Select entry type or press Enter to go back: ");
    if (!choice) return;
    let filter: string | null;
    if (choice === "1") filter = null;
    else if (optionMap[choice]) filter = optionMap[choice]!;
    else {
      fail(s.ui, "Invalid choice.");
      await pause(s.ui);
      continue;
    }
    await listAndPick(s, filter, false, "Main Menu > List Entries");
  }
}

async function listArchived(s: Session): Promise<void> {
  await listAndPick(s, null, true, "Main Menu > List Archived");
}

async function listAndPick(
  s: Session,
  filter: string | null,
  archivedOnly: boolean,
  breadcrumb: string,
): Promise<void> {
  for (;;) {
    await reload(s);
    title(s, breadcrumb);
    const rows = entriesOf(s.vault.index).filter(({ entry }) => {
      if (archivedOnly !== isArchived(entry)) return false;
      return filter === null || kindOf(entry) === filter;
    });
    if (rows.length === 0) {
      const what = filter ? `${prettyKind(filter)} ` : "";
      warn(s.ui, archivedOnly ? "No archived entries found." : `No active ${what}entries found.`);
      await pause(s.ui);
      return;
    }
    s.ui.say(`\n${ansi.green}[+] Entries:${ansi.reset}\n`);
    for (const { id, entry } of rows) {
      const shown = filter === null ? `${prettyKind(kindOf(entry))} - ${entry.label}` : String(entry.label);
      s.ui.say(`  ${ansi.cyan}${id}.${ansi.reset} ${shown}`);
    }
    s.ui.say();
    const id = await askIndex(s, "Enter index to view details or press Enter to go back: ");
    if (id === null) return;
    await entryDetails(s, id);
  }
}

// ---------------------------------------------------------- entry details

async function entryDetails(s: Session, id: string): Promise<void> {
  for (;;) {
    await reload(s);
    const entry = s.vault.index.entries[id] as Entry | undefined;
    if (!entry) return;
    const kind = kindOf(entry);
    title(s, `Main Menu > Entry ${id}`);

    // Metadata first, redacted exactly as the CLI and the agent's read scope
    // redact it — stored secrets appear as has_* flags, never values.
    s.ui.say();
    for (const [k, v] of Object.entries(entryMetadata(id, entry))) {
      if (v === "" || v === null || (Array.isArray(v) && v.length === 0)) continue;
      s.ui.say(`  ${ansi.dim}${k.padEnd(16)}${ansi.reset} ${Array.isArray(v) ? v.join(", ") : String(v)}`);
    }

    const options = [
      { key: "S", label: "Show secret" },
      { key: "C", label: "Copy secret to clipboard" },
      { key: isArchived(entry) ? "U" : "A", label: isArchived(entry) ? "Unarchive" : "Archive" },
      { key: "N", label: "Add Note" },
      { key: "F", label: "Add Custom Field" },
      { key: "H", label: "Add Hidden Field" },
      { key: "E", label: "Edit" },
      { key: "T", label: "Edit Tags" },
    ];
    if (kind === "seed" || kind === "managed_account" || kind === "nostr") {
      options.push({ key: "Q", label: "Show QR codes" });
    }
    if (kind === "document") options.push({ key: "X", label: "Export Document to File" });
    menu(s.ui, options);

    const choice = (await s.ui.ask("Select an action or press Enter to return: ")).toLowerCase();
    if (!choice) return;
    switch (choice) {
      case "s":
      case "c": {
        const secret = sessionSecret(s, id, entry);
        if (choice === "c") {
          try {
            const r = await copyToClipboard(s, secret.value);
            ok(s.ui, `Copied ${secret.descriptor} (${r.detail}).`);
          } catch (e) {
            fail(s.ui, `Clipboard unavailable: ${(e as Error).message}`);
          }
        } else {
          await reveal(s, secret.value, secret.descriptor);
        }
        await pause(s.ui);
        break;
      }
      case "a":
      case "u":
        await mutate(s, (v) => {
          if (isArchived(entry)) restoreEntry(v.index, id);
          else archiveEntry(v.index, id);
        });
        ok(s.ui, isArchived(entry) ? "Unarchived." : "Archived.");
        await pause(s.ui);
        break;
      case "n": {
        const notes = await s.ui.ask("Note: ");
        await mutate(s, (v) => modifyEntry(v.index, id, { notes }));
        ok(s.ui, "Note saved.");
        await pause(s.ui);
        break;
      }
      case "f":
      case "h":
        await addCustomField(s, id, entry, choice === "h");
        break;
      case "e":
        await editEntryMenu(s, id);
        break;
      case "t": {
        const raw = await s.ui.ask("Tags, comma separated: ");
        const tags = raw.split(",").map((t) => t.trim()).filter(Boolean);
        await mutate(s, (v) => modifyEntry(v.index, id, { tags }));
        ok(s.ui, "Tags saved.");
        await pause(s.ui);
        break;
      }
      case "q":
        await showQr(s, id, entry);
        break;
      case "x":
        await exportDocument(s, id, entry);
        break;
      default:
        fail(s.ui, "Invalid choice.");
        await pause(s.ui);
    }
  }
}

async function addCustomField(
  s: Session,
  id: string,
  entry: Entry,
  hidden: boolean,
): Promise<void> {
  const label = await s.ui.ask("Field label: ");
  if (!label) return;
  const value = hidden
    ? await s.ui.askHidden("Field value (hidden): ")
    : await s.ui.ask("Field value: ");
  const existing = Array.isArray(entry.custom_fields)
    ? (entry.custom_fields as Record<string, unknown>[])
    : [];
  const custom_fields = [...existing, { label, value, is_hidden: hidden }];
  await mutate(s, (v) => modifyEntry(v.index, id, { custom_fields }));
  ok(s.ui, `${hidden ? "Hidden field" : "Custom field"} added.`);
  await pause(s.ui);
}

async function editEntryMenu(s: Session, id: string): Promise<void> {
  for (;;) {
    await reload(s);
    const entry = s.vault.index.entries[id] as Entry | undefined;
    if (!entry) return;
    const kind = kindOf(entry);
    title(s, `Main Menu > Entry ${id} > Edit`);
    const options = [{ key: "L", label: "Edit Label" }];
    if (kind === "key_value") {
      options.push({ key: "K", label: "Edit Key" }, { key: "V", label: "Edit Value" });
    } else if (kind === "document") {
      options.push({ key: "C", label: "Edit Content" }, { key: "F", label: "Edit File Type" });
    }
    if (kind === "password") {
      options.push({ key: "U", label: "Edit Username" }, { key: "R", label: "Edit URL" });
    } else if (kind === "totp") {
      options.push({ key: "P", label: "Edit Period" }, { key: "D", label: "Edit Digits" });
    }
    menu(s.ui, options);
    const choice = (await s.ui.ask("Select option or press Enter to go back: ")).toLowerCase();
    if (!choice) return;

    const setField = async (changes: Record<string, unknown>): Promise<void> => {
      await mutate(s, (v) => modifyEntry(v.index, id, changes));
      ok(s.ui, "Saved.");
      await pause(s.ui);
    };

    switch (choice) {
      case "l":
        await setField({ label: await s.ui.ask("New label: ") });
        break;
      case "k":
        await setField({ key: await s.ui.ask("New key: ") });
        break;
      case "v":
        await setField({ value: await s.ui.askHidden("New value (hidden): ") });
        break;
      case "c":
        await setField({ content: await s.ui.ask("New content: ") });
        break;
      case "f":
        await setField({ file_type: await s.ui.ask("New file type: ") });
        break;
      case "u":
        await setField({ username: await s.ui.ask("New username: ") });
        break;
      case "r":
        await setField({ url: await s.ui.ask("New URL: ") });
        break;
      case "p": {
        const period = await askInt(s, "New period (seconds): ", { min: 1 });
        if (period !== null) await setField({ period });
        else await pause(s.ui);
        break;
      }
      case "d": {
        const digits = await askInt(s, "New digits: ", { min: 4, max: 10 });
        if (digits !== null) await setField({ digits });
        else await pause(s.ui);
        break;
      }
      default:
        fail(s.ui, "Invalid choice.");
        await pause(s.ui);
    }
  }
}

async function showQr(s: Session, id: string, entry: Entry): Promise<void> {
  // Python renders a QR block in the terminal. This build does not have a QR
  // encoder, and inventing one for a display convenience is not worth a
  // dependency in a process that holds unlocked seeds — say so plainly and
  // offer the underlying value instead.
  warn(s.ui, "QR rendering is not available in this build.");
  const secret = sessionSecret(s, id, entry);
  if (await confirm(s.ui, "Show the value it would encode instead?")) {
    await reveal(s, secret.value, secret.descriptor);
  }
  await pause(s.ui);
}

async function exportDocument(s: Session, id: string, entry: Entry): Promise<void> {
  const out = await s.ui.ask("Output path: ");
  if (!out) return;
  const secret = sessionSecret(s, id, entry);
  try {
    if (await writeSecretFile(s, out, secret.value)) {
      ok(s.ui, `Document exported to: ${out}`);
    }
  } catch (e) {
    fail(s.ui, `Export failed: ${(e as Error).message}`);
  }
  await pause(s.ui);
}

async function modifyEntryFlow(s: Session): Promise<void> {
  title(s, "Main Menu > Modify an Existing Entry");
  const query = await s.ui.ask("Enter index, sp:// reference, or label: ");
  if (!query) return;
  const id = await resolveQuery(s, query);
  if (id === null) return;
  await editEntryMenu(s, id);
}

// -------------------------------------------------------------- 2FA codes

async function totpCodes(s: Session): Promise<void> {
  title(s, "Main Menu > 2FA Codes");
  const rows = entriesOf(s.vault.index).filter(
    ({ entry }) => kindOf(entry) === "totp" && !isArchived(entry),
  );
  if (rows.length === 0) {
    warn(s.ui, "No 2FA entries found.");
    await pause(s.ui);
    return;
  }
  rows.sort((a, b) =>
    String(a.entry.label ?? "").toLowerCase().localeCompare(String(b.entry.label ?? "").toLowerCase()),
  );
  const now = Math.floor(Date.now() / 1000);
  s.ui.say();
  for (const { id, entry } of rows) {
    const period = Number(entry.period ?? 30);
    const remaining = period - (now % period);
    const secret = sessionSecret(s, id, entry, { timestamp: now });
    const code = secretModeOn(s) ? "".padEnd(6, "•") : secret.value;
    s.ui.say(
      `  ${ansi.cyan}${String(entry.label)}${ansi.reset}  ${ansi.bold}${code}${ansi.reset}  ` +
        `${ansi.dim}${remaining}s left${ansi.reset}`,
    );
  }
  s.ui.say();
  if (secretModeOn(s)) warn(s.ui, "Secret Mode is on, so codes are hidden.");
  await pause(s.ui);
}

// --------------------------------------------------------------- settings

async function settingsMenu(s: Session): Promise<void> {
  for (;;) {
    title(s, "Main Menu > Settings");
    menu(s.ui, [
      { key: "1", label: "Profiles" },
      { key: "2", label: "Nostr" },
      { key: "3", label: "Change password" },
      { key: "4", label: "Verify Script Checksum" },
      { key: "5", label: "Generate Script Checksum" },
      { key: "6", label: "Backup Parent Seed" },
      { key: "7", label: "Export database" },
      { key: "8", label: "Import database" },
      { key: "9", label: "Export 2FA codes" },
      { key: "10", label: "Set additional backup location" },
      { key: "11", label: "KDF strength & benchmark" },
      { key: "12", label: "Set inactivity timeout" },
      { key: "13", label: "Lock Vault" },
      { key: "14", label: "Stats" },
      { key: "15", label: "Toggle Secret Mode" },
      { key: "16", label: "Toggle Offline Mode" },
      { key: "17", label: "Toggle Quick Unlock" },
      { key: "18", label: "Semantic Index" },
    ]);
    const choice = await s.ui.ask("Select an option or press Enter to go back: ");
    if (!choice) return;
    try {
      switch (choice) {
        case "1":
          await profilesMenu(s);
          break;
        case "2":
          await nostrMenu(s);
          break;
        case "3":
          await changePassword(s);
          break;
        case "4":
        case "5":
          warn(
            s.ui,
            "Script checksums cover the Python source tree. This build ships a " +
              "single signed bundle; verify it with the .sha256 beside it.",
          );
          await pause(s.ui);
          break;
        case "6":
          await backupParentSeed(s);
          break;
        case "7":
          await exportDatabase(s);
          break;
        case "8":
          await importDatabase(s);
          break;
        case "9":
          await exportTotpCodes(s);
          break;
        case "10":
          await setBackupLocation(s);
          break;
        case "11":
          await kdfSettings(s);
          break;
        case "12":
          await setInactivityTimeout(s);
          break;
        case "13":
          await lockVault(s);
          break;
        case "14":
          await showStats(s);
          break;
        case "15":
          await toggleConfig(s, "secret_mode_enabled", "Secret Mode");
          break;
        case "16":
          await toggleConfig(s, "offline_mode", "Offline Mode");
          break;
        case "17":
          await toggleConfig(s, "quick_unlock_enabled", "Quick Unlock");
          break;
        case "18":
          warn(s.ui, "The semantic index is not part of this build.");
          await pause(s.ui);
          break;
        default:
          fail(s.ui, "Invalid choice.");
          await pause(s.ui);
      }
    } catch (e) {
      fail(s.ui, `Action failed: ${(e as Error).message}`);
      await pause(s.ui);
    }
  }
}

async function saveSetting(s: Session, key: string, value: unknown): Promise<void> {
  await mutateConfig(s.app.profileDir(s.fingerprint), s.vault.mnemonic, (cfg) => {
    cfg[key] = value;
  });
  s.config[key] = value;
}

async function toggleConfig(s: Session, key: string, label: string): Promise<void> {
  const next = !s.config[key];
  await saveSetting(s, key, next);
  ok(s.ui, `${label} is now ${next ? "ON" : "OFF"}.`);
  await pause(s.ui);
}

// --------------------------------------------------------------- profiles

async function profilesMenu(s: Session): Promise<void> {
  for (;;) {
    title(s, "Main Menu > Settings > Profiles");
    menu(s.ui, [
      { key: "1", label: "Switch Seed Profile" },
      { key: "2", label: "Add a New Seed Profile" },
      { key: "3", label: "Remove an Existing Seed Profile" },
      { key: "4", label: "List All Seed Profiles" },
      { key: "5", label: "Set Seed Profile Name" },
    ]);
    const choice = await s.ui.ask("Select an option or press Enter to go back: ");
    if (!choice) return;
    try {
      switch (choice) {
        case "1":
          if (await switchProfile(s)) return;
          break;
        case "2":
          await addProfile(s);
          break;
        case "3":
          await removeProfile(s);
          break;
        case "4":
          await listProfiles(s);
          break;
        case "5":
          await setProfileName(s);
          break;
        default:
          fail(s.ui, "Invalid choice.");
          await pause(s.ui);
      }
    } catch (e) {
      fail(s.ui, `Action failed: ${(e as Error).message}`);
      await pause(s.ui);
    }
  }
}

async function pickProfile(s: Session, prompt: string): Promise<string | null> {
  const data = await s.app.readFingerprints();
  if (data.fingerprints.length === 0) {
    warn(s.ui, "No profiles.");
    await pause(s.ui);
    return null;
  }
  s.ui.say();
  data.fingerprints.forEach((fp, i) => {
    const current = fp === s.fingerprint ? `${ansi.green} (current)${ansi.reset}` : "";
    s.ui.say(`  ${ansi.cyan}${i + 1}.${ansi.reset} ${fp}  ${data.names[fp] ?? ""}${current}`);
  });
  s.ui.say();
  const raw = await s.ui.ask(prompt);
  if (!raw) return null;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > data.fingerprints.length) {
    fail(s.ui, "Invalid selection.");
    await pause(s.ui);
    return null;
  }
  return data.fingerprints[n - 1]!;
}

async function switchProfile(s: Session): Promise<boolean> {
  title(s, "Main Menu > Settings > Profiles > Switch");
  const fp = await pickProfile(s, "Select a profile or press Enter to go back: ");
  if (fp === null || fp === s.fingerprint) return false;
  // A different profile is a different seed: unlock it on its own terms
  // rather than reusing the seed already in hand.
  const mnemonic = await s.relock(fp);
  s.vault = await openVault(join(s.app.profileDir(fp), INDEX_FILENAME), mnemonic);
  s.fingerprint = fp;
  s.name = (await s.app.readFingerprints()).names[fp] ?? null;
  s.config = await loadConfig(s.app.profileDir(fp), mnemonic);
  await s.app.switchProfile(fp);
  ok(s.ui, `Switched to ${s.name ?? fp}.`);
  await pause(s.ui);
  return true;
}

async function addProfile(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Profiles > Add");
  menu(s.ui, [
    { key: "1", label: "Generate a new seed" },
    { key: "2", label: "Enter an existing seed phrase" },
  ]);
  const how = await s.ui.ask("Select an option or press Enter to go back: ");
  if (!how) return;

  let mnemonic: string;
  let generated = false;
  if (how === "1") {
    const words = await askInt(s, "Word count 12 or 24 (default 24): ", { default: 24 });
    if (words !== 12 && words !== 24) {
      fail(s.ui, "Word count must be 12 or 24.");
      await pause(s.ui);
      return;
    }
    mnemonic = generateMnemonic(words);
    generated = true;
  } else if (how === "2") {
    mnemonic = await s.ui.askHidden("Seed phrase (hidden): ");
    if (!mnemonic) return;
  } else {
    fail(s.ui, "Invalid choice.");
    await pause(s.ui);
    return;
  }

  const name = await s.ui.ask("Profile name (optional): ");
  const password = await s.ui.askHidden("Master password for the new profile: ");
  const again = await s.ui.askHidden("Confirm password: ");
  if (password !== again) {
    fail(s.ui, "Passwords do not match. Nothing was created.");
    await pause(s.ui);
    return;
  }

  if (generated) {
    // Show it before creating anything: a generated seed that is never seen
    // is a vault nobody can recover.
    s.ui.say();
    warn(s.ui, "Write this seed phrase down and store it offline.");
    warn(s.ui, "It is the ONLY way to recover this profile.");
    s.ui.say();
    s.ui.say(`${ansi.bold}${mnemonic}${ansi.reset}`);
    s.ui.say();
    await pause(s.ui);
    if (!(await confirm(s.ui, "Have you written it down?"))) {
      warn(s.ui, "Cancelled. Nothing was created.");
      await pause(s.ui);
      return;
    }
  }

  const fp = await s.app.createProfile(mnemonic, password, name || undefined, kdfIterations(s));
  ok(s.ui, `Profile ${fp} created.`);
  await pause(s.ui);
}

async function removeProfile(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Profiles > Remove");
  const fp = await pickProfile(s, "Select a profile to REMOVE or press Enter to go back: ");
  if (fp === null) return;
  warn(s.ui, `This deletes the profile directory for ${fp}.`);
  warn(s.ui, "Entries derived from the seed can be recreated; imported secrets cannot.");
  const typed = await s.ui.ask(`Type the fingerprint to confirm: `);
  if (typed !== fp) {
    warn(s.ui, "Fingerprint did not match. Nothing was removed.");
    await pause(s.ui);
    return;
  }
  await s.app.removeProfile(fp);
  ok(s.ui, `Removed ${fp}.`);
  if (fp === s.fingerprint) {
    warn(s.ui, "That was the active profile. Restart seedpass-js to pick another.");
    await pause(s.ui);
    process.exit(0);
  }
  await pause(s.ui);
}

async function listProfiles(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Profiles > List");
  const data = await s.app.readFingerprints();
  s.ui.say();
  for (const fp of data.fingerprints) {
    const current = fp === s.fingerprint ? `${ansi.green} (current)${ansi.reset}` : "";
    s.ui.say(`  ${fp}  ${data.names[fp] ?? ""}${current}`);
  }
  s.ui.say();
  await pause(s.ui);
}

async function setProfileName(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Profiles > Set Name");
  const fp = await pickProfile(s, "Select a profile or press Enter to go back: ");
  if (fp === null) return;
  const name = await s.ui.ask("New name (blank to clear): ");
  await s.app.setProfileName(fp, name);
  if (fp === s.fingerprint) s.name = name || null;
  ok(s.ui, "Name saved.");
  await pause(s.ui);
}

// ------------------------------------------------------------------ nostr

async function nostrMenu(s: Session): Promise<void> {
  for (;;) {
    title(s, "Main Menu > Settings > Nostr");
    menu(s.ui, [
      { key: "1", label: "Backup to Nostr" },
      { key: "2", label: "Restore from Nostr" },
      { key: "3", label: "View current relays" },
      { key: "4", label: "Add a relay URL" },
      { key: "5", label: "Remove a relay by number" },
      { key: "6", label: "Reset to default relays" },
      { key: "7", label: "Display Nostr Public Key" },
      { key: "8", label: "Reset Nostr sync state" },
      { key: "9", label: "Start fresh Nostr namespace (new key index)" },
    ]);
    const choice = await s.ui.ask("Select an option or press Enter to go back: ");
    if (!choice) return;
    try {
      switch (choice) {
        case "1":
        case "2":
          warn(
            s.ui,
            `Run it from the command line: ${ansi.cyan}seedpass-js nostr ` +
              `${choice === "1" ? "sync" : "restore"}${ansi.reset}`,
          );
          warn(s.ui, "Relay traffic prints progress that does not belong inside a menu.");
          await pause(s.ui);
          break;
        case "3":
          await viewRelays(s);
          break;
        case "4":
          await addRelay(s);
          break;
        case "5":
          await removeRelay(s);
          break;
        case "6":
          await saveSetting(s, "relays", [...DEFAULT_RELAYS]);
          ok(s.ui, "Relays reset to defaults.");
          await pause(s.ui);
          break;
        case "7":
          await displayNpub(s);
          break;
        case "8":
          await saveSetting(s, "last_sync_ts", 0);
          ok(s.ui, "Nostr sync state reset; the next sync republishes everything.");
          await pause(s.ui);
          break;
        case "9":
          await startFreshNamespace(s);
          break;
        default:
          fail(s.ui, "Invalid choice.");
          await pause(s.ui);
      }
    } catch (e) {
      fail(s.ui, `Action failed: ${(e as Error).message}`);
      await pause(s.ui);
    }
  }
}

function relaysOf(s: Session): string[] {
  const relays = s.config["relays"];
  return Array.isArray(relays) ? (relays as string[]) : [...DEFAULT_RELAYS];
}

async function viewRelays(s: Session): Promise<void> {
  s.ui.say();
  relaysOf(s).forEach((r, i) => s.ui.say(`  ${ansi.cyan}${i + 1}.${ansi.reset} ${r}`));
  s.ui.say();
  await pause(s.ui);
}

async function addRelay(s: Session): Promise<void> {
  const url = await s.ui.ask("Relay URL (wss://...): ");
  if (!url) return;
  if (!/^wss?:\/\//i.test(url)) {
    fail(s.ui, "A relay URL must start with ws:// or wss://.");
    await pause(s.ui);
    return;
  }
  const relays = relaysOf(s);
  if (relays.includes(url)) {
    warn(s.ui, "That relay is already configured.");
    await pause(s.ui);
    return;
  }
  await saveSetting(s, "relays", [...relays, url]);
  ok(s.ui, "Relay added.");
  await pause(s.ui);
}

async function removeRelay(s: Session): Promise<void> {
  const relays = relaysOf(s);
  s.ui.say();
  relays.forEach((r, i) => s.ui.say(`  ${ansi.cyan}${i + 1}.${ansi.reset} ${r}`));
  s.ui.say();
  const n = await askInt(s, "Remove which number? ", { min: 1, max: relays.length });
  if (n === null) return;
  if (relays.length === 1 && !(await confirm(s.ui, "That is the last relay. Remove it anyway?"))) {
    return;
  }
  await saveSetting(s, "relays", relays.filter((_, i) => i !== n - 1));
  ok(s.ui, "Relay removed.");
  await pause(s.ui);
}

async function displayNpub(s: Session): Promise<void> {
  const keys = deriveNostrKeys(Bip85.fromMnemonic(s.vault.mnemonic));
  s.ui.say();
  s.ui.say(`  ${ansi.dim}npub${ansi.reset} ${keys.npub}`);
  s.ui.say(`  ${ansi.dim}hex ${ansi.reset} ${keys.publicKeyHex}`);
  s.ui.say();
  await pause(s.ui);
}

async function startFreshNamespace(s: Session): Promise<void> {
  warn(s.ui, "This moves sync to a new Nostr key index.");
  warn(s.ui, "Snapshots under the old index stay on the relays but are no longer used.");
  if (!(await confirm(s.ui, "Continue?"))) return;
  const current = Number(s.config["nostr_key_index"] ?? 0);
  await saveSetting(s, "nostr_key_index", current + 1);
  await saveSetting(s, "last_sync_ts", 0);
  ok(s.ui, `Now using Nostr key index ${current + 1}. Run 'seedpass-js nostr sync' to publish.`);
  await pause(s.ui);
}

// ------------------------------------------------------- settings actions

async function changePassword(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Change password");
  const oldPw = await s.ui.askHidden("Current password: ");
  if (!oldPw) return;
  const newPw = await s.ui.askHidden("New password: ");
  if (!newPw) return;
  const again = await s.ui.askHidden("Confirm new password: ");
  if (newPw !== again) {
    fail(s.ui, "Passwords do not match. Nothing was changed.");
    await pause(s.ui);
    return;
  }
  try {
    await s.app.changePassword(s.fingerprint, oldPw, newPw, kdfIterations(s));
    ok(s.ui, "Password changed.");
  } catch {
    // Indistinguishable from any other failure on purpose: the only useful
    // signal here is "that password was wrong".
    fail(s.ui, "Incorrect password.");
  }
  await pause(s.ui);
}

async function backupParentSeed(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Backup Parent Seed");
  warn(s.ui, "This displays the master seed phrase for this profile.");
  warn(s.ui, "Anyone who sees it owns the vault.");
  if (!(await confirm(s.ui, "Show it?"))) return;
  const password = await s.ui.askHidden("Master password: ");
  if (!password) return;
  try {
    const mnemonic = await s.app.decryptParentSeed(s.fingerprint, password);
    s.ui.say();
    s.ui.say(`${ansi.bold}${mnemonic}${ansi.reset}`);
    s.ui.say();
  } catch {
    fail(s.ui, "Incorrect password.");
  }
  await pause(s.ui);
}

async function exportDatabase(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Export database");
  const suggested = defaultBackupFilename(s.fingerprint);
  const raw = await s.ui.ask(`Destination file or directory (e.g. ${suggested}): `);
  if (!raw) return;
  // Interactive convenience, not applied to CLI scripts: a directory gets
  // the generated name inside it, and a bare name with no extension gets
  // the .seedpass suffix so backups self-identify on disk.
  let dest = raw;
  if (existsSync(dest) && statSync(dest).isDirectory()) {
    dest = join(dest, suggested);
  } else if (!basename(dest).includes(".")) {
    dest = `${dest}${BACKUP_EXTENSION}`;
  }
  const payload = await exportBackup(s.vault.index as unknown as Record<string, unknown>, {
    mnemonic: s.vault.mnemonic,
    fingerprint: s.fingerprint,
  });
  if (!(await writeSecretFile(s, dest, JSON.stringify(payload, null, 2)))) {
    await pause(s.ui);
    return;
  }
  ok(s.ui, `Exported to ${dest}`);
  await pause(s.ui);
}

async function importDatabase(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Import database");
  const src = await s.ui.ask("Path to backup file: ");
  if (!src) return;
  let raw: string;
  try {
    raw = await readFile(src, "utf8");
  } catch {
    fail(s.ui, `Import failed: file '${src}' not found.`);
    await pause(s.ui);
    return;
  }
  const imported = (await importBackup(raw, { mnemonic: s.vault.mnemonic })) as {
    entries?: Record<string, unknown>;
    schema_version?: number;
  };
  const entries = imported.entries ?? {};
  const count = Object.keys(entries).length;
  warn(s.ui, `This REPLACES the current vault (${Object.keys(s.vault.index.entries).length} entries)`);
  warn(s.ui, `with the backup's ${count} entries.`);
  if (!(await confirm(s.ui, "Continue?"))) return;
  await mutate(s, (v) => {
    v.index.entries = entries as VaultIndex["entries"];
    v.index.schema_version = Number(imported.schema_version ?? v.index.schema_version);
  });
  ok(s.ui, `Imported ${count} entries.`);
  await pause(s.ui);
}

async function exportTotpCodes(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Export 2FA codes");
  const dest = await s.ui.ask("Destination file: ");
  if (!dest) return;
  const rows = entriesOf(s.vault.index).filter(
    ({ entry }) => kindOf(entry) === "totp" && !isArchived(entry),
  );
  const uris = rows.map(({ entry }) => ({
    label: String((entry as unknown as Record<string, unknown>)["label"] ?? ""),
    uri: totpUri(entry, s.vault.mnemonic),
  }));
  // This file is every 2FA secret in the vault, in plaintext.
  if (!(await writeSecretFile(s, dest, JSON.stringify({ entries: uris }, null, 2)))) {
    await pause(s.ui);
    return;
  }
  ok(s.ui, `Exported ${uris.length} 2FA entries to ${dest}`);
  warn(s.ui, "That file contains the secrets themselves. Move it somewhere safe or delete it.");
  await pause(s.ui);
}

async function setBackupLocation(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Additional backup location");
  s.ui.say(`Current: ${String(s.config["additional_backup_path"] || "(none)")}`);
  const path = await s.ui.ask("New path (blank to clear): ");
  await saveSetting(s, "additional_backup_path", path);
  ok(s.ui, path ? `Additional backups will be written to ${path}` : "Additional backup cleared.");
  await pause(s.ui);
}

async function kdfSettings(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > KDF strength");
  s.ui.say(`Current iterations: ${String(s.config["kdf_iterations"] ?? 200000)}`);
  s.ui.say(`Current mode:       ${String(s.config["kdf_mode"] ?? "pbkdf2")}`);
  s.ui.say();
  if (await confirm(s.ui, "Benchmark this machine?")) {
    const { deriveKeyFromPassword } = await import("@seedpass/core");
    for (const iters of [100_000, 200_000, 400_000]) {
      const started = Date.now();
      deriveKeyFromPassword("benchmark", "benchmark-salt", iters);
      s.ui.say(`  ${String(iters).padStart(7)} iterations: ${Date.now() - started} ms`);
    }
    s.ui.say();
  }
  const iterations = await askInt(s, "New iteration count (blank to keep): ", { min: 50_000 });
  if (iterations === null) {
    await pause(s.ui);
    return;
  }
  await saveSetting(s, "kdf_iterations", iterations);
  warn(
    s.ui,
    "Saved. This applies to profiles created from now on; use Change password " +
      "to re-wrap this profile's seed at the new strength.",
  );
  await pause(s.ui);
}

async function setInactivityTimeout(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Inactivity timeout");
  s.ui.say(`Current: ${String(s.config["inactivity_timeout"] ?? 900)} seconds`);
  const seconds = await askInt(s, "New timeout in seconds: ", { min: 30 });
  if (seconds === null) {
    await pause(s.ui);
    return;
  }
  await saveSetting(s, "inactivity_timeout", seconds);
  ok(s.ui, `Inactivity timeout set to ${seconds} seconds.`);
  await pause(s.ui);
}

async function lockVault(s: Session): Promise<void> {
  warn(s.ui, "Vault locked. Please re-enter your password.");
  const mnemonic = await s.relock(s.fingerprint);
  s.vault = await openVault(s.vault.path, mnemonic);
  ok(s.ui, "Unlocked.");
  await pause(s.ui);
}

async function showStats(s: Session): Promise<void> {
  title(s, "Main Menu > Settings > Stats");
  await reload(s);
  const rows = entriesOf(s.vault.index);
  const counts = new Map<string, number>();
  let archived = 0;
  for (const { entry } of rows) {
    counts.set(kindOf(entry), (counts.get(kindOf(entry)) ?? 0) + 1);
    if (isArchived(entry)) archived++;
  }
  s.ui.say(`\n${ansi.bold}=== Seed Profile Stats ===${ansi.reset}`);
  s.ui.say(`Total entries: ${rows.length}`);
  for (const kind of [...counts.keys()].sort()) {
    s.ui.say(`  ${kind}: ${counts.get(kind)}`);
  }
  s.ui.say(`Archived: ${archived}`);
  s.ui.say(`Relays configured: ${relaysOf(s).length}`);
  s.ui.say(`Schema version: ${String(s.vault.index.schema_version)}`);
  s.ui.say(`Profile: ${s.fingerprint}${s.name ? ` (${s.name})` : ""}`);
  s.ui.say(`Secret Mode: ${secretModeOn(s) ? "ON" : "OFF"}`);
  s.ui.say(`Offline Mode: ${s.config["offline_mode"] ? "ON" : "OFF"}`);
  s.ui.say();
  await pause(s.ui);
}

export { totpCodeAt };
