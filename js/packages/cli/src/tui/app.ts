/**
 * The interactive mode: `seedpass-js` with no subcommand.
 *
 * Parity note: Python's `seedpass` launches a TUI when invoked bare, and this
 * exists because the port did not — a new user typing the bare command got a
 * help dump and no way in.
 *
 * The agent-blind rule from plan section 9.3 holds here exactly as it does in
 * the CLI: the list and detail views render metadata only, `c` copies to the
 * clipboard without ever displaying the value, and `r` is the one explicit
 * plaintext egress — it requires a keypress, says what it is about to do, and
 * the value is erased from the screen when dismissed. Combined with the
 * alternate screen buffer (see terminal.ts) a revealed secret cannot be
 * recovered from scrollback after quitting.
 */

import process from "node:process";
import { join } from "node:path";
import {
  archiveEntry,
  restoreEntry,
  addPasswordEntry,
  addTotpDeterministic,
  addKeyValueEntry,
  assertValidMnemonic,
  isValidMnemonic,
  type Entry,
} from "@seedpass/core";
import { AppDir, resolveAppDir, INDEX_FILENAME } from "../appDir.js";
import { openVault, saveVaultHoldingLock, withVaultLock, type OpenedVault } from "../vaultFile.js";
import { entryMetadata, refFor } from "../refs.js";
import { materializeSecret } from "../secrets.js";
import { clipboardSink } from "../sinks.js";
import { AgentClient, agentSocketPath } from "../agent.js";
import { Terminal, ansi, visibleLength, type Key } from "./terminal.js";

type Screen = "list" | "detail" | "reveal" | "add" | "help" | "profiles";

interface Row {
  id: string;
  label: string;
  kind: string;
  archived: boolean;
  meta: Record<string, unknown>;
}

const ADD_KINDS = ["password", "totp", "key-value"] as const;
type AddKind = (typeof ADD_KINDS)[number];

interface AddState {
  kind: AddKind;
  /** Which field is focused; -1 means the kind picker. */
  field: number;
  values: string[];
}

const ADD_FIELDS: Record<AddKind, string[]> = {
  password: ["label", "length", "username"],
  totp: ["label"],
  "key-value": ["label", "key", "value"],
};

export interface TuiOptions {
  appDir?: string;
  fingerprint?: string;
}

/**
 * What the app needs from a terminal. Narrowed to an interface so tests can
 * drive the real screens through a fake, rather than a pty the test runner
 * cannot allocate — the redaction rules below are worth asserting directly.
 */
export interface TerminalLike {
  readonly columns: number;
  readonly rows: number;
  start(): void;
  restore(): void;
  onKey(handler: (key: Key) => void): void;
  onResize(handler: () => void): void;
  draw(lines: string[]): void;
}

export async function runTui(opts: TuiOptions, terminal?: TerminalLike): Promise<number> {
  if (!terminal && !Terminal.isInteractive()) {
    process.stderr.write(
      "seedpass-js: interactive mode needs a terminal on both stdin and stdout.\n" +
        "Run a subcommand instead — 'seedpass-js --help' lists them.\n",
    );
    return 1;
  }

  const app = new AppDir(resolveAppDir(opts.appDir));
  const fps = await app.readFingerprints();
  if (fps.fingerprints.length === 0) {
    process.stderr.write(
      "No vault yet. Create one with:\n\n" +
        "  export SEEDPASS_PASSWORD='a master password'\n" +
        "  seedpass-js fingerprint create --name personal --words 24 --out ~/seed.txt\n",
    );
    return 1;
  }

  const tui = new Tui(app, opts, terminal ?? new Terminal());
  return tui.run();
}

class Tui {
  private screen: Screen = "list";
  private vault: OpenedVault | null = null;
  private fingerprint = "";
  private profileNames: Record<string, string | null> = {};
  private profiles: string[] = [];
  private rows: Row[] = [];
  private filtered: Row[] = [];
  private cursor = 0;
  private scroll = 0;
  private query = "";
  private searching = false;
  private status = "";
  private statusKind: "info" | "error" | "ok" = "info";
  private revealed: { label: string; value: string; descriptor: string } | null = null;
  private add: AddState | null = null;
  private showArchived = false;
  private profileCursor = 0;
  private done = false;
  private exitCode = 0;
  private resolveDone: (() => void) | null = null;

  constructor(
    private readonly app: AppDir,
    private readonly opts: TuiOptions,
    private readonly term: TerminalLike,
  ) {}

  async run(): Promise<number> {
    // Unlock before touching the terminal: the password prompt is a plain
    // line-mode read, and failures should print normally rather than inside
    // an alternate screen that is about to be torn down.
    try {
      await this.unlock();
    } catch (e) {
      process.stderr.write(`seedpass-js: ${(e as Error).message}\n`);
      return 1;
    }

    this.term.start();
    this.term.onResize(() => this.render());
    this.term.onKey((key) => {
      void this.handleKey(key).catch((e: unknown) => {
        this.setStatus((e as Error).message, "error");
        this.render();
      });
    });

    this.render();
    await new Promise<void>((resolve) => {
      this.resolveDone = resolve;
    });
    this.term.restore();
    return this.exitCode;
  }

  private quit(code = 0): void {
    this.done = true;
    this.exitCode = code;
    this.resolveDone?.();
  }

  // ---------------------------------------------------------------- unlock

  private async unlock(): Promise<void> {
    const fps = await this.app.readFingerprints();
    this.profiles = fps.fingerprints;
    this.profileNames = fps.names;
    this.fingerprint = this.opts.fingerprint ?? fps.last_used ?? fps.fingerprints[0]!;

    const mnemonic = await this.resolveMnemonic(this.fingerprint);
    await this.loadVault(this.fingerprint, mnemonic);
  }

  /**
   * Same resolution order as the CLI: environment, then the session agent,
   * then ask. Asking is last because the other two mean the user already
   * decided how this session is unlocked.
   */
  private async resolveMnemonic(fingerprint: string): Promise<string> {
    const env = process.env["SEEDPASS_MNEMONIC"];
    if (env) {
      assertValidMnemonic(env, "SEEDPASS_MNEMONIC");
      return env;
    }
    try {
      const held = await new AgentClient(agentSocketPath(this.app.root)).ownerMnemonic(fingerprint);
      if (held) return held;
    } catch {
      // no agent, or it holds nothing for this profile — fall through to ask
    }

    const name = this.profileNames[fingerprint];
    const prompt = new HiddenPrompt();
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        const password = await prompt.ask(
          `Master password for ${name ? `${name} (${fingerprint})` : fingerprint}: `,
        );
        if (password === null) throw new Error("cancelled");
        try {
          return await this.app.decryptParentSeed(fingerprint, password);
        } catch {
          process.stderr.write("Wrong password.\n");
        }
      }
      throw new Error("too many failed password attempts");
    } finally {
      prompt.close();
    }
  }

  private async loadVault(fingerprint: string, mnemonic: string): Promise<void> {
    const path = join(this.app.profileDir(fingerprint), INDEX_FILENAME);
    this.vault = await openVault(path, mnemonic);
    this.fingerprint = fingerprint;
    this.refreshRows();
  }

  private refreshRows(): void {
    const index = this.vault!.index;
    this.rows = Object.entries(index.entries)
      .map(([id, entry]) => {
        const meta = entryMetadata(id, entry as Entry);
        return {
          id,
          label: String((entry as Entry).label ?? ""),
          kind: String((entry as Entry).kind ?? (entry as Entry).type ?? "unknown"),
          archived: Boolean((entry as Entry).archived),
          meta,
        };
      })
      .sort((a, b) => Number(a.id) - Number(b.id));
    this.applyFilter();
  }

  private applyFilter(): void {
    const q = this.query.trim().toLowerCase();
    this.filtered = this.rows.filter((r) => {
      if (r.archived && !this.showArchived) return false;
      if (!q) return true;
      const tags = Array.isArray(r.meta["tags"]) ? (r.meta["tags"] as string[]).join(" ") : "";
      return `${r.label} ${r.kind} ${tags} ${String(r.meta["username"] ?? "")}`
        .toLowerCase()
        .includes(q);
    });
    if (this.cursor >= this.filtered.length) this.cursor = Math.max(0, this.filtered.length - 1);
  }

  private current(): Row | null {
    return this.filtered[this.cursor] ?? null;
  }

  private setStatus(text: string, kind: "info" | "error" | "ok" = "info"): void {
    this.status = text;
    this.statusKind = kind;
  }

  // ------------------------------------------------------------------ keys

  private async handleKey(key: Key): Promise<void> {
    if (this.done) return;
    if (key.name === "ctrl-c") {
      this.quit(130);
      return;
    }

    switch (this.screen) {
      case "list":
        await this.keyList(key);
        break;
      case "detail":
        await this.keyDetail(key);
        break;
      case "reveal":
        this.keyReveal(key);
        break;
      case "add":
        await this.keyAdd(key);
        break;
      case "help":
        this.screen = "list";
        break;
      case "profiles":
        await this.keyProfiles(key);
        break;
    }
    if (!this.done) this.render();
  }

  private async keyList(key: Key): Promise<void> {
    if (this.searching) {
      switch (key.name) {
        case "enter":
        case "escape":
          this.searching = false;
          if (key.name === "escape") {
            this.query = "";
            this.applyFilter();
          }
          return;
        case "backspace":
          this.query = this.query.slice(0, -1);
          this.applyFilter();
          return;
        case "char":
          this.query += key.ch;
          this.applyFilter();
          return;
        default:
          return;
      }
    }

    switch (key.name) {
      case "up":
        this.move(-1);
        return;
      case "down":
        this.move(1);
        return;
      case "pageup":
        this.move(-this.pageSize());
        return;
      case "pagedown":
        this.move(this.pageSize());
        return;
      case "home":
        this.cursor = 0;
        return;
      case "end":
        this.cursor = Math.max(0, this.filtered.length - 1);
        return;
      case "enter":
        if (this.current()) this.screen = "detail";
        return;
      case "escape":
        if (this.query) {
          this.query = "";
          this.applyFilter();
        }
        return;
      case "char":
        break;
      default:
        return;
    }

    switch (key.ch) {
      case "/":
        this.searching = true;
        this.setStatus("");
        return;
      case "q":
        this.quit(0);
        return;
      case "?":
        this.screen = "help";
        return;
      case "c":
        await this.copyCurrent();
        return;
      case "r":
        this.revealCurrent();
        return;
      case "a":
        this.add = { kind: "password", field: -1, values: ["", "", ""] };
        this.screen = "add";
        return;
      case "d":
        await this.toggleArchive();
        return;
      case "A":
        this.showArchived = !this.showArchived;
        this.applyFilter();
        this.setStatus(this.showArchived ? "showing archived" : "hiding archived");
        return;
      case "p":
        this.screen = "profiles";
        this.profileCursor = Math.max(0, this.profiles.indexOf(this.fingerprint));
        return;
      case "g":
        await this.reload();
        return;
      default:
        return;
    }
  }

  private async keyDetail(key: Key): Promise<void> {
    if (key.name === "escape" || (key.name === "char" && (key.ch === "q" || key.ch === "h"))) {
      this.screen = "list";
      return;
    }
    if (key.name === "char") {
      switch (key.ch) {
        case "c":
          await this.copyCurrent();
          return;
        case "r":
          this.revealCurrent();
          return;
        case "d":
          await this.toggleArchive();
          return;
        case "?":
          this.screen = "help";
          return;
        default:
          return;
      }
    }
    if (key.name === "up") this.move(-1);
    if (key.name === "down") this.move(1);
  }

  private keyReveal(_key: Key): void {
    // Any key dismisses. The value is dropped here and the frame is redrawn
    // without it, so it exists on screen only while being looked at.
    this.revealed = null;
    this.screen = "detail";
    this.setStatus("hidden");
  }

  private async keyProfiles(key: Key): Promise<void> {
    switch (key.name) {
      case "up":
        this.profileCursor = Math.max(0, this.profileCursor - 1);
        return;
      case "down":
        this.profileCursor = Math.min(this.profiles.length - 1, this.profileCursor + 1);
        return;
      case "escape":
        this.screen = "list";
        return;
      case "enter": {
        const fp = this.profiles[this.profileCursor];
        if (!fp || fp === this.fingerprint) {
          this.screen = "list";
          return;
        }
        await this.switchProfile(fp);
        return;
      }
      case "char":
        if (key.ch === "q") this.screen = "list";
        return;
      default:
        return;
    }
  }

  private async keyAdd(key: Key): Promise<void> {
    const state = this.add!;
    const fields = ADD_FIELDS[state.kind];

    if (key.name === "escape") {
      this.add = null;
      this.screen = "list";
      this.setStatus("cancelled");
      return;
    }

    // Kind picker.
    if (state.field === -1) {
      if (key.name === "left" || key.name === "up") {
        const i = ADD_KINDS.indexOf(state.kind);
        state.kind = ADD_KINDS[(i - 1 + ADD_KINDS.length) % ADD_KINDS.length]!;
        state.values = ADD_FIELDS[state.kind].map(() => "");
        return;
      }
      if (key.name === "right" || key.name === "down" || key.name === "tab") {
        const i = ADD_KINDS.indexOf(state.kind);
        state.kind = ADD_KINDS[(i + 1) % ADD_KINDS.length]!;
        state.values = ADD_FIELDS[state.kind].map(() => "");
        return;
      }
      if (key.name === "enter") {
        state.field = 0;
        return;
      }
      return;
    }

    switch (key.name) {
      case "enter":
        if (state.field < fields.length - 1) {
          state.field += 1;
          return;
        }
        await this.commitAdd();
        return;
      case "tab":
        state.field = (state.field + 1) % fields.length;
        return;
      case "up":
        state.field = Math.max(0, state.field - 1);
        return;
      case "down":
        state.field = Math.min(fields.length - 1, state.field + 1);
        return;
      case "backspace":
        state.values[state.field] = state.values[state.field]!.slice(0, -1);
        return;
      case "char":
        state.values[state.field] += key.ch;
        return;
      default:
        return;
    }
  }

  private move(delta: number): void {
    if (this.filtered.length === 0) return;
    this.cursor = Math.min(this.filtered.length - 1, Math.max(0, this.cursor + delta));
  }

  private pageSize(): number {
    return Math.max(1, this.term.rows - 6);
  }

  // ---------------------------------------------------------------- actions

  private async copyCurrent(): Promise<void> {
    const row = this.current();
    if (!row) return;
    const secret = materializeSecret(
      this.vault!.index,
      row.id,
      this.vault!.index.entries[row.id] as Entry,
      this.vault!.mnemonic,
    );
    const result = await clipboardSink(secret.value);
    // Deliberately reports the descriptor, never the value.
    this.setStatus(`copied ${secret.descriptor} (${result.detail})`, "ok");
  }

  private revealCurrent(): void {
    const row = this.current();
    if (!row) return;
    const secret = materializeSecret(
      this.vault!.index,
      row.id,
      this.vault!.index.entries[row.id] as Entry,
      this.vault!.mnemonic,
    );
    this.revealed = { label: row.label, value: secret.value, descriptor: secret.descriptor };
    this.screen = "reveal";
  }

  private async toggleArchive(): Promise<void> {
    const row = this.current();
    if (!row) return;
    const wasArchived = row.archived;
    await this.mutate((vault) => {
      if (wasArchived) restoreEntry(vault.index, row.id);
      else archiveEntry(vault.index, row.id);
    });
    this.setStatus(`${wasArchived ? "unarchived" : "archived"} ${row.label}`, "ok");
  }

  private async commitAdd(): Promise<void> {
    const state = this.add!;
    const fields = ADD_FIELDS[state.kind];
    const value = (name: string): string => state.values[fields.indexOf(name)]?.trim() ?? "";

    const label = value("label");
    if (!label) {
      this.setStatus("label is required", "error");
      return;
    }

    let newId = "";
    await this.mutate((vault) => {
      switch (state.kind) {
        case "password": {
          const raw = value("length");
          const length = raw ? Number(raw) : 20;
          if (!Number.isInteger(length) || length < 8 || length > 128) {
            throw new Error("length must be a whole number between 8 and 128");
          }
          const username = value("username");
          newId = addPasswordEntry(vault.index, label, length, {
            ...(username && { username }),
          });
          return;
        }
        case "totp":
          newId = addTotpDeterministic(vault.index, label, vault.mnemonic);
          return;
        case "key-value": {
          const key = value("key");
          if (!key) throw new Error("key is required");
          newId = addKeyValueEntry(vault.index, label, key, value("value"));
          return;
        }
      }
    });

    this.add = null;
    this.screen = "list";
    // Land the cursor on what was just created.
    const at = this.filtered.findIndex((r) => r.id === newId);
    if (at >= 0) this.cursor = at;
    this.setStatus(`added ${refFor(newId)} ${label}`, "ok");
  }

  /**
   * Apply a change under the vault lock and re-read afterwards.
   *
   * The whole read-modify-write cycle is inside the lock, matching the CLI:
   * the TUI holds an in-memory index for the length of a session, so writing
   * it back without re-reading would clobber anything a concurrent
   * `seedpass-js` or a `nostr restore` wrote in the meantime.
   */
  private async mutate(fn: (vault: OpenedVault) => void): Promise<void> {
    const path = this.vault!.path;
    const mnemonic = this.vault!.mnemonic;
    await withVaultLock(path, async () => {
      const fresh = await openVault(path, mnemonic);
      fn(fresh);
      await saveVaultHoldingLock(fresh);
      this.vault = fresh;
    });
    this.refreshRows();
  }

  private async reload(): Promise<void> {
    this.vault = await openVault(this.vault!.path, this.vault!.mnemonic);
    this.refreshRows();
    this.setStatus("reloaded", "ok");
  }

  private async switchProfile(fingerprint: string): Promise<void> {
    // A different profile is a different seed; the current one must not be
    // reused to open it.
    this.term.restore();
    try {
      const mnemonic = await this.resolveMnemonic(fingerprint);
      await this.loadVault(fingerprint, mnemonic);
      await this.app.switchProfile(fingerprint);
      this.cursor = 0;
      this.query = "";
      this.applyFilter();
      this.setStatus(`switched to ${this.profileNames[fingerprint] ?? fingerprint}`, "ok");
    } finally {
      this.term.start();
    }
    this.screen = "list";
  }

  // ---------------------------------------------------------------- render

  private render(): void {
    if (this.done) return;
    const width = this.term.columns;
    const rows = this.term.rows;
    const lines: string[] = [];

    const name = this.profileNames[this.fingerprint];
    const title = ` SeedPass  ${ansi.dim}${name ? `${name} · ` : ""}${this.fingerprint}${ansi.reset}`;
    lines.push(`${ansi.reverse}${pad(title, width)}${ansi.reset}`);

    switch (this.screen) {
      case "list":
      case "detail":
        this.renderList(lines, width, rows);
        break;
      case "reveal":
        this.renderReveal(lines, width);
        break;
      case "add":
        this.renderAdd(lines, width);
        break;
      case "help":
        this.renderHelp(lines);
        break;
      case "profiles":
        this.renderProfiles(lines);
        break;
    }

    while (lines.length < rows - 1) lines.push("");
    lines.push(this.renderStatus(width));
    this.term.draw(lines.slice(0, rows));
  }

  private renderList(lines: string[], width: number, rows: number): void {
    const detail = this.screen === "detail";
    const listHeight = Math.max(3, (detail ? Math.floor((rows - 4) / 2) : rows - 4));

    // Keep the cursor inside the window.
    if (this.cursor < this.scroll) this.scroll = this.cursor;
    if (this.cursor >= this.scroll + listHeight) this.scroll = this.cursor - listHeight + 1;
    if (this.scroll > Math.max(0, this.filtered.length - listHeight)) {
      this.scroll = Math.max(0, this.filtered.length - listHeight);
    }

    const header = this.searching
      ? `${ansi.cyan}/${this.query}${ansi.reset}${ansi.dim}▌${ansi.reset}`
      : this.query
        ? `${ansi.dim}filter:${ansi.reset} ${this.query}   ${ansi.dim}(esc clears)${ansi.reset}`
        : `${ansi.dim}${this.filtered.length} entr${this.filtered.length === 1 ? "y" : "ies"}${
            this.showArchived ? " (incl. archived)" : ""
          }${ansi.reset}`;
    lines.push(` ${header}`);

    if (this.filtered.length === 0) {
      lines.push("");
      lines.push(
        `  ${ansi.dim}${this.rows.length === 0 ? "No entries yet — press 'a' to add one." : "Nothing matches."}${ansi.reset}`,
      );
    }

    for (let i = this.scroll; i < Math.min(this.filtered.length, this.scroll + listHeight); i++) {
      const row = this.filtered[i]!;
      const selected = i === this.cursor;
      const marker = selected ? `${ansi.cyan}❯${ansi.reset}` : " ";
      const kind = pad(row.kind, 10);
      const label = row.archived ? `${ansi.dim}${row.label}${ansi.reset}` : row.label;
      const secretFlag = hasSecret(row.meta) ? `${ansi.dim}•${ansi.reset}` : " ";
      const line = ` ${marker} ${ansi.grey}${pad(refFor(row.id), 14)}${ansi.reset}${secretFlag} ${ansi.dim}${kind}${ansi.reset} ${label}`;
      lines.push(selected ? highlight(line, width) : line);
    }

    if (detail) {
      lines.push(`${ansi.dim}${"─".repeat(width)}${ansi.reset}`);
      this.renderDetail(lines);
    }
  }

  private renderDetail(lines: string[]): void {
    const row = this.current();
    if (!row) return;
    // Straight from entryMetadata, which is the same redaction the CLI and
    // the agent's read scope use — secret fields arrive as has_* flags.
    for (const [k, v] of Object.entries(row.meta)) {
      if (v === "" || v === null || (Array.isArray(v) && v.length === 0)) continue;
      lines.push(`  ${ansi.dim}${pad(k, 16)}${ansi.reset} ${formatValue(v)}`);
    }
  }

  private renderReveal(lines: string[], width: number): void {
    const r = this.revealed!;
    lines.push("");
    // materializeSecret's descriptor already names the entry ("password for
    // github.com"), so appending the label again read as a stutter.
    lines.push(`  ${ansi.yellow}${r.descriptor}${ansi.reset}`);
    lines.push("");
    lines.push(`  ${ansi.bold}${r.value}${ansi.reset}`);
    lines.push("");
    lines.push(
      `  ${ansi.dim}On screen only until you press a key. Nothing is written to${ansi.reset}`,
    );
    lines.push(`  ${ansi.dim}scrollback — this view disappears with the session.${ansi.reset}`);
    void width;
  }

  private renderAdd(lines: string[], width: number): void {
    const state = this.add!;
    const fields = ADD_FIELDS[state.kind];
    lines.push("");
    const picker = ADD_KINDS.map((k) =>
      k === state.kind ? `${ansi.reverse} ${k} ${ansi.reset}` : ` ${ansi.dim}${k}${ansi.reset} `,
    ).join(" ");
    lines.push(`  ${state.field === -1 ? `${ansi.cyan}❯${ansi.reset}` : " "} ${picker}`);
    lines.push("");
    fields.forEach((field, i) => {
      const focused = state.field === i;
      const marker = focused ? `${ansi.cyan}❯${ansi.reset}` : " ";
      const raw = state.values[i] ?? "";
      // The key-value "value" is a secret being imported, so it is masked
      // like any other secret: the rule here is that nothing secret reaches
      // the screen without an explicit reveal, and a field being typed is no
      // exception. Check it afterwards with 'r'.
      const secretField = state.kind === "key-value" && field === "value";
      const shown = secretField ? "•".repeat(raw.length) : raw;
      const hint =
        field === "length" && !raw
          ? `${ansi.dim}20${ansi.reset}`
          : secretField
            ? `${ansi.dim}${raw ? "hidden" : "(optional, hidden as you type)"}${ansi.reset}`
            : "";
      lines.push(
        `  ${marker} ${ansi.dim}${pad(field, 10)}${ansi.reset} ${shown}${focused ? `${ansi.cyan}▌${ansi.reset}` : ""} ${hint}`,
      );
    });
    lines.push("");
    if (state.kind === "password") {
      lines.push(
        `  ${ansi.dim}The password is derived from your seed — it is never shown here${ansi.reset}`,
      );
      lines.push(`  ${ansi.dim}and never stored. Use 'c' to copy it afterwards.${ansi.reset}`);
    }
    if (state.kind === "totp") {
      lines.push(`  ${ansi.dim}A deterministic TOTP secret is derived at the next free index.${ansi.reset}`);
    }
    void width;
  }

  private renderHelp(lines: string[]): void {
    const keys: [string, string][] = [
      ["↑ ↓ / pgup pgdn", "move"],
      ["enter", "open entry"],
      ["/", "search (esc clears)"],
      ["c", "copy secret to clipboard (never displayed)"],
      ["r", "reveal secret on screen until a key is pressed"],
      ["a", "add an entry"],
      ["d", "archive / unarchive"],
      ["A", "show or hide archived entries"],
      ["p", "switch profile"],
      ["g", "reload the vault from disk"],
      ["?", "this help"],
      ["q", "quit"],
    ];
    lines.push("");
    for (const [k, what] of keys) lines.push(`  ${ansi.cyan}${pad(k, 18)}${ansi.reset} ${what}`);
    lines.push("");
    lines.push(`  ${ansi.dim}Entries show metadata only. 'c' and 'r' are the only ways${ansi.reset}`);
    lines.push(`  ${ansi.dim}a secret leaves the vault, and both need a keypress.${ansi.reset}`);
    lines.push("");
    lines.push(`  ${ansi.dim}press any key${ansi.reset}`);
  }

  private renderProfiles(lines: string[]): void {
    lines.push("");
    this.profiles.forEach((fp, i) => {
      const marker = i === this.profileCursor ? `${ansi.cyan}❯${ansi.reset}` : " ";
      const active = fp === this.fingerprint ? `${ansi.green}●${ansi.reset}` : " ";
      lines.push(`  ${marker} ${active} ${pad(fp, 20)} ${ansi.dim}${this.profileNames[fp] ?? ""}${ansi.reset}`);
    });
    lines.push("");
    lines.push(`  ${ansi.dim}enter to switch (asks for that profile's password), esc to cancel${ansi.reset}`);
  }

  private renderStatus(width: number): string {
    const hints =
      this.screen === "add"
        ? "enter next · esc cancel"
        : this.screen === "reveal"
          ? "any key hides"
          : "/ search · c copy · r reveal · a add · ? help · q quit";
    const colour =
      this.statusKind === "error" ? ansi.red : this.statusKind === "ok" ? ansi.green : ansi.dim;
    const left = this.status ? `${colour}${this.status}${ansi.reset}` : `${ansi.dim}${hints}${ansi.reset}`;
    return ` ${truncate(left, width - 2)}`;
  }
}

// ------------------------------------------------------------------ helpers

function hasSecret(meta: Record<string, unknown>): boolean {
  return Object.entries(meta).some(([k, v]) => k.startsWith("has_") && v === true);
}

function formatValue(v: unknown): string {
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
}

function pad(s: string, width: number): string {
  const len = visibleLength(s);
  return len >= width ? s : s + " ".repeat(width - len);
}

function truncate(s: string, width: number): string {
  return visibleLength(s) <= width ? s : s.slice(0, Math.max(0, width - 1)) + "…";
}

function highlight(line: string, width: number): string {
  return `${ansi.reverse}${pad(truncate(line, width), width)}${ansi.reset}`;
}

/**
 * Reads passwords with echo off.
 *
 * Raw mode is entered once and held for the whole sequence rather than per
 * prompt. Toggling it around each read re-enables echo between attempts, so
 * anything typed in that window — a retried password after a typo, most
 * likely — was echoed to the screen in clear text.
 *
 * Written against the tty directly rather than readline, whose line editing
 * echoes what it receives.
 */
class HiddenPrompt {
  private readonly wasRaw: boolean;
  private closed = false;

  constructor() {
    this.wasRaw = process.stdin.isRaw ?? false;
    process.stdin.setRawMode?.(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
  }

  ask(prompt: string): Promise<string | null> {
    return new Promise((resolve) => {
      process.stderr.write(prompt);
      let value = "";
      const finish = (result: string | null): void => {
        process.stdin.removeListener("data", onData);
        process.stderr.write("\n");
        resolve(result);
      };
      const onData = (chunk: string): void => {
        for (const ch of chunk) {
          if (ch === "\r" || ch === "\n") return finish(value);
          if (ch === "\x03") return finish(null);
          if (ch === "\x7f" || ch === "\b") {
            value = value.slice(0, -1);
            continue;
          }
          if (ch >= " ") value += ch;
        }
      };
      process.stdin.on("data", onData);
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    process.stdin.setRawMode?.(this.wasRaw);
    process.stdin.pause();
  }
}

export { isValidMnemonic };
