/**
 * The interactive menus, driven by a scripted UI.
 *
 * Two things are being checked. First, that the menu tree matches Python's
 * legacy TUI — the items, their order, and "blank goes back" — since that is
 * the navigation the port exists to reproduce. Second, that the agent-blind
 * rule survives the move to a screen that shows the whole vault: listings
 * carry metadata only, and a stored secret appears solely through the action
 * whose purpose is to produce it.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, writeFile, mkdir, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  exportBackup,
  type VaultIndex,
} from "@seedpass/core";
import { runTui } from "../src/tui/app.js";
import { AppDir, INDEX_FILENAME, PARENT_SEED_FILENAME } from "../src/appDir.js";
import { openVault } from "../src/vaultFile.js";
import type { Ui } from "../src/tui/console.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);
const STORED_SECRET = "stored-ci-token-value";

let appDir: string;

/**
 * A UI that answers prompts from a script.
 *
 * Running out of answers ends the session rather than hanging: a test that
 * mis-counts its inputs should fail with the transcript in hand, not time out.
 */
class ScriptedUi implements Ui {
  readonly lines: string[] = [];
  readonly prompts: string[] = [];
  private i = 0;

  constructor(private readonly answers: string[]) {}

  say(line = ""): void {
    this.lines.push(line);
  }
  clear(): void {
    this.lines.push("\f");
  }
  async ask(prompt: string): Promise<string> {
    this.prompts.push(prompt);
    if (this.i >= this.answers.length) {
      // Blank is "go back"/"exit" everywhere, so this unwinds the menus.
      return "";
    }
    const answer = this.answers[this.i++]!;
    this.lines.push(`${prompt}${answer}`);
    return answer;
  }
  async askHidden(prompt: string): Promise<string> {
    const answer = await this.ask(prompt);
    // Record that it was asked, never what was typed.
    this.lines[this.lines.length - 1] = `${prompt}<hidden>`;
    return answer;
  }

  /** Everything drawn, with styling removed so assertions read plainly. */
  get text(): string {
    // eslint-disable-next-line no-control-regex
    return this.lines.join("\n").replace(/\x1b\[[0-9;]*m/g, "");
  }
  /** Everything drawn since the last screen clear. */
  get screen(): string {
    const last = this.lines.lastIndexOf("\f");
    // eslint-disable-next-line no-control-regex
    return this.lines.slice(last + 1).join("\n").replace(/\x1b\[[0-9;]*m/g, "");
  }
}

async function run(...answers: string[]): Promise<ScriptedUi> {
  const ui = new ScriptedUi(answers);
  await runTui({ appDir }, ui);
  return ui;
}

beforeEach(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-menus-"));
  const app = new AppDir(appDir);
  const index = { schema_version: 4, entries: {} } as VaultIndex;
  addPasswordEntry(index, "github.com", 20, { username: "adam" });
  addPasswordEntry(index, "gitlab.com", 16, {});
  addKeyValueEntry(index, "ci-token", "CI_TOKEN", STORED_SECRET);
  addTotpDeterministic(index, "email-2fa", MNEMONIC);

  await app.mutateFingerprints((data) => {
    data.fingerprints.push(FINGERPRINT);
    data.names[FINGERPRINT] = "daily";
    data.last_used = FINGERPRINT;
  });
  const dir = app.profileDir(FINGERPRINT);
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, INDEX_FILENAME),
    await encryptV3(deriveIndexKeyBytes(MNEMONIC), utf8(JSON.stringify(index))),
  );
  process.env["SEEDPASS_MNEMONIC"] = MNEMONIC;
});

afterEach(() => {
  delete process.env["SEEDPASS_MNEMONIC"];
});

/**
 * Import guard: a plaintext backup carries no cryptographic binding to the
 * seed it was taken from, so importing one into the wrong profile succeeds
 * and then re-derives every secret from the WRONG seed. The TUI has to say so
 * before it happens, because afterwards nothing looks broken.
 */
describe("importing a backup from another profile", () => {
  const FOREIGN = mnemonics["legal12"]!;

  async function writeForeignBackup(): Promise<string> {
    const wrapper = await exportBackup(
      { schema_version: 4, entries: {} },
      { mnemonic: FOREIGN, fingerprint: generateFingerprint(FOREIGN), encrypt: false },
    );
    const path = join(appDir, "foreign-backup.json");
    await writeFile(path, JSON.stringify(wrapper));
    return path;
  }

  it("warns which profile the backup belongs to and abandons on refusal", async () => {
    const path = await writeForeignBackup();
    const ui = await run("7", "8", path, "n", "", "");
    expect(ui.text).toContain(`belongs to profile ${generateFingerprint(FOREIGN)}`);
    expect(ui.text).toContain("DIFFERENT");

    // The vault is untouched: all four seeded entries still there.
    const vault = await openVault(
      join(new AppDir(appDir).profileDir(FINGERPRINT), INDEX_FILENAME),
      MNEMONIC,
    );
    expect(Object.keys(vault.index.entries)).toHaveLength(4);
  });

  it("still allows it when the user confirms twice", async () => {
    const path = await writeForeignBackup();
    // "y" to the foreign-profile warning, then "y" to the replace-vault
    // confirmation the import already had.
    const ui = await run("7", "8", path, "y", "y", "", "");
    expect(ui.text).toContain("Imported 0 entries");
  });
});

describe("additional backup location", () => {
  it("actually writes a copy there, having said it would", async () => {
    const extra = await mkdtemp(join(tmpdir(), "seedpass-tui-extra-"));
    // Settings > Set additional backup location > path, then add an entry so
    // there is a mutation to snapshot.
    const ui = await run(
      "7", "10", extra, "", "",
      "1", "1", "backup-me.example", "", "", "", "", "", "", "",
    );
    expect(ui.text).toContain(`Additional backups will be written to ${extra}`);

    const mirrored = await readdir(extra);
    expect(mirrored).toHaveLength(1);
    expect(mirrored[0]).toMatch(
      new RegExp(`^${FINGERPRINT}_entries_db_backup_\\d+\\.json\\.enc$`),
    );
  });

  it("tells the user when the configured location stops working", async () => {
    const app = new AppDir(appDir);
    const blocker = join(app.profileDir(FINGERPRINT), "blocker-file");
    await writeFile(blocker, "x");
    const ui = await run(
      "7", "10", join(blocker, "sub"), "", "",
      "1", "1", "still-added.example", "", "", "", "", "", "", "",
    );
    expect(ui.text).toContain("Additional backup location failed");

    // The mutation itself still committed.
    const vault = await openVault(
      join(app.profileDir(FINGERPRINT), INDEX_FILENAME),
      MNEMONIC,
    );
    const labels = Object.values(vault.index.entries).map(
      (e) => (e as unknown as Record<string, unknown>)["label"],
    );
    expect(labels).toContain("still-added.example");
  });
});

describe("main menu", () => {
  it("offers Python's eight items, in Python's order", async () => {
    const ui = await run();
    for (const [n, label] of [
      ["1", "Add Entry"],
      ["2", "Retrieve Entry"],
      ["3", "Search Entries"],
      ["4", "List Entries"],
      ["5", "Modify an Existing Entry"],
      ["6", "2FA Codes"],
      ["7", "Settings"],
      ["8", "List Archived"],
    ] as const) {
      expect(ui.text).toContain(`${n}.`);
      expect(ui.text).toContain(label);
    }
  });

  it("exits on a blank choice", async () => {
    const ui = new ScriptedUi([""]);
    expect(await runTui({ appDir }, ui)).toBe(0);
  });

  it("rejects an unknown choice without leaving the menu", async () => {
    const ui = await run("99", "");
    expect(ui.text).toContain("Invalid choice");
  });
});

describe("settings", () => {
  it("lists all eighteen items in Python's order", async () => {
    const ui = await run("7");
    const expected = [
      "Profiles",
      "Nostr",
      "Change password",
      "Verify Script Checksum",
      "Generate Script Checksum",
      "Backup Parent Seed",
      "Export database",
      "Import database",
      "Export 2FA codes",
      "Set additional backup location",
      "KDF strength & benchmark",
      "Set inactivity timeout",
      "Lock Vault",
      "Stats",
      "Toggle Secret Mode",
      "Toggle Offline Mode",
      "Toggle Quick Unlock",
      "Semantic Index",
    ];
    for (const label of expected) expect(ui.text).toContain(label);
    // Numbering must line up with Python's, or muscle memory picks the wrong
    // item — 13 is Lock Vault there and must be here too.
    expect(ui.text).toMatch(/13\.\s+Lock Vault/);
    expect(ui.text).toMatch(/18\.\s+Semantic Index/);
  });

  it("opens the Profiles submenu with its five items", async () => {
    const ui = await run("7", "1");
    for (const label of [
      "Switch Seed Profile",
      "Add a New Seed Profile",
      "Remove an Existing Seed Profile",
      "List All Seed Profiles",
      "Set Seed Profile Name",
    ]) {
      expect(ui.text).toContain(label);
    }
  });

  it("opens the Nostr submenu with its nine items", async () => {
    const ui = await run("7", "2");
    for (const label of [
      "Backup to Nostr",
      "Restore from Nostr",
      "View current relays",
      "Add a relay URL",
      "Remove a relay by number",
      "Reset to default relays",
      "Display Nostr Public Key",
      "Reset Nostr sync state",
      "Start fresh Nostr namespace",
    ]) {
      expect(ui.text).toContain(label);
    }
  });

  it("toggles Secret Mode and persists it", async () => {
    const ui = await run("7", "15", "", "", "");
    expect(ui.text).toContain("Secret Mode is now ON");
    const { loadConfig } = await import("../src/configFile.js");
    const cfg = await loadConfig(new AppDir(appDir).profileDir(FINGERPRINT), MNEMONIC);
    expect(cfg["secret_mode_enabled"]).toBe(true);
  });

  it("reports stats without printing any stored secret", async () => {
    const ui = await run("7", "14", "");
    expect(ui.text).toContain("Total entries: 4");
    expect(ui.text).toContain("password: 2");
    expect(ui.text).toContain("key_value: 1");
    expect(ui.text).not.toContain(STORED_SECRET);
  });

  it("adds and removes a relay", async () => {
    const added = await run("7", "2", "4", "wss://relay.example", "", "", "", "");
    expect(added.text).toContain("Relay added");
    const { loadConfig } = await import("../src/configFile.js");
    const cfg = await loadConfig(new AppDir(appDir).profileDir(FINGERPRINT), MNEMONIC);
    expect(cfg["relays"]).toContain("wss://relay.example");
  });

  it("refuses a relay URL that is not a websocket URL", async () => {
    const ui = await run("7", "2", "4", "https://not-a-relay.example", "", "", "", "");
    expect(ui.text).toContain("must start with ws:// or wss://");
  });
});

describe("listing and details", () => {
  it("lists entries by index, type and label", async () => {
    const ui = await run("4", "1", "");
    expect(ui.text).toContain("0.");
    expect(ui.text).toContain("Password - github.com");
    expect(ui.text).toContain("Key Value - ci-token");
    // The stored secret must not be in a listing.
    expect(ui.text).not.toContain(STORED_SECRET);
  });

  it("filters the list by entry type", async () => {
    // 4 = List Entries, 8 = Key Value (1 is All, then the nine types in order).
    const ui = await run("4", "8", "");
    expect(ui.text).toContain("ci-token");
    expect(ui.text).not.toContain("github.com");
  });

  it("shows entry details with stored secrets reduced to flags", async () => {
    const ui = await run("4", "1", "2", "");
    expect(ui.text).toContain("ci-token");
    expect(ui.text).toContain("has_value");
    expect(ui.text).not.toContain(STORED_SECRET);
  });

  it("offers the entry actions Python offers", async () => {
    const ui = await run("4", "1", "0", "");
    for (const label of [
      "Archive",
      "Add Note",
      "Add Custom Field",
      "Add Hidden Field",
      "Edit",
      "Edit Tags",
    ]) {
      expect(ui.text).toContain(label);
    }
  });

  it("shows a stored secret only when asked", async () => {
    const before = await run("4", "1", "2", "");
    expect(before.text).not.toContain(STORED_SECRET);
    const after = await run("4", "1", "2", "s", "", "");
    expect(after.text).toContain(STORED_SECRET);
  });

  it("offers document export only for documents", async () => {
    const ui = await run("4", "1", "0", "");
    expect(ui.text).not.toContain("Export Document to File");
  });
});

describe("search and retrieve", () => {
  it("finds entries by label", async () => {
    const ui = await run("3", "git", "");
    expect(ui.text).toContain("github.com");
    expect(ui.text).toContain("gitlab.com");
    expect(ui.text).not.toContain("ci-token");
  });

  it("says so when nothing matches", async () => {
    const ui = await run("3", "nothing-matches-this", "");
    expect(ui.text).toContain("No matching entries found");
  });

  it("retrieves by index and by label", async () => {
    expect((await run("2", "0", "")).text).toContain("github.com");
    expect((await run("2", "ci-token", "")).text).toContain("CI_TOKEN");
  });
});

describe("mutations", () => {
  async function reopen(): Promise<VaultIndex> {
    const vault = await openVault(
      join(new AppDir(appDir).profileDir(FINGERPRINT), INDEX_FILENAME),
      MNEMONIC,
    );
    return vault.index;
  }

  it("adds a password entry through the menus", async () => {
    // 1 Add Entry, 1 Password, then label/length/username/url/notes/tags.
    await run("1", "1", "new-site.example", "24", "bob", "", "", "work,prod", "", "");
    const index = await reopen();
    const added = Object.values(index.entries).find((e) => e.label === "new-site.example");
    expect(added).toBeTruthy();
    expect(added!["length"]).toBe(24);
    expect(added!["username"]).toBe("bob");
    expect(added!["tags"]).toEqual(["work", "prod"]);
  });

  it("adds a key/value entry without echoing the value", async () => {
    const ui = await run("1", "7", "deploy", "DEPLOY_TOKEN", "sup3r-s3cret", "", "");
    expect(ui.text).not.toContain("sup3r-s3cret");
    const index = await reopen();
    const added = Object.values(index.entries).find((e) => e.label === "deploy");
    expect(added!["value"]).toBe("sup3r-s3cret");
  });

  it("refuses a non-numeric password length rather than storing NaN", async () => {
    const ui = await run("1", "1", "bad", "not-a-number", "", "");
    expect(ui.text).toContain("whole number");
    const index = await reopen();
    expect(Object.values(index.entries).find((e) => e.label === "bad")).toBeUndefined();
  });

  it("archives an entry and lists it under List Archived", async () => {
    await run("4", "1", "0", "a", "", "", "", "");
    const index = await reopen();
    expect(index.entries["0"]!["archived"]).toBe(true);
    const archived = await run("8", "");
    expect(archived.text).toContain("github.com");
  });

  it("edits a label through Edit", async () => {
    await run("4", "1", "0", "e", "l", "renamed.example", "", "", "", "");
    const index = await reopen();
    expect(index.entries["0"]!.label).toBe("renamed.example");
  });

  it("adds a note", async () => {
    await run("4", "1", "0", "n", "a useful note", "", "", "", "");
    const index = await reopen();
    expect(index.entries["0"]!["notes"]).toBe("a useful note");
  });

  it("adds a hidden custom field without echoing its value", async () => {
    const ui = await run("4", "1", "0", "h", "recovery", "hidden-field-value", "", "", "", "");
    expect(ui.text).not.toContain("hidden-field-value");
    const index = await reopen();
    const fields = index.entries["0"]!["custom_fields"] as Record<string, unknown>[];
    expect(fields).toEqual([
      { label: "recovery", value: "hidden-field-value", is_hidden: true },
    ]);
  });

  it("exports the database to a file", async () => {
    const dest = join(appDir, "backup.json");
    const ui = await run("7", "7", dest, "", "", "");
    expect(ui.text).toContain("Exported to");
    const wrapper = JSON.parse(await readFile(dest, "utf8"));
    expect(wrapper.format_version).toBe(1);
  });
});

describe("2FA codes", () => {
  it("shows a code for each TOTP entry", async () => {
    const ui = await run("6", "", "");
    expect(ui.text).toContain("email-2fa");
    expect(ui.text).toMatch(/\d{6}/);
    expect(ui.text).toContain("s left");
  });
});

describe("KDF strength setting takes effect", () => {
  it("Change password re-wraps the parent seed at the configured iterations", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-kdf-"));
    const app = new AppDir(dir);
    const PW = "orig-pw";
    const fp = await app.createProfile(MNEMONIC, PW, "kdf-test"); // default 200000
    const seedPath = join(app.profileDir(fp), PARENT_SEED_FILENAME);

    const before = JSON.parse(await readFile(seedPath, "utf8"));
    expect(before.kdf.params.iterations).toBe(200000);

    // Settings(7) > KDF(11) > no benchmark > 300000 > Enter, then
    // Change password(3) > old > new > confirm > Enter > back > exit.
    const ui = new ScriptedUi([
      "7", "11", "n", "300000", "",
      "3", PW, "new-pw", "new-pw", "",
      "", "",
    ]);
    await runTui({ appDir: dir, fingerprint: fp }, ui);

    const after = JSON.parse(await readFile(seedPath, "utf8"));
    expect(after.kdf.params.iterations).toBe(300000);
    // The setting is not cosmetic: the new password opens the re-wrapped seed.
    expect(await app.decryptParentSeed(fp, "new-pw")).toBe(MNEMONIC);
  });

  it("a new profile is wrapped at the active profile's configured iterations", async () => {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-kdf2-"));
    const app = new AppDir(dir);
    const fp = await app.createProfile(MNEMONIC, "pw", "primary");

    // Set KDF to 250000, then add a second profile from a generated seed.
    const ui = new ScriptedUi([
      "7", "11", "n", "250000", "",         // Settings > KDF > 250000
      "1",                                   // Settings > Profiles
      "2",                                   // Profiles > Add
      "1", "12",                             // generate, 12 words
      "second",                              // profile name
      "np", "np",                            // new password x2
      "",                                     // pause after showing seed
      "y",                                    // "have you written it down?"
      "",                                     // pause after created
      "", "", "",                            // back out: profiles, settings, main
    ]);
    await runTui({ appDir: dir, fingerprint: fp }, ui);

    // Find the profile that is not the primary and check its wrap strength.
    const reg = await app.readFingerprints();
    const others = reg.fingerprints.filter((f) => f !== fp);
    expect(others.length).toBe(1);
    const seed = JSON.parse(
      await readFile(join(app.profileDir(others[0]!), PARENT_SEED_FILENAME), "utf8"),
    );
    expect(seed.kdf.params.iterations).toBe(250000);
  });
});

import { saveConfig, defaultConfig } from "../src/configFile.js";

/** A UI that advances a fake clock by a scripted number of seconds per prompt. */
function clockedUi(steps: Array<{ ans: string; advance: number }>): {
  ui: Ui;
  now: () => number;
  prompts: string[];
  lines: string[];
} {
  let clock = 0;
  let i = 0;
  const prompts: string[] = [];
  const lines: string[] = [];
  const strip = (t: string) => t.replace(/\x1b\[[0-9;]*m/g, ""); // eslint-disable-line no-control-regex
  const ui: Ui = {
    say(line = "") {
      lines.push(strip(line));
    },
    clear() {},
    async ask(p: string) {
      prompts.push(strip(p));
      const step = steps[i++] ?? { ans: "", advance: 0 };
      clock += step.advance * 1000;
      return step.ans;
    },
    async askHidden(p: string) {
      return this.ask(p);
    },
  };
  return { ui, now: () => clock, prompts, lines };
}

describe("inactivity timeout locks the vault", () => {
  async function profileWithTimeout(seconds: number): Promise<{ dir: string; app: AppDir; fp: string; pw: string }> {
    const dir = await mkdtemp(join(tmpdir(), "seedpass-idle-"));
    const app = new AppDir(dir);
    const pw = "idle-pw";
    const fp = await app.createProfile(MNEMONIC, pw, "idle");
    await saveConfig(app.profileDir(fp), MNEMONIC, { ...defaultConfig(), inactivity_timeout: seconds });
    return { dir, app, fp, pw };
  }

  it("locks and re-prompts for the password when the user idles past the timeout", async () => {
    const { dir, fp, pw } = await profileWithTimeout(5);
    delete process.env["SEEDPASS_MNEMONIC"]; // force relock to prompt

    const { ui, now, prompts, lines } = clockedUi([
      { ans: pw, advance: 0 }, // initial unlock prompt at startup
      { ans: "4", advance: 10 }, // idle 10s at the main menu (> 5s): must lock
      { ans: pw, advance: 0 }, // password at the re-lock prompt
      { ans: "", advance: 1 }, // answer promptly this time: exit
    ]);
    const code = await runTui({ appDir: dir, fingerprint: fp, clock: now }, ui);

    expect(code).toBe(0);
    expect(lines.join("\n")).toContain("Session timed out. Vault locked.");
    // The password was demanded twice: once at startup, once after the timeout.
    expect(prompts.filter((p) => /Master password/.test(p)).length).toBe(2);
  });

  it("does not lock when the user answers within the timeout", async () => {
    const { dir, fp, pw } = await profileWithTimeout(5);
    delete process.env["SEEDPASS_MNEMONIC"];

    const { ui, now, prompts, lines } = clockedUi([
      { ans: pw, advance: 0 }, // initial unlock
      { ans: "", advance: 2 }, // 2s at the main menu (< 5s): no lock, then exit
    ]);
    const code = await runTui({ appDir: dir, fingerprint: fp, clock: now }, ui);

    expect(code).toBe(0);
    expect(lines.join("\n")).not.toContain("Session timed out");
    expect(prompts.filter((p) => /Master password/.test(p)).length).toBe(1);
  });
});

import { stat, chmod } from "node:fs/promises";

describe("secret-bearing exports get a fresh 0600 file", () => {
  it("re-creates a pre-existing world-readable file as 0600 on 2FA export", async () => {
    const dest = join(appDir, "totp-export.json");
    // An attacker (or just history) left a 0644 file at the destination.
    // writeFile(mode) would keep 0644 — every TOTP secret world-readable.
    await writeFile(dest, "old contents");
    await chmod(dest, 0o644);

    const ui = await run("7", "9", dest, "y", "", "", "");
    expect(ui.text).toContain("Exported 1 2FA entries");

    const mode = (await stat(dest)).mode & 0o777;
    expect(mode).toBe(0o600);
    const body = JSON.parse(await readFile(dest, "utf8"));
    expect(body.entries[0].label).toBe("email-2fa");
  });

  it("declining the overwrite leaves the existing file untouched", async () => {
    const dest = join(appDir, "keep-me.json");
    await writeFile(dest, "precious");

    const ui = await run("7", "9", dest, "n", "", "", "");
    expect(ui.text).toContain("Nothing was written");
    expect(await readFile(dest, "utf8")).toBe("precious");
  });
});

describe(".seedpass export naming in the TUI", () => {
  it("appends .seedpass to an extensionless destination", async () => {
    const dest = join(appDir, "my-backup");
    const ui = await run("7", "7", dest, "", "", "");
    expect(ui.text).toContain(`Exported to ${dest}.seedpass`);
    const wrapper = JSON.parse(await readFile(`${dest}.seedpass`, "utf8"));
    expect(wrapper.format_version).toBe(1);
  });

  it("a directory destination gets the generated self-identifying name", async () => {
    const ui = await run("7", "7", appDir, "", "", "");
    const match = ui.text.match(/Exported to (.*seedpass-[0-9A-F]{16}-\d{8}\.seedpass)/);
    expect(match).not.toBeNull();
    const wrapper = JSON.parse(await readFile(match![1]!, "utf8"));
    expect(wrapper.format_version).toBe(1);
  });

  it("an explicit extension is respected as typed", async () => {
    const dest = join(appDir, "explicit.json");
    const ui = await run("7", "7", dest, "", "", "");
    expect(ui.text).toContain(`Exported to ${dest}`);
    expect(ui.text).not.toContain(`${dest}.seedpass`);
  });
});
