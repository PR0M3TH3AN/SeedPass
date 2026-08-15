/**
 * Interactive mode: `seedpass-js` with no subcommand.
 *
 * Python's `seedpass` launches its TUI when invoked bare; this is the port of
 * that experience, following the legacy (v1) menu tree in `src/main.py` —
 * numbered menus, blank line to go back, the same items in the same order.
 *
 * The agent-blind rule from plan section 9.3 still applies: listings show
 * metadata with stored secrets reduced to `has_*` flags, and a secret appears
 * only through an action whose purpose is to produce it. Secret Mode (a
 * setting Python also has) routes those to the clipboard instead.
 */

import process from "node:process";
import { join } from "node:path";
import { assertValidMnemonic } from "@seedpass/core";
import { AppDir, resolveAppDir, INDEX_FILENAME } from "../appDir.js";
import { openVault } from "../vaultFile.js";
import { loadConfig } from "../configFile.js";
import { AgentClient, agentSocketPath } from "../agent.js";
import { ConsoleUi, fail, warn, type Ui } from "./console.js";
import { mainMenu, type Session } from "./menus.js";

export interface TuiOptions {
  appDir?: string;
  fingerprint?: string;
}

function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

export async function runTui(opts: TuiOptions, injectedUi?: Ui): Promise<number> {
  if (!injectedUi && !isInteractive()) {
    process.stderr.write(
      "seedpass-js: interactive mode needs a terminal on both stdin and stdout.\n" +
        "Run a subcommand instead — 'seedpass-js --help' lists them.\n",
    );
    return 1;
  }

  const ui = injectedUi ?? new ConsoleUi();
  const app = new AppDir(resolveAppDir(opts.appDir));
  const registry = await app.readFingerprints();

  if (registry.fingerprints.length === 0) {
    process.stderr.write(
      "No vault yet. Create one with:\n\n" +
        "  export SEEDPASS_PASSWORD='a master password'\n" +
        "  seedpass-js fingerprint create --name personal --words 24 --out ~/seed.txt\n",
    );
    return 1;
  }

  const fingerprint =
    opts.fingerprint ?? registry.last_used ?? registry.fingerprints[0]!;

  /**
   * Resolve a profile's seed: environment, then the session agent, then ask.
   * The same order the CLI uses, so a session unlocked with `vault unlock`
   * does not ask again.
   */
  const relock = async (fp: string): Promise<string> => {
    const env = process.env["SEEDPASS_MNEMONIC"];
    if (env) {
      assertValidMnemonic(env, "SEEDPASS_MNEMONIC");
      return env;
    }
    try {
      const held = await new AgentClient(agentSocketPath(app.root)).ownerMnemonic(fp);
      if (held) return held;
    } catch {
      // no agent running, or it holds nothing for this profile
    }
    const names = (await app.readFingerprints()).names;
    const who = names[fp] ? `${names[fp]} (${fp})` : fp;
    for (let attempt = 0; attempt < 3; attempt++) {
      const password = await ui.askHidden(`Master password for ${who}: `);
      if (!password) throw new Error("cancelled");
      try {
        return await app.decryptParentSeed(fp, password);
      } catch {
        warn(ui, "Wrong password.");
      }
    }
    throw new Error("too many failed password attempts");
  };

  let session: Session;
  try {
    const mnemonic = await relock(fingerprint);
    session = {
      ui,
      app,
      fingerprint,
      name: registry.names[fingerprint] ?? null,
      vault: await openVault(join(app.profileDir(fingerprint), INDEX_FILENAME), mnemonic),
      config: await loadConfig(app.profileDir(fingerprint), mnemonic),
      relock,
    };
  } catch (e) {
    process.stderr.write(`seedpass-js: ${(e as Error).message}\n`);
    return 1;
  }

  try {
    return await mainMenu(session);
  } catch (e) {
    fail(ui, `Unexpected error: ${(e as Error).message}`);
    return 1;
  }
}
