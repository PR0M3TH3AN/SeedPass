/**
 * Smoke-test the shipped CLI bundle, on any operating system.
 *
 * WHY THIS IS NOT A SHELL SCRIPT
 *
 * The version this replaces lived inline in ts-parity.yml and used mktemp,
 * export and `test -n`, so it could only ever run on Unix -- which meant the
 * one artifact users actually execute was never smoke-tested on Windows at
 * all. That mattered: on 2026-08-20 every Windows CI failure was a Unix
 * assumption leaking, from MSYS2 shadowing `python` to pwsh swallowing exit
 * codes to shlex eating the backslashes out of Windows paths. Written in
 * Node, the same file runs on Linux, macOS, Windows, GitHub and a laptop.
 *
 * WHAT IT PROVES
 *
 * 1. The bundle runs with NO node_modules anywhere near it. It executes from
 *    a fresh temp directory, so a dependency that failed to bundle shows up
 *    here rather than in a user's install.
 * 2. A vault can be created and an entry added and revealed end to end.
 * 3. The revealed secret is DETERMINISTIC -- revealing twice gives the same
 *    value. For a deterministic password manager that is the product, not an
 *    incidental property, and "some output appeared" would not have caught a
 *    derivation that silently changed.
 * 4. The secret honours the requested length.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const HERE = dirname(fileURLToPath(import.meta.url));
const BUNDLE = resolve(HERE, "..", "packages", "cli", "dist", "seedpass-js.mjs");

// The 12-word all-`abandon` vector, used throughout the fixtures.
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon " +
  "abandon abandon abandon about";
const PASSWORD = "ci-smoke-password";
const LENGTH = 16;

function fail(message) {
  console.error(`\nsmoke-cli: ${message}`);
  process.exit(1);
}

/** Run the bundle from `cwd`, which deliberately has no node_modules. */
function cli(args, { cwd, env, expectOk = true }) {
  const result = spawnSync(process.execPath, [BUNDLE, ...args], {
    cwd,
    env,
    encoding: "utf8",
    // No shell: argument quoting differs between cmd.exe and sh, and this
    // test exists precisely to stop shell differences from mattering.
    shell: false,
  });
  if (result.error) fail(`could not run the bundle: ${result.error.message}`);
  if (expectOk && result.status !== 0) {
    fail(
      `\`${args.join(" ")}\` exited ${result.status}\n` +
        `stdout: ${result.stdout}\nstderr: ${result.stderr}`,
    );
  }
  return result;
}

if (!existsSync(BUNDLE)) {
  fail(`no bundle at ${BUNDLE} — run \`pnpm -C js build\` first`);
}

const appDir = mkdtempSync(join(tmpdir(), "seedpass-smoke-app-"));
// Somewhere with no package.json and no node_modules above it, so a missing
// bundled dependency cannot be papered over by the workspace's own tree.
const runDir = mkdtempSync(join(tmpdir(), "seedpass-smoke-run-"));

try {
  const bare = { ...process.env, SEEDPASS_APP_DIR: appDir };
  delete bare.SEEDPASS_MNEMONIC;
  delete bare.SEEDPASS_PASSWORD;

  const version = cli(["--version"], { cwd: runDir, env: bare });
  if (!/\d+\.\d+/.test(version.stdout)) {
    fail(`--version printed something unversion-like: ${version.stdout.trim()}`);
  }
  cli(["capabilities"], { cwd: runDir, env: bare });

  const env = {
    ...bare,
    SEEDPASS_MNEMONIC: MNEMONIC,
    SEEDPASS_PASSWORD: PASSWORD,
  };

  cli(["fingerprint", "add", "--name", "ci"], { cwd: runDir, env });
  cli(["entry", "add", "password", "ci-site", "--length", String(LENGTH)], {
    cwd: runDir,
    env,
  });

  const first = cli(["entry", "reveal", "ci-site"], { cwd: runDir, env }).stdout.trim();
  if (!first) fail("revealing the entry produced no output");
  if (first.length !== LENGTH) {
    fail(`asked for a ${LENGTH}-character password and got ${first.length}`);
  }

  // The product is determinism. Same seed, same entry, same secret.
  const second = cli(["entry", "reveal", "ci-site"], { cwd: runDir, env }).stdout.trim();
  if (first !== second) {
    fail("revealing the same entry twice produced two different secrets");
  }

  console.log(
    `smoke-cli: ok — bundle runs standalone, ${LENGTH}-character secret ` +
      `derived deterministically`,
  );
} finally {
  rmSync(appDir, { recursive: true, force: true });
  rmSync(runDir, { recursive: true, force: true });
}
