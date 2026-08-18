/**
 * Secret sinks: deliver a secret to a destination without routing it
 * through the CLI's stdout (plan section 9.3). The orchestrating agent sees
 * only a delivery confirmation.
 */

import { spawn } from "node:child_process";
import process from "node:process";

export interface SinkResult {
  sink: string;
  detail: string;
  exitCode?: number;
}

/** Env var the --exec sink injects into the child process. */
export const EXEC_ENV_VAR = "SEEDPASS_SECRET";

/**
 * Variables that must never reach a sink child.
 *
 * A helper invoked to receive one password would otherwise inherit the
 * parent seed, the master password, a bearer token and the agent socket
 * path — everything needed to take the whole vault.
 */
const FORBIDDEN_ENV = [
  "SEEDPASS_MNEMONIC",
  "SEEDPASS_PASSWORD",
  "SEEDPASS_TOKEN",
  "SEEDPASS_AGENT_SOCK",
  "SEEDPASS_AGENT_CAP",
  "SEEDPASS_APP_DIR",
];

/** Variables a child plausibly needs to run at all. */
const PASSTHROUGH_ENV = ["PATH", "HOME", "LANG", "LC_ALL", "TERM", "TZ", "TMPDIR", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"];

/**
 * Build the environment for a sink child: a minimal allowlist, never the
 * caller's full environment.
 */
export function sinkEnv(extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of PASSTHROUGH_ENV) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  for (const key of FORBIDDEN_ENV) delete env[key];
  return { ...env, ...extra };
}

/**
 * Split a sink command spec into [command, ...args].
 *
 * Commander's variadic options stop collecting at the next token starting
 * with "-", so `--exec wc -c` loses the flag. Passing the whole command as
 * one quoted string (`--exec "wc -c"`) is the documented way to include
 * flags; split it here.
 *
 * Quotes group, they do not pass through. Splitting on whitespace alone was
 * wrong for the single most common sink command there is:
 * `--exec 'sh -c "do the thing"'` handed sh the two tokens `"do` and
 * `the` and `thing"`, so sh died on an unterminated string. Note this is
 * tokenization only — no shell runs here, so there is no expansion,
 * globbing, or substitution, and a `$VAR` inside the spec stays literal.
 */
export function parseCommandSpec(spec: string[]): [string, string[]] {
  const parts = spec.length === 1 && /\s/.test(spec[0]!) ? tokenize(spec[0]!) : spec;
  const [cmd, ...args] = parts;
  if (!cmd) throw new Error("empty command");
  return [cmd, args];
}

/** Whitespace split that honours '...', "...", and backslash escapes. */
function tokenize(spec: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let started = false;
  let quote: "'" | '"' | null = null;

  for (let i = 0; i < spec.length; i++) {
    const ch = spec[i]!;
    if (quote === null && (ch === " " || ch === "\t" || ch === "\n")) {
      if (started) tokens.push(current);
      current = "";
      started = false;
      continue;
    }
    started = true;
    if (quote === null && (ch === "'" || ch === '"')) {
      quote = ch;
    } else if (ch === quote) {
      quote = null;
    } else if (ch === "\\" && quote !== "'" && i + 1 < spec.length) {
      // Backslash escapes the next character, except inside single quotes
      // where POSIX makes it literal.
      current += spec[++i]!;
    } else {
      current += ch;
    }
  }
  if (quote !== null) {
    throw new Error(`unterminated ${quote === "'" ? "single" : "double"} quote in command spec`);
  }
  if (started) tokens.push(current);
  return tokens;
}

/** Run a command with the secret injected as an env var (never on argv). */
export async function execSink(
  secret: string,
  command: string,
  args: string[],
): Promise<SinkResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "inherit", "inherit"],
      env: sinkEnv({ [EXEC_ENV_VAR]: secret }),
    });
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        sink: "exec",
        detail: `ran ${command} with ${EXEC_ENV_VAR} injected`,
        exitCode: code ?? -1,
      });
    });
  });
}

/** Pipe the secret to a command's stdin. */
export async function stdinSink(
  secret: string,
  command: string,
  args: string[],
): Promise<SinkResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["pipe", "inherit", "inherit"],
      env: sinkEnv(),
    });
    let spawnFailed = false;
    child.on("error", (e) => {
      spawnFailed = true;
      reject(e);
    });
    // A command that exits before reading stdin makes this write fail with
    // EPIPE. With no listener that becomes an *unhandled* error event, which
    // crashes the whole process — and the session agent runs sinks in-process,
    // so a use-scoped token holder could take the agent down (dropping every
    // held seed) just by naming a command that exits early. Swallow the stdin
    // error: the child's exit code, delivered on `close`, is the real result.
    child.stdin.on("error", () => {});
    child.stdin.end(secret);
    child.on("close", (code) => {
      if (spawnFailed) return;
      resolve({ sink: "stdin", detail: `piped to ${command}`, exitCode: code ?? -1 });
    });
  });
}

const CLIPBOARD_COMMANDS: Array<{ cmd: string; args: string[] }> = [
  { cmd: "wl-copy", args: [] },
  { cmd: "xclip", args: ["-selection", "clipboard"] },
  { cmd: "xsel", args: ["--clipboard", "--input"] },
  { cmd: "pbcopy", args: [] },
  { cmd: "clip.exe", args: [] },
];

/**
 * Feed a secret to one clipboard tool.
 *
 * X11/Wayland clipboard tools (xclip, wl-copy) fork a resident process that
 * owns the selection until another client takes it. So we must NOT wait for
 * the process to exit, and must NOT let it inherit our stdio — a resident
 * child holding our stdout blocks every reader of this CLI's output. We
 * detach it, ignore its stdio, and treat "stdin accepted and flushed"
 * as success.
 */
function feedClipboardTool(secret: string, cmd: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio: ["pipe", "ignore", "ignore"],
      detached: true,
      env: sinkEnv(),
    });
    let settled = false;
    const fail = (e: Error) => {
      if (!settled) {
        settled = true;
        reject(e);
      }
    };
    child.on("error", fail);
    // An immediate non-zero exit means the tool rejected the input
    // (e.g. no display); a tool that stays resident never fires this.
    child.on("exit", (code) => {
      if (code !== 0) fail(new Error(`${cmd} exited ${code}`));
    });
    child.stdin.on("error", fail);
    child.stdin.end(secret, () => {
      // Give a failing tool a moment to report before declaring success.
      setTimeout(() => {
        if (!settled) {
          settled = true;
          child.unref();
          resolve();
        }
      }, 150);
    });
  });
}

/** Copy the secret to the system clipboard via the first available tool. */
export async function clipboardSink(secret: string): Promise<SinkResult> {
  let lastError: unknown = new Error("no clipboard tool found");
  for (const { cmd, args } of CLIPBOARD_COMMANDS) {
    try {
      await feedClipboardTool(secret, cmd, args);
      return { sink: "clipboard", detail: `copied via ${cmd}` };
    } catch (e) {
      lastError = e;
    }
  }
  throw new Error(
    `clipboard delivery failed: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
  );
}
