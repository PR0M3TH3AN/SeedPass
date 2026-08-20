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
 * Variables a child plausibly needs to run at all. This allowlist is the
 * control that keeps SEEDPASS_MNEMONIC, SEEDPASS_PASSWORD, tokens and the
 * agent socket path out of sink children — a helper invoked to receive one
 * password must not inherit everything needed to take the whole vault.
 */
const PASSTHROUGH_ENV = ["PATH", "HOME", "LANG", "LC_ALL", "TERM", "TZ", "TMPDIR", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"];

/**
 * Build the environment for a sink child: the allowlist above, never the
 * caller's full environment.
 */
export function sinkEnv(
  extra: Record<string, string> = {},
  // The allowlist is a parameter purely so the SEEDPASS_ backstop below can
  // be tested. No entry in PASSTHROUGH_ENV starts with SEEDPASS_ today, so
  // the check cannot fire against the real list -- which is what makes it a
  // backstop, and also what made removing it invisible to the suite.
  passthrough: readonly string[] = PASSTHROUGH_ENV,
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of passthrough) {
    // Backstop, not the control: nothing SEEDPASS-prefixed rides along even
    // if a future edit adds one to the allowlist. `extra` is exempt — the
    // exec sink's whole job is injecting SEEDPASS_SECRET.
    if (key.startsWith("SEEDPASS_")) continue;
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
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
 * On Windows a backslash is a path separator and never an escape; on POSIX
 * it escapes, as a shell would. Quotes group on both.
 *
 * Quotes group, they do not pass through. Splitting on whitespace alone was
 * wrong for the single most common sink command there is:
 * `--exec 'sh -c "do the thing"'` handed sh the two tokens `"do` and
 * `the` and `thing"`, so sh died on an unterminated string. Note this is
 * tokenization only — no shell runs here, so there is no expansion,
 * globbing, or substitution, and a `$VAR` inside the spec stays literal.
 */
export function parseCommandSpec(
  spec: string[],
  // Explicit rather than read from process.platform, so BOTH branches are
  // testable from either operating system. The Windows branch could
  // otherwise only ever run on Windows, which is exactly how the bug below
  // survived until this repository started testing there.
  options: { windows?: boolean } = {},
): [string, string[]] {
  const onWindows = options.windows ?? process.platform === "win32";
  const parts =
    spec.length === 1 && /\s/.test(spec[0]!) ? tokenize(spec[0]!, onWindows) : spec;
  const [cmd, ...args] = parts;
  if (!cmd) throw new Error("empty command");
  return [cmd, args];
}

/** Whitespace split that honours '...', "...", and backslash escapes. */
function tokenize(spec: string, onWindows: boolean): string[] {
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
    } else if (ch === "\\" && !onWindows && quote !== "'" && i + 1 < spec.length) {
      // POSIX: backslash escapes the next character, except inside single
      // quotes. NOT on Windows, where it is the path separator -- treating it
      // as an escape there turned `C:\\Program Files\\tool.exe` into
      // `C:Program` plus `Filestool.exe`, so every --exec and --stdin-to
      // naming a real Windows path was silently mangled before it was
      // spawned. Found when this suite first ran on Windows.
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

/**
 * Clipboard tools, each paired with the command that reads the same
 * selection back. The read command lets a scheduled clear check that the
 * clipboard still holds *our* secret before wiping it, so it never clobbers
 * something the user copied in the meantime. `paste: null` means the platform
 * has a writer but no reliable reader here (Windows `clip.exe`).
 */
const CLIPBOARD_TOOLS: Array<{
  copy: { cmd: string; args: string[] };
  paste: { cmd: string; args: string[] } | null;
}> = [
  { copy: { cmd: "wl-copy", args: [] }, paste: { cmd: "wl-paste", args: ["-n"] } },
  {
    copy: { cmd: "xclip", args: ["-selection", "clipboard"] },
    paste: { cmd: "xclip", args: ["-selection", "clipboard", "-o"] },
  },
  {
    copy: { cmd: "xsel", args: ["--clipboard", "--input"] },
    paste: { cmd: "xsel", args: ["--clipboard", "--output"] },
  },
  { copy: { cmd: "pbcopy", args: [] }, paste: { cmd: "pbpaste", args: [] } },
  { copy: { cmd: "clip.exe", args: [] }, paste: null },
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
/** Read the current clipboard via a paste tool; null if it cannot be read. */
function readClipboard(cmd: string, args: string[]): Promise<string | null> {
  return new Promise((resolve) => {
    let out = "";
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "ignore"], env: sinkEnv() });
    child.on("error", () => resolve(null));
    child.stdout.on("data", (c: Buffer) => {
      out += c.toString("utf8");
    });
    child.on("close", (code) => resolve(code === 0 ? out : null));
  });
}

/**
 * After `delaySeconds`, clear the clipboard — but only if it still holds the
 * secret we put there, so a value the user copied since is left alone. When
 * the clipboard cannot be read back (no paste tool, or it failed), clear
 * unconditionally: leaving a secret parked on a session-wide clipboard is the
 * worse failure. Mirrors Python's copy_to_clipboard(text, timeout).
 *
 * The timer is unref'd: it fires while the (long-running) TUI is still up, but
 * never keeps a process alive on its own. A one-shot CLI that exits before the
 * delay will not clear — the same limitation Python's daemon thread has.
 */
function scheduleClipboardClear(
  secret: string,
  delaySeconds: number,
  tool: { copy: { cmd: string; args: string[] }; paste: { cmd: string; args: string[] } | null },
): void {
  const timer = setTimeout(() => {
    void (async () => {
      if (tool.paste) {
        const current = await readClipboard(tool.paste.cmd, tool.paste.args);
        // Trailing newline is common from paste tools; compare trimmed.
        if (current !== null && current.replace(/\n$/, "") !== secret) return;
      }
      try {
        await feedClipboardTool("", tool.copy.cmd, tool.copy.args);
      } catch {
        // Best effort: nothing useful to do if the wipe itself fails.
      }
    })();
  }, delaySeconds * 1000);
  timer.unref?.();
}

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

/**
 * Copy the secret to the system clipboard via the first available tool.
 *
 * With `clearAfterSeconds > 0`, schedule a clear that wipes the value after
 * the delay (see scheduleClipboardClear). The default — no options — leaves
 * the clipboard untouched afterwards, preserving the behaviour the one-shot
 * CLI and the agent rely on; only the long-running TUI passes a delay.
 */
export async function clipboardSink(
  secret: string,
  opts: { clearAfterSeconds?: number } = {},
): Promise<SinkResult> {
  let lastError: unknown = new Error("no clipboard tool found");
  for (const tool of CLIPBOARD_TOOLS) {
    try {
      await feedClipboardTool(secret, tool.copy.cmd, tool.copy.args);
      const clear = opts.clearAfterSeconds ?? 0;
      if (clear > 0) scheduleClipboardClear(secret, clear, tool);
      return {
        sink: "clipboard",
        detail:
          clear > 0
            ? `copied via ${tool.copy.cmd}; clears in ${clear}s`
            : `copied via ${tool.copy.cmd}`,
      };
    } catch (e) {
      lastError = e;
    }
  }
  throw new Error(
    `clipboard delivery failed: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
  );
}
