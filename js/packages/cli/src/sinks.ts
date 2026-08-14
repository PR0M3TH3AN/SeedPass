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
 * Split a sink command spec into [command, ...args].
 *
 * Commander's variadic options stop collecting at the next token starting
 * with "-", so `--exec wc -c` loses the flag. Passing the whole command as
 * one quoted string (`--exec "wc -c"`) is the documented way to include
 * flags; split it here. Splitting is on whitespace only — no shell is
 * involved, so quoting/expansion never happens.
 */
export function parseCommandSpec(spec: string[]): [string, string[]] {
  const parts =
    spec.length === 1 && /\s/.test(spec[0]!) ? spec[0]!.trim().split(/\s+/) : spec;
  const [cmd, ...args] = parts;
  if (!cmd) throw new Error("empty command");
  return [cmd, args];
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
      env: { ...process.env, [EXEC_ENV_VAR]: secret },
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
      env: process.env,
    });
    child.on("error", reject);
    child.stdin.write(secret);
    child.stdin.end();
    child.on("close", (code) => {
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
    const child = spawn(cmd, args, { stdio: ["pipe", "ignore", "ignore"], detached: true });
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
