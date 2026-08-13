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

/** Copy the secret to the system clipboard via the first available tool. */
export async function clipboardSink(secret: string): Promise<SinkResult> {
  let lastError: unknown = new Error("no clipboard tool found");
  for (const { cmd, args } of CLIPBOARD_COMMANDS) {
    try {
      const result = await stdinSink(secret, cmd, args);
      if (result.exitCode === 0) {
        return { sink: "clipboard", detail: `copied via ${cmd}` };
      }
      lastError = new Error(`${cmd} exited ${result.exitCode}`);
    } catch (e) {
      lastError = e;
    }
  }
  throw new Error(
    `clipboard delivery failed: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
  );
}
