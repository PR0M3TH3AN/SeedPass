/**
 * Console I/O for the interactive menus.
 *
 * Python's legacy TUI is line-based: clear the screen, print a header and a
 * numbered menu, read a line, act, repeat. This mirrors that model rather
 * than the full-screen raw-mode approach, because the navigation *is* the
 * interface — typing a number and pressing Enter, blank to go back.
 *
 * Everything the menus do goes through the `Ui` interface so the whole tree
 * can be driven by a scripted test without a pty.
 */

import process from "node:process";
import { createInterface } from "node:readline";

export const ansi = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
} as const;

export interface Ui {
  /** Print a line. */
  say(line?: string): void;
  /** Read a line. Returns "" when the user just presses Enter. */
  ask(prompt: string): Promise<string>;
  /** Read a line without echoing it. */
  askHidden(prompt: string): Promise<string>;
  /** Clear the screen (no-op when not a terminal). */
  clear(): void;
}

/** A menu option: the key the user types, and its label. */
export interface MenuOption {
  key: string;
  label: string;
}

export class ConsoleUi implements Ui {
  constructor(
    private readonly out: NodeJS.WritableStream = process.stdout,
    private readonly input: NodeJS.ReadableStream & { isTTY?: boolean } = process.stdin,
  ) {}

  say(line = ""): void {
    this.out.write(line + "\n");
  }

  clear(): void {
    // `in` narrows instead of asserting: NodeJS.WritableStream has no isTTY,
    // but the process streams do, and this asks rather than declares.
    if ("isTTY" in this.out && this.out.isTTY) {
      // Clear and reset the cursor, then clear scrollback: menus redraw
      // constantly, and without the third sequence a session leaves hundreds
      // of stale screens behind it.
      this.out.write("\x1b[2J\x1b[H\x1b[3J");
    }
  }

  async ask(prompt: string): Promise<string> {
    const rl = createInterface({ input: this.input, output: this.out, terminal: true });
    try {
      return (await new Promise<string>((resolve) => rl.question(prompt, resolve))).trim();
    } finally {
      rl.close();
    }
  }

  /**
   * Read without echo.
   *
   * Not readline: its line editing echoes what it receives, and a master
   * password must not reach the screen or a terminal log. Raw mode is entered
   * and left around this single read; the menus are otherwise line-mode.
   */
  askHidden(prompt: string): Promise<string> {
    const stdin = this.input as NodeJS.ReadableStream & {
      isTTY?: boolean;
      setRawMode?: (v: boolean) => void;
      isRaw?: boolean;
    };
    if (!stdin.isTTY) return this.ask(prompt);

    return new Promise<string>((resolve) => {
      const wasRaw = stdin.isRaw ?? false;
      this.out.write(prompt);
      stdin.setRawMode?.(true);
      stdin.resume();
      (stdin as NodeJS.ReadableStream & { setEncoding(e: string): void }).setEncoding("utf8");

      let value = "";
      const finish = (result: string): void => {
        stdin.removeListener("data", onData);
        stdin.setRawMode?.(wasRaw);
        stdin.pause();
        this.out.write("\n");
        resolve(result);
      };
      const onData = (chunk: string): void => {
        for (const ch of chunk) {
          if (ch === "\r" || ch === "\n") return finish(value);
          // Ctrl-C inside a password prompt should abort the program, not
          // silently return an empty password that then "fails to unlock".
          if (ch === "\x03") {
            finish("");
            process.exit(130);
            return;
          }
          if (ch === "\x7f" || ch === "\b") {
            value = value.slice(0, -1);
            continue;
          }
          if (ch >= " ") value += ch;
        }
      };
      stdin.on("data", onData);
    });
  }
}

/** Header shown at the top of every screen: profile, then breadcrumb. */
export function header(ui: Ui, fingerprint: string, name: string | null, title: string): void {
  ui.clear();
  const who = name ? `${name} (${fingerprint})` : fingerprint;
  ui.say(`${ansi.dim}SeedPass — ${who}${ansi.reset}`);
  ui.say(`${ansi.bold}${title}${ansi.reset}`);
}

export function menu(ui: Ui, options: MenuOption[]): void {
  ui.say();
  for (const { key, label } of options) {
    ui.say(`  ${ansi.cyan}${key}.${ansi.reset} ${label}`);
  }
  ui.say();
}

export async function pause(ui: Ui): Promise<void> {
  await ui.ask(`${ansi.dim}Press Enter to continue.${ansi.reset} `);
}

export async function confirm(ui: Ui, question: string): Promise<boolean> {
  const answer = (await ui.ask(`${question} (y/N): `)).toLowerCase();
  return answer === "y" || answer === "yes";
}

export function ok(ui: Ui, message: string): void {
  ui.say(`${ansi.green}${message}${ansi.reset}`);
}

export function warn(ui: Ui, message: string): void {
  ui.say(`${ansi.yellow}${message}${ansi.reset}`);
}

export function fail(ui: Ui, message: string): void {
  ui.say(`${ansi.red}${message}${ansi.reset}`);
}
