/**
 * Terminal control for the interactive mode: raw input, the alternate screen,
 * and — above all — putting the terminal back the way we found it.
 *
 * Two properties this file is responsible for:
 *
 * 1. **The shell survives.** Raw mode with the cursor hidden is a broken
 *    terminal: no echo, no line editing, no visible cursor. If we exit
 *    without restoring — including on a crash or a signal — the user's shell
 *    is left unusable and `reset` is the only way out. Restoration is
 *    therefore idempotent and wired to every exit path there is.
 *
 * 2. **Secrets do not reach scrollback.** Everything is drawn on the
 *    alternate screen buffer, which the terminal discards on exit. A revealed
 *    password cannot be recovered by scrolling up after quitting, and never
 *    lands in a terminal-logging setup that captures the main buffer.
 *
 * No dependencies: this is a security tool, and a TUI framework would pull a
 * React runtime and its transitive tree into the process that handles seed
 * phrases.
 */

import process from "node:process";
import type { ReadStream } from "node:tty";

export const ESC = "\x1b";
const CSI = `${ESC}[`;

export const ansi = {
  reset: `${CSI}0m`,
  bold: `${CSI}1m`,
  dim: `${CSI}2m`,
  italic: `${CSI}3m`,
  underline: `${CSI}4m`,
  reverse: `${CSI}7m`,
  red: `${CSI}31m`,
  green: `${CSI}32m`,
  yellow: `${CSI}33m`,
  blue: `${CSI}34m`,
  magenta: `${CSI}35m`,
  cyan: `${CSI}36m`,
  grey: `${CSI}90m`,
} as const;

/** Strip SGR sequences so width maths counts glyphs, not escape bytes. */
export function visibleLength(s: string): number {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, "").length;
}

export interface Key {
  /** Symbolic name for non-printing keys, else "char". */
  name:
    | "char"
    | "up"
    | "down"
    | "left"
    | "right"
    | "enter"
    | "backspace"
    | "delete"
    | "tab"
    | "escape"
    | "home"
    | "end"
    | "pageup"
    | "pagedown"
    | "ctrl-c"
    | "ctrl-d"
    | "unknown";
  /** The character, for name === "char". */
  ch: string;
}

/**
 * Decode one input chunk into keys.
 *
 * A chunk can hold several keypresses (fast typing, or a paste), so this
 * returns a list rather than a single key — dropping the remainder would
 * silently swallow input.
 */
export function decodeKeys(data: string): Key[] {
  const keys: Key[] = [];
  let i = 0;
  while (i < data.length) {
    const ch = data[i]!;

    if (ch === ESC) {
      const rest = data.slice(i);
      const seq = matchEscape(rest);
      if (seq) {
        keys.push(seq.key);
        i += seq.length;
        continue;
      }
      keys.push({ name: "escape", ch: "" });
      i += 1;
      continue;
    }

    switch (ch) {
      case "\x03":
        keys.push({ name: "ctrl-c", ch: "" });
        break;
      case "\x04":
        keys.push({ name: "ctrl-d", ch: "" });
        break;
      case "\r":
      case "\n":
        keys.push({ name: "enter", ch: "" });
        break;
      case "\x7f":
      case "\b":
        keys.push({ name: "backspace", ch: "" });
        break;
      case "\t":
        keys.push({ name: "tab", ch: "" });
        break;
      default:
        // Ignore remaining C0 controls; they are not text and have no binding.
        if (ch >= " ") keys.push({ name: "char", ch });
        break;
    }
    i += 1;
  }
  return keys;
}

function matchEscape(s: string): { key: Key; length: number } | null {
  const table: Record<string, Key["name"]> = {
    "[A": "up",
    "[B": "down",
    "[C": "right",
    "[D": "left",
    "[H": "home",
    "[F": "end",
    "OA": "up",
    "OB": "down",
    "OC": "right",
    "OD": "left",
    "OH": "home",
    "OF": "end",
    "[5~": "pageup",
    "[6~": "pagedown",
    "[3~": "delete",
    "[1~": "home",
    "[4~": "end",
    "[7~": "home",
    "[8~": "end",
  };
  for (const [seq, name] of Object.entries(table)) {
    if (s.startsWith(ESC + seq)) return { key: { name, ch: "" }, length: seq.length + 1 };
  }
  return null;
}

export class Terminal {
  private restored = false;
  private readonly cleanup: () => void;
  private onKeyHandler: ((key: Key) => void) | null = null;
  private onResizeHandler: (() => void) | null = null;
  private readonly stdin: ReadStream;

  constructor() {
    this.stdin = process.stdin as ReadStream;
    this.cleanup = () => this.restore();
  }

  static isInteractive(): boolean {
    return Boolean(process.stdin.isTTY && process.stdout.isTTY);
  }

  get columns(): number {
    return process.stdout.columns ?? 80;
  }

  get rows(): number {
    return process.stdout.rows ?? 24;
  }

  start(): void {
    // Alternate screen first, so nothing we draw touches the scrollback the
    // user keeps.
    this.write(`${CSI}?1049h${CSI}?25l`);
    this.stdin.setRawMode?.(true);
    this.stdin.resume();
    this.stdin.setEncoding("utf8");

    this.stdin.on("data", this.handleData);
    process.stdout.on("resize", this.handleResize);

    // Every path out of the process restores the terminal. "exit" covers
    // normal returns and process.exit; the signals cover Ctrl-C at the OS
    // level and `kill`; the exception handlers cover our own bugs, which is
    // exactly when a broken terminal is least welcome.
    process.on("exit", this.cleanup);
    process.on("SIGINT", this.onSignal);
    process.on("SIGTERM", this.onSignal);
    process.on("SIGHUP", this.onSignal);
    process.on("uncaughtException", this.onFatal);
    process.on("unhandledRejection", this.onFatal);
  }

  private readonly handleData = (chunk: string): void => {
    if (!this.onKeyHandler) return;
    for (const key of decodeKeys(chunk)) this.onKeyHandler(key);
  };

  private readonly handleResize = (): void => {
    this.onResizeHandler?.();
  };

  private readonly onSignal = (): void => {
    this.restore();
    process.exit(130);
  };

  private readonly onFatal = (err: unknown): void => {
    this.restore();
    // Report on the real screen, after the alternate one is gone, or the
    // message is discarded along with it.
    process.stderr.write(
      `seedpass-js: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`,
    );
    process.exit(1);
  };

  onKey(handler: (key: Key) => void): void {
    this.onKeyHandler = handler;
  }

  onResize(handler: () => void): void {
    this.onResizeHandler = handler;
  }

  write(s: string): void {
    process.stdout.write(s);
  }

  /** Redraw the whole frame. Cheap enough at this size, and never tears. */
  draw(lines: string[]): void {
    const rows = this.rows;
    const visible = lines.slice(0, rows);
    // Home, then clear each line as we go: clearing the whole screen first
    // makes the display flicker on slower terminals.
    let out = `${CSI}H`;
    for (let i = 0; i < rows; i++) {
      out += `${CSI}${i + 1};1H${CSI}2K`;
      if (i < visible.length) out += visible[i];
    }
    this.write(out);
  }

  restore(): void {
    if (this.restored) return;
    this.restored = true;
    try {
      this.stdin.setRawMode?.(false);
      this.stdin.pause();
      this.stdin.removeListener("data", this.handleData);
      process.stdout.removeListener("resize", this.handleResize);
      process.removeListener("exit", this.cleanup);
      process.removeListener("SIGINT", this.onSignal);
      process.removeListener("SIGTERM", this.onSignal);
      process.removeListener("SIGHUP", this.onSignal);
      process.removeListener("uncaughtException", this.onFatal);
      process.removeListener("unhandledRejection", this.onFatal);
    } finally {
      // Show the cursor and leave the alternate screen even if unwinding the
      // listeners threw: this is the part the user's shell depends on.
      this.write(`${CSI}?25h${CSI}?1049l`);
    }
  }
}
