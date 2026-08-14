/**
 * Session agent: a small daemon that holds unlocked parent seeds in memory
 * with a TTL, so the CLI can be used across invocations without exporting
 * the mnemonic into every process environment (ssh-agent model).
 *
 * Transport: unix domain socket (0600), one JSON object per line.
 *   {op:"put", fingerprint, mnemonic, ttl?}  -> {ok, expires_at}
 *   {op:"get", fingerprint}                  -> {ok, mnemonic?}
 *   {op:"lock", fingerprint?}                -> {ok, locked: n}
 *   {op:"status"}                            -> {ok, profiles: [...]}
 *   {op:"shutdown"}                          -> {ok}
 *
 * This process is the designed enforcement point for the plan-section-9.3
 * lease/token layer: scoped grants and one-time leases attach here, not in
 * the stateless CLI.
 */

import { createServer, createConnection, type Socket } from "node:net";
import { chmod, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

export const DEFAULT_TTL_SECONDS = 900;

export function agentSocketPath(appDir: string): string {
  return process.env["SEEDPASS_AGENT_SOCK"] ?? join(appDir, "agent.sock");
}

interface Held {
  mnemonic: string;
  expiresAt: number;
}

export interface AgentStatusProfile {
  fingerprint: string;
  expires_at: number;
}

export class AgentDaemon {
  private held = new Map<string, Held>();
  private server = createServer((socket) => this.serve(socket));

  constructor(
    private readonly socketPath: string,
    private readonly defaultTtl = DEFAULT_TTL_SECONDS,
  ) {}

  async start(): Promise<void> {
    if (existsSync(this.socketPath)) {
      // A live agent refuses to be replaced; a stale socket file is cleaned.
      const alive = await AgentClient.ping(this.socketPath);
      if (alive) throw new Error(`agent already running at ${this.socketPath}`);
      await rm(this.socketPath, { force: true });
    }
    await new Promise<void>((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(this.socketPath, () => resolve());
    });
    await chmod(this.socketPath, 0o600);
  }

  async stop(): Promise<void> {
    this.held.clear();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    await rm(this.socketPath, { force: true });
  }

  private expire(): void {
    const now = Date.now() / 1000;
    for (const [fp, held] of this.held) {
      if (held.expiresAt <= now) this.held.delete(fp);
    }
  }

  private handle(msg: Record<string, unknown>): Record<string, unknown> {
    this.expire();
    switch (msg["op"]) {
      case "put": {
        const fingerprint = String(msg["fingerprint"] ?? "");
        const mnemonic = String(msg["mnemonic"] ?? "");
        if (!fingerprint || !mnemonic) return { ok: false, error: "missing fields" };
        const ttl = Number(msg["ttl"] ?? this.defaultTtl);
        const expiresAt = Math.floor(Date.now() / 1000 + ttl);
        this.held.set(fingerprint, { mnemonic, expiresAt });
        return { ok: true, expires_at: expiresAt };
      }
      case "get": {
        const held = this.held.get(String(msg["fingerprint"] ?? ""));
        return held ? { ok: true, mnemonic: held.mnemonic } : { ok: false, error: "locked" };
      }
      case "lock": {
        const fp = msg["fingerprint"];
        if (fp === undefined) {
          const n = this.held.size;
          this.held.clear();
          return { ok: true, locked: n };
        }
        const had = this.held.delete(String(fp));
        return { ok: true, locked: had ? 1 : 0 };
      }
      case "status": {
        const profiles: AgentStatusProfile[] = [...this.held.entries()].map(
          ([fingerprint, h]) => ({ fingerprint, expires_at: h.expiresAt }),
        );
        return { ok: true, profiles };
      }
      case "ping":
        return { ok: true, pong: true };
      case "shutdown":
        setImmediate(() => void this.stop().then(() => process.exit(0)));
        return { ok: true };
      default:
        return { ok: false, error: `unknown op ${String(msg["op"])}` };
    }
  }

  private serve(socket: Socket): void {
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let nl;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 1);
        let reply: Record<string, unknown>;
        try {
          reply = this.handle(JSON.parse(line) as Record<string, unknown>);
        } catch (e) {
          reply = { ok: false, error: String(e) };
        }
        socket.write(JSON.stringify(reply) + "\n");
      }
    });
    socket.on("error", () => socket.destroy());
  }
}

export class AgentClient {
  constructor(private readonly socketPath: string) {}

  static async ping(socketPath: string): Promise<boolean> {
    try {
      await new AgentClient(socketPath).request({ op: "ping" });
      return true;
    } catch {
      return false;
    }
  }

  async request(msg: Record<string, unknown>): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const socket = createConnection(this.socketPath);
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error("agent request timed out"));
      }, 2000);
      let buffer = "";
      socket.on("connect", () => socket.write(JSON.stringify(msg) + "\n"));
      socket.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        const nl = buffer.indexOf("\n");
        if (nl >= 0) {
          clearTimeout(timer);
          socket.end();
          try {
            resolve(JSON.parse(buffer.slice(0, nl)) as Record<string, unknown>);
          } catch (e) {
            reject(e instanceof Error ? e : new Error(String(e)));
          }
        }
      });
      socket.on("error", (e) => {
        clearTimeout(timer);
        reject(e);
      });
    });
  }

  async put(fingerprint: string, mnemonic: string, ttl?: number): Promise<number> {
    const r = await this.request({ op: "put", fingerprint, mnemonic, ...(ttl && { ttl }) });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return Number(r["expires_at"]);
  }

  async get(fingerprint: string): Promise<string | null> {
    try {
      const r = await this.request({ op: "get", fingerprint });
      return r["ok"] ? String(r["mnemonic"]) : null;
    } catch {
      return null;
    }
  }

  async lock(fingerprint?: string): Promise<number> {
    const r = await this.request({ op: "lock", ...(fingerprint && { fingerprint }) });
    return Number(r["locked"] ?? 0);
  }

  async status(): Promise<AgentStatusProfile[]> {
    const r = await this.request({ op: "status" });
    return (r["profiles"] ?? []) as AgentStatusProfile[];
  }
}
