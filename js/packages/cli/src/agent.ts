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
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import process from "node:process";
import { deriveKeyIndex, sha256Hex, utf8, type Entry } from "@seedpass/core";
import { openVault } from "./vaultFile.js";
import { materializeSecret } from "./secrets.js";
import { AuditLog } from "./audit.js";
import { INDEX_FILENAME } from "./appDir.js";

export const DEFAULT_TTL_SECONDS = 900;

export type TokenScope = "read" | "use" | "reveal";

export interface TokenRecord {
  id: string;
  name: string;
  fingerprint: string;
  secret_hash: string;
  scopes: TokenScope[];
  kinds: string[] | null;
  label_regex: string;
  expires_at: number;
  uses_remaining: number;
  revoked: boolean;
}

export type TokenInfo = Omit<TokenRecord, "secret_hash">;

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
  private tokens = new Map<string, TokenRecord>();
  private audits = new Map<string, AuditLog>();
  private server = createServer((socket) => this.serve(socket));

  constructor(
    private readonly socketPath: string,
    private readonly defaultTtl = DEFAULT_TTL_SECONDS,
    /** Profile root; required for token-mode vault/secret serving. */
    private readonly appDir?: string,
  ) {}

  private audit(fingerprint: string): AuditLog | null {
    if (!this.appDir) return null;
    const held = this.held.get(fingerprint);
    if (!held) return null;
    let log = this.audits.get(fingerprint);
    if (!log) {
      log = new AuditLog(
        join(this.appDir, fingerprint, "audit.log"),
        deriveKeyIndex(held.mnemonic),
      );
      this.audits.set(fingerprint, log);
    }
    return log;
  }

  /**
   * Validate a bearer token for an action against an entry, consuming one
   * use on success. Returns the token record or a denial reason.
   */
  private authorize(
    tokenSecret: string,
    fingerprint: string,
    action: TokenScope,
    entry?: { kind: string; label: string },
  ): { token?: TokenRecord; deny?: string } {
    const hash = sha256Hex(utf8(tokenSecret));
    const token = [...this.tokens.values()].find(
      (t) => t.secret_hash === hash && t.fingerprint === fingerprint,
    );
    if (!token) return { deny: "unknown token" };
    if (token.revoked) return { deny: "token revoked" };
    if (token.expires_at <= Date.now() / 1000) return { deny: "token expired" };
    if (token.uses_remaining <= 0) return { deny: "token exhausted" };
    if (!token.scopes.includes(action)) return { deny: `scope '${action}' not granted` };
    if (entry) {
      if (token.kinds && !token.kinds.includes(entry.kind)) {
        return { deny: `kind '${entry.kind}' not granted` };
      }
      if (!new RegExp(token.label_regex).test(entry.label)) {
        return { deny: "label not matched by token constraint" };
      }
    }
    // "read" is not consumption; secret-bearing actions decrement uses
    if (action !== "read") token.uses_remaining -= 1;
    return { token };
  }

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

  private async handle(msg: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.expire();
    switch (msg["op"]) {
      case "token-issue": {
        // Owner-only op: local socket (0600) is the trust boundary, and the
        // profile must currently be unlocked in this agent.
        const fingerprint = String(msg["fingerprint"] ?? "");
        if (!this.held.has(fingerprint)) return { ok: false, error: "profile not unlocked" };
        const scopes = (msg["scopes"] as TokenScope[] | undefined) ?? ["read"];
        const bad = scopes.filter((s) => !["read", "use", "reveal"].includes(s));
        if (bad.length) return { ok: false, error: `unknown scopes: ${bad.join(",")}` };
        const secret = randomBytes(24).toString("base64url");
        const record: TokenRecord = {
          id: `tok-${randomBytes(6).toString("hex")}`,
          name: String(msg["name"] ?? "agent"),
          fingerprint,
          secret_hash: sha256Hex(utf8(secret)),
          scopes,
          kinds: (msg["kinds"] as string[] | undefined) ?? null,
          label_regex: String(msg["label_regex"] ?? ".*"),
          expires_at: Math.floor(Date.now() / 1000 + Number(msg["ttl"] ?? 300)),
          uses_remaining: Number(msg["uses"] ?? 1),
          revoked: false,
        };
        this.tokens.set(record.id, record);
        await this.audit(fingerprint)?.log("token_issued", {
          token_id: record.id,
          name: record.name,
          scopes: record.scopes,
          kinds: record.kinds,
          label_regex: record.label_regex,
          uses: record.uses_remaining,
        });
        // The plaintext token is returned exactly once, at issuance.
        return { ok: true, token: secret, record: { ...record, secret_hash: undefined } };
      }
      case "token-list": {
        const fingerprint = String(msg["fingerprint"] ?? "");
        const list = [...this.tokens.values()]
          .filter((t) => t.fingerprint === fingerprint)
          .map(({ secret_hash: _hash, ...info }) => info);
        return { ok: true, tokens: list };
      }
      case "token-revoke": {
        const token = this.tokens.get(String(msg["token_id"] ?? ""));
        if (!token) return { ok: false, error: "unknown token id" };
        token.revoked = true;
        await this.audit(token.fingerprint)?.log("token_revoked", { token_id: token.id });
        return { ok: true };
      }
      case "vault-index": {
        // Token-mode read of the decrypted index (metadata access).
        const fingerprint = String(msg["fingerprint"] ?? "");
        const held = this.held.get(fingerprint);
        if (!held || !this.appDir) return { ok: false, error: "profile not unlocked" };
        const auth = this.authorize(String(msg["token"] ?? ""), fingerprint, "read");
        if (!auth.token) {
          await this.audit(fingerprint)?.log("access_denied", {
            action: "read", reason: auth.deny,
          });
          return { ok: false, error: `denied: ${auth.deny}` };
        }
        const vault = await openVault(
          join(this.appDir, fingerprint, INDEX_FILENAME),
          held.mnemonic,
        );
        await this.audit(fingerprint)?.log("index_read", { token_id: auth.token.id });
        return { ok: true, index: vault.index };
      }
      case "secret": {
        // Token-mode secret materialization for a single entry.
        const fingerprint = String(msg["fingerprint"] ?? "");
        const held = this.held.get(fingerprint);
        if (!held || !this.appDir) return { ok: false, error: "profile not unlocked" };
        const action = msg["action"] === "reveal" ? "reveal" : "use";
        const id = String(msg["id"] ?? "");
        const vault = await openVault(
          join(this.appDir, fingerprint, INDEX_FILENAME),
          held.mnemonic,
        );
        const entry = vault.index.entries[id] as Entry | undefined;
        if (!entry) return { ok: false, error: `no entry ${id}` };
        const auth = this.authorize(String(msg["token"] ?? ""), fingerprint, action, {
          kind: entry.kind,
          label: entry.label,
        });
        if (!auth.token) {
          await this.audit(fingerprint)?.log("access_denied", {
            action, entry_id: id, kind: entry.kind, reason: auth.deny,
          });
          return { ok: false, error: `denied: ${auth.deny}` };
        }
        const ts = msg["timestamp"] !== undefined ? Number(msg["timestamp"]) : undefined;
        const secret = materializeSecret(vault.index, id, entry, held.mnemonic, {
          ...(ts !== undefined && { timestamp: ts }),
        });
        await this.audit(fingerprint)?.log("secret_delivered", {
          action,
          entry_id: id,
          kind: entry.kind,
          label: entry.label,
          token_id: auth.token.id,
          uses_remaining: auth.token.uses_remaining,
        });
        return { ok: true, value: secret.value, descriptor: secret.descriptor };
      }
      case "put": {
        const fingerprint = String(msg["fingerprint"] ?? "");
        const mnemonic = String(msg["mnemonic"] ?? "");
        if (!fingerprint || !mnemonic) return { ok: false, error: "missing fields" };
        const ttl = Number(msg["ttl"] ?? this.defaultTtl);
        const expiresAt = Math.floor(Date.now() / 1000 + ttl);
        this.held.set(fingerprint, { mnemonic, expiresAt });
        await this.audit(fingerprint)?.log("vault_unlocked", { ttl });
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
        void (async () => {
          let reply: Record<string, unknown>;
          try {
            reply = await this.handle(JSON.parse(line) as Record<string, unknown>);
          } catch (e) {
            reply = { ok: false, error: String(e) };
          }
          socket.write(JSON.stringify(reply) + "\n");
        })();
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

  async tokenIssue(options: {
    fingerprint: string;
    name?: string;
    scopes?: TokenScope[];
    kinds?: string[];
    labelRegex?: string;
    ttl?: number;
    uses?: number;
  }): Promise<{ token: string; record: TokenInfo }> {
    const r = await this.request({
      op: "token-issue",
      fingerprint: options.fingerprint,
      name: options.name,
      scopes: options.scopes,
      kinds: options.kinds,
      label_regex: options.labelRegex,
      ttl: options.ttl,
      uses: options.uses,
    });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return { token: String(r["token"]), record: r["record"] as TokenInfo };
  }

  async tokenList(fingerprint: string): Promise<TokenInfo[]> {
    const r = await this.request({ op: "token-list", fingerprint });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return r["tokens"] as TokenInfo[];
  }

  async tokenRevoke(tokenId: string): Promise<void> {
    const r = await this.request({ op: "token-revoke", token_id: tokenId });
    if (!r["ok"]) throw new Error(String(r["error"]));
  }

  async vaultIndex(fingerprint: string, token: string): Promise<unknown> {
    const r = await this.request({ op: "vault-index", fingerprint, token });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return r["index"];
  }

  async secret(options: {
    fingerprint: string;
    id: string;
    token: string;
    action: "use" | "reveal";
    timestamp?: number;
  }): Promise<{ value: string; descriptor: string }> {
    const r = await this.request({
      op: "secret",
      fingerprint: options.fingerprint,
      id: options.id,
      token: options.token,
      action: options.action,
      ...(options.timestamp !== undefined && { timestamp: options.timestamp }),
    });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return { value: String(r["value"]), descriptor: String(r["descriptor"]) };
  }
}
