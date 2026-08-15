/**
 * Session agent: a small daemon that holds unlocked parent seeds in memory
 * with a TTL, so the CLI can be used across invocations without exporting
 * the mnemonic into every process environment (ssh-agent model).
 *
 * Transport: unix domain socket (0600), one JSON object per line.
 *
 * Two classes of caller, distinguished by the server — not by the client:
 *
 *  - Owner ops (put, owner-mnemonic, token-issue/list/revoke, lock, status,
 *    shutdown) require the capability secret written to a 0600 file beside
 *    the socket. Socket permissions alone cannot tell the owner's CLI apart
 *    from a scoped agent that merely holds a token.
 *  - Token ops (vault-index, secret, use-sink) require a bearer token and
 *    are constrained by its scopes. vault-index returns redacted metadata,
 *    never the decrypted index; `secret` requires the reveal scope; and
 *    `use-sink` runs the sink here so plaintext never crosses back.
 *
 * This process is the enforcement point for the plan-section-9.3 lease and
 * token model. Enforcement must live here because the CLI is untrusted from
 * the daemon's point of view: any local process can speak this protocol.
 */

import { createServer, createConnection, type Socket } from "node:net";
import { chmod, rm } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import process from "node:process";
import { deriveKeyIndex, sha256Hex, utf8, type Entry } from "@seedpass/core";
import { openVault } from "./vaultFile.js";
import { materializeSecret } from "./secrets.js";
import { entryMetadata } from "./refs.js";
import {
  clipboardSink,
  execSink,
  parseCommandSpec,
  stdinSink,
  type SinkResult,
} from "./sinks.js";
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
  /**
   * Commands this token may hand a secret to. Empty/absent means any.
   *
   * A `use`-scoped holder who picks the command can always read the secret
   * from inside it, so this is the only mechanism that actually contains a
   * `use` grant rather than merely recording it.
   */
  exec_allowlist?: string[];
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

/** Operations only the owner may invoke, proven by the capability secret. */
const OWNER_OPS = new Set([
  "put",
  "owner-mnemonic",
  "token-issue",
  "token-list",
  "token-revoke",
  "lock",
  "status",
  "shutdown",
]);

export class AgentDaemon {
  private held = new Map<string, Held>();
  private tokens = new Map<string, TokenRecord>();
  private audits = new Map<string, AuditLog>();
  private auditQueue: Promise<unknown> = Promise.resolve();
  private capability = "";
  private server = createServer((socket) => this.serve(socket));

  constructor(
    private readonly socketPath: string,
    private readonly defaultTtl = DEFAULT_TTL_SECONDS,
    /** Profile root; required for token-mode vault/secret serving. */
    private readonly appDir?: string,
  ) {}

  /** Path of the 0600 file holding the owner capability. */
  get capabilityPath(): string {
    return `${this.socketPath}.cap`;
  }

  /**
   * Owner authentication.
   *
   * The socket's 0600 mode proves only "some process running as this user";
   * it does not distinguish the owner's CLI from a scoped agent that was
   * handed a token. Privileged operations therefore require a capability
   * secret written to a 0600 file at startup, which raises the bar to
   * "can read the owner's files" — the same bar as the vault itself.
   *
   * Residual risk, stated plainly: a same-uid attacker who can read that
   * file (or ptrace this process) still wins. Defending against that
   * requires an OS-level boundary this daemon cannot provide.
   */
  private isOwner(msg: Record<string, unknown>): boolean {
    const presented = String(msg["cap"] ?? "");
    if (!presented || !this.capability) return false;
    const a = Buffer.from(presented);
    const b = Buffer.from(this.capability);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  /** Serialize audit appends so concurrent requests cannot break the chain. */
  private auditLog(
    fingerprint: string,
    event: string,
    details: Record<string, unknown>,
  ): Promise<void> {
    const log = this.audit(fingerprint);
    if (!log) return Promise.resolve();
    this.auditQueue = this.auditQueue.then(
      () => log.log(event, details),
      () => log.log(event, details),
    );
    return this.auditQueue as Promise<void>;
  }

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

  /** Would this token be allowed to act on this entry at all? */
  private tokenMaySee(token: TokenRecord, entry: { kind: string; label: string }): boolean {
    if (token.kinds && !token.kinds.includes(entry.kind)) return false;
    try {
      return new RegExp(token.label_regex).test(entry.label);
    } catch {
      return false;
    }
  }

  /**
   * Common path for token-authorized secret access: open the vault, find the
   * entry, authorize the action, and materialize the secret. Never returns
   * the secret to a caller that was not authorized for the exact action.
   */
  private async resolveForToken(
    msg: Record<string, unknown>,
    fingerprint: string,
    action: Exclude<TokenScope, "read">,
    sinkSpec?: { sink: string; command: string[] },
  ): Promise<
    | { error: Record<string, unknown> }
    | {
        entry: Entry;
        id: string;
        token: TokenRecord;
        secret: { value: string; descriptor: string };
      }
  > {
    const held = this.held.get(fingerprint);
    if (!held || !this.appDir) {
      return { error: { ok: false, error: "profile not unlocked" } };
    }
    const id = String(msg["id"] ?? "");
    const vault = await openVault(
      join(this.appDir, fingerprint, INDEX_FILENAME),
      held.mnemonic,
    );
    const entry = vault.index.entries[id] as Entry | undefined;
    if (!entry) return { error: { ok: false, error: `no entry ${id}` } };

    const auth = this.authorize(String(msg["token"] ?? ""), fingerprint, action, {
      kind: entry.kind,
      label: entry.label,
    });
    if (!auth.token) {
      await this.auditLog(fingerprint, "access_denied", {
        action,
        entry_id: id,
        kind: entry.kind,
        reason: auth.deny,
      });
      return { error: { ok: false, error: `denied: ${auth.deny}` } };
    }

    if (sinkSpec) {
      const allowed = auth.token.exec_allowlist;
      if (sinkSpec.sink !== "clipboard" && allowed && allowed.length > 0) {
        const [cmd] = parseCommandSpec(sinkSpec.command);
        if (!allowed.includes(cmd)) {
          await this.auditLog(fingerprint, "access_denied", {
            action,
            entry_id: id,
            reason: `command '${cmd}' not in the token's exec allowlist`,
          });
          return {
            error: { ok: false, error: `denied: command '${cmd}' not permitted by this token` },
          };
        }
      }
    }

    const ts = msg["timestamp"] !== undefined ? Number(msg["timestamp"]) : undefined;
    const secret = materializeSecret(vault.index, id, entry, held.mnemonic, {
      ...(ts !== undefined && { timestamp: ts }),
    });
    return { entry, id, token: auth.token, secret };
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

    this.capability = randomBytes(32).toString("base64url");
    await writeFile(this.capabilityPath, this.capability, { mode: 0o600 });
    await chmod(this.capabilityPath, 0o600);
  }

  async stop(): Promise<void> {
    this.held.clear();
    this.tokens.clear();
    this.audits.clear();
    this.capability = "";
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    await rm(this.socketPath, { force: true });
    await rm(this.capabilityPath, { force: true });
  }

  /** Drop everything derived from a profile's seed. */
  private forget(fingerprint: string): void {
    this.held.delete(fingerprint);
    // Tokens are only meaningful while the profile is unlocked; leaving them
    // resident would let them spring back to life on the next unlock.
    for (const [id, token] of this.tokens) {
      if (token.fingerprint === fingerprint) this.tokens.delete(id);
    }
    // The audit logger holds a key derived from the seed.
    this.audits.delete(fingerprint);
  }

  private expire(): void {
    const now = Date.now() / 1000;
    for (const [fp, held] of this.held) {
      if (held.expiresAt <= now) this.forget(fp);
    }
  }

  private async handle(msg: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.expire();
    const op = String(msg["op"] ?? "");
    if (OWNER_OPS.has(op) && !this.isOwner(msg)) {
      // Do not reveal whether the profile exists or is unlocked.
      return { ok: false, error: "owner capability required" };
    }
    switch (op) {
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
          ...(Array.isArray(msg["exec_allowlist"]) && (msg["exec_allowlist"] as string[]).length
            ? { exec_allowlist: msg["exec_allowlist"] as string[] }
            : {}),
        };
        this.tokens.set(record.id, record);
        await this.auditLog(fingerprint, "token_issued", {
          token_id: record.id,
          name: record.name,
          scopes: record.scopes,
          kinds: record.kinds,
          label_regex: record.label_regex,
          uses: record.uses_remaining,
          exec_allowlist: record.exec_allowlist ?? null,
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
        await this.auditLog(token.fingerprint, "token_revoked", { token_id: token.id });
        return { ok: true };
      }
      case "vault-index": {
        // Token-mode read. Returns REDACTED metadata only: handing back the
        // decrypted index would give a read-scoped token every imported TOTP
        // secret, key-value value and document body in the vault.
        const fingerprint = String(msg["fingerprint"] ?? "");
        const held = this.held.get(fingerprint);
        if (!held || !this.appDir) return { ok: false, error: "profile not unlocked" };
        const auth = this.authorize(String(msg["token"] ?? ""), fingerprint, "read");
        if (!auth.token) {
          await this.auditLog(fingerprint, "access_denied", {
            action: "read",
            reason: auth.deny,
          });
          return { ok: false, error: `denied: ${auth.deny}` };
        }
        const vault = await openVault(
          join(this.appDir, fingerprint, INDEX_FILENAME),
          held.mnemonic,
        );
        // Only entries the token could actually act on are listed at all.
        const rows = Object.entries(vault.index.entries)
          .filter(([, e]) => this.tokenMaySee(auth.token!, e))
          .map(([id, e]) => entryMetadata(id, e));
        await this.auditLog(fingerprint, "index_read", {
          token_id: auth.token.id,
          entries_returned: rows.length,
        });
        return { ok: true, entries: rows, schema_version: vault.index.schema_version };
      }
      case "secret": {
        // Plaintext egress. Requires the `reveal` scope specifically: `use`
        // must not be able to pull a secret back across the socket.
        const fingerprint = String(msg["fingerprint"] ?? "");
        const resolved = await this.resolveForToken(msg, fingerprint, "reveal");
        if ("error" in resolved) return resolved.error;
        const { entry, id, secret, token } = resolved;
        await this.auditLog(fingerprint, "secret_revealed", {
          entry_id: id,
          kind: entry.kind,
          label: entry.label,
          token_id: token.id,
          uses_remaining: token.uses_remaining,
        });
        return { ok: true, value: secret.value, descriptor: secret.descriptor };
      }
      case "use-sink": {
        // The `use` scope delivers a secret to a sink WITHOUT returning it.
        // The child process runs here, in the agent, so the plaintext never
        // crosses the socket back to the token holder.
        const fingerprint = String(msg["fingerprint"] ?? "");
        const sink = String(msg["sink"] ?? "");
        const command = (msg["command"] as string[] | undefined) ?? [];
        const resolved = await this.resolveForToken(msg, fingerprint, "use", {
          sink,
          command,
        });
        if ("error" in resolved) return resolved.error;
        const { entry, id, secret, token } = resolved;

        let result: SinkResult;
        try {
          if (sink === "clipboard") {
            result = await clipboardSink(secret.value);
          } else {
            const [cmd, args] = parseCommandSpec(command);
            result =
              sink === "exec"
                ? await execSink(secret.value, cmd, args)
                : await stdinSink(secret.value, cmd, args);
          }
        } catch (e) {
          await this.auditLog(fingerprint, "delivery_failed", {
            entry_id: id,
            token_id: token.id,
            sink,
            command,
            reason: String(e),
          });
          return { ok: false, error: `sink failed: ${String(e)}` };
        }

        await this.auditLog(fingerprint, "secret_delivered", {
          entry_id: id,
          kind: entry.kind,
          label: entry.label,
          token_id: token.id,
          uses_remaining: token.uses_remaining,
          sink,
          // Record exactly what received the secret. A `use` token holder who
          // chooses the command can still read the value from inside it —
          // containment comes from the exec allowlist, accountability from here.
          command,
        });
        return { ok: true, descriptor: secret.descriptor, ...result };
      }
      case "put": {
        const fingerprint = String(msg["fingerprint"] ?? "");
        const mnemonic = String(msg["mnemonic"] ?? "");
        if (!fingerprint || !mnemonic) return { ok: false, error: "missing fields" };
        const ttl = Number(msg["ttl"] ?? this.defaultTtl);
        const expiresAt = Math.floor(Date.now() / 1000 + ttl);
        this.held.set(fingerprint, { mnemonic, expiresAt });
        await this.auditLog(fingerprint, "vault_unlocked", { ttl });
        return { ok: true, expires_at: expiresAt };
      }
      case "owner-mnemonic": {
        // Owner-capability gated: this hands back the parent seed so the
        // owner's CLI can operate the vault locally. It is deliberately NOT
        // reachable with a scoped token.
        const held = this.held.get(String(msg["fingerprint"] ?? ""));
        return held ? { ok: true, mnemonic: held.mnemonic } : { ok: false, error: "locked" };
      }
      case "lock": {
        const fp = msg["fingerprint"];
        if (fp === undefined) {
          const n = this.held.size;
          for (const held of [...this.held.keys()]) this.forget(held);
          return { ok: true, locked: n };
        }
        const key = String(fp);
        const had = this.held.has(key);
        this.forget(key);
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
  private capability: string | null = null;

  constructor(private readonly socketPath: string) {}

  /** Owner capability, read from the 0600 file the daemon writes. */
  private ownerCapability(): string {
    if (this.capability !== null) return this.capability;
    const fromEnv = process.env["SEEDPASS_AGENT_CAP"];
    if (fromEnv) {
      this.capability = fromEnv;
      return fromEnv;
    }
    try {
      this.capability = readFileSync(`${this.socketPath}.cap`, "utf8").trim();
    } catch {
      this.capability = "";
    }
    return this.capability;
  }

  private ownerRequest(msg: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request({ ...msg, cap: this.ownerCapability() });
  }

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
    const r = await this.ownerRequest({ op: "put", fingerprint, mnemonic, ...(ttl && { ttl }) });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return Number(r["expires_at"]);
  }

  /** Owner-only: fetch the parent seed for local vault operations. */
  async ownerMnemonic(fingerprint: string): Promise<string | null> {
    try {
      const r = await this.ownerRequest({ op: "owner-mnemonic", fingerprint });
      return r["ok"] ? String(r["mnemonic"]) : null;
    } catch {
      return null;
    }
  }

  async lock(fingerprint?: string): Promise<number> {
    const r = await this.ownerRequest({ op: "lock", ...(fingerprint && { fingerprint }) });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return Number(r["locked"] ?? 0);
  }

  async status(): Promise<AgentStatusProfile[]> {
    const r = await this.ownerRequest({ op: "status" });
    if (!r["ok"]) throw new Error(String(r["error"]));
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
    const r = await this.ownerRequest({
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
    const r = await this.ownerRequest({ op: "token-list", fingerprint });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return r["tokens"] as TokenInfo[];
  }

  async tokenRevoke(tokenId: string): Promise<void> {
    const r = await this.ownerRequest({ op: "token-revoke", token_id: tokenId });
    if (!r["ok"]) throw new Error(String(r["error"]));
  }

  /** Redacted entry metadata the token is allowed to see. */
  async vaultEntries(
    fingerprint: string,
    token: string,
  ): Promise<Record<string, unknown>[]> {
    const r = await this.request({ op: "vault-index", fingerprint, token });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return r["entries"] as Record<string, unknown>[];
  }

  /** Ask the agent to deliver a secret to a sink; plaintext stays inside it. */
  async useSink(options: {
    fingerprint: string;
    id: string;
    token: string;
    sink: "clipboard" | "exec" | "stdin";
    command: string[];
    timestamp?: number;
  }): Promise<Record<string, unknown>> {
    const r = await this.request({
      op: "use-sink",
      fingerprint: options.fingerprint,
      id: options.id,
      token: options.token,
      sink: options.sink,
      command: options.command,
      ...(options.timestamp !== undefined && { timestamp: options.timestamp }),
    });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return r;
  }

  async secret(options: {
    fingerprint: string;
    id: string;
    token: string;
    timestamp?: number;
  }): Promise<{ value: string; descriptor: string }> {
    const r = await this.request({
      op: "secret",
      fingerprint: options.fingerprint,
      id: options.id,
      token: options.token,
      ...(options.timestamp !== undefined && { timestamp: options.timestamp }),
    });
    if (!r["ok"]) throw new Error(String(r["error"]));
    return { value: String(r["value"]), descriptor: String(r["descriptor"]) };
  }
}
