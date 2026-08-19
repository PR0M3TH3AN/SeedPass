/**
 * API route handlers — parity with src/seedpass/api.py.
 *
 * Every handler reuses the CLI's own vault plumbing (openVault, mutateVault,
 * materializeSecret, loadConfig) rather than reimplementing it. That is the
 * point: an API that derived secrets its own way would be a second
 * implementation to keep in parity, and the first place the two would drift
 * is the part nobody notices — which secret a given entry produces.
 */

import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename, dirname, join, resolve as resolvePath } from "node:path";
import {
  addDocumentEntry,
  addKeyValueEntry,
  addManagedAccountEntry,
  addNostrKeyEntry,
  addPasswordEntry,
  addPgpKeyEntry,
  addSeedEntry,
  addSshKeyEntry,
  addTotpDeterministic,
  addTotpImported,
  addLink,
  archiveEntry,
  deriveNostrKeys,
  deriveTotpSecret,
  exportBackup,
  findDerivationCollisions,
  generateFingerprint,
  generatePassword,
  getLinks,
  importBackup,
  modifyEntry,
  parseBackupWrapper,
  parseVaultIndex,
  passwordPolicyFromRecord,
  removeLink,
  restoreEntry,
  buildSemanticRecords,
  searchSemanticRecords,
  semanticManifest,
  semanticStatus,
  type SemanticRecord,
  totpCodeAt,
  Bip85,
  type Entry,
  type PasswordPolicy,
  type VaultIndex,
} from "@seedpass/core";
import { AppDir, INDEX_FILENAME, DEFAULT_PBKDF2_ITERATIONS } from "../appDir.js";
import { loadConfig, mutateConfig, passwordPolicyFromConfig, DEFAULT_RELAYS } from "../configFile.js";
import { openVault, saveVault, saveVaultHoldingLock, withVaultLock, atomicWrite } from "../vaultFile.js";
import { entryMetadata, refFor, resolveEntry } from "../refs.js";
import { materializeSecret } from "../secrets.js";
import { createIndexBackup } from "../backups.js";
import { HttpError, type ApiRequest, type ApiResponse, type ApiServer } from "./server.js";

/**
 * Features that exist in the Python API but are deliberately not ported.
 *
 * These hang off subsystems the TypeScript port does not implement at all
 * (see capabilities().not_yet_ported). They answer 501 with the reason rather
 * than 404, because a 404 reads as "you typed the path wrong" and would send
 * an integrator hunting for a spelling mistake that is not there.
 */
export const UNPORTED_PREFIXES: Array<{ prefix: string; feature: string }> = [
  { prefix: "/api/v1/high-risk", feature: "high-risk partitions" },
  { prefix: "/api/v1/agent/job-profiles", feature: "agent job profiles" },
  { prefix: "/api/v1/agent/recovery", feature: "agent recovery split" },
];

export interface ApiContext {
  appDir: AppDir;
  /** Fingerprint of the profile the server was started against. */
  fingerprint: string;
  /**
   * The unlocked parent seed, or null when locked.
   *
   * Held in this object rather than captured, so `vault lock` can genuinely
   * drop it: every handler reads it through `requireUnlocked` at call time.
   */
  mnemonic: string | null;
  /** Verify a master password without unlocking. */
  verifyPassword: (password: string) => Promise<boolean>;
  /** Unlock and populate `mnemonic`; returns seconds taken. */
  unlock: (password: string) => Promise<number>;
  /** Queued notifications, drained by GET /notifications. */
  notifications: Array<{ level: string; message: string }>;
  /** Requests the process to exit; wired by the CLI command. */
  requestShutdown: () => void;
  now: () => number;
}

function requireUnlocked(ctx: ApiContext): string {
  if (!ctx.mnemonic) throw new HttpError(423, "Vault is locked");
  return ctx.mnemonic;
}

async function requirePassword(ctx: ApiContext, req: ApiRequest): Promise<void> {
  const password = req.headers["x-seedpass-password"];
  if (!password || !(await ctx.verifyPassword(password))) {
    throw new HttpError(401, "Invalid password");
  }
}

function profileDir(ctx: ApiContext): string {
  return ctx.appDir.profileDir(ctx.fingerprint);
}

function indexPath(ctx: ApiContext): string {
  return join(profileDir(ctx), INDEX_FILENAME);
}

async function readVault(ctx: ApiContext) {
  return openVault(indexPath(ctx), requireUnlocked(ctx));
}

/** Read-modify-write the vault under one lock, then snapshot it. */
async function mutate<T>(
  ctx: ApiContext,
  fn: (index: VaultIndex) => T | Promise<T>,
): Promise<T> {
  const path = indexPath(ctx);
  const mnemonic = requireUnlocked(ctx);
  const result = await withVaultLock(path, async () => {
    const vault = await openVault(path, mnemonic);
    const out = await fn(vault.index);
    await saveVaultHoldingLock(vault);
    return out;
  });
  try {
    const config = await loadConfig(profileDir(ctx), mnemonic);
    await createIndexBackup({ indexPath: path, config });
  } catch {
    // Best-effort, exactly as the CLI and TUI treat it: a failed snapshot
    // must not make a committed write look like it failed.
  }
  return result;
}

function entryIdOf(req: ApiRequest): string {
  const raw = req.params["entry_id"] ?? "";
  if (!/^\d+$/.test(raw)) throw new HttpError(400, "entry id must be a non-negative integer");
  return raw;
}

function bodyObject(req: ApiRequest): Record<string, unknown> {
  if (req.body === undefined) return {};
  if (typeof req.body !== "object" || req.body === null || Array.isArray(req.body)) {
    throw new HttpError(400, "expected a JSON object body");
  }
  return req.body as Record<string, unknown>;
}

function str(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new HttpError(400, `${field} is required`);
  }
  return value;
}

function optInt(value: unknown, field: string): number | undefined {
  if (value === undefined || value === null) return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new HttpError(400, `${field} must be a non-negative integer`);
  return n;
}

/**
 * Resolve a caller-supplied path, refusing anything outside the profile.
 *
 * Parity with Python's `_validate_encryption_path`. A path traversal here
 * would let an authenticated caller read or write arbitrary files as the
 * user running a process that holds unlocked seeds.
 */
function resolveWithinProfile(ctx: ApiContext, raw: string): string {
  const root = resolvePath(profileDir(ctx));
  const target = resolvePath(root, raw);
  if (target !== root && !target.startsWith(root + "/")) {
    throw new HttpError(400, "path must stay inside the profile directory");
  }
  return target;
}

/** Register every ported route on `server`. */
export function registerRoutes(server: ApiServer, ctx: ApiContext): void {
  // ---------------------------------------------------------------- entries

  server.route("GET", "/api/v1/entry", async (req) => {
    const vault = await readVault(ctx);
    const query = (req.query.get("query") ?? "").trim().toLowerCase();
    const kindFilter = req.query.get("kind");
    const includeArchived = ["1", "true", "yes"].includes(
      (req.query.get("archived") ?? "").toLowerCase(),
    );
    const rows = Object.entries(vault.index.entries)
      .map(([id, entry]) => ({ id, entry: entry as Entry }))
      .filter(({ entry }) => {
        const e = entry as unknown as Record<string, unknown>;
        if (!includeArchived && e["archived"] === true) return false;
        if (kindFilter && String(e["kind"] ?? e["type"] ?? "") !== kindFilter) return false;
        if (!query) return true;
        const haystack = [e["label"], e["username"], e["url"], e["notes"], ...(Array.isArray(e["tags"]) ? e["tags"] : [])]
          .map((v) => String(v ?? "").toLowerCase())
          .join(" ");
        return haystack.includes(query);
      })
      // Reference-first, like every other surface: a listing carries metadata
      // and never a secret value.
      .map(({ id, entry }) => entryMetadata(id, entry));
    return { json: rows };
  });

  server.route(
    "GET",
    "/api/v1/entry/:entry_id",
    async (req) => {
      await requirePassword(ctx, req);
      const vault = await readVault(ctx);
      const id = entryIdOf(req);
      const entry = vault.index.entries[id];
      if (!entry) throw new HttpError(404, "Not found");
      return { json: { id, ref: refFor(id), ...(entry as object) } };
    },
    { requiresPassword: true },
  );

  server.route(
    "GET",
    "/api/v1/entry/:entry_id/secret",
    async (req) => {
      // Not in the Python surface: there, GET /entry/{id} returns stored
      // secrets directly because Python stores some of them. Derived secrets
      // need an explicit route, and making it explicit is the better shape —
      // "give me the entry" and "give me the plaintext" are different asks.
      await requirePassword(ctx, req);
      const mnemonic = requireUnlocked(ctx);
      const vault = await readVault(ctx);
      const id = entryIdOf(req);
      const entry = vault.index.entries[id];
      if (!entry) throw new HttpError(404, "Not found");
      const timestamp = optInt(req.query.get("at") ?? undefined, "at");
      const config = await loadConfig(profileDir(ctx), mnemonic);
      const secret = materializeSecret(vault.index, id, entry as Entry, mnemonic, {
        ...(timestamp !== undefined && { timestamp }),
        basePolicy: passwordPolicyFromConfig(config),
      });
      return { json: { id, descriptor: secret.descriptor, value: secret.value } };
    },
    { requiresPassword: true },
  );

  server.route("POST", "/api/v1/entry", async (req) => {
    const mnemonic = requireUnlocked(ctx);
    const body = bodyObject(req);
    const kind = str(body["kind"] ?? body["type"], "kind");
    const label = str(body["label"], "label");
    // Built by omission rather than by assigning undefined: the entry
    // constructors distinguish "not supplied" from "supplied as undefined".
    const common: { username?: string; url?: string; notes?: string; tags?: string[] } = {
      ...(typeof body["username"] === "string" && { username: body["username"] }),
      ...(typeof body["url"] === "string" && { url: body["url"] }),
      ...(typeof body["notes"] === "string" && { notes: body["notes"] }),
      ...(Array.isArray(body["tags"]) && { tags: body["tags"] as string[] }),
    };
    const created = await mutate(ctx, (index) => {
      switch (kind) {
        case "password":
          return addPasswordEntry(index, label, optInt(body["length"], "length") ?? 16, common);
        case "totp": {
          const secret = body["secret"];
          if (typeof secret === "string" && secret.length > 0) {
            return addTotpImported(index, label, secret, {
              period: optInt(body["period"], "period") ?? 30,
              digits: optInt(body["digits"], "digits") ?? 6,
              ...common,
            });
          }
          return addTotpDeterministic(index, label, mnemonic, {
            period: optInt(body["period"], "period") ?? 30,
            digits: optInt(body["digits"], "digits") ?? 6,
            ...common,
          });
        }
        case "key_value":
          return addKeyValueEntry(
            index,
            label,
            str(body["key"], "key"),
            str(body["value"], "value"),
            common,
          );
        case "document":
          return addDocumentEntry(index, label, str(body["content"], "content"), common);
        case "ssh":
          return addSshKeyEntry(index, label, common);
        case "pgp":
          return addPgpKeyEntry(index, label, common);
        case "nostr":
          return addNostrKeyEntry(index, label, common);
        case "seed": {
          const wordCount = optInt(body["word_count"], "word_count") ?? 12;
          if (wordCount !== 12 && wordCount !== 18 && wordCount !== 24) {
            throw new HttpError(400, "word_count must be 12, 18 or 24");
          }
          return addSeedEntry(index, label, { ...common, wordCount });
        }
        case "managed_account":
          return addManagedAccountEntry(index, label, mnemonic, common);
        default:
          throw new HttpError(400, `unsupported entry kind '${kind}'`);
      }
    });
    // Provision-blind, matching every other surface: creating an entry hands
    // back a reference, never the secret it will derive.
    return { status: 201, json: { id: created, ref: refFor(String(created)) } };
  });

  server.route("PUT", "/api/v1/entry/:entry_id", async (req) => {
    const id = entryIdOf(req);
    const body = bodyObject(req);
    await mutate(ctx, (index) => {
      if (!index.entries[id]) throw new HttpError(404, "Not found");
      try {
        modifyEntry(index, id, body as Parameters<typeof modifyEntry>[2]);
      } catch (e) {
        throw new HttpError(400, (e as Error).message);
      }
    });
    return { json: { status: "ok" } };
  });

  server.route("POST", "/api/v1/entry/:entry_id/archive", async (req) => {
    const id = entryIdOf(req);
    await mutate(ctx, (index) => {
      if (!index.entries[id]) throw new HttpError(404, "Not found");
      archiveEntry(index, id);
    });
    return { json: { status: "archived" } };
  });

  server.route("POST", "/api/v1/entry/:entry_id/unarchive", async (req) => {
    const id = entryIdOf(req);
    await mutate(ctx, (index) => {
      if (!index.entries[id]) throw new HttpError(404, "Not found");
      restoreEntry(index, id);
    });
    return { json: { status: "active" } };
  });

  server.route("GET", "/api/v1/entry/:entry_id/links", async (req) => {
    const vault = await readVault(ctx);
    const id = entryIdOf(req);
    if (!vault.index.entries[id]) throw new HttpError(404, "Not found");
    return { json: { entry_id: id, links: getLinks(vault.index, id) } };
  });

  server.route("POST", "/api/v1/entry/:entry_id/links", async (req) => {
    const id = entryIdOf(req);
    const body = bodyObject(req);
    const targetRaw = body["target"] ?? body["to"];
    const target = optInt(targetRaw, "target");
    if (target === undefined) throw new HttpError(400, "target is required");
    const links = await mutate(ctx, (index) => {
      if (!index.entries[id]) throw new HttpError(404, "Not found");
      try {
        addLink(index, id, target, {
          ...(typeof body["relation"] === "string" && { relation: body["relation"] }),
        });
      } catch (e) {
        throw new HttpError(400, (e as Error).message);
      }
      return getLinks(index, id);
    });
    return { json: { entry_id: id, links } };
  });

  server.route("DELETE", "/api/v1/entry/:entry_id/links", async (req) => {
    const id = entryIdOf(req);
    const targetRaw = req.query.get("target") ?? bodyObject(req)["target"];
    const target = optInt(targetRaw, "target");
    if (target === undefined) throw new HttpError(400, "target is required");
    const links = await mutate(ctx, (index) => {
      if (!index.entries[id]) throw new HttpError(404, "Not found");
      removeLink(index, id, target);
      return getLinks(index, id);
    });
    return { json: { entry_id: id, links } };
  });

  server.route("POST", "/api/v1/entry/document/import", async (req) => {
    const body = bodyObject(req);
    const label = str(body["label"], "label");
    let content: string;
    if (typeof body["content"] === "string") {
      content = body["content"];
    } else if (typeof body["path"] === "string") {
      const path = resolveWithinProfile(ctx, body["path"]);
      if (!existsSync(path)) throw new HttpError(404, "file not found");
      content = await readFile(path, "utf8");
    } else {
      throw new HttpError(400, "content or path is required");
    }
    const id = await mutate(ctx, (index) => addDocumentEntry(index, label, content, {}));
    return { status: 201, json: { id, ref: refFor(String(id)) } };
  });

  server.route(
    "POST",
    "/api/v1/entry/:entry_id/document/export",
    async (req) => {
      await requirePassword(ctx, req);
      const mnemonic = requireUnlocked(ctx);
      const id = entryIdOf(req);
      const vault = await readVault(ctx);
      const entry = vault.index.entries[id];
      if (!entry) throw new HttpError(404, "Not found");
      const body = bodyObject(req);
      const dest = resolveWithinProfile(ctx, str(body["path"], "path"));
      const config = await loadConfig(profileDir(ctx), mnemonic);
      const secret = materializeSecret(vault.index, id, entry as Entry, mnemonic, {
        basePolicy: passwordPolicyFromConfig(config),
      });
      // 0600 via a fresh file, the way every other export path here does it —
      // writeFile's mode argument applies only at creation and would leave an
      // existing world-readable file exactly as it found it.
      await atomicWrite(dest, new TextEncoder().encode(secret.value));
      return { json: { path: dest } };
    },
    { requiresPassword: true },
  );

  // ----------------------------------------------------------------- config

  server.route("GET", "/api/v1/config/:key", async (req) => {
    const mnemonic = requireUnlocked(ctx);
    const key = req.params["key"]!;
    const config = await loadConfig(profileDir(ctx), mnemonic);
    if (key === "password_hash" || key === "pin_hash") {
      // Never hand back a credential verifier over the wire, even to an
      // authenticated caller: it is offline-crackable and nothing legitimate
      // needs it.
      return { json: { key, value: "<redacted>" } };
    }
    return { json: { key, value: config[key] ?? null } };
  });

  server.route("PUT", "/api/v1/config/:key", async (req) => {
    const mnemonic = requireUnlocked(ctx);
    const key = req.params["key"]!;
    if (key === "password_hash" || key === "pin_hash") {
      throw new HttpError(400, `${key} is not settable through the API`);
    }
    const body = bodyObject(req);
    if (!("value" in body)) throw new HttpError(400, "value is required");
    await mutateConfig(profileDir(ctx), mnemonic, (config) => {
      config[key] = body["value"];
    });
    return { json: { status: "ok" } };
  });

  server.route("POST", "/api/v1/secret-mode", async (req) => {
    const mnemonic = requireUnlocked(ctx);
    const body = bodyObject(req);
    const enabled = Boolean(body["enabled"]);
    const delay = optInt(body["delay"], "delay");
    await mutateConfig(profileDir(ctx), mnemonic, (config) => {
      config["secret_mode_enabled"] = enabled;
      if (delay !== undefined) config["clipboard_clear_delay"] = delay;
    });
    return { json: { status: "ok" } };
  });

  // ------------------------------------------------------------ fingerprints

  server.route("GET", "/api/v1/fingerprint", async () => {
    const data = await ctx.appDir.readFingerprints();
    return {
      json: data.fingerprints.map((fp) => ({
        fingerprint: fp,
        name: data.names[fp] ?? null,
        current: fp === ctx.fingerprint,
      })),
    };
  });

  server.route("POST", "/api/v1/fingerprint/select", async (req) => {
    const body = bodyObject(req);
    const fingerprint = str(body["fingerprint"], "fingerprint");
    const data = await ctx.appDir.readFingerprints();
    if (!data.fingerprints.includes(fingerprint)) throw new HttpError(404, "no such profile");
    await ctx.appDir.switchProfile(fingerprint);
    // Switching profiles drops the held seed: the seed in memory belongs to
    // the profile we are leaving, and carrying it across would let a caller
    // read one profile's vault while believing they had selected another.
    ctx.mnemonic = null;
    ctx.fingerprint = fingerprint;
    return { json: { status: "ok", fingerprint, locked: true } };
  });

  server.route("DELETE", "/api/v1/fingerprint/:fingerprint", async (req) => {
    await requirePassword(ctx, req);
    const fingerprint = req.params["fingerprint"]!;
    if (fingerprint === ctx.fingerprint) {
      throw new HttpError(400, "refusing to delete the profile this server is serving");
    }
    await ctx.appDir.removeProfile(fingerprint);
    return { json: { status: "deleted" } };
  }, { requiresPassword: true });

  // ------------------------------------------------------------------- totp

  server.route("GET", "/api/v1/totp", async () => {
    const mnemonic = requireUnlocked(ctx);
    const vault = await readVault(ctx);
    const now = Math.floor(ctx.now() / 1000);
    const codes = Object.entries(vault.index.entries)
      .filter(([, e]) => String((e as unknown as Record<string, unknown>)["kind"] ?? "") === "totp")
      .map(([id, e]) => {
        const entry = e as unknown as Record<string, unknown>;
        const secret = materializeSecret(vault.index, id, e as Entry, mnemonic, {
          timestamp: now,
        });
        const period = Number(entry["period"] ?? 30);
        return {
          id,
          label: String(entry["label"] ?? ""),
          code: secret.value,
          seconds_remaining: period - (now % period),
        };
      });
    return { json: { codes } };
  });

  server.route(
    "GET",
    "/api/v1/totp/export",
    async (req) => {
      await requirePassword(ctx, req);
      const mnemonic = requireUnlocked(ctx);
      const vault = await readVault(ctx);
      // Every TOTP secret in the vault, in plaintext. Password-gated for
      // that reason alone.
      const entries = Object.entries(vault.index.entries)
        .filter(([, e]) => String((e as unknown as Record<string, unknown>)["kind"] ?? "") === "totp")
        .map(([, e]) => {
          const entry = e as unknown as Record<string, unknown>;
          // The SECRET, not a code. materializeSecret returns the current
          // 6-digit code for a totp entry, which would make this export look
          // correct and be useless — an authenticator cannot be seeded from
          // a code. Imported entries store their secret; deterministic ones
          // re-derive it, exactly as the TUI's 2FA export does.
          const secret =
            typeof entry["secret"] === "string" && entry["secret"]
              ? (entry["secret"] as string)
              : deriveTotpSecret(mnemonic, Number(entry["index"] ?? 0));
          const label = String(entry["label"] ?? "");
          const period = Number(entry["period"] ?? 30);
          const digits = Number(entry["digits"] ?? 6);
          return {
            label,
            secret,
            period,
            digits,
            // The form an authenticator can actually consume.
            uri:
              `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}` +
              `&issuer=SeedPass&period=${period}&digits=${digits}`,
          };
        });
      return { json: { entries } };
    },
    { requiresPassword: true },
  );

  // ------------------------------------------------------------- vault state

  server.route("POST", "/api/v1/vault/unlock", async (req) => {
    const password = req.headers["x-seedpass-password"];
    if (!password) throw new HttpError(401, "master password header required");
    try {
      const duration = await ctx.unlock(password);
      return { json: { status: "unlocked", duration } };
    } catch {
      server.recordUnlockFailure(req);
      throw new HttpError(401, "Invalid password");
    }
  });

  server.route("POST", "/api/v1/vault/lock", async () => {
    ctx.mnemonic = null;
    return { json: { status: "locked" } };
  });

  server.route("GET", "/api/v1/vault/status", async () => {
    return {
      json: {
        fingerprint: ctx.fingerprint,
        locked: ctx.mnemonic === null,
      },
    };
  });

  server.route("POST", "/api/v1/change-password", async (req) => {
    const body = bodyObject(req);
    const current = str(body["current_password"] ?? body["old_password"], "current_password");
    const next = str(body["new_password"], "new_password");
    const mnemonic = requireUnlocked(ctx);
    const config = await loadConfig(profileDir(ctx), mnemonic);
    const iterations = Number(config["kdf_iterations"] ?? DEFAULT_PBKDF2_ITERATIONS);
    try {
      await ctx.appDir.changePassword(ctx.fingerprint, current, next, iterations);
    } catch (e) {
      throw new HttpError(401, (e as Error).message);
    }
    return { json: { status: "ok" } };
  });

  // ------------------------------------------------------------------ vault

  server.route(
    "POST",
    "/api/v1/vault/export",
    async (req) => {
      await requirePassword(ctx, req);
      const mnemonic = requireUnlocked(ctx);
      const vault = await readVault(ctx);
      const body = bodyObject(req);
      const encrypt = body["plaintext"] !== true;
      const wrapper = await exportBackup(vault.index as unknown as Record<string, unknown>, {
        mnemonic,
        fingerprint: generateFingerprint(mnemonic),
        encrypt,
      });
      return {
        bytes: new TextEncoder().encode(JSON.stringify(wrapper, null, 2)),
        contentType: "application/octet-stream",
        headers: {
          "content-disposition": `attachment; filename="seedpass-${generateFingerprint(mnemonic)}.seedpass"`,
        },
      };
    },
    { requiresPassword: true },
  );

  server.route(
    "POST",
    "/api/v1/vault/import",
    async (req) => {
      await requirePassword(ctx, req);
      const mnemonic = requireUnlocked(ctx);
      if (req.rawBody.length === 0) throw new HttpError(400, "a backup body is required");
      const wrapper = parseBackupWrapper(req.rawBody);
      const target = generateFingerprint(mnemonic);
      const allowMismatch = (req.query.get("allow_fingerprint_mismatch") ?? "") === "true";
      if (wrapper.fingerprint !== target && !allowMismatch) {
        throw new HttpError(
          409,
          `backup belongs to profile ${wrapper.fingerprint}, but this server ` +
            `serves ${target}. Importing it would re-derive every secret from ` +
            `this profile's seed, silently producing different passwords than ` +
            `the backup holds. Retry with ?allow_fingerprint_mismatch=true if ` +
            `that is really intended.`,
        );
      }
      const parsed = await importBackup(req.rawBody, { mnemonic });
      const index = parseVaultIndex(parsed);
      await saveVault({ index, mnemonic, path: indexPath(ctx) });
      const collisions = findDerivationCollisions(index);
      return {
        json: {
          status: "ok",
          entry_count: Object.keys(index.entries).length,
          ...(collisions.length > 0 && {
            derivation_collisions: collisions.map((c) => ({
              index: c.index,
              severity: c.severity,
              entries: c.entries,
            })),
          }),
        },
      };
    },
    { requiresPassword: true },
  );

  server.route(
    "POST",
    "/api/v1/vault/backup-parent-seed",
    async (req) => {
      await requirePassword(ctx, req);
      const mnemonic = requireUnlocked(ctx);
      const body = bodyObject(req);
      const dest = resolveWithinProfile(ctx, str(body["path"], "path"));
      await atomicWrite(dest, new TextEncoder().encode(mnemonic + "\n"));
      return { json: { status: "saved", path: dest } };
    },
    { requiresPassword: true },
  );

  // ------------------------------------------------------------------ nostr

  server.route("GET", "/api/v1/nostr/pubkey", async () => {
    const mnemonic = requireUnlocked(ctx);
    return { json: { npub: deriveNostrKeys(Bip85.fromMnemonic(mnemonic), 0).npub } };
  });

  server.route("GET", "/api/v1/relays", async () => {
    const mnemonic = requireUnlocked(ctx);
    const config = await loadConfig(profileDir(ctx), mnemonic);
    return { json: { relays: config["relays"] ?? [] } };
  });

  server.route("POST", "/api/v1/relays", async (req) => {
    const mnemonic = requireUnlocked(ctx);
    const url = str(bodyObject(req)["url"], "url");
    if (!/^wss?:\/\//.test(url)) throw new HttpError(400, "relay must be a ws:// or wss:// URL");
    const relays = await mutateConfig(profileDir(ctx), mnemonic, (config) => {
      const list = Array.isArray(config["relays"]) ? (config["relays"] as string[]) : [];
      if (!list.includes(url)) list.push(url);
      config["relays"] = list;
      return list;
    });
    return { json: { status: "ok", relays } };
  });

  server.route("DELETE", "/api/v1/relays/:idx", async (req) => {
    const mnemonic = requireUnlocked(ctx);
    const idx = Number(req.params["idx"]);
    if (!Number.isInteger(idx) || idx < 0) throw new HttpError(400, "idx must be a non-negative integer");
    const relays = await mutateConfig(profileDir(ctx), mnemonic, (config) => {
      const list = Array.isArray(config["relays"]) ? [...(config["relays"] as string[])] : [];
      if (idx >= list.length) throw new HttpError(404, "no relay at that index");
      list.splice(idx, 1);
      config["relays"] = list;
      return list;
    });
    return { json: { status: "ok", relays } };
  });

  server.route("POST", "/api/v1/relays/reset", async () => {
    const mnemonic = requireUnlocked(ctx);
    const relays = await mutateConfig(profileDir(ctx), mnemonic, (config) => {
      config["relays"] = [...DEFAULT_RELAYS];
      return config["relays"] as string[];
    });
    return { json: { status: "ok", relays } };
  });

  // -------------------------------------------------------------- utilities

  server.route("POST", "/api/v1/password", async (req) => {
    const mnemonic = requireUnlocked(ctx);
    const body = bodyObject(req);
    const length = optInt(body["length"], "length") ?? 16;
    const config = await loadConfig(profileDir(ctx), mnemonic);
    const policy: PasswordPolicy = {
      ...passwordPolicyFromConfig(config),
      ...passwordPolicyFromRecord(body),
    };
    try {
      const password = generatePassword(Bip85.fromMnemonic(mnemonic), {
        length,
        index: optInt(body["index"], "index") ?? 0,
        genVersion: optInt(body["gen_version"], "gen_version") ?? 2,
        policy,
      });
      return { json: { password } };
    } catch (e) {
      throw new HttpError(400, (e as Error).message);
    }
  });

  server.route("GET", "/api/v1/stats", async () => {
    const vault = await readVault(ctx);
    const counts: Record<string, number> = {};
    let archived = 0;
    for (const entry of Object.values(vault.index.entries)) {
      const e = entry as unknown as Record<string, unknown>;
      const kind = String(e["kind"] ?? e["type"] ?? "unknown");
      counts[kind] = (counts[kind] ?? 0) + 1;
      if (e["archived"] === true) archived++;
    }
    return {
      json: {
        fingerprint: ctx.fingerprint,
        schema_version: vault.index.schema_version,
        total_entries: Object.keys(vault.index.entries).length,
        archived_entries: archived,
        by_kind: counts,
      },
    };
  });

  server.route("GET", "/api/v1/notifications", async () => {
    // Drain: reading them clears them, matching Python's queue semantics.
    const notes = ctx.notifications.splice(0, ctx.notifications.length);
    return { json: notes };
  });

  server.route("GET", "/api/v1/check-derivation", async () => {
    const vault = await readVault(ctx);
    const collisions = findDerivationCollisions(vault.index);
    return {
      json: {
        checked: Object.keys(vault.index.entries).length,
        collisions: collisions.map((c) => ({
          index: c.index,
          severity: c.severity,
          entries: c.entries,
          message: c.message,
        })),
      },
    };
  });

  // --------------------------------------------------------------- semantic

  const semanticDir = (): string => join(profileDir(ctx), "semantic_index");
  const semanticRecordsPath = (): string => join(semanticDir(), "records.json");
  const semanticManifestPath = (): string => join(semanticDir(), "manifest.json");

  async function readSemanticRecords(): Promise<SemanticRecord[]> {
    if (!existsSync(semanticRecordsPath())) return [];
    try {
      const data = JSON.parse(await readFile(semanticRecordsPath(), "utf8"));
      return Array.isArray(data) ? (data as SemanticRecord[]) : [];
    } catch {
      return [];
    }
  }

  async function buildSemantic(): Promise<number> {
    const vault = await readVault(ctx);
    const entries = Object.entries(vault.index.entries).map(([id, e]) => ({
      ...(e as object),
      id: Number(id),
    })) as Array<Record<string, unknown>>;
    const records = buildSemanticRecords(entries);
    await mkdir(semanticDir(), { recursive: true });
    // The records file is plaintext, so it holds metadata only and is written
    // through atomicWrite for a genuine 0600 inode.
    await atomicWrite(semanticRecordsPath(), new TextEncoder().encode(JSON.stringify(records, null, 2)));
    await atomicWrite(
      semanticManifestPath(),
      new TextEncoder().encode(
        JSON.stringify(
          semanticManifest({
            enabled: true,
            built: true,
            recordCount: records.length,
            updatedAt: ctx.now() / 1000,
          }),
          null,
          2,
        ),
      ),
    );
    return records.length;
  }

  server.route("GET", "/api/v1/semantic/status", async () => {
    let manifest: Record<string, unknown> = {};
    if (existsSync(semanticManifestPath())) {
      try {
        manifest = JSON.parse(await readFile(semanticManifestPath(), "utf8"));
      } catch {
        // Corrupt manifest reports as not-built; the fix is a rebuild.
      }
    }
    return { json: semanticStatus(manifest, (await readSemanticRecords()).length) };
  });

  for (const path of ["/api/v1/semantic/build", "/api/v1/semantic/rebuild"]) {
    server.route("POST", path, async () => {
      // Build and rebuild are the same operation here: the records file is
      // rewritten wholesale either way, so there is no stale state to clear.
      return { json: { status: "ok", records: await buildSemantic() } };
    });
  }

  server.route("POST", "/api/v1/semantic/search", async (req) => {
    const body = bodyObject(req);
    const records = await readSemanticRecords();
    if (records.length === 0) {
      throw new HttpError(409, "no semantic index; POST /api/v1/semantic/build first");
    }
    const hits = searchSemanticRecords(records, str(body["query"], "query"), {
      k: optInt(body["k"], "k") ?? 10,
      ...(typeof body["kind"] === "string" && { kind: body["kind"] }),
    });
    return { json: { results: hits.map((h) => ({ ...h, ref: refFor(String(h.entry_id)) })) } };
  });

  server.route("POST", "/api/v1/shutdown", async () => {
    ctx.requestShutdown();
    return { json: { status: "shutting down" } };
  });

  // ----------------------------------------------------- deliberate 501s

  for (const { prefix, feature } of UNPORTED_PREFIXES) {
    for (const method of ["GET", "POST", "PUT", "DELETE"]) {
      for (const pattern of [prefix, `${prefix}/:rest`, `${prefix}/:rest/:more`]) {
        server.route(method, pattern, () => {
          throw new HttpError(
            501,
            `${feature} is not implemented in the TypeScript port. This is a ` +
              `deliberate omission, not a missing path — see capabilities().not_yet_ported.`,
          );
        });
      }
    }
  }
}
