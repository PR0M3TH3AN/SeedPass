/**
 * API route handlers — parity with src/seedpass/api.py.
 *
 * Every handler reuses the CLI's own vault plumbing (openVault, mutateVault,
 * materializeSecret, loadConfig) rather than reimplementing it. That is the
 * point: an API that derived secrets its own way would be a second
 * implementation to keep in parity, and the first place the two would drift
 * is the part nobody notices — which secret a given entry produces.
 */

import { readFile, mkdir, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve as resolvePath, relative, isAbsolute, sep } from "node:path";
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
  isPartitionStub,
  parsePartitionRecord,
  emitEntryEvents,
  splitSecret,
  recoverSecret,
  buildSemanticRecords,
  searchSemanticRecords,
  semanticManifest,
  semanticStatus,
  isStaleSemanticIndex,
  type SemanticRecord,
  Bip85,
  type Entry,
  type PasswordPolicy,
  type VaultIndex,
} from "@seedpass/core";
import { AppDir, INDEX_FILENAME, DEFAULT_PBKDF2_ITERATIONS } from "../appDir.js";
import {
  loadConfig,
  mutateConfig,
  passwordPolicyFromConfig,
  DEFAULT_RELAYS,
  SETTABLE_CONFIG_KEYS,
  SENSITIVE_CONFIG_KEYS,
  ConfigValueError,
} from "../configFile.js";
import { openVault, saveVault, saveVaultHoldingLock, withVaultLock, atomicWrite } from "../vaultFile.js";
import { entryMetadata, refFor } from "../refs.js";
import { materializeSecret } from "../secrets.js";
import { createIndexBackup } from "../backups.js";
import { factorConfigured, tagForFactor, readPartition, partitionPath } from "../highRisk.js";
import {
  createJobProfile,
  currentPolicyStamp,
  listJobProfiles,
  revokeJobProfile,
  checkJobProfiles,
} from "../jobProfiles.js";
import {
  recordRecoveryDrill,
  listRecoveryDrills,
  verifyRecoveryDrills,
} from "../recoveryDrills.js";
import { HttpError, type ApiRequest, type ApiServer } from "./server.js";

/**
 * Route prefixes that exist in the Python API but are not implemented here.
 *
 * Currently EMPTY — every Python endpoint now has a TypeScript equivalent.
 * The mechanism is kept because the honest answer for an unimplemented
 * subsystem is 501 naming the feature, not 404: a 404 reads as "you typed the
 * path wrong" and sends an integrator hunting for a spelling mistake that is
 * not there.
 */
export const UNPORTED_PREFIXES: Array<{ prefix: string; feature: string }> = [];

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
  /**
   * Live high-risk partition key tag, or null when locked.
   *
   * In memory only — this value is the partition's encryption key, so writing
   * it anywhere would let a reader of that file open the partition without
   * the second factor.
   */
  highRiskTag: string | null;
  /** Unix seconds at which the high-risk unlock lapses. */
  highRiskExpiresAt: number;
  now: () => number;
}

/**
 * Replace a high-risk stub with its real record, or refuse.
 *
 * A stub carries only kind/label/archived, so deriving from one produces the
 * wrong secret rather than an error — which is why this refuses loudly
 * instead of falling through.
 */
async function hydratePartitionedFor(
  ctx: ApiContext,
  id: string,
  entry: Entry,
): Promise<Entry> {
  if (!isPartitionStub(entry)) return entry;
  const live = ctx.highRiskTag !== null && ctx.highRiskExpiresAt > ctx.now() / 1000;
  if (!live) {
    ctx.highRiskTag = null;
    throw new HttpError(
      423,
      `entry ${id} is in the high-risk partition, which is locked. ` +
        `POST /api/v1/high-risk/unlock with the factor first.`,
    );
  }
  const partition = await readPartition(profileDir(ctx), ctx.highRiskTag!);
  const full = partition[String(entry["partition_ref"] ?? id)];
  if (!full) {
    throw new HttpError(
      409,
      `entry ${id} points at a high-risk record that is not in the partition file`,
    );
  }
  // Validated, not asserted: this record is about to become a secret. A
  // HighRiskError here is a 409 like the missing-record case above -- the
  // request is fine, the stored data is not what it claims to be.
  try {
    return parsePartitionRecord(id, full);
  } catch (e) {
    throw new HttpError(409, (e as Error).message);
  }
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
    // Snapshot before mutating so the index0 differ sees what changed.
    const before = structuredClone(vault.index.entries) as Record<string, unknown>;
    const out = await fn(vault.index);
    try {
      const updated = emitEntryEvents(vault.index, {
        before,
        after: vault.index.entries,
        fingerprintDir: profileDir(ctx),
        now: Math.floor(ctx.now() / 1000),
      });
      (vault.index)["_system"] = updated["_system"];
    } catch {
      // Derived state; never fail a committed write over it.
    }
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
  // `relative`, not string prefixes. The previous check was
  // `target.startsWith(root + "/")` with a hardcoded forward slash, which on
  // Windows never matched anything: resolve() returns
  // `C:\profile\file.txt` and the comparison asked for `C:\profile/`. It
  // failed CLOSED, so nothing leaked — it simply refused every path,
  // including the legitimate ones, which meant document export and import
  // did not work on Windows at all. Found the first time this suite ran
  // there.
  //
  // A path inside root has a relative form that is neither empty-with-`..`
  // nor absolute; that holds on every platform and needs no separator of our
  // own choosing.
  const rel = relative(root, target);
  if (rel !== "" && (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel))) {
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
        const e = entry;
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
      const stub = vault.index.entries[id];
      if (!stub) throw new HttpError(404, "Not found");
      const entry = await hydratePartitionedFor(ctx, id, stub);
      const timestamp = optInt(req.query.get("at") ?? undefined, "at");
      const config = await loadConfig(profileDir(ctx), mnemonic);
      const secret = materializeSecret(vault.index, id, entry, mnemonic, {
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
    if (SENSITIVE_CONFIG_KEYS.has(key)) {
      // Never hand back a credential verifier over the wire, even to an
      // authenticated caller: it is offline-crackable and nothing legitimate
      // needs it. Answers with a placeholder rather than Python's 403 so a
      // client can tell "exists but withheld" from "no such key" — the value
      // is withheld either way.
      return { json: { key, value: "<redacted>" } };
    }
    return { json: { key, value: config[key] ?? null } };
  });

  server.route("PUT", "/api/v1/config/:key", async (req) => {
    const mnemonic = requireUnlocked(ctx);
    const key = req.params["key"]!;
    if (SENSITIVE_CONFIG_KEYS.has(key)) {
      // 403, matching Python. These are credential verifiers, not settings.
      throw new HttpError(403, `${key} is not settable through the API`);
    }
    // Unknown keys are refused rather than stored. This route used to accept
    // any key at all, so a typo became a permanent config entry that nothing
    // ever read, while the API answered ok and the setting never moved.
    const normalize = Object.prototype.hasOwnProperty.call(SETTABLE_CONFIG_KEYS, key)
      ? SETTABLE_CONFIG_KEYS[key]
      : undefined;
    if (!normalize) throw new HttpError(400, "Unknown key");
    const body = bodyObject(req);
    if (!("value" in body)) throw new HttpError(400, "value is required");
    let value: unknown;
    try {
      value = normalize(body["value"]);
    } catch (e) {
      if (e instanceof ConfigValueError) throw new HttpError(400, e.message);
      throw e;
    }
    await mutateConfig(profileDir(ctx), mnemonic, (config) => {
      config[key] = value;
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

  server.route(
    "GET",
    "/api/v1/totp",
    async (req) => {
      // A live TOTP code authenticates. Python gates this on the master
      // password (`_require_password` in api.py) and this port did not, so a
      // leaked bearer token yielded working second factors for every TOTP
      // entry in the vault. Found by the route-table invariant test below,
      // which exists because mutation testing showed the gating was
      // structurally unenforced.
      await requirePassword(ctx, req);
      const mnemonic = requireUnlocked(ctx);
    const vault = await readVault(ctx);
    const now = Math.floor(ctx.now() / 1000);
    const codes = Object.entries(vault.index.entries)
      .filter(([, e]) => String((e)["kind"] ?? "") === "totp")
      .map(([id, e]) => {
        const entry = e;
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
    },
    { requiresPassword: true },
  );

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
        .filter(([, e]) => String((e)["kind"] ?? "") === "totp")
        .map(([, e]) => {
          const entry = e;
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
      const wrapper = await exportBackup(vault.index, {
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
      const e = entry;
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

  // -------------------------------------------------------------- high risk

  /**
   * The high-risk unlock lives on the ApiContext, in memory, for exactly the
   * reason the CLI keeps it in the agent: the partition key tag IS the
   * partition's encryption key, so persisting it would let anything that can
   * read the directory open the partition without the second factor.
   */
  server.route("GET", "/api/v1/high-risk/status", async () => {
    return {
      json: {
        fingerprint: ctx.fingerprint,
        configured: factorConfigured(ctx.appDir.root),
        unlocked: ctx.highRiskTag !== null && ctx.highRiskExpiresAt > ctx.now() / 1000,
        expires_at: ctx.highRiskTag !== null ? ctx.highRiskExpiresAt : null,
        partition_exists: existsSync(partitionPath(profileDir(ctx))),
      },
    };
  });

  server.route(
    "POST",
    "/api/v1/high-risk/unlock",
    async (req) => {
      // Password-gated on top of the bearer token, like every other route
      // that reaches secrets — and then the FACTOR on top of that. The whole
      // point of the partition is that the master password alone is not
      // enough for these kinds.
      await requirePassword(ctx, req);
      const factor = req.headers["x-seedpass-high-risk-factor"];
      if (!factor) {
        throw new HttpError(
          401,
          "the high-risk factor is required in the X-SeedPass-High-Risk-Factor header",
        );
      }
      if (!factorConfigured(ctx.appDir.root)) {
        throw new HttpError(409, "high_risk_factor_not_configured");
      }
      const ttl = optInt(bodyObject(req)["ttl"], "ttl") ?? 300;
      let tag: string;
      try {
        tag = await tagForFactor(ctx.appDir.root, factor);
      } catch {
        // One reason for every factor failure: a caller must not be able to
        // tell "wrong factor" from "corrupt envelope" by probing.
        throw new HttpError(401, "high_risk_factor_invalid");
      }
      ctx.highRiskTag = tag;
      ctx.highRiskExpiresAt = Math.floor(ctx.now() / 1000 + ttl);
      return { json: { status: "unlocked", expires_at: ctx.highRiskExpiresAt } };
    },
    { requiresPassword: true },
  );

  server.route("POST", "/api/v1/high-risk/lock", async () => {
    const was = ctx.highRiskTag !== null;
    ctx.highRiskTag = null;
    ctx.highRiskExpiresAt = 0;
    return { json: { status: "ok", locked: was } };
  });

  // --------------------------------------------------------------- semantic

  const semanticDir = (): string => join(profileDir(ctx), "semantic_index");
  const semanticRecordsPath = (): string => join(semanticDir(), "records.json");
  const semanticManifestPath = (): string => join(semanticDir(), "manifest.json");

  async function readSemanticManifest(): Promise<Record<string, unknown>> {
    if (!existsSync(semanticManifestPath())) return {};
    try {
      return JSON.parse(await readFile(semanticManifestPath(), "utf8")) as Record<string, unknown>;
    } catch {
      return {};
    }
  }

  /**
   * Delete an index written before secrets stopped being indexed.
   *
   * Such a file holds stored secrets in the clear, and fixing the writer does
   * not rewrite what is already on disk. Deleting is safe — it is a derived
   * cache — and serving results from it would mean serving results derived
   * from secrets it should never have held.
   */
  async function purgeStaleSemantic(): Promise<void> {
    if (!isStaleSemanticIndex(await readSemanticManifest())) return;
    for (const path of [semanticRecordsPath(), semanticManifestPath()]) {
      if (existsSync(path)) await rm(path, { force: true });
    }
  }

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
    await purgeStaleSemantic();
    const manifest = await readSemanticManifest();
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
    await purgeStaleSemantic();
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

  // ---------------------------------------------------------- job profiles

  server.route("GET", "/api/v1/agent/job-profiles", async () => {
    return { json: await listJobProfiles(ctx.appDir.root) };
  });

  server.route("POST", "/api/v1/agent/job-profiles", async (req) => {
    const body = bodyObject(req);
    try {
      const record = await createJobProfile(ctx.appDir.root, {
        jobId: str(body["id"] ?? body["job_id"], "id"),
        fingerprint: String(body["fingerprint"] ?? ctx.fingerprint),
        query: str(body["query"], "query"),
        ...(typeof body["auth_broker"] === "string" && { authBroker: body["auth_broker"] }),
        ...(typeof body["schedule"] === "string" && { schedule: body["schedule"] }),
        ...(typeof body["description"] === "string" && { description: body["description"] }),
        policyStamp: await currentPolicyStamp(ctx.appDir.root),
        leaseOnly: Boolean(body["lease_only"]),
        leaseTtl: optInt(body["lease_ttl"], "lease_ttl") ?? 0,
        leaseUses: optInt(body["lease_uses"], "lease_uses") ?? 0,
        reveal: Boolean(body["reveal"]),
      });
      return { status: 201, json: record };
    } catch (e) {
      // job_exists / job_id_required are caller errors, not server faults.
      throw new HttpError(400, (e as Error).message);
    }
  });

  server.route("DELETE", "/api/v1/agent/job-profiles/:job_id", async (req) => {
    const jobId = req.params["job_id"]!;
    if (!(await revokeJobProfile(ctx.appDir.root, jobId))) {
      throw new HttpError(404, `no active job profile ${jobId}`);
    }
    return { json: { status: "ok", revoked: jobId } };
  });

  server.route("GET", "/api/v1/agent/job-profiles/check", async () => {
    const checks = await checkJobProfiles(
      ctx.appDir.root,
      await currentPolicyStamp(ctx.appDir.root),
    );
    return {
      json: {
        checks,
        // Surfaced as a field rather than a status code: the request
        // succeeded, and it is the ANSWER that is the warning.
        stale: checks.filter((c) => !c.policy_current).map((c) => c.id),
      },
    };
  });

  // -------------------------------------------------------- recovery split

  server.route(
    "POST",
    "/api/v1/agent/recovery/split",
    async (req) => {
      // The thing being split is typically a parent seed, so this is gated
      // like every other plaintext route and returns shares exactly once.
      await requirePassword(ctx, req);
      const body = bodyObject(req);
      try {
        const shares = splitSecret(str(body["secret"], "secret"), {
          totalShares: optInt(body["total_shares"], "total_shares") ?? 0,
          threshold: optInt(body["threshold"], "threshold") ?? 0,
          ...(typeof body["label"] === "string" && { label: body["label"] }),
        });
        return { json: { shares } };
      } catch (e) {
        throw new HttpError(400, (e as Error).message);
      }
    },
    { requiresPassword: true },
  );

  server.route(
    "POST",
    "/api/v1/agent/recovery/recover",
    async (req) => {
      await requirePassword(ctx, req);
      const body = bodyObject(req);
      const shares = body["shares"];
      if (!Array.isArray(shares)) throw new HttpError(400, "shares must be an array");
      try {
        return { json: { secret: recoverSecret(shares.map((s) => String(s))) } };
      } catch (e) {
        // Reason strings are the contract here (insufficient_shares,
        // invalid_share_checksum, ...), so they pass through unchanged.
        throw new HttpError(400, (e as Error).message);
      }
    },
    { requiresPassword: true },
  );

  server.route("POST", "/api/v1/agent/recovery/drill", async (req) => {
    const body = bodyObject(req);
    const record = await recordRecoveryDrill(ctx.appDir.root, {
      fingerprint: ctx.fingerprint,
      backupPath: str(body["backup_path"], "backup_path"),
      simulated: Boolean(body["simulated"]),
      expectedMaxAgeDays: optInt(body["expected_max_age_days"], "expected_max_age_days") ?? null,
      now: ctx.now(),
    });
    return { json: record };
  });

  server.route("GET", "/api/v1/agent/recovery/drills", async (req) => {
    const limit = optInt(req.query.get("limit") ?? undefined, "limit") ?? 20;
    return { json: await listRecoveryDrills(ctx.appDir.root, { limit }) };
  });

  server.route("POST", "/api/v1/agent/recovery/drills/verify", async () => {
    return { json: await verifyRecoveryDrills(ctx.appDir.root) };
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
