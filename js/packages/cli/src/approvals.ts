/**
 * Approval gates — parity with src/seedpass/core/agent_approval.py.
 *
 * An approval is a one-shot (or N-shot) authorization for a named dangerous
 * action, issued out of band and consumed at the moment the action runs. It
 * is the "someone deliberately said yes to this" record that sits between a
 * policy saying an action NEEDS approval and the action happening.
 *
 * Approvals are stored at the app level rather than per profile, matching
 * Python, and hold no secret material: an approval id is a capability to
 * perform an action that the caller must ALSO be otherwise authorized for.
 * It is not a credential on its own, which is why the store is readable
 * without unlocking anything.
 */

import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { atomicWrite, withVaultLock } from "./vaultFile.js";
import { utf8 } from "@seedpass/core";

export const APPROVAL_STORE_VERSION = 1;
export const APPROVAL_STORE_FILENAME = "agent_approvals.json";

/** Actions an approval may cover. Anything else is refused at issue time. */
export const VALID_APPROVAL_ACTIONS = [
  "export",
  "reveal_parent_seed",
  "private_key_retrieval",
] as const;

export type ApprovalAction = (typeof VALID_APPROVAL_ACTIONS)[number];

export interface ApprovalRecord {
  id: string;
  action: string;
  resource: string;
  issued_by: string;
  created_at_utc: string;
  expires_at_utc: string;
  uses_remaining: number;
  revoked_at_utc: string | null;
}

interface ApprovalStore {
  version: number;
  approvals: ApprovalRecord[];
}

function emptyStore(): ApprovalStore {
  return { version: APPROVAL_STORE_VERSION, approvals: [] };
}

export function approvalStorePath(appRoot: string): string {
  return join(appRoot, APPROVAL_STORE_FILENAME);
}

async function loadStore(path: string): Promise<ApprovalStore> {
  if (!existsSync(path)) return emptyStore();
  try {
    const data = JSON.parse(await readFile(path, "utf8"));
    if (typeof data !== "object" || data === null || !Array.isArray(data.approvals)) {
      return emptyStore();
    }
    return data as ApprovalStore;
  } catch {
    // A corrupt store reads as empty, which fails CLOSED: every approval
    // check then denies rather than accidentally allowing.
    return emptyStore();
  }
}

async function saveStore(path: string, store: ApprovalStore): Promise<void> {
  await atomicWrite(path, utf8(JSON.stringify(store, null, 2)));
}

/** Read-modify-write under a lock, so two agents cannot both spend one use. */
async function mutateStore<T>(
  path: string,
  fn: (store: ApprovalStore) => T | Promise<T>,
): Promise<T> {
  return withVaultLock(path, async () => {
    const store = await loadStore(path);
    const result = await fn(store);
    await saveStore(path, store);
    return result;
  });
}

export function isValidApprovalAction(action: string): action is ApprovalAction {
  return (VALID_APPROVAL_ACTIONS as readonly string[]).includes(action);
}

export async function issueApproval(
  appRoot: string,
  options: {
    action: string;
    ttlSeconds: number;
    uses: number;
    resource?: string;
    issuedBy?: string;
    now?: number;
  },
): Promise<ApprovalRecord> {
  if (!isValidApprovalAction(options.action)) {
    throw new Error(
      `unknown approval action '${options.action}' ` +
        `(expected one of ${VALID_APPROVAL_ACTIONS.join(", ")})`,
    );
  }
  if (!Number.isInteger(options.ttlSeconds) || options.ttlSeconds < 1) {
    throw new Error("ttl must be a positive integer number of seconds");
  }
  if (!Number.isInteger(options.uses) || options.uses < 1) {
    throw new Error("uses must be a positive integer");
  }
  const now = options.now ?? Date.now();
  const record: ApprovalRecord = {
    // 18 random bytes, like Python's token_urlsafe(18). The id is the whole
    // reference to this approval, so it must not be guessable.
    id: randomBytes(18).toString("base64url"),
    action: options.action,
    resource: options.resource ?? "*",
    issued_by: options.issuedBy ?? "manual",
    created_at_utc: new Date(now).toISOString(),
    expires_at_utc: new Date(now + options.ttlSeconds * 1000).toISOString(),
    uses_remaining: options.uses,
    revoked_at_utc: null,
  };
  await mutateStore(approvalStorePath(appRoot), (store) => {
    store.approvals.push(record);
  });
  return record;
}

export async function listApprovals(
  appRoot: string,
  options: { includeRevoked?: boolean } = {},
): Promise<ApprovalRecord[]> {
  const approvals = (await loadStore(approvalStorePath(appRoot))).approvals;
  if (options.includeRevoked) return approvals;
  return approvals.filter((a) => !a.revoked_at_utc);
}

export async function revokeApproval(
  appRoot: string,
  approvalId: string,
  options: { now?: number } = {},
): Promise<boolean> {
  const stamp = new Date(options.now ?? Date.now()).toISOString();
  return mutateStore(approvalStorePath(appRoot), (store) => {
    for (const record of store.approvals) {
      if (record.id === approvalId && !record.revoked_at_utc) {
        record.revoked_at_utc = stamp;
        return true;
      }
    }
    return false;
  });
}

/** Does this policy require an approval for `action`? */
export function approvalRequired(policy: Record<string, unknown>, action: string): boolean {
  const approvals = policy["approvals"];
  if (typeof approvals !== "object" || approvals === null) return false;
  const required = (approvals as Record<string, unknown>)["require_for"];
  if (!Array.isArray(required)) return false;
  const wanted = action.trim().toLowerCase();
  return required.some((v) => String(v).trim().toLowerCase() === wanted);
}

export interface ConsumeResult {
  ok: boolean;
  /** Machine-readable outcome, matching Python's strings exactly. */
  reason: string;
}

/**
 * Spend one use of an approval.
 *
 * Every failure mode gets its own reason, and the whole check runs under the
 * store lock so two callers cannot both spend the last use. The use is
 * decremented and persisted BEFORE the caller acts on the result — an
 * approval that was consumed but whose action then failed is the safe
 * direction to err.
 */
export async function consumeApproval(
  appRoot: string,
  options: { approvalId: string; action: string; resource?: string; now?: number },
): Promise<ConsumeResult> {
  const now = options.now ?? Date.now();
  const resource = options.resource ?? "*";
  return mutateStore(approvalStorePath(appRoot), (store) => {
    for (const record of store.approvals) {
      if (record.id !== options.approvalId) continue;
      if (record.revoked_at_utc) return { ok: false, reason: "approval_revoked" };
      if (String(record.action).toLowerCase() !== options.action.toLowerCase()) {
        return { ok: false, reason: "approval_action_mismatch" };
      }
      const recordResource = String(record.resource ?? "*");
      if (recordResource !== "*" && recordResource !== resource) {
        return { ok: false, reason: "approval_resource_mismatch" };
      }
      const expires = record.expires_at_utc;
      if (!expires || Date.parse(expires) <= now) {
        return { ok: false, reason: "approval_expired" };
      }
      const uses = Number(record.uses_remaining ?? 0);
      if (!Number.isFinite(uses) || uses <= 0) {
        return { ok: false, reason: "approval_exhausted" };
      }
      record.uses_remaining = uses - 1;
      return { ok: true, reason: "approval_consumed" };
    }
    return { ok: false, reason: "approval_not_found" };
  });
}
