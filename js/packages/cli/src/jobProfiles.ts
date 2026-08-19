/**
 * Agent job profiles — parity with src/seedpass/core/agent_job.py.
 *
 * A job profile is a named, stored description of an unattended retrieval:
 * which profile, which entry query, where the credential comes from, and
 * under which policy. It is configuration, not a credential — running one
 * still requires everything an interactive run requires.
 *
 * The one security-relevant field is `policy_stamp`: a hash of the policy in
 * force when the profile was created. `checkJobProfiles` reports profiles
 * whose stamp no longer matches, so a policy that was tightened after a job
 * was set up does not leave the job quietly running under the old rules.
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { sha256Hex, utf8 } from "@seedpass/core";
import { atomicWrite, withVaultLock } from "./vaultFile.js";

export const JOB_STORE_VERSION = 1;
export const JOB_STORE_FILENAME = "agent_jobs.json";

export interface JobProfile {
  id: string;
  fingerprint: string;
  query: string;
  auth_broker: string;
  broker_service: string;
  broker_account: string;
  broker_command: string | null;
  policy_binding: string;
  policy_stamp: string;
  schedule: string;
  description: string;
  host_binding: string;
  lease_only: boolean;
  lease_ttl: number;
  lease_uses: number;
  reveal: boolean;
  created_at_utc: string;
  revoked_at_utc: string | null;
}

interface JobStore {
  version: number;
  jobs: JobProfile[];
}

export function jobStorePath(appRoot: string): string {
  return join(appRoot, JOB_STORE_FILENAME);
}

function emptyStore(): JobStore {
  return { version: JOB_STORE_VERSION, jobs: [] };
}

async function loadStore(path: string): Promise<JobStore> {
  if (!existsSync(path)) return emptyStore();
  try {
    const data = JSON.parse(await readFile(path, "utf8"));
    if (typeof data !== "object" || data === null || !Array.isArray(data.jobs)) {
      return emptyStore();
    }
    return data as JobStore;
  } catch {
    // A corrupt store reads as empty: no profile resolves, which fails closed.
    return emptyStore();
  }
}

async function mutateStore<T>(path: string, fn: (store: JobStore) => T): Promise<T> {
  return withVaultLock(path, async () => {
    const store = await loadStore(path);
    const result = fn(store);
    await atomicWrite(path, utf8(JSON.stringify(store, null, 2)));
    return result;
  });
}

export async function listJobProfiles(
  appRoot: string,
  options: { includeRevoked?: boolean } = {},
): Promise<JobProfile[]> {
  const jobs = (await loadStore(jobStorePath(appRoot))).jobs;
  if (options.includeRevoked) return jobs;
  return jobs.filter((j) => !j.revoked_at_utc);
}

export async function getJobProfile(
  appRoot: string,
  jobId: string,
): Promise<JobProfile | null> {
  const target = String(jobId).trim();
  if (!target) return null;
  const jobs = (await loadStore(jobStorePath(appRoot))).jobs;
  return jobs.find((j) => String(j.id) === target) ?? null;
}

export interface CreateJobProfileInput {
  jobId: string;
  fingerprint: string;
  query: string;
  authBroker?: string;
  brokerService?: string;
  brokerAccount?: string;
  brokerCommand?: string | null;
  policyBinding?: string;
  policyStamp?: string;
  schedule?: string;
  description?: string;
  hostBinding?: string;
  leaseOnly?: boolean;
  leaseTtl?: number;
  leaseUses?: number;
  reveal?: boolean;
  now?: number;
}

export async function createJobProfile(
  appRoot: string,
  input: CreateJobProfileInput,
): Promise<JobProfile> {
  const jobId = String(input.jobId).trim();
  if (!jobId) throw new Error("job_id_required");
  if (await getJobProfile(appRoot, jobId)) throw new Error("job_exists");

  const record: JobProfile = {
    id: jobId,
    fingerprint: String(input.fingerprint).trim(),
    query: String(input.query),
    auth_broker: String(input.authBroker ?? "env").trim().toLowerCase(),
    broker_service: String(input.brokerService ?? "seedpass").trim(),
    broker_account: String(input.brokerAccount ?? "").trim(),
    // Empty means "not set", not an empty command, matching Python's
    // `str(...) or None`.
    broker_command: String(input.brokerCommand ?? "").trim() || null,
    policy_binding: String(input.policyBinding ?? "").trim() || "default",
    policy_stamp: String(input.policyStamp ?? "").trim(),
    schedule: String(input.schedule ?? "").trim(),
    description: String(input.description ?? "").trim(),
    host_binding: String(input.hostBinding ?? "").trim(),
    lease_only: Boolean(input.leaseOnly ?? false),
    lease_ttl: Number(input.leaseTtl ?? 0),
    lease_uses: Number(input.leaseUses ?? 0),
    reveal: Boolean(input.reveal ?? false),
    created_at_utc: new Date(input.now ?? Date.now()).toISOString(),
    revoked_at_utc: null,
  };
  await mutateStore(jobStorePath(appRoot), (store) => {
    store.version ??= JOB_STORE_VERSION;
    store.jobs.push(record);
  });
  return record;
}

export async function revokeJobProfile(
  appRoot: string,
  jobId: string,
  options: { now?: number } = {},
): Promise<boolean> {
  const target = String(jobId).trim();
  if (!target) return false;
  const stamp = new Date(options.now ?? Date.now()).toISOString();
  return mutateStore(jobStorePath(appRoot), (store) => {
    for (const job of store.jobs) {
      if (String(job.id) === target && !job.revoked_at_utc) {
        job.revoked_at_utc = stamp;
        return true;
      }
    }
    return false;
  });
}

export interface JobProfileCheck {
  id: string;
  fingerprint: string;
  /** False when the policy has changed since this profile was created. */
  policy_current: boolean;
  stored_policy_stamp: string;
  current_policy_stamp: string;
}

/**
 * Report profiles whose recorded policy stamp no longer matches.
 *
 * A job created under a permissive policy keeps its stamp; if the policy is
 * later tightened, the mismatch is the signal that the job should be
 * reviewed rather than left running under assumptions that no longer hold.
 * Revoked profiles are excluded — they are not running.
 */
export async function checkJobProfiles(
  appRoot: string,
  currentPolicyStamp: string,
): Promise<JobProfileCheck[]> {
  const jobs = await listJobProfiles(appRoot);
  return jobs.map((job) => ({
    id: job.id,
    fingerprint: job.fingerprint,
    policy_current: job.policy_stamp === currentPolicyStamp,
    stored_policy_stamp: job.policy_stamp,
    current_policy_stamp: currentPolicyStamp,
  }));
}

export const POLICY_FILENAME = "agent_policy.json";

export function policyPath(appRoot: string): string {
  return join(appRoot, POLICY_FILENAME);
}

/**
 * Canonical JSON matching Python's
 * `json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=True)`.
 *
 * `ensure_ascii` is the part that is easy to miss: Python escapes every
 * non-ASCII character as \uXXXX, JSON.stringify does not. A policy with a
 * non-ASCII value would otherwise hash differently in the two
 * implementations, and the stamp would appear to have changed when nothing
 * had.
 */
function canonicalAscii(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (typeof value !== "string") return encoded;
    return encoded.replace(/[\u007f-\uffff]/g, (c) =>
      `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
  }
  if (Array.isArray(value)) return `[${value.map(canonicalAscii).join(",")}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys
    .map(
      (k) => `${canonicalAscii(k)}:${canonicalAscii((value as Record<string, unknown>)[k])}`,
    )
    .join(",")}}`;
}

/**
 * Hash of the agent policy currently in force.
 *
 * Reads the same `agent_policy.json` Python writes, so a policy managed from
 * either implementation produces the same stamp. An absent file hashes the
 * empty policy rather than throwing: a job created with no policy in place is
 * legitimate, and it will show as stale the moment one appears — which is the
 * correct signal.
 */
export async function currentPolicyStamp(appRoot: string): Promise<string> {
  let policy: unknown = {};
  const path = policyPath(appRoot);
  if (existsSync(path)) {
    try {
      policy = JSON.parse(await readFile(path, "utf8"));
    } catch {
      // An unreadable policy is not "no policy": treat it as its own state so
      // every job reads as stale rather than silently matching the empty one.
      return sha256Hex(utf8("seedpass:unreadable-policy"));
    }
  }
  return sha256Hex(utf8(canonicalAscii(policy)));
}
