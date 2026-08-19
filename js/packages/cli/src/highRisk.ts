/**
 * High-risk partition: factor configuration and profile-level access.
 *
 * The on-disk formats (partition file, key envelope) live in core and are
 * byte-compatible with Python, so a partition created by either
 * implementation opens in the other. What lives here is the local plumbing:
 * where the envelope sits, and how an unlock session is held.
 *
 * ONE DELIBERATE DIVERGENCE, and it is the whole reason this module exists
 * rather than a straight port. Python records an unlock session in
 * `agent_high_risk_unlock.json`, and that record contains the
 * `partition_key_tag` — from which the partition file's encryption key is
 * derived. So for the life of any Python unlock session, the high-risk
 * partition is decryptable from disk alone, with no factor, by anything that
 * can read the app directory. That voids the guarantee the partition exists
 * to provide: these are precisely the secrets deemed to need a SECOND factor.
 *
 * The TypeScript port holds the unlocked tag in the session agent's memory
 * instead, next to the parent seeds it already holds, with the same TTL
 * discipline. Nothing derived from the factor is ever written to disk. This
 * changes no file format and no interop — only where the live session lives.
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  buildPartitionEnvelope,
  decryptPartition,
  encryptPartition,
  generatePartitionKey,
  partitionKeyTag,
  unwrapPartitionKey,
  HighRiskError,
  PARTITION_FILENAME,
  utf8,
} from "@seedpass/core";
import { atomicWrite } from "./vaultFile.js";

export const ENVELOPE_FILENAME = "agent_high_risk_partition.key.enc.json";

export function envelopePath(appRoot: string): string {
  return join(appRoot, ENVELOPE_FILENAME);
}

export function partitionPath(profileDir: string): string {
  return join(profileDir, PARTITION_FILENAME);
}

/** Has a high-risk factor been configured for this installation? */
export function factorConfigured(appRoot: string): boolean {
  return existsSync(envelopePath(appRoot));
}

/**
 * Set (or replace) the high-risk factor.
 *
 * Replacing the factor generates a NEW partition key, which makes any
 * existing partition file undecryptable — so callers must re-encrypt an
 * existing partition under the new key, or refuse. `setFactor` deliberately
 * does not do that silently: losing a partition is losing secrets.
 */
export async function setFactor(appRoot: string, factor: string): Promise<string> {
  if (!factor) throw new Error("the high-risk factor cannot be empty");
  const partitionKey = generatePartitionKey();
  const envelope = await buildPartitionEnvelope(partitionKey, factor);
  await atomicWrite(envelopePath(appRoot), utf8(JSON.stringify(envelope, null, 2)));
  return partitionKeyTag(partitionKey);
}

async function readEnvelope(appRoot: string): Promise<Record<string, unknown>> {
  const path = envelopePath(appRoot);
  if (!existsSync(path)) {
    throw new HighRiskError("high_risk_partition_not_configured");
  }
  try {
    return JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  } catch {
    throw new HighRiskError("invalid_partition_envelope");
  }
}

/**
 * Turn the factor into the partition key tag.
 *
 * The returned value is key material, not an identifier — see
 * `partitionKeyTag` in core. Hold it in memory and drop it; never persist it.
 */
export async function tagForFactor(appRoot: string, factor: string): Promise<string> {
  return partitionKeyTag(await unwrapPartitionKey(await readEnvelope(appRoot), factor));
}

/** Is this the configured factor? Answers without disclosing the tag. */
export async function verifyFactor(appRoot: string, factor: string): Promise<boolean> {
  try {
    await tagForFactor(appRoot, factor);
    return true;
  } catch {
    return false;
  }
}

/** Read a profile's partition, or `{}` when it has none. */
export async function readPartition(
  profileDir: string,
  tag: string,
): Promise<Record<string, Record<string, unknown>>> {
  const path = partitionPath(profileDir);
  if (!existsSync(path)) return {};
  return decryptPartition(new Uint8Array(await readFile(path)), tag);
}

/** Write a profile's partition at 0600. */
export async function writePartition(
  profileDir: string,
  tag: string,
  entries: Record<string, Record<string, unknown>>,
): Promise<string> {
  const path = partitionPath(profileDir);
  await atomicWrite(path, await encryptPartition(entries, tag));
  return path;
}
