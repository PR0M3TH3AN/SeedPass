/**
 * Detect entries that share a BIP-85 derivation coordinate.
 *
 * Three entry kinds derive from the same BIP-85 application, app 32, at the
 * entry's derivation index:
 *
 *   ssh@N       -> 32 bytes of m/83696968'/32'/N'
 *   pgp@N       -> 32 bytes of m/83696968'/32'/N'   (the SAME 32 bytes)
 *   password@N  -> 64 bytes of m/83696968'/32'/N', then PBKDF2
 *
 * So an SSH entry and a PGP entry at the same index are byte-for-byte the
 * same Ed25519 private key, and a password entry at that index takes the
 * SSH/PGP private key as the first half of its own input entropy. The
 * password itself stays safe -- 256 unknown bits remain and PBKDF2 is
 * one-way -- but this is not key separation, and SSH keys are exactly the
 * sort of secret that gets exported to a server or uploaded to a forge.
 *
 * Neither implementation can CREATE this state: a derivation index is the
 * entry's vault id, ids are unique, and the persisted watermark stops them
 * being reused after deletion. It arrives as data -- an imported backup, a
 * vault written by another tool, or a sync merge -- and both implementations
 * will then faithfully derive identical keys from it.
 *
 * Fixing the derivation itself means domain-separating the three uses behind
 * a version, so existing entries keep deriving as they do; that is a protocol
 * change for both implementations and is tracked in TODO.md. Until then, the
 * defensible thing is to notice and say so, rather than hand over two
 * "different" keys that are the same key.
 */

import type { VaultIndex } from "../schema/entries.js";

/** Entry kinds that derive from BIP-85 app 32 at their derivation index. */
export const APP32_KINDS = ["ssh", "pgp", "password"] as const;

export type App32Kind = (typeof APP32_KINDS)[number];

export interface DerivationCollision {
  /** The shared BIP-85 app-32 index. */
  index: number;
  /** Colliding entries, by vault id, in id order. */
  entries: Array<{ id: string; kind: App32Kind; label: string }>;
  /**
   * `identical-key` — ssh and pgp at this index are literally the same
   * Ed25519 private key. `entropy-prefix` — a password shares its input
   * entropy prefix with an ssh or pgp key here.
   */
  severity: "identical-key" | "entropy-prefix";
  /** One line fit to show a user. */
  message: string;
}

function derivationIndexOf(id: string, entry: Record<string, unknown>): number | null {
  // The derivation index is the entry's own `index` when it carries one, and
  // otherwise its vault id -- which is what both implementations pass to
  // BIP-85 for password entries.
  const explicit = entry["index"];
  if (typeof explicit === "number" && Number.isInteger(explicit) && explicit >= 0) {
    return explicit;
  }
  const fromId = Number(id);
  return Number.isInteger(fromId) && fromId >= 0 ? fromId : null;
}

/**
 * Entries sharing an app-32 derivation index, worst first.
 *
 * Archived entries are included: archiving hides an entry from listings, it
 * does not change what its index derives, and the key may already be in use
 * somewhere.
 */
export function findDerivationCollisions(index: VaultIndex): DerivationCollision[] {
  const byIndex = new Map<number, Array<{ id: string; kind: App32Kind; label: string }>>();

  for (const [id, raw] of Object.entries(index.entries)) {
    const entry = raw as unknown as Record<string, unknown>;
    const kind = String(entry["kind"] ?? entry["type"] ?? "");
    if (!(APP32_KINDS as readonly string[]).includes(kind)) continue;
    const derivationIndex = derivationIndexOf(id, entry);
    if (derivationIndex === null) continue;
    const bucket = byIndex.get(derivationIndex) ?? [];
    bucket.push({ id, kind: kind as App32Kind, label: String(entry["label"] ?? "") });
    byIndex.set(derivationIndex, bucket);
  }

  const collisions: DerivationCollision[] = [];
  for (const [derivationIndex, bucket] of byIndex) {
    if (bucket.length < 2) continue;
    const kinds = new Set(bucket.map((e) => e.kind));
    // Two entries of the SAME kind at one index are the same secret by
    // definition and are not a key-separation failure -- that is a duplicate,
    // which the id rules already prevent. Only a cross-kind clash matters.
    if (kinds.size < 2) continue;

    const sorted = [...bucket].sort((a, b) => a.id.localeCompare(b.id));
    const identical = kinds.has("ssh") && kinds.has("pgp");
    const labels = sorted.map((e) => `${e.kind} '${e.label}' (#${e.id})`).join(" and ");

    collisions.push({
      index: derivationIndex,
      entries: sorted,
      severity: identical ? "identical-key" : "entropy-prefix",
      message: identical
        ? `${labels} derive the SAME private key (BIP-85 app 32, index ` +
          `${derivationIndex}). They are one key with two labels, not two keys.`
        : `${labels} share BIP-85 app-32 index ${derivationIndex}: the key ` +
          `material of one is the entropy prefix of the other.`,
    });
  }

  // Identical keys first, then by index, so the worst case is what a caller
  // showing only the first line will show.
  return collisions.sort(
    (a, b) =>
      Number(b.severity === "identical-key") - Number(a.severity === "identical-key") ||
      a.index - b.index,
  );
}
