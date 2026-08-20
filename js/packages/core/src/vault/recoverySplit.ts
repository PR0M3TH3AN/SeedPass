/**
 * Threshold secret sharing — parity with src/seedpass/core/agent_recovery.py.
 *
 * Shamir over GF(257), one polynomial per secret byte, shares encoded as
 * `sprec1:<label>:<threshold>:<total>:<index>:<digest>:<payload>`. The prime
 * is 257 rather than 256 because 256 is not prime; a secret byte is 0..255 so
 * it embeds injectively, and a share value needs two bytes because it can be
 * 256.
 *
 * COEFFICIENTS MUST BE RANDOM. Python originally derived every coefficient by
 * HMAC-ing the secret, which made the whole share set a deterministic
 * function of it — and Shamir's defining property is that a sub-threshold set
 * of shares is information-theoretically independent of the secret. Deriving
 * them from the secret turns any single share into an offline verifier:
 * guess a secret, re-run the split, compare. That is fixed in Python and was
 * never done here. The share format is identical either way, and recovery is
 * pure Lagrange interpolation that never recomputes coefficients, so shares
 * from either implementation and either version interoperate.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { base64urlnopad } from "@scure/base";
import { bytesToHex, utf8 } from "../util/bytes.js";

export const SHARE_PREFIX = "sprec1";
/** GF(257). Share values need two bytes because 256 is representable. */
export const RECOVERY_PRIME = 257;
export const MAX_TOTAL_SHARES = 32;

export class RecoveryError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "RecoveryError";
  }
}

export interface ParsedShare {
  label: string;
  threshold: number;
  total: number;
  index: number;
  values: number[];
}

/** Modular inverse in GF(257) by Fermat's little theorem. */
function modInv(value: number): number {
  let result = 1;
  let base = ((value % RECOVERY_PRIME) + RECOVERY_PRIME) % RECOVERY_PRIME;
  // 257 is prime, so a^(p-2) == a^-1.
  let exponent = RECOVERY_PRIME - 2;
  while (exponent > 0) {
    if (exponent & 1) result = (result * base) % RECOVERY_PRIME;
    base = (base * base) % RECOVERY_PRIME;
    exponent >>= 1;
  }
  return result;
}

function evaluate(secretByte: number, coefficients: number[], x: number): number {
  let total = secretByte % RECOVERY_PRIME;
  let power = x % RECOVERY_PRIME;
  for (const coefficient of coefficients) {
    total = (total + coefficient * power) % RECOVERY_PRIME;
    power = (power * x) % RECOVERY_PRIME;
  }
  return total;
}

/**
 * Python encodes the payload with `base64.urlsafe_b64encode`, which PADS.
 * @scure's base64url also pads; base64urlnopad does not. Getting this wrong
 * produces a token Python rejects on checksum, so it is pinned here.
 */
function encodePayload(raw: Uint8Array): string {
  const unpadded = base64urlnopad.encode(raw);
  const remainder = unpadded.length % 4;
  return remainder === 0 ? unpadded : unpadded + "=".repeat(4 - remainder);
}

function decodePayload(payload: string): Uint8Array {
  return base64urlnopad.decode(payload.replace(/=+$/, ""));
}

/** Split `secret` into `totalShares` shares, any `threshold` of which recover it. */
export function splitSecret(
  secret: string,
  options: { totalShares: number; threshold: number; label?: string },
): string[] {
  const { totalShares, threshold } = options;
  const secretBytes = utf8(secret);
  // Reason strings match Python's so callers can branch identically.
  if (threshold < 2) throw new RecoveryError("threshold_must_be_at_least_2");
  if (totalShares < threshold) throw new RecoveryError("total_shares_must_be_gte_threshold");
  if (totalShares > MAX_TOTAL_SHARES) throw new RecoveryError("total_shares_too_large");
  if (secretBytes.length === 0) throw new RecoveryError("secret_required");
  const label = (options.label ?? "default").trim() || "default";

  // One random polynomial per byte, drawn ONCE. Drawing per share would put
  // the points on different polynomials and recovery would silently return
  // rubbish rather than fail.
  const coefficients: number[][] = [];
  for (let i = 0; i < secretBytes.length; i++) {
    const row: number[] = [];
    for (let p = 1; p < threshold; p++) row.push(randomBelowPrime());
    coefficients.push(row);
  }

  const shares: string[] = [];
  for (let x = 1; x <= totalShares; x++) {
    const raw = new Uint8Array(secretBytes.length * 2);
    for (let i = 0; i < secretBytes.length; i++) {
      const value = evaluate(secretBytes[i]!, coefficients[i]!, x);
      raw[i * 2] = (value >> 8) & 0xff;
      raw[i * 2 + 1] = value & 0xff;
    }
    const digest = bytesToHex(sha256(raw)).slice(0, 16);
    shares.push(
      `${SHARE_PREFIX}:${label}:${threshold}:${totalShares}:${x}:${digest}:${encodePayload(raw)}`,
    );
  }
  return shares;
}

/**
 * Uniform in [0, 257) without modulo bias.
 *
 * 257 does not divide 2^16, so taking a 16-bit draw mod 257 would favour the
 * low values. Rejection sampling keeps the distribution flat, which matters:
 * biased coefficients leak information about the polynomial.
 */
function randomBelowPrime(): number {
  const limit = Math.floor(65536 / RECOVERY_PRIME) * RECOVERY_PRIME;
  const buffer = new Uint16Array(1);
  for (;;) {
    globalThis.crypto.getRandomValues(buffer);
    if (buffer[0]! < limit) return buffer[0]! % RECOVERY_PRIME;
  }
}

export function parseShare(token: string): ParsedShare {
  // maxsplit 6 in Python, so the payload may itself contain colons.
  const parts = String(token).split(":");
  if (parts.length < 7 || parts[0] !== SHARE_PREFIX) {
    throw new RecoveryError("invalid_share_format");
  }
  const [, label, thresholdRaw, totalRaw, indexRaw, digest] = parts;
  const payload = parts.slice(6).join(":");
  const threshold = Number(thresholdRaw);
  const total = Number(totalRaw);
  const index = Number(indexRaw);
  if (!Number.isInteger(threshold) || !Number.isInteger(total) || !Number.isInteger(index)) {
    throw new RecoveryError("invalid_share_metadata");
  }
  let raw: Uint8Array;
  try {
    raw = decodePayload(payload);
  } catch {
    throw new RecoveryError("invalid_share_payload");
  }
  if (bytesToHex(sha256(raw)).slice(0, 16) !== digest) {
    throw new RecoveryError("invalid_share_checksum");
  }
  if (raw.length % 2 !== 0) throw new RecoveryError("invalid_share_payload");
  const values: number[] = [];
  for (let i = 0; i < raw.length; i += 2) {
    const value = (raw[i]! << 8) | raw[i + 1]!;
    if (value < 0 || value >= RECOVERY_PRIME) throw new RecoveryError("invalid_share_value");
    values.push(value);
  }
  return { label: label!, threshold, total, index, values };
}

/** Recover the secret from at least `threshold` shares. */
export function recoverSecret(tokens: string[]): string {
  if (tokens.length === 0) throw new RecoveryError("shares_required");
  const parsed = tokens.map(parseShare);
  const first = parsed[0]!;
  const { label, threshold } = first;
  const expectedLength = first.values.length;
  const seen = new Set<number>();
  for (const share of parsed) {
    if (share.label !== label) throw new RecoveryError("share_label_mismatch");
    if (share.threshold !== threshold) throw new RecoveryError("share_threshold_mismatch");
    if (share.values.length !== expectedLength) throw new RecoveryError("share_length_mismatch");
    // Two shares at one x are the same point; using both would make the
    // interpolation singular rather than merely wrong.
    if (seen.has(share.index)) throw new RecoveryError("duplicate_share_index");
    seen.add(share.index);
  }
  if (parsed.length < threshold) throw new RecoveryError("insufficient_shares");

  const used = parsed.slice(0, threshold);
  const xs = used.map((s) => ((s.index % RECOVERY_PRIME) + RECOVERY_PRIME) % RECOVERY_PRIME);
  const out = new Uint8Array(expectedLength);
  for (let byteIndex = 0; byteIndex < expectedLength; byteIndex++) {
    const ys = used.map((s) => s.values[byteIndex]! % RECOVERY_PRIME);
    let secretValue = 0;
    for (let i = 0; i < threshold; i++) {
      let numerator = 1;
      let denominator = 1;
      for (let j = 0; j < threshold; j++) {
        if (i === j) continue;
        numerator = (numerator * (((-xs[j]! % RECOVERY_PRIME) + RECOVERY_PRIME) % RECOVERY_PRIME)) % RECOVERY_PRIME;
        denominator =
          (denominator * (((xs[i]! - xs[j]!) % RECOVERY_PRIME) + RECOVERY_PRIME)) % RECOVERY_PRIME;
      }
      const basis = (numerator * modInv(denominator)) % RECOVERY_PRIME;
      secretValue = (secretValue + ys[i]! * basis) % RECOVERY_PRIME;
    }
    // 256 is a legal field element but not a byte: it means these shares do
    // not describe a valid secret (wrong set, or tampering that survived the
    // per-share checksum).
    if (secretValue < 0 || secretValue > 255) {
      throw new RecoveryError("recovered_secret_out_of_range");
    }
    out[byteIndex] = secretValue;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(out);
}
