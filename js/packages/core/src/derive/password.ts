/**
 * Deterministic password generation, versions 1 and 2.
 *
 * Parity target: src/seedpass/core/password_generation.py. v1 is frozen
 * forever — vault entries re-derive passwords on demand, so every branch
 * below (including the odd ones) must reproduce Python byte-for-byte. Do
 * not "fix" v1 behavior; a changed algorithm is a new version.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { Bip85 } from "./bip85.js";
import { be32, bigintFromBytes, utf8 } from "../util/bytes.js";

export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 128;
export const DEFAULT_PASSWORD_LENGTH = 16;
export const SAFE_SPECIAL_CHARS = "!@#$%^*-_+=?";
export const LEGACY_PASSWORD_GEN_VERSION = 1;
export const CURRENT_PASSWORD_GEN_VERSION = 2;

// Python string module constants (order matters for byte->char mapping)
const ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const ASCII_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ASCII_LETTERS = ASCII_LOWERCASE + ASCII_UPPERCASE;
const DIGITS = "0123456789";
const PUNCTUATION = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const AMBIGUOUS = "O0Il1";

export interface PasswordPolicy {
  minUppercase?: number;
  minLowercase?: number;
  minDigits?: number;
  minSpecial?: number;
  includeSpecialChars?: boolean;
  allowedSpecialChars?: string | null;
  specialMode?: string | null;
  excludeAmbiguous?: boolean;
}

interface ResolvedPolicy {
  minUppercase: number;
  minLowercase: number;
  minDigits: number;
  minSpecial: number;
  includeSpecialChars: boolean;
  allowedSpecialChars: string | null;
  specialMode: string | null;
  excludeAmbiguous: boolean;
}

function resolvePolicy(p: PasswordPolicy = {}): ResolvedPolicy {
  return {
    minUppercase: p.minUppercase ?? 2,
    minLowercase: p.minLowercase ?? 2,
    minDigits: p.minDigits ?? 2,
    minSpecial: p.minSpecial ?? 2,
    includeSpecialChars: p.includeSpecialChars ?? true,
    allowedSpecialChars: p.allowedSpecialChars ?? null,
    specialMode: p.specialMode ?? null,
    excludeAmbiguous: p.excludeAmbiguous ?? false,
  };
}

function stripAmbiguous(chars: string): string {
  return [...chars].filter((c) => !AMBIGUOUS.includes(c)).join("");
}

/** v1 byte stream: cycles dk with wraparound (a repeating pad — kept for parity). */
class DeterministicStream {
  private index = 0;
  constructor(private readonly dk: Uint8Array) {}

  getValue(): number {
    const value = this.dk[this.index % this.dk.length]!;
    this.index += 1;
    return value;
  }

  get currentIndex(): number {
    return this.index;
  }

  get length(): number {
    return this.dk.length;
  }
}

/** v2 unbounded stream: HMAC(dk, info || counter_be32) blocks on demand. */
class ExpandedStream {
  private block = new Uint8Array(0);
  private pos = 0;
  private counter = 0;

  constructor(
    private readonly key: Uint8Array,
    private readonly info: Uint8Array,
  ) {}

  getValue(): number {
    if (this.pos >= this.block.length) {
      const msg = new Uint8Array(this.info.length + 4);
      msg.set(this.info, 0);
      msg.set(be32(this.counter), this.info.length);
      this.block = hmac(sha256, this.key, msg);
      this.counter += 1;
      this.pos = 0;
    }
    return this.block[this.pos++]!;
  }
}

/** Uniform [0, maxExclusive) by rejection sampling (v2 only). */
function uniformIndex(stream: ExpandedStream, maxExclusive: number): number {
  if (maxExclusive <= 0) throw new Error("maxExclusive must be positive");
  if (maxExclusive > 256) throw new Error("single-byte ranges only");
  const limit = 256 - (256 % maxExclusive);
  for (;;) {
    const value = stream.getValue();
    if (value < limit) return value % maxExclusive;
  }
}

/** HMAC-SHA256-driven Fisher–Yates; j = int(digest) % (i+1) over the full 256-bit digest. */
function fisherYatesHmac(items: string[], key: Uint8Array): string[] {
  let counter = 0;
  for (let i = items.length - 1; i > 0; i--) {
    const digest = hmac(sha256, key, be32(counter));
    const j = Number(bigintFromBytes(digest) % BigInt(i + 1));
    const tmp = items[i]!;
    items[i] = items[j]!;
    items[j] = tmp;
    counter += 1;
  }
  return items;
}

interface ClassChars {
  uppercase: string;
  lowercase: string;
  digits: string;
  special: string;
}

function alphabets(policy: ResolvedPolicy): { allAllowed: string; allowedSpecial: string } {
  let letters = ASCII_LETTERS;
  let digits = DIGITS;
  if (policy.excludeAmbiguous) {
    letters = stripAmbiguous(letters);
    digits = stripAmbiguous(digits);
  }
  let allowedSpecial: string;
  if (!policy.includeSpecialChars) allowedSpecial = "";
  else if (policy.allowedSpecialChars !== null) allowedSpecial = policy.allowedSpecialChars;
  else if (policy.specialMode === "safe") allowedSpecial = SAFE_SPECIAL_CHARS;
  else allowedSpecial = PUNCTUATION;
  return { allAllowed: letters + digits + allowedSpecial, allowedSpecial };
}

function classChars(policy: ResolvedPolicy, allowedSpecial: string): ClassChars {
  let uppercase = ASCII_UPPERCASE;
  let lowercase = ASCII_LOWERCASE;
  let digits = DIGITS;
  if (policy.excludeAmbiguous) {
    uppercase = stripAmbiguous(uppercase);
    lowercase = stripAmbiguous(lowercase);
    digits = stripAmbiguous(digits);
  }
  return { uppercase, lowercase, digits, special: allowedSpecial };
}

/** Entropy chain: BIP-85 (64 bytes, app 32) -> PBKDF2-HMAC-SHA256(salt="", 100k) -> 32 bytes. */
export function derivePasswordDk(bip85: Bip85, index: number): Uint8Array {
  const entropy = bip85.deriveEntropy({ index, entropyBytes: 64, appNo: 32 });
  return pbkdf2(sha256, entropy, new Uint8Array(0), { c: 100000, dkLen: 32 });
}

function mapEntropyToChars(dk: Uint8Array, alphabet: string): string[] {
  const out: string[] = [];
  for (const byte of dk) out.push(alphabet[byte % alphabet.length]!);
  return out;
}

function countCharTypes(chars: string[], sets: ClassChars): [number, number, number, number] {
  let upper = 0;
  let lower = 0;
  let digs = 0;
  let specs = 0;
  for (const c of chars) {
    if (sets.uppercase.includes(c)) upper++;
    if (sets.lowercase.includes(c)) lower++;
    if (sets.digits.includes(c)) digs++;
    if (sets.special !== "" && sets.special.includes(c)) specs++;
  }
  return [upper, lower, digs, specs];
}

/** v1 complexity pass: minimum counts, extra symbols, segment balancing, keyed shuffle. */
function enforceComplexityV1(
  chars: string[],
  policy: ResolvedPolicy,
  sets: ClassChars,
  dk: Uint8Array,
): string[] {
  const stream = new DeterministicStream(dk);
  const [curUpper, curLower, curDigits, curSpecial] = countCharTypes(chars, sets);

  const minSpecial = sets.special !== "" ? policy.minSpecial : 0;
  const deficits: Array<[string, number]> = [
    [sets.uppercase, policy.minUppercase - curUpper],
    [sets.lowercase, policy.minLowercase - curLower],
    [sets.digits, policy.minDigits - curDigits],
  ];
  if (sets.special !== "") deficits.push([sets.special, minSpecial - curSpecial]);
  for (const [members, deficit] of deficits) {
    for (let n = 0; n < deficit; n++) {
      const index = stream.getValue() % chars.length;
      chars[index] = members[stream.getValue() % members.length]!;
    }
  }

  // Additional symbols toward a target of 3, bounded by the 32-byte stream
  if (sets.special !== "") {
    const currentSymbols = chars.filter((c) => sets.special.includes(c)).length;
    const needed = Math.max(3 - currentSymbols, 0);
    for (let n = 0; n < needed; n++) {
      if (stream.currentIndex >= stream.length) break;
      const index = stream.getValue() % chars.length;
      chars[index] = sets.special[stream.getValue() % sets.special.length]!;
    }
  }

  // Segment balancing: force class membership per segment
  const charTypes: string[] = [sets.uppercase, sets.lowercase, sets.digits];
  if (sets.special !== "") charTypes.push(sets.special);
  const segmentLength = Math.floor(chars.length / charTypes.length);
  if (segmentLength > 0) {
    for (let i = 0; i < charTypes.length; i++) {
      const start = i * segmentLength;
      const end = Math.min(start + segmentLength, chars.length);
      for (let j = start; j < end; j++) {
        const c = chars[j]!;
        if (i === 0 && !sets.uppercase.includes(c)) {
          chars[j] = sets.uppercase[stream.getValue() % sets.uppercase.length]!;
        } else if (i === 1 && !sets.lowercase.includes(c)) {
          chars[j] = sets.lowercase[stream.getValue() % sets.lowercase.length]!;
        } else if (i === 2 && !sets.digits.includes(c)) {
          chars[j] = sets.digits[stream.getValue() % sets.digits.length]!;
        } else if (sets.special !== "" && i === charTypes.length - 1 && !sets.special.includes(c)) {
          chars[j] = sets.special[stream.getValue() % sets.special.length]!;
        }
      }
    }
  }

  const shuffleKey = hmac(sha256, dk, be32(stream.currentIndex));
  return fisherYatesHmac(chars, shuffleKey);
}

function generateV1(
  length: number,
  dk: Uint8Array,
  policy: ResolvedPolicy,
  allAllowed: string,
  sets: ClassChars,
): string {
  let chars = mapEntropyToChars(dk, allAllowed);
  chars = enforceComplexityV1(chars, policy, sets, dk);
  chars = fisherYatesHmac(chars, dk);

  // Extension loop reassigns dk — the final complexity pass uses the last dk,
  // exactly as Python does.
  let currentDk = dk;
  while (chars.length < length) {
    currentDk = pbkdf2(sha256, currentDk, new Uint8Array(0), { c: 1, dkLen: 32 });
    chars = chars.concat(mapEntropyToChars(currentDk, allAllowed));
    chars = fisherYatesHmac(chars, currentDk);
  }

  chars = chars.slice(0, length);
  chars = enforceComplexityV1(chars, policy, sets, currentDk);
  chars = fisherYatesHmac(chars, currentDk);
  return chars.join("");
}

type ClassName = "upper" | "lower" | "digit" | "special";
const CLASS_ORDER: ClassName[] = ["upper", "lower", "digit", "special"];

function classify(char: string, classSets: Record<ClassName, string>): ClassName | null {
  for (const name of CLASS_ORDER) {
    if (classSets[name] !== "" && classSets[name].includes(char)) return name;
  }
  return null;
}

function generateV2(
  length: number,
  dk: Uint8Array,
  policy: ResolvedPolicy,
  allAllowed: string,
  sets: ClassChars,
): string {
  const classSets: Record<ClassName, string> = {
    upper: sets.uppercase,
    lower: sets.lowercase,
    digit: sets.digits,
    special: sets.special,
  };
  const minimaAll: Array<[ClassName, number]> = [
    ["upper", policy.minUppercase],
    ["lower", policy.minLowercase],
    ["digit", policy.minDigits],
    ["special", sets.special !== "" ? policy.minSpecial : 0],
  ];
  const minima = minimaAll.filter(([name]) => classSets[name] !== "");
  const minimaMap = new Map(minima);

  const required = minima.reduce((n, [, v]) => n + v, 0);
  if (required > length) {
    throw new Error(
      `Policy requires at least ${required} characters but the requested length is ${length}.`,
    );
  }

  const charStream = new ExpandedStream(dk, utf8("seedpass-v2-chars"));
  const policyStream = new ExpandedStream(dk, utf8("seedpass-v2-policy"));

  const chars: string[] = [];
  for (let i = 0; i < length; i++) {
    chars.push(allAllowed[uniformIndex(charStream, allAllowed.length)]!);
  }

  // Enforce minima using donor positions from surplus classes only
  const counts: Record<ClassName, number> = { upper: 0, lower: 0, digit: 0, special: 0 };
  for (const c of chars) {
    const name = classify(c, classSets);
    if (name !== null) counts[name] += 1;
  }
  for (const [name, minimum] of minima) {
    while (counts[name] < minimum) {
      const donors: number[] = [];
      for (let i = 0; i < chars.length; i++) {
        const other = classify(chars[i]!, classSets);
        if (other !== name && other !== null && counts[other] > (minimaMap.get(other) ?? 0)) {
          donors.push(i);
        }
      }
      if (donors.length === 0) {
        throw new Error(`Cannot satisfy minimum for '${name}' without violating another.`);
      }
      const position = donors[uniformIndex(policyStream, donors.length)]!;
      const donorClass = classify(chars[position]!, classSets)!;
      const members = classSets[name];
      chars[position] = members[uniformIndex(policyStream, members.length)]!;
      counts[donorClass] -= 1;
      counts[name] += 1;
    }
  }

  const shuffleKey = hmac(sha256, dk, utf8("seedpass-v2-shuffle"));
  return fisherYatesHmac(chars, shuffleKey).join("");
}

/**
 * Build a policy from an entry's stored `policy` block.
 *
 * Parity target: PasswordManager._generate_password_for_entry, which merges
 * the entry's overrides onto the base policy before deriving. Ignoring this
 * block yields a different password for any entry created with policy flags.
 */
export function passwordPolicyFromRecord(raw: unknown): PasswordPolicy {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {};
  const o = raw as Record<string, unknown>;
  const num = (v: unknown): number | undefined =>
    v === undefined || v === null ? undefined : Math.trunc(Number(v));
  return {
    ...(o["include_special_chars"] !== undefined && {
      includeSpecialChars: Boolean(o["include_special_chars"]),
    }),
    ...(o["allowed_special_chars"] !== undefined && {
      allowedSpecialChars: String(o["allowed_special_chars"]),
    }),
    ...(o["special_mode"] !== undefined && { specialMode: String(o["special_mode"]) }),
    ...(o["exclude_ambiguous"] !== undefined && {
      excludeAmbiguous: Boolean(o["exclude_ambiguous"]),
    }),
    ...(o["min_uppercase"] !== undefined && { minUppercase: num(o["min_uppercase"])! }),
    ...(o["min_lowercase"] !== undefined && { minLowercase: num(o["min_lowercase"])! }),
    ...(o["min_digits"] !== undefined && { minDigits: num(o["min_digits"])! }),
    ...(o["min_special"] !== undefined && { minSpecial: num(o["min_special"])! }),
  };
}

export function generatePassword(
  bip85: Bip85,
  options: {
    length?: number;
    index?: number;
    genVersion?: number;
    policy?: PasswordPolicy;
  } = {},
): string {
  const length = options.length ?? DEFAULT_PASSWORD_LENGTH;
  const index = options.index ?? 0;
  const genVersion = options.genVersion ?? LEGACY_PASSWORD_GEN_VERSION;
  const policy = resolvePolicy(options.policy);

  if (length < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password length must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  }
  if (length > MAX_PASSWORD_LENGTH) {
    throw new Error(`Password length must not exceed ${MAX_PASSWORD_LENGTH} characters.`);
  }

  const dk = derivePasswordDk(bip85, index);
  const { allAllowed, allowedSpecial } = alphabets(policy);
  const sets = classChars(policy, allowedSpecial);

  if (genVersion === CURRENT_PASSWORD_GEN_VERSION) {
    return generateV2(length, dk, policy, allAllowed, sets);
  }
  if (genVersion !== LEGACY_PASSWORD_GEN_VERSION) {
    throw new Error(`Unknown password generation version: ${genVersion}`);
  }
  return generateV1(length, dk, policy, allAllowed, sets);
}
