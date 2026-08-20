/**
 * Deterministic PGP (Ed25519/EdDSA) key derivation.
 *
 * Parity target: src/seedpass/core/password_generation.py::derive_pgp_key,
 * which builds a PGPy key from BIP-85 app-32 entropy with a pinned creation
 * time (2000-01-01T00:00:00Z).
 *
 * Everything here is byte-reproducible: the key material is deterministic,
 * EdDSA signatures are deterministic (RFC 8032), and the packet layout is
 * fixed. That makes byte-for-byte parity with PGPy achievable without an
 * OpenPGP dependency — the packets are emitted directly.
 *
 * Only the ed25519 key type is ported. Python also supports RSA via a
 * seeded DRNG; RSA keygen is not reproducible without reimplementing
 * PyCryptodome's prime search, so it is deliberately unsupported here
 * rather than silently producing a different key.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base64 } from "@scure/base";
import { Bip85 } from "./bip85.js";
import { bytesToHex, concatBytes, utf8 } from "../util/bytes.js";

/** PGPy pins created to 2000-01-01T00:00:00Z. */
export const PGP_CREATED_AT = 946684800;

const ALGO_EDDSA = 22;
const HASH_SHA256 = 8;
const SIGTYPE_POSITIVE_CERT = 0x13;
/** OID 1.3.6.1.4.1.11591.15.1 (Ed25519). */
const ED25519_OID = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]);

function be16(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

function be32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/** OpenPGP MPI: 2-byte bit length, then the minimal big-endian bytes. */
function mpi(value: Uint8Array): Uint8Array {
  let start = 0;
  while (start < value.length && value[start] === 0) start++;
  const trimmed = value.slice(start);
  if (trimmed.length === 0) return be16(0);
  const first = trimmed[0]!;
  let bits = (trimmed.length - 1) * 8;
  for (let b = 7; b >= 0; b--) {
    if (first & (1 << b)) {
      bits += b + 1;
      break;
    }
  }
  return concatBytes(be16(bits), trimmed);
}

/**
 * New-format packet header (RFC 4880 §4.2.2), which is what PGPy emits.
 * Lengths below 192 take one byte, below 8384 two, otherwise a five-byte
 * form introduced by 0xff.
 */
function packet(tag: number, body: Uint8Array): Uint8Array {
  const header = new Uint8Array([0xc0 | tag]);
  const n = body.length;
  if (n < 192) {
    return concatBytes(header, new Uint8Array([n]), body);
  }
  if (n < 8384) {
    const offset = n - 192;
    return concatBytes(
      header,
      new Uint8Array([(offset >> 8) + 192, offset & 0xff]),
      body,
    );
  }
  return concatBytes(header, new Uint8Array([0xff]), be32(n), body);
}

function subpacket(type: number, data: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([data.length + 1, type]), data);
}

/** Public-key packet body: shared by the key packet and the fingerprint. */
function publicKeyBody(publicKey: Uint8Array, createdAt: number): Uint8Array {
  const point = concatBytes(new Uint8Array([0x40]), publicKey);
  return concatBytes(
    new Uint8Array([4]),
    be32(createdAt),
    new Uint8Array([ALGO_EDDSA, ED25519_OID.length]),
    ED25519_OID,
    mpi(point),
  );
}

/** v4 fingerprint: SHA-1 over 0x99 || len16 || public-key packet body. */
export function pgpFingerprint(publicKey: Uint8Array, createdAt = PGP_CREATED_AT): string {
  const body = publicKeyBody(publicKey, createdAt);
  const digest = sha1(concatBytes(new Uint8Array([0x99]), be16(body.length), body));
  return bytesToHex(digest).toUpperCase();
}

function secretKeyBody(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  createdAt: number,
): Uint8Array {
  const secretMpi = mpi(privateKey);
  // Unencrypted secret material carries a 16-bit sum of the MPI bytes.
  let checksum = 0;
  for (const b of secretMpi) checksum = (checksum + b) & 0xffff;
  return concatBytes(
    publicKeyBody(publicKey, createdAt),
    new Uint8Array([0x00]), // s2k usage: unencrypted
    secretMpi,
    be16(checksum),
  );
}

/** CRC-24 over the packet stream, as required by the ASCII armor footer. */
function crc24(data: Uint8Array): number {
  let crc = 0xb704ce;
  for (const byte of data) {
    crc ^= byte << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

function armor(label: string, data: Uint8Array): string {
  const body = base64.encode(data).replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  const checksum = base64.encode(
    new Uint8Array([(crc24(data) >> 16) & 0xff, (crc24(data) >> 8) & 0xff, crc24(data) & 0xff]),
  );
  return `-----BEGIN PGP ${label}-----\n\n${body}\n=${checksum}\n-----END PGP ${label}-----\n`;
}

export interface PgpKeyPair {
  privateKeyArmored: string;
  publicKeyArmored: string;
  fingerprint: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Derive a deterministic PGP key pair.
 *
 * `keyType` accepts only "ed25519"; see the module note on RSA.
 */
export function derivePgpKey(
  mnemonic: string,
  index: number,
  options: { userId?: string; keyType?: string; createdAt?: number } = {},
): PgpKeyPair {
  const keyType = (options.keyType ?? "ed25519").toLowerCase();
  if (keyType !== "ed25519") {
    throw new Error(
      `PGP key type "${keyType}" is not supported by the TypeScript port ` +
        `(only ed25519; RSA generation is not byte-reproducible)`,
    );
  }
  const createdAt = options.createdAt ?? PGP_CREATED_AT;
  const userId = options.userId ?? "";

  const privateKey = Bip85.fromMnemonic(mnemonic).deriveEntropy({
    index,
    entropyBytes: 32,
    appNo: 32,
  });
  const publicKey = ed25519.getPublicKey(privateKey);

  const pubBody = publicKeyBody(publicKey, createdAt);
  const secBody = secretKeyBody(privateKey, publicKey, createdAt);
  const fingerprint = pgpFingerprint(publicKey, createdAt);
  const fpBytes = new Uint8Array(
    (fingerprint.match(/../g) ?? []).map((h) => parseInt(h, 16)),
  );
  const keyId = fpBytes.slice(12);

  // Self-certification over the primary key and user id. Subpacket set and
  // order mirror what PGPy emits for these usage/preference arguments.
  const hashedSubpackets = concatBytes(
    subpacket(2, be32(createdAt)), // creation time
    subpacket(27, new Uint8Array([0x0e])), // key flags: sign + encrypt comms + storage
    subpacket(11, new Uint8Array([9])), // preferred symmetric: AES256
    subpacket(21, new Uint8Array([HASH_SHA256])), // preferred hash: SHA256
    subpacket(22, new Uint8Array([2])), // preferred compression: ZLIB
    subpacket(30, new Uint8Array([1])), // features: MDC
    subpacket(33, concatBytes(new Uint8Array([4]), fpBytes)), // issuer fingerprint
  );
  const unhashedSubpackets = subpacket(16, keyId); // issuer key id

  const sigHeader = concatBytes(
    new Uint8Array([4, SIGTYPE_POSITIVE_CERT, ALGO_EDDSA, HASH_SHA256]),
    be16(hashedSubpackets.length),
    hashedSubpackets,
  );

  const uidBytes = utf8(userId);
  const toHash = concatBytes(
    new Uint8Array([0x99]),
    be16(pubBody.length),
    pubBody,
    new Uint8Array([0xb4]),
    be32(uidBytes.length),
    uidBytes,
    sigHeader,
    new Uint8Array([0x04, 0xff]),
    be32(sigHeader.length),
  );
  const digest = sha256(toHash);
  const signature = ed25519.sign(digest, privateKey);

  const sigBody = concatBytes(
    sigHeader,
    be16(unhashedSubpackets.length),
    unhashedSubpackets,
    digest.slice(0, 2),
    mpi(signature.slice(0, 32)),
    mpi(signature.slice(32, 64)),
  );

  const uidPacket = packet(13, uidBytes);
  const sigPacket = packet(2, sigBody);
  const privateStream = concatBytes(packet(5, secBody), uidPacket, sigPacket);
  const publicStream = concatBytes(packet(6, pubBody), uidPacket, sigPacket);

  return {
    privateKeyArmored: armor("PRIVATE KEY BLOCK", privateStream),
    publicKeyArmored: armor("PUBLIC KEY BLOCK", publicStream),
    fingerprint,
    privateKey,
    publicKey,
  };
}
