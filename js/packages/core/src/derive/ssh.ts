/**
 * Deterministic SSH (Ed25519) key derivation.
 *
 * Parity target: src/seedpass/core/password_generation.py::derive_ssh_key_pair.
 * BIP-85 app 32 yields 32 bytes used directly as the Ed25519 private key;
 * Python serializes with `cryptography` as PKCS#8 (private) and
 * SubjectPublicKeyInfo (public) PEM.
 *
 * Both DER structures are fixed-shape for Ed25519, so they are emitted
 * literally rather than pulling in an ASN.1 encoder:
 *
 *   PKCS#8:  30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 || key(32)
 *   SPKI:    30 2a 30 05 06 03 2b 65 70 03 21 00             || pubkey(32)
 *
 * (2b 65 70 is OID 1.3.101.112, id-Ed25519.)
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { base64 } from "@scure/base";
import { Bip85 } from "./bip85.js";
import { concatBytes } from "../util/bytes.js";

const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
  0x04, 0x20,
]);
const SPKI_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/** PEM with the 64-character line wrapping OpenSSL and `cryptography` use. */
function toPem(label: string, der: Uint8Array): string {
  const body = base64.encode(der).replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

export interface SshKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
  /** Raw 32-byte private key (the BIP-85 entropy). */
  privateKey: Uint8Array;
  /** Raw 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
}

/** 32 bytes of BIP-85 entropy for an SSH key (app 32). */
export function deriveSshEntropy(bip85: Bip85, index: number): Uint8Array {
  return bip85.deriveEntropy({ index, entropyBytes: 32, appNo: 32 });
}

export function deriveSshKeyPair(mnemonic: string, index: number): SshKeyPair {
  const privateKey = deriveSshEntropy(Bip85.fromMnemonic(mnemonic), index);
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    privateKeyPem: toPem("PRIVATE KEY", concatBytes(PKCS8_ED25519_PREFIX, privateKey)),
    publicKeyPem: toPem("PUBLIC KEY", concatBytes(SPKI_ED25519_PREFIX, publicKey)),
  };
}

/**
 * OpenSSH `authorized_keys` one-liner for the same key.
 *
 * Python does not emit this format; it is provided because a PEM Ed25519
 * key is not directly usable by ssh(1). Marked as a TS-only addition in the
 * compatibility matrix.
 */
export function sshPublicKeyOpenSsh(publicKey: Uint8Array, comment = ""): string {
  const type = new TextEncoder().encode("ssh-ed25519");
  const be32 = (n: number) =>
    new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  const blob = concatBytes(be32(type.length), type, be32(publicKey.length), publicKey);
  const encoded = base64.encode(blob);
  return comment ? `ssh-ed25519 ${encoded} ${comment}` : `ssh-ed25519 ${encoded}`;
}
