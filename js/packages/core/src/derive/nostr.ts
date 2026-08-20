/**
 * Nostr key derivation.
 *
 * Parity target: src/nostr/key_manager.py. BIP-85 app 1237, 32 bytes of
 * entropy as the secp256k1 private key. Public key is x-only (compressed
 * public key minus the parity prefix byte). npub/nsec are plain bech32.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bech32 } from "@scure/base";
import { Bip85 } from "./bip85.js";
import { bytesToHex, hexToBytes } from "../util/bytes.js";

export const NOSTR_KEY_APP_ID = 1237;

export interface NostrKeys {
  privateKeyHex: string;
  publicKeyHex: string;
  npub: string;
  nsec: string;
}

export function hexToBech32(keyHex: string, prefix: "npub" | "nsec"): string {
  return bech32.encode(prefix, bech32.toWords(hexToBytes(keyHex)));
}

export function bech32ToHex(key: string): string {
  const { words } = bech32.decode(key as `${string}1${string}`);
  return bytesToHex(new Uint8Array(bech32.fromWords(words)));
}

export function deriveNostrKeys(bip85: Bip85, accountIndex = 0): NostrKeys {
  const entropy = bip85.deriveEntropy({
    index: accountIndex,
    entropyBytes: 32,
    appNo: NOSTR_KEY_APP_ID,
  });
  const privateKeyHex = bytesToHex(entropy);
  const compressed = secp256k1.getPublicKey(entropy, true);
  const publicKeyHex = bytesToHex(compressed.slice(1));
  return {
    privateKeyHex,
    publicKeyHex,
    npub: hexToBech32(publicKeyHex, "npub"),
    nsec: hexToBech32(privateKeyHex, "nsec"),
  };
}
