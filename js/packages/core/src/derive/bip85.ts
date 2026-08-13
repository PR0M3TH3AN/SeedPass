/**
 * BIP-85 deterministic entropy derivation.
 *
 * Parity target: src/local_bip85/bip85.py. Derivation paths:
 *   app 39 (BIP-39):  m/83696968'/39'/0'/{word_count}'/{index}'
 *   app 32:           m/83696968'/32'/{index}'
 *   other apps:       m/83696968'/{app_no}'/{index}'
 * Entropy = HMAC-SHA512(key=b"bip-entropy-from-k", child_private_key)[:n].
 */

import { HDKey } from "@scure/bip32";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { mnemonicToSeedSync, entropyToMnemonic } from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { utf8 } from "../util/bytes.js";

const HMAC_KEY = utf8("bip-entropy-from-k");

export interface DeriveEntropyOptions {
  index: number;
  entropyBytes: number;
  appNo?: number;
  /** Word count used in the app-39 path; defaults to entropyBytes (Python quirk, kept). */
  wordCount?: number;
}

export class Bip85 {
  private readonly root: HDKey;

  constructor(seed: Uint8Array) {
    this.root = HDKey.fromMasterSeed(seed);
  }

  static fromMnemonic(mnemonic: string, passphrase = ""): Bip85 {
    return new Bip85(mnemonicToSeedSync(mnemonic, passphrase));
  }

  deriveEntropy(opts: DeriveEntropyOptions): Uint8Array {
    const appNo = opts.appNo ?? 39;
    let path: string;
    if (appNo === 39) {
      const wordCount = opts.wordCount ?? opts.entropyBytes;
      path = `m/83696968'/${appNo}'/0'/${wordCount}'/${opts.index}'`;
    } else {
      path = `m/83696968'/${appNo}'/${opts.index}'`;
    }
    const child = this.root.derive(path);
    const k = child.privateKey;
    if (!k) throw new Error(`no private key at ${path}`);
    const digest = hmac(sha512, HMAC_KEY, k);
    if (opts.entropyBytes > digest.length) {
      throw new Error(
        `requested ${opts.entropyBytes} bytes but HMAC-SHA512 yields ${digest.length}`,
      );
    }
    return digest.slice(0, opts.entropyBytes);
  }

  /** BIP-85 child mnemonic (BIP-39 English), parity with derive_mnemonic. */
  deriveMnemonic(index: number, wordsNum: 12 | 18 | 24): string {
    const entropyBytes = { 12: 16, 18: 24, 24: 32 }[wordsNum];
    const entropy = this.deriveEntropy({
      index,
      entropyBytes,
      appNo: 39,
      wordCount: wordsNum,
    });
    return entropyToMnemonic(entropy, english);
  }
}
