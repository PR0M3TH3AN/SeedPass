/**
 * BIP-85 official spec test vectors, run directly against this implementation.
 *
 * Every other derivation check in this repo compares us against the Python
 * implementation — which is cross-verification, not ground truth. These
 * vectors come from the BIP-85 specification itself (also pinned in Python's
 * test_bip85_vectors.py), so a shared misconception between our two
 * implementations cannot pass here.
 */

import { describe, expect, it } from "vitest";
import { Bip85, deriveTotpSecret, bytesToHex } from "@seedpass/core";

// The spec's master key (BIP-85 test vectors section).
const MASTER_XPRV =
  "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

// Official BIP-39 application vectors (12 and 24 English words, index 0).
const SPEC_12 =
  "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose";
const SPEC_24 =
  "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano";

// SeedPass-specific derivations from the same master, pinned identically in
// Python's suite (not spec vectors, but a cross-family anchor for app 32 and
// the TOTP path).
const PY_SSH_ENTROPY =
  "52405cd0dd21c5be78314a7c1a3c65ffd8d896536cc7dee3157db5824f0c92e2";
const PY_TOTP_SECRET = "VQYTWDNEWYBY2G3LOGGCEKR4LZ3LNEYY";

describe("BIP-85 spec vectors", () => {
  const bip85 = Bip85.fromExtendedKey(MASTER_XPRV);

  it("derives the spec's 12-word BIP-39 vector", () => {
    expect(bip85.deriveMnemonic(0, 12)).toBe(SPEC_12);
  });

  it("derives the spec's 24-word BIP-39 vector", () => {
    expect(bip85.deriveMnemonic(0, 24)).toBe(SPEC_24);
  });

  it("matches Python's pinned app-32 entropy from the spec master", () => {
    const entropy = bip85.deriveEntropy({ index: 0, entropyBytes: 32, appNo: 32 });
    expect(bytesToHex(entropy)).toBe(PY_SSH_ENTROPY);
  });

  it("matches Python's pinned TOTP secret derived from the spec's 24-word child", () => {
    expect(deriveTotpSecret(SPEC_24, 0)).toBe(PY_TOTP_SECRET);
  });
});
