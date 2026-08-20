/**
 * PGP key derivation parity against PGPy's output.
 *
 * The key material is deterministic and EdDSA signatures are deterministic,
 * so the armored blocks are expected to match byte-for-byte.
 */

import { describe, expect, it } from "vitest";
import { pgpKeyCases, pgpCreatedAt, mnemonics } from "@seedpass/test-vectors";
import { derivePgpKey, pgpFingerprint, PGP_CREATED_AT } from "@seedpass/core";

describe("PGP key derivation", () => {
  it("agrees with Python on the pinned creation time", () => {
    expect(PGP_CREATED_AT).toBe(pgpCreatedAt);
  });

  it.each(pgpKeyCases)("$mnemonic_id index $index fingerprint", (c) => {
    const pair = derivePgpKey(mnemonics[c.mnemonic_id]!, c.index, { userId: c.user_id });
    expect(pair.fingerprint).toBe(c.fingerprint);
    expect(pgpFingerprint(pair.publicKey)).toBe(c.fingerprint);
  });

  it.each(pgpKeyCases)("$mnemonic_id index $index armored private key", (c) => {
    const pair = derivePgpKey(mnemonics[c.mnemonic_id]!, c.index, { userId: c.user_id });
    expect(pair.privateKeyArmored).toBe(c.private_key_armored);
  });

  it.each(pgpKeyCases)("$mnemonic_id index $index armored public key", (c) => {
    const pair = derivePgpKey(mnemonics[c.mnemonic_id]!, c.index, { userId: c.user_id });
    expect(pair.publicKeyArmored).toBe(c.public_key_armored);
  });

  it("refuses unsupported key types rather than deriving a different key", () => {
    expect(() =>
      derivePgpKey(mnemonics["abandon12"]!, 0, { keyType: "rsa" }),
    ).toThrow(/not supported/);
  });
});
