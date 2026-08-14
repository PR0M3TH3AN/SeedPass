/** SSH key derivation parity: PEM output must match Python byte-for-byte. */

import { describe, expect, it } from "vitest";
import { sshKeyCases, mnemonics } from "@seedpass/test-vectors";
import {
  deriveSshKeyPair,
  deriveSshEntropy,
  sshPublicKeyOpenSsh,
  Bip85,
  bytesToHex,
} from "@seedpass/core";

describe("SSH key derivation", () => {
  it.each(sshKeyCases)("$mnemonic_id index $index", (c) => {
    const mnemonic = mnemonics[c.mnemonic_id]!;
    const pair = deriveSshKeyPair(mnemonic, c.index);
    expect(bytesToHex(pair.privateKey)).toBe(c.entropy_hex);
    expect(pair.privateKeyPem).toBe(c.private_key_pem);
    expect(pair.publicKeyPem).toBe(c.public_key_pem);
  });

  it("uses BIP-85 app 32 for its entropy", () => {
    const c = sshKeyCases[0]!;
    const bip85 = Bip85.fromMnemonic(mnemonics[c.mnemonic_id]!);
    expect(bytesToHex(deriveSshEntropy(bip85, c.index))).toBe(c.entropy_hex);
  });

  it("emits an OpenSSH public key line (TS-only convenience)", () => {
    const pair = deriveSshKeyPair(mnemonics["abandon12"]!, 0);
    const line = sshPublicKeyOpenSsh(pair.publicKey, "seedpass");
    expect(line).toMatch(/^ssh-ed25519 [A-Za-z0-9+/=]+ seedpass$/);
    // The blob embeds the same 32-byte key the PEM carries
    const blob = Buffer.from(line.split(" ")[1]!, "base64");
    expect(blob.subarray(blob.length - 32).toString("hex")).toBe(
      bytesToHex(pair.publicKey),
    );
  });
});
