/**
 * @seedpass/core — SeedPass protocol core (TypeScript port).
 *
 * Python remains the normative reference until the compatibility matrix is
 * green; see docs/typescript_web_extension_port_plan.md.
 */

export { Bip85, type DeriveEntropyOptions } from "./derive/bip85.js";
export {
  generatePassword,
  derivePasswordDk,
  type PasswordPolicy,
  LEGACY_PASSWORD_GEN_VERSION,
  CURRENT_PASSWORD_GEN_VERSION,
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  DEFAULT_PASSWORD_LENGTH,
  SAFE_SPECIAL_CHARS,
} from "./derive/password.js";
export { deriveTotpSecret, totpCodeAt, hotp } from "./derive/totp.js";
export {
  deriveNostrKeys,
  hexToBech32,
  bech32ToHex,
  NOSTR_KEY_APP_ID,
  type NostrKeys,
} from "./derive/nostr.js";
export { generateFingerprint } from "./derive/fingerprint.js";
export { deriveIndexKey, deriveIndexKeyBytes } from "./vault/indexKey.js";
export { decryptV3, encryptV3, isV3Payload } from "./vault/aead.js";
export * from "./util/bytes.js";
