/**
 * @seedpass/core — SeedPass protocol core (TypeScript port).
 *
 * Python remains the normative reference until the compatibility matrix is
 * green; see docs/typescript_web_extension_port_plan.md.
 */

export {
  Bip85,
  isValidMnemonic,
  assertValidMnemonic,
  type DeriveEntropyOptions,
} from "./derive/bip85.js";
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
export {
  deriveSshKeyPair,
  deriveSshEntropy,
  sshPublicKeyOpenSsh,
  type SshKeyPair,
} from "./derive/ssh.js";
export { deriveIndexKey, deriveIndexKeyBytes } from "./vault/indexKey.js";
export { decryptV3, encryptV3, isV3Payload } from "./vault/aead.js";
export {
  deriveKeyFromPassword,
  deriveKeyFromPasswordArgon2,
  kdfConfigSchema,
  type KdfConfig,
} from "./vault/passwordKdf.js";
export { fernetDecrypt, FernetError } from "./vault/fernet.js";
export { decryptPayload, parseEncryptedFile, type EncryptedFile } from "./vault/payload.js";
export {
  entrySchema,
  vaultIndexSchema,
  parseVaultIndex,
  customFieldSchema,
  passwordEntrySchema,
  totpEntrySchema,
  sshEntrySchema,
  seedEntrySchema,
  pgpEntrySchema,
  nostrEntrySchema,
  keyValueEntrySchema,
  managedAccountEntrySchema,
  documentEntrySchema,
  UnsupportedSchemaVersionError,
  CURRENT_SCHEMA_VERSION,
  type Entry,
  type VaultIndex,
} from "./schema/entries.js";
export {
  applyMigrations,
  needsMigration,
  SchemaMigrationError,
} from "./schema/migrations.js";
export {
  importBackup,
  exportBackup,
  portableBackupSchema,
  BackupImportError,
  PORTABLE_FORMAT_VERSION,
  type PortableBackup,
} from "./vault/portableBackup.js";
export {
  addPasswordEntry,
  addTotpDeterministic,
  addTotpImported,
  addSshKeyEntry,
  addNostrKeyEntry,
  addKeyValueEntry,
  addDocumentEntry,
  addSeedEntry,
  addManagedAccountEntry,
  addPgpKeyEntry,
  nextIndex,
  nextTotpIndex,
  isoFromUnix,
  systemClock,
  type Clock,
} from "./vault/entryOps.js";
export {
  modifyEntry,
  archiveEntry,
  restoreEntry,
  addLink,
  removeLink,
  getLinks,
  normalizeLinks,
  type ModifyChanges,
  type EntryLink,
  type ResolvedLink,
} from "./vault/entryMod.js";
export { canonicalJson, canonicalHash } from "./sync/canonical.js";
export {
  mergeIndexPayloads,
  emptyIndex0,
  safeInt,
  TOMBSTONE_RETENTION_CAP,
  MERGE_STRATEGY,
} from "./sync/merge.js";
export {
  KIND_MANIFEST,
  KIND_SNAPSHOT_CHUNK,
  KIND_DELTA,
  chunkMetaSchema,
  manifestSchema,
  parseManifest,
  prepareSnapshot,
  reassembleSnapshot,
  gzipCompress,
  gzipDecompress,
  deriveKeyIndex,
  manifestIdFromNonce,
  newManifestId,
  ChunkVerificationError,
  type ChunkMeta,
  type Manifest,
} from "./sync/snapshot.js";
export {
  computeEventId,
  serializeEventForId,
  signEvent,
  verifyEvent,
  signerPublicKeyHex,
  buildChunkEvent,
  buildManifestEvent,
  buildDeltaEvent,
  reqMessage,
  eventMessage,
  closeMessage,
  parseRelayMessage,
  type NostrEvent,
  type UnsignedEvent,
  type Filter,
  type RelayMessage,
} from "./sync/events.js";
export { RelayPool, type PublishResult, type RelayPoolOptions } from "./sync/relay.js";
export {
  publishSnapshot,
  fetchLatestSnapshot,
  publishDelta,
  fetchDeltasSince,
  type PublishedSnapshot,
  type FetchedSnapshot,
} from "./sync/syncFlows.js";
export * from "./util/bytes.js";
