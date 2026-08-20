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
  canonicalizeMnemonic,
  generateMnemonic,
  SUPPORTED_SEED_WORD_COUNTS,
  DEFAULT_SEED_WORD_COUNT,
  type SeedWordCount,
  type DeriveEntropyOptions,
} from "./derive/bip85.js";
export {
  generatePassword,
  passwordPolicyFromRecord,
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
  derivePgpKey,
  pgpFingerprint,
  PGP_CREATED_AT,
  type PgpKeyPair,
} from "./derive/pgp.js";
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
  KDF_LIMITS,
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
  unknownEntrySchema,
  KNOWN_ENTRY_KINDS,
  UnsupportedSchemaVersionError,
  CURRENT_SCHEMA_VERSION,
  type Entry,
  type UnknownEntry,
  type VaultIndex,
} from "./schema/entries.js";
export {
  applyMigrations,
  needsMigration,
  SchemaMigrationError,
} from "./schema/migrations.js";
export {
  PARTITION_FILENAME,
  PARTITION_KDF_ITERATIONS,
  HIGH_RISK_KINDS,
  HighRiskError,
  partitionKeyTag,
  decryptPartition,
  encryptPartition,
  buildPartitionEnvelope,
  unwrapPartitionKey,
  generatePartitionKey,
  partitionStub,
  isPartitionStub,
  parsePartitionRecord,
  type PartitionEnvelope,
} from "./vault/highRiskPartition.js";
export {
  splitSecret,
  recoverSecret,
  parseShare,
  RecoveryError,
  SHARE_PREFIX,
  RECOVERY_PRIME,
  MAX_TOTAL_SHARES,
  type ParsedShare,
} from "./vault/recoverySplit.js";
export {
  normalizeIndex0,
  normalizeIndex0Event,
  normalizeIndex0Checkpoint,
  normalizeCanonicalView,
  normalizeHead,
  normalizeViewManifest,
  ensureIndex0Payload,
  deriveIndex0Context,
  makeIndex0Event,
  appendIndex0Event,
  buildDailyCheckpoint,
  rebuildIndex0Checkpoints,
  compactIndex0,
  compactIndex0Payload,
  rebuildCanonicalViewsPayload,
  buildManifestIndex0Metadata,
  listCanonicalViews,
  getCanonicalView,
  mergeSystemIndex0,
  recomputeIndex0Stats,
  // Aliased: `computeEventId` is already taken by the Nostr event module,
  // and the two hash entirely different things.
  computeEventHash as computeIndex0EventHash,
  computeEventId as computeIndex0EventId,
  computeHeadHash as computeIndex0HeadHash,
  computeCheckpointHash as computeIndex0CheckpointHash,
  computeViewHash as computeIndex0ViewHash,
  INDEX0_SCHEMA_VERSION,
  INDEX0_CANONICAL_VIEW_TYPES,
  LOCAL_ONLY_VIEW_TYPES,
  INDEX0_MAX_CHECKPOINTS_PER_WRITER,
  type Index0,
  type Index0Context,
} from "./vault/index0.js";
export { emitEntryEvents, type EmitOptions } from "./vault/index0Events.js";
export { encodeQr, renderQrText, EC_LEVELS, type QrMatrix, type EcLevel } from "./util/qr.js";
export {
  buildSemanticRecords,
  searchSemanticRecords,
  semanticText,
  semanticManifest,
  semanticStatus,
  isStaleSemanticIndex,
  tokenize,
  SEMANTIC_KINDS,
  SEMANTIC_MODEL_ID,
  SEMANTIC_SCHEMA_VERSION,
  type SemanticRecord,
  type SemanticHit,
  type SemanticStatus,
} from "./vault/semanticIndex.js";
export {
  findDerivationCollisions,
  APP32_KINDS,
  type DerivationCollision,
  type App32Kind,
} from "./vault/derivationCollisions.js";
export {
  importBackup,
  exportBackup,
  parseBackupWrapper,
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
export { findAmbiguousNumbers, canonicalJson, canonicalHash } from "./sync/canonical.js";
export {
  mergeIndexPayloads,
  entryEventHash,
  emptyIndex0,
  safeInt,
  TOMBSTONE_RETENTION_CAP,
  MERGE_STRATEGY,
  newMergeReport,
  type MergeOptions,
  type MergeReport,
  type MergeConflict,
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
