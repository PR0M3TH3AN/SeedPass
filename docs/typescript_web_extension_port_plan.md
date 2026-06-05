# SeedPass TypeScript / Web / Extension Port Plan

Status: planning draft  
Branch baseline: `beta`  
Reference implementation: current Python SeedPass core, CLI, API, TUI v3, and tests  

## 1. Purpose

This document defines a detailed plan for porting SeedPass from the current
Python-first implementation into a TypeScript-first product that can support:

- a CLI with the same terminal-first workflows Adam wants to preserve
- a local-first static/PWA web app
- a browser extension for autofill and browser-native password workflows
- an optional packaged desktop app
- future agent and automation interfaces

The goal is not a screen-by-screen rewrite of the Python TUI. The goal is a
protocol-compatible TypeScript implementation of SeedPass core behavior, with
multiple thin interface adapters.

## 2. Product Direction

The TypeScript version should make SeedPass easier to use without weakening the
security posture that makes SeedPass worth using.

Recommended product shape:

```text
packages/core       Shared SeedPass protocol and crypto core
packages/cli        Node.js CLI and interactive terminal UI
apps/web            Static/PWA vault manager
apps/extension      Browser extension for autofill and quick retrieval
apps/desktop        Optional Tauri shell around the web app
packages/test-vectors  Python/TypeScript parity fixtures
```

The Python repo remains the reference until the TypeScript core proves parity.
The TypeScript implementation should become authoritative only after deterministic
derivation, vault compatibility, sync compatibility, and safety tests pass.

## 3. Non-Goals

- Do not port Textual/TUI v3 screens directly to browser components.
- Do not require a hosted server for normal use.
- Do not store plaintext seeds, passwords, TOTP secrets, or private keys in
  browser `localStorage`.
- Do not introduce analytics, telemetry, or remote feature flags.
- Do not depend on a large frontend dependency graph for cryptographic behavior.
- Do not retire the Python implementation until TypeScript parity is proven.

## 4. Current Python Reference Surface

The current Python implementation provides the following reference points:

- `seedpass.core`: encryption, derivation, vault, sync, search, index0, policy
- `seedpass.cli`: Typer command surface, default interactive TUI v3 route
- `seedpass.api`: FastAPI automation/API surface
- `seedpass.tui_v3`: current default UI and active product roadmap
- `seedpass.tui_v2`: maintained legacy/reference UI logic
- `src/tests`: large regression suite and parity evidence
- `docs/SPEC.md`: key hierarchy, KDF, Nostr event formats, conflict model
- `docs/entry_types.md`: canonical entry kinds and fields
- `docs/threat_model.md`: security objectives and attacker profiles
- `docs/dev_control_center.md`: current priorities and branch status

The TypeScript implementation must treat Python behavior as normative until a
formal TypeScript spec replaces it.

## 5. Target Architecture

### 5.1 Shared Core

`packages/core` should contain all reusable logic:

- BIP-39 seed parsing and mnemonic handling
- BIP-85-compatible derivations
- deterministic password generation
- deterministic TOTP secret derivation
- SSH / PGP / Nostr key derivation where supported
- entry schema validation and migrations
- vault encryption/decryption
- portable backup import/export
- Nostr snapshot/chunk/delta encoding and decoding
- deterministic conflict resolution
- tags, links, graph, search, and index0/atlas behavior
- policy, approvals, leases, tokens, and audit primitives
- safe redaction and display formatting

The core must not depend on browser DOM APIs, Node filesystem APIs, React, or
extension APIs. It may depend on small cross-platform crypto/encoding libraries
only when WebCrypto or Node crypto cannot reasonably cover the need.

### 5.2 Storage Adapters

Use explicit adapters instead of letting each interface invent storage behavior.

Required adapters:

- `MemoryStore`: tests and ephemeral sessions
- `NodeFileStore`: CLI vault files, backups, audit log
- `IndexedDbStore`: static/PWA browser vault storage
- `ExtensionStore`: browser extension storage with encrypted payloads
- `NativeKeyStore`: optional Tauri/desktop OS keychain adapter

All adapters must store encrypted vault payloads by default. Plaintext export
must be an explicit high-risk operation guarded by policy and warnings.

### 5.3 Crypto Providers

Define a provider interface so Node, browser, and optional WASM can share the
same high-level code:

```ts
export interface CryptoProvider {
  randomBytes(length: number): Uint8Array;
  sha256(data: Uint8Array): Promise<Uint8Array>;
  hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
  hkdfSha256(inputKey: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
  pbkdf2Sha256(password: string, salt: Uint8Array, iterations: number, length: number): Promise<Uint8Array>;
  encryptAead(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<EncryptedPayload>;
  decryptAead(key: Uint8Array, payload: EncryptedPayload, aad?: Uint8Array): Promise<Uint8Array>;
}
```

Providers:

- Browser: WebCrypto first
- Node CLI: Node `crypto.webcrypto` first
- Optional: audited WASM/Rust for BIP-85 edge cases or memory-hard operations

### 5.4 Interfaces

#### CLI

The CLI should be a first-class interface, not an afterthought.

Recommended implementation:

- Node.js + TypeScript
- `commander`, `clipanion`, or `oclif` for command parsing
- `ink` or a minimal terminal UI library for interactive mode, if needed
- JSON output mode for automation
- shell completions
- packaged binary via `pkg`, `nexe`, `tsx` wrapper, or npm executable

Initial CLI command groups should mirror Python:

- `seedpass`
- `seedpass capabilities`
- `seedpass entry ...`
- `seedpass vault ...`
- `seedpass nostr ...`
- `seedpass config ...`
- `seedpass fingerprint ...`
- `seedpass util ...`
- `seedpass agent ...`
- `seedpass semantic ...`

#### Static/PWA Web App

The web app should be local-first and deployable as static files.

Recommended implementation:

- Vite + TypeScript
- small UI framework only if useful; React/Solid/Svelte are acceptable, but
  crypto/core logic must remain framework-independent
- strict Content Security Policy
- no third-party runtime analytics
- encrypted IndexedDB storage
- optional service worker for offline app shell only
- Nostr sync over browser WebSocket

#### Browser Extension

The extension should be focused and permission-minimal.

Recommended implementation:

- Manifest V3
- same TypeScript core
- background service worker for vault session state
- popup for quick search/retrieve
- content scripts only for autofill on active pages
- explicit host permissions or activeTab where possible
- no direct secret exposure to content scripts unless needed for an active fill

Autofill should be staged:

1. active-site lookup and manual copy
2. explicit fill button
3. optional match rules
4. controlled autosuggest
5. never auto-submit by default

#### Desktop App

If a desktop app is desired, prefer Tauri over Electron unless there is a strong
reason to accept Electron's size and larger attack surface.

Tauri can provide:

- filesystem-backed local vault storage
- OS keychain integration
- native clipboard control
- packaged app distribution
- reuse of the static web UI

## 6. Compatibility Requirements

The TypeScript version must preserve these behaviors unless an explicit migration
document says otherwise.

### 6.1 Deterministic Artifact Parity

The same parent seed, profile, entry parameters, and policy must produce the same:

- passwords
- deterministic TOTP secrets
- Nostr keys
- SSH keys, if ported
- PGP keys, if ported
- managed account seeds
- fingerprints
- QR payloads where deterministic

If any artifact cannot be reproduced exactly in TypeScript, the mismatch must be
documented before release and fenced behind a compatibility version.

### 6.2 Vault Compatibility

The TypeScript version must be able to:

- import encrypted Python vault exports
- read and migrate current entry schemas
- preserve tags, links, archived state, notes, custom fields, and modified
  timestamps
- export data that the Python reference can read during the transition window
- preserve KDF metadata and legacy migration behavior

### 6.3 Sync Compatibility

The TypeScript version must support the current Nostr sync model:

- manifest event kind `30070`
- snapshot chunk event kind `30071`
- delta event kind `30072`
- compressed encrypted chunks
- manifest checksums
- deterministic conflict resolution
- tombstones
- stale/replay detection
- relay failure handling

### 6.4 Entry Compatibility

Supported entry kinds:

- `password`
- `totp`
- `ssh`
- `seed`
- `pgp`
- `nostr`
- `key_value`
- `managed_account`
- `document`

Shared fields:

- `type`
- `kind`
- `label`
- `archived`
- `date_added`
- `date_modified`
- `notes`
- `tags`
- `links`
- `modified_ts`

### 6.5 Agent Compatibility

Agent features should be ported after user-facing core functionality, but the
architecture must not block them.

Reference features:

- auth brokers
- scoped tokens
- identities
- one-time/N-use secret leases
- approval gates
- high-risk secret-class isolation
- policy as code
- job profiles and signed templates
- recovery split/drill workflows
- deterministic export controls
- document import/export
- posture checks
- HMAC-chained audit records

## 7. Security Model for Browser-Based SeedPass

Browser support improves usability, but it changes the threat model. The browser
version must explicitly account for:

- XSS
- malicious extensions
- content script isolation failure
- extension permission abuse
- service worker lifecycle surprises
- dependency compromise
- clipboard leakage
- IndexedDB extraction by local malware
- supply-chain attacks on bundled JS
- phishing through lookalike extension/app pages

Required browser rules:

- no plaintext secret storage in `localStorage`
- encrypted vault payloads in IndexedDB or extension storage only
- strict CSP with no inline script
- no remote script loading
- no analytics
- no eval-like APIs
- minimal dependencies
- lockfile and software bill of materials
- deterministic bundled artifact checksums
- extension permissions kept narrow
- content scripts receive only the minimum secret needed for the immediate fill
- secrets cleared from UI and extension background state after timeout
- explicit user action for high-risk reveal/export/parent-seed operations

## 8. Dependency Strategy

Prefer small, audited, stable packages. Avoid convenience dependencies that
increase supply-chain risk in the crypto path.

Likely acceptable categories:

- BIP-39/BIP-85 implementation or audited primitives
- bech32
- secp256k1 / Schnorr / Nostr key support
- QR rendering
- TOTP/HOTP
- CBOR/MessagePack if needed
- zstd/gzip/deflate compression
- schema validation
- test runners

Likely avoid:

- runtime analytics
- UI kits with large transitive dependency trees
- crypto wrappers without clear maintenance
- packages that require remote runtime resources
- dependencies that use dynamic code execution

Every crypto dependency must be listed in a dedicated dependency review doc.

## 9. Repository Strategy

Two viable paths exist.

### Option A: Monorepo Inside Current SeedPass

Pros:

- keeps Python reference and TypeScript port together
- easier parity test generation
- easier docs alignment
- single issue/branch history

Cons:

- repo becomes larger and more complex
- Python and TypeScript tooling live together

Recommended for the initial port.

Suggested layout:

```text
js/
  package.json
  pnpm-workspace.yaml
  packages/
    core/
    cli/
    test-vectors/
  apps/
    web/
    extension/
    desktop/
```

### Option B: New `SeedPass-Web` Repo

Pros:

- cleaner TypeScript-first development
- simpler frontend tooling

Cons:

- harder to keep parity with Python
- more cross-repo coordination
- easier for specs/tests to drift

Recommended only after the TypeScript core has stabilized.

## 10. Build Tooling

Recommended baseline:

- package manager: `pnpm`
- language: TypeScript strict mode
- test runner: `vitest`
- bundler: `vite`
- CLI runtime: Node.js LTS
- web app bundler: Vite
- extension bundler: Vite or WXT
- linting: ESLint
- formatting: Prettier
- schema validation: Zod or Valibot
- docs/test reports: generated markdown and JSON fixtures

The core package must emit both ESM and browser-compatible bundles.

## 11. Milestones

### Milestone 0: Planning and Fixtures

Deliverables:

- this plan reviewed and accepted
- feature inventory generated from `seedpass capabilities --format json`
- Python test-vector generator script
- compatibility matrix for every deterministic artifact
- first dependency review list

Exit criteria:

- at least 20 deterministic fixtures cover password, TOTP, Nostr, seed,
  managed account, vault KDF metadata, and entry schemas
- fixtures can be regenerated from Python with one command

### Milestone 1: TypeScript Core Skeleton

Deliverables:

- `js/packages/core`
- strict TypeScript config
- schema definitions for entries, vaults, manifests, deltas, policies
- crypto provider interface
- Node and browser crypto provider stubs
- fixture loader

Exit criteria:

- TypeScript tests run in Node and browser-like environment
- schemas validate Python-generated fixtures

### Milestone 2: Deterministic Derivation Parity

Deliverables:

- BIP-39 seed parsing
- HKDF domain separation
- password derivation parity
- TOTP secret derivation parity
- Nostr key derivation parity
- managed seed derivation parity
- fingerprint parity

Exit criteria:

- Python-vs-TypeScript parity tests pass for deterministic artifacts
- mismatches are either fixed or formally documented as versioned incompatibilities

### Milestone 3: Vault and Entry Compatibility

Deliverables:

- vault encryption/decryption
- KDF config parsing
- entry CRUD model
- import/export compatibility
- legacy migration support needed for current beta data
- portable backup support

Exit criteria:

- TypeScript imports Python encrypted export fixtures
- TypeScript exports can be read by Python reference where intended
- entry schema roundtrip passes for every supported kind

### Milestone 4: Nostr Sync Compatibility

Deliverables:

- Nostr event model for kinds `30070`, `30071`, `30072`
- chunking and compression
- manifest verification
- delta replay
- conflict merge and tombstone handling
- relay adapter using WebSocket

Exit criteria:

- offline fixture replay matches Python state
- local test relay roundtrip succeeds
- stale/replayed/missing chunk cases are covered

### Milestone 5: Node CLI

Deliverables:

- `seedpass-js` or replacement `seedpass` CLI command
- config/profile management
- entry add/get/search/list/modify/archive/restore/delete
- vault lock/unlock/export/import
- Nostr sync commands
- JSON output mode
- interactive terminal mode MVP

Exit criteria:

- CLI can operate a real encrypted vault from Node
- core commands match Python behavior for fixtures
- CLI usability is good enough to preserve terminal-first workflow

### Milestone 6: Static/PWA Web App

Deliverables:

- app shell
- profile onboarding
- unlock/lock
- entry grid/search/filter/sort
- inspector/detail view
- add/edit/archive/restore/delete
- TOTP display
- QR rendering
- import/export
- Nostr sync controls
- encrypted IndexedDB storage

Exit criteria:

- static build can run without a server backend
- browser tests cover lock/unlock, CRUD, sync fixture replay, and secret reveal timeout
- strict CSP passes

### Milestone 7: Browser Extension

Deliverables:

- MV3 extension shell
- encrypted extension storage
- popup search and quick actions
- active-site match by URL/domain
- explicit fill flow
- TOTP quick display/copy
- content script bridge
- permissions review

Exit criteria:

- extension can retrieve/fill a test login in Chromium and Firefox-compatible target if supported
- content script does not hold vault-wide secrets
- permission set is documented and minimal

### Milestone 8: Agent and Automation Features

Deliverables:

- token model
- identity model
- approval gates
- leases
- policy lint/review/apply
- audit chain
- high-risk secret partition model
- document import/export
- posture checks

Exit criteria:

- core security controls match Python capability map
- CLI JSON mode supports automation workflows
- high-risk operations require explicit approval/token/factor where configured

### Milestone 9: Release and Migration

Deliverables:

- migration guide from Python to TypeScript
- installer/package strategy
- signed releases
- extension store submission plan
- static deployment plan
- rollback plan
- release verification docs

Exit criteria:

- users can export/import or directly migrate from Python vaults
- release artifacts have checksums and signatures
- production beta can run side-by-side with Python reference

## 12. Work Breakdown

### Core Work Packages

1. Python fixture generator
2. TypeScript schema package
3. TypeScript crypto providers
4. deterministic derivation parity
5. entry model and migrations
6. vault encryption and KDF
7. backup import/export
8. Nostr manifests/chunks/deltas
9. conflict merge/tombstones
10. index0/atlas/search
11. policy and agent controls

### Interface Work Packages

1. Node CLI command parser
2. CLI interactive mode
3. CLI JSON automation mode
4. PWA app shell
5. PWA profile/vault management
6. PWA entry workflows
7. PWA Nostr sync
8. extension popup
9. extension content script autofill
10. optional Tauri packaging

### QA Work Packages

1. Python/TypeScript parity tests
2. browser crypto parity tests
3. vault import/export tests
4. Nostr replay tests
5. extension permission tests
6. XSS/CSP tests
7. dependency audit
8. release artifact integrity

## 13. Testing Strategy

### 13.1 Fixture Types

Generate fixture families from Python:

- seeds and fingerprints
- password derivation cases
- TOTP derivation/import cases
- Nostr key cases
- SSH/PGP derivation cases
- managed account seed cases
- entry schema cases for every kind
- encrypted vault export cases
- Nostr manifest/chunk/delta cases
- conflict merge/tombstone cases
- index0/atlas/search cases
- policy/token/approval/lease cases

Each fixture should include:

- input
- expected output
- Python version / commit
- compatibility version
- notes for secret redaction

### 13.2 Test Layers

Core tests:

- deterministic parity
- schema validation
- encryption/decryption
- migration
- sync replay
- conflict resolution

CLI tests:

- command output
- JSON mode
- noninteractive unlock
- file storage
- export/import

Web tests:

- lock/unlock
- IndexedDB encrypted storage
- UI workflows
- CSP
- reveal/copy timeout

Extension tests:

- popup search
- active tab matching
- explicit fill
- service worker session expiry
- permission boundaries

### 13.3 Release Gates

Minimum gates before public beta:

- all TypeScript core tests pass
- Python/TypeScript fixture parity passes
- dependency audit passes or exceptions are documented
- static app CSP check passes
- extension permission review is documented
- encrypted Python vault import works
- Nostr fixture replay works
- CLI JSON mode works for automation

## 14. Migration Strategy

Migration should be explicit and reversible during beta.

Supported paths:

1. Python encrypted export -> TypeScript import
2. TypeScript encrypted export -> Python import, during transition
3. Nostr restore from existing Python-published state
4. seed-only deterministic recovery

The migration UI should:

- detect old schema versions
- show compatibility warnings
- require explicit confirmation before writing migrated data
- keep a pre-migration backup
- avoid publishing migrated Nostr state until the user confirms sync

## 15. UX Principles

### CLI

- preserve fast keyboard-driven workflows
- keep JSON output stable for automation
- make high-risk operations explicit
- support scriptable noninteractive mode without exposing plaintext env secrets

### Web App

- first screen should be the usable vault experience, not marketing
- keep offline mode and sync state visible
- make lock state obvious
- keep reveal/copy actions deliberate
- avoid cluttered admin-console feel while still supporting dense scanning

### Extension

- match current browser context quickly
- reveal/fill only after explicit user action
- never surprise-fill sensitive fields
- show lock state and profile clearly
- keep permissions narrow and understandable

## 16. Open Decisions

1. Should the TypeScript work live in this repo under `js/`, or start as a new
   repo after core parity?
2. Should the first CLI interactive mode be a rich terminal UI or command-first
   with a simple fuzzy picker?
3. Should PGP and SSH derivation be exact parity requirements for the first beta,
   or deferred behind compatibility warnings?
4. Which browser extension target ships first: Chromium only, or Chromium plus
   Firefox from the start?
5. Should the web app ever persist the encrypted parent seed, or require seed
   entry/import per session unless the user explicitly enables encrypted
   persistence?
6. Should a Rust/WASM helper be introduced early for crypto and memory handling,
   or only after TypeScript parity identifies weak spots?
7. What is the public beta cutoff: CLI + web app, or CLI + web app + extension?

## 17. Recommended First Slice

Start with the smallest slice that proves the whole strategy:

1. Add Python fixture generator for deterministic password, TOTP, Nostr key,
   managed seed, and entry schema fixtures.
2. Create `js/packages/core` with strict TypeScript, Vitest, schema validation,
   and crypto provider abstraction.
3. Make TypeScript pass the first fixture set.
4. Add a minimal Node CLI command:

   ```bash
   seedpass-js derive password --fixture fixtures/password-001.json
   seedpass-js capabilities --format json
   ```

5. Document mismatches immediately.

This slice avoids premature UI work and tells the truth about feasibility before
time is spent on polish.

## 18. Success Criteria

The port should be considered successful when:

- a user can manage the same SeedPass vault from CLI, web, and extension surfaces
- deterministic artifacts match Python reference behavior
- existing encrypted vaults and Nostr snapshots can be migrated or restored
- browser usage improves daily ergonomics without weakening high-risk workflows
- the CLI remains a first-class interface
- security controls are preserved or deliberately redesigned with documented
  rationale
- release artifacts are reproducible enough to verify and audit

