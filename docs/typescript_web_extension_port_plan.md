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

## 4. Design Principles

1. Core before UI:
   implement the shared protocol, schemas, and deterministic functions first.
   UI work should wait until fixtures prove that the TypeScript core can
   reproduce Python behavior.
2. One core, many adapters:
   CLI, web, extension, desktop, and automation surfaces must call the same
   TypeScript core rather than duplicating derivation, vault, or sync logic.
3. Local-first by default:
   normal use must work without a hosted backend. Nostr relay sync is optional
   and remains explicitly user-controlled.
4. Security posture over polish:
   browser ergonomics are valuable only if they do not silently weaken secret
   handling, high-risk approvals, or recovery guarantees.
5. Versioned compatibility:
   every format, derivation, and migration must have an explicit compatibility
   version so unavoidable TypeScript differences can be isolated instead of
   becoming silent regressions.
6. CLI remains first-class:
   the terminal workflow should be preserved as a product surface with equal
   priority to web and extension interfaces.

## 5. Current Python Reference Surface

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

## 6. Reference-to-Spec Governance

The current Python code is the reference implementation, but the TypeScript
project should gradually extract a language-neutral protocol spec. Without this
step, the port risks encoding Python implementation accidents into a second
implementation.

Required spec artifacts:

- `docs/seedpass_protocol_spec.md`: canonical derivation, vault, sync, entry,
  backup, and migration behavior
- `docs/typescript_port_compatibility_matrix.md`: feature-by-feature parity
  status, fixture coverage, and known mismatches
- `docs/typescript_dependency_review.md`: dependency and supply-chain review for
  TypeScript, browser, extension, and optional WASM packages
- `docs/browser_security_model.md`: browser/PWA/extension-specific threat model
  and mitigations
- `js/packages/test-vectors/fixtures/manifest.json`: fixture inventory with
  Python commit, fixture version, secret-redaction policy, and expected outputs

Governance rules:

- Python behavior is normative until a protocol spec section is marked
  `accepted`.
- Once a spec section is accepted, both Python and TypeScript should be tested
  against the spec fixtures.
- Any intentional TypeScript divergence must include:
  - a compatibility version
  - a migration or fallback path
  - user-visible release notes
  - tests proving old and new behavior are not silently confused
- The TypeScript core cannot become authoritative until the P0 compatibility
  matrix is green.

## 7. Target Architecture

### 7.1 Shared Core

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

### 7.2 Storage Adapters

Use explicit adapters instead of letting each interface invent storage behavior.

Required adapters:

- `MemoryStore`: tests and ephemeral sessions
- `NodeFileStore`: CLI vault files, backups, audit log
- `IndexedDbStore`: static/PWA browser vault storage
- `ExtensionStore`: browser extension storage with encrypted payloads
- `NativeKeyStore`: optional Tauri/desktop OS keychain adapter

All adapters must store encrypted vault payloads by default. Plaintext export
must be an explicit high-risk operation guarded by policy and warnings.

### 7.3 Crypto Providers

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

Implementation cautions:

- WebCrypto does not expose every primitive in the same shape as Python
  dependencies. Do not assume parity until fixtures prove byte-for-byte output.
- AES-GCM, PBKDF2, HKDF, HMAC, and SHA-256 are realistic browser targets.
- secp256k1/Schnorr/Nostr, BIP-85, PGP, and SSH key generation may require
  carefully selected third-party libraries or WASM.
- Argon2 support is not native in WebCrypto and requires a reviewed WASM or JS
  implementation if Argon2 parity is required.
- PGP parity is a likely risk area because Python currently relies on PGPy
  behavior, and browser PGP libraries may serialize keys differently.

### 7.4 Interfaces

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

## 8. Compatibility Requirements

The TypeScript version must preserve these behaviors unless an explicit migration
document says otherwise.

### 8.1 Deterministic Artifact Parity

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

### 8.2 Vault Compatibility

The TypeScript version must be able to:

- import encrypted Python vault exports
- read and migrate current entry schemas
- preserve tags, links, archived state, notes, custom fields, and modified
  timestamps
- export data that the Python reference can read during the transition window
- preserve KDF metadata and legacy migration behavior

### 8.3 Sync Compatibility

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

### 8.4 Entry Compatibility

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

### 8.5 Compatibility Priority Matrix

| Area | Priority | Required before first public TypeScript beta | Notes |
|---|---|---:|---|
| Password derivation | P0 | Yes | Core product identity; must be byte-for-byte compatible. |
| BIP-39 seed handling | P0 | Yes | Required for seed-first recovery. |
| BIP-85 managed seeds | P0 | Yes | Required for managed account workflows. |
| Fingerprints | P0 | Yes | Required for profile identity and migration confidence. |
| Vault decrypt/import | P0 | Yes | Existing users must not be stranded. |
| Entry schemas | P0 | Yes | All current kinds must roundtrip even if some derived artifacts are deferred. |
| Nostr manifest/chunk restore | P0 | Yes | Existing Nostr recovery path must work before broad beta. |
| Deterministic conflict merge | P0 | Yes | Prevents cross-client state corruption. |
| TOTP | P1 | Strongly preferred | Product-relevant, but can be staged if password/vault parity lands first. |
| Nostr keys | P1 | Strongly preferred | Needed for complete Nostr workflows. |
| SSH keys | P1 | Maybe | Can be imported/roundtripped before exact derivation is complete. |
| PGP keys | P1/P2 | Maybe | Highest parity risk; may require compatibility warning. |
| Semantic search | P2 | No | Local derived index can be rebuilt and may differ by implementation. |
| TUI v3 visual layout | P2 | No | UI should be redesigned for web/extension instead of copied. |
| Agent controls | P2 | No | Architecture should preserve them, but full port can come after user core. |

### 8.6 Agent Compatibility

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

## 9. Security Model for Browser-Based SeedPass

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

### 9.1 Browser Secret-Handling Requirements

The browser version cannot guarantee perfect memory erasure. It should still
reduce exposure by design:

- keep decrypted vault state in memory only while unlocked
- store only encrypted payloads at rest
- derive session keys after unlock instead of persisting them
- minimize React/component state copies of secret values
- avoid placing secrets in URLs, DOM attributes, logs, analytics, or error
  messages
- clear clipboard after a short user-configurable timeout when the platform
  permits it
- require a fresh unlock or high-risk factor for parent seed, private key, full
  export, and destructive migration flows
- use separate message types for metadata queries and secret retrieval in the
  extension background/content-script boundary

### 9.2 Extension Boundary Rules

The extension must treat content scripts as less trusted than the extension
background/popup state.

Required rules:

- content scripts may request a fill for the current tab; they must not receive
  vault-wide data
- popup/background must verify active tab origin before returning a fill payload
- fill payloads should be single-use and short-lived
- extension storage must not contain plaintext secrets
- autofill should never submit forms automatically by default
- site matching must be explainable to the user before filling
- extension permissions must be documented in release notes and reviewed before
  store submission

## 10. Dependency Strategy

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

## 11. Repository Strategy

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

## 12. Build Tooling

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

## 13. Milestones

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
- compatibility matrix includes P0/P1/P2 status for every current feature

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
- package exports are side-effect-free and do not import Node or browser APIs
  from shared schema modules

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
- P0 derivations pass in both Node and browser-compatible test environments

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
- migration refuses unknown future schema versions instead of silently writing
  incompatible data

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
- restored state is not published back to relays until the user explicitly
  confirms migration/sync

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
- CLI supports `--format json` for machine-readable command output where
  Python already exposes automation behavior

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
- app can be opened from static hosting and does not require a server process
  for normal vault operations

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
- extension service worker session expiry is tested so unlocked state does not
  persist indefinitely by accident

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
- audit records can be verified after cross-process CLI runs

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
- rollback path is tested with a migrated fixture before public release

## 14. Work Breakdown

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

## 15. Testing Strategy

### 15.1 Fixture Types

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

Fixture safety rules:

- fixtures must not contain Adam's real seed, vault, passwords, keys, or Nostr
  secrets
- use deterministic test mnemonics only
- fixture names should make it obvious when values are fake
- if a fixture includes a secret-shaped expected output, it must live under
  `test-vectors/` and be labeled as generated test material
- never publish a fixture generated from a live profile

### 15.2 Test Layers

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

### 15.3 Release Gates

Minimum gates before public beta:

- all TypeScript core tests pass
- Python/TypeScript fixture parity passes
- dependency audit passes or exceptions are documented
- static app CSP check passes
- extension permission review is documented
- encrypted Python vault import works
- Nostr fixture replay works
- CLI JSON mode works for automation

## 16. Migration Strategy

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

## 17. UX Principles

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

## 18. Portability Risk Register

| Risk | Severity | Why it matters | Mitigation |
|---|---|---|---|
| PGP byte-for-byte parity fails | High | Different PGP libraries may serialize keys differently. | Treat PGP as P1/P2 until fixtures prove parity; preserve import/roundtrip first. |
| Browser memory exposure | High | JS cannot guarantee strong zeroization. | Minimize secret copies, lock quickly, isolate high-risk flows, document limits. |
| Extension content script leakage | High | Content scripts run near untrusted page DOMs. | Keep vault state in background/popup; send only single-use fill payloads. |
| Nostr replay/stale restore bug | High | Could corrupt or roll back vault state. | Fixture replay tests, tombstone tests, explicit sync confirmation after migration. |
| Dependency supply-chain attack | High | Frontend dependencies expand attack surface. | Minimal dependency set, lockfile, audit, dependency review, signed artifacts. |
| Python/TypeScript silent derivation drift | Critical | Users could regenerate wrong passwords. | P0 parity fixtures before beta; compatibility versioning; no silent fallback. |
| Static app hosted from compromised origin | Medium | Static hosting can serve malicious JS. | Signed release bundles, checksums, extension/desktop packaging, verification docs. |
| CLI and web behavior drift | Medium | Multi-interface product could fragment. | One shared core, cross-interface fixture tests, capability map parity. |

## 19. Recommended Defaults for Open Decisions

These defaults should stand unless maintainers intentionally choose otherwise:

1. Start in this repo under `js/` so Python parity fixtures and TypeScript code
   evolve together.
2. Build the command-first CLI before a rich terminal UI. Add a fuzzy/interactive
   mode after core command behavior is stable.
3. Require P0 parity for passwords, seeds, fingerprints, vault import, and Nostr
   restore before beta. Defer exact PGP/SSH derivation if needed, while preserving
   import and schema roundtrip.
4. Ship Chromium extension first if cross-browser support slows the first beta.
   Keep Firefox compatibility in the architecture.
5. Do not persist the parent seed by default in the web app. Allow encrypted
   persistence only behind an explicit setting and warning.
6. Do not introduce Rust/WASM until fixture work proves where TypeScript/WebCrypto
   is insufficient, except for primitives such as Argon2 if required.
7. Public beta should target CLI + static/PWA first, then extension. The extension
   should not block core parity.

## 20. Open Decisions

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

## 21. Recommended First Slice

Start with the smallest slice that proves the whole strategy:

1. Add a Python fixture generator, for example
   `scripts/generate_ts_port_fixtures.py`, covering deterministic password,
   TOTP, Nostr key, managed seed, fingerprint, entry schema, and a small
   encrypted vault export.
2. Create `js/` with `pnpm-workspace.yaml`, `packages/core`, and
   `packages/test-vectors`.
3. Add strict TypeScript, Vitest, schema validation, and crypto provider
   abstraction.
4. Make TypeScript pass the first fixture set in Node.
5. Add a browser-compatible test run for the same fixture set.
6. Add a minimal Node CLI command:

   ```bash
   seedpass-js derive password --fixture fixtures/password-001.json
   seedpass-js capabilities --format json
   ```

7. Document mismatches immediately in
   `docs/typescript_port_compatibility_matrix.md`.

This slice avoids premature UI work and tells the truth about feasibility before
time is spent on polish.

Exit criteria for this first slice:

- `pnpm test` passes in `js/`
- fixture generator output is deterministic across two runs
- at least one Python-generated encrypted vault fixture validates in TypeScript
- P0 derivation fixtures pass in Node
- browser-compatible test environment passes the same P0 derivation fixtures
- no web app or extension UI work has started before core fixture parity

## 22. Success Criteria

The port should be considered successful when:

- a user can manage the same SeedPass vault from CLI, web, and extension surfaces
- deterministic artifacts match Python reference behavior
- existing encrypted vaults and Nostr snapshots can be migrated or restored
- browser usage improves daily ergonomics without weakening high-risk workflows
- the CLI remains a first-class interface
- security controls are preserved or deliberately redesigned with documented
  rationale
- release artifacts are reproducible enough to verify and audit
