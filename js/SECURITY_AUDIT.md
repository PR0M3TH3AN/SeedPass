# SeedPass TypeScript Port — Security Audit

- **Date:** 2026-08-18
- **Auditor:** Claude (Fable 5), full manual source review
- **Scope:** the TypeScript port only — `js/packages/core`, `js/packages/cli`, build/CI supply chain
- **Commit audited:** `e9d8908` (`port/typescript-web-extension`), clean working tree
- **Method:** line-by-line read of every non-test source file (~7,400 lines), cross-checked
  against the Python reference where parity claims matter, plus a full test-suite run as a
  baseline probe. No edits were made to the repository other than this report.

## Verdict

**No critical or high-severity vulnerabilities were found.** The cryptographic core, the
agent trust boundary, the relay sync transport, and the filesystem layer are unusually
well-engineered, with prior audit cycles visibly absorbed into the code. The findings below
are two medium-severity correctness/data-loss issues (one with a reproducible failing test),
a cluster of low-severity hardening and parity gaps, and informational notes. Nothing found
here allows secret extraction by an attacker who does not already hold the seed, the master
password, or same-uid code execution (the documented trust boundary).

Baseline at this commit: `pnpm -r typecheck` clean; **391 of 392 tests pass**. The single
failure is flaky and is the direct evidence for finding M-1.

---

## Findings

### M-1 (Medium) — Restore can non-deterministically return a stale snapshot when two syncs share a second

- **Where:** `js/packages/core/src/sync/syncFlows.ts:115-117` (`fetchLatestSnapshot` sort)
- **What:** Manifests are ordered by `created_at` (Nostr grants only whole-second
  resolution) with the event id as tie-break. The id tie-break is stable and
  relay-independent — but it is *arbitrary with respect to time*. Two snapshots published
  within the same second tie on `created_at`, and the older one wins the id comparison
  roughly half the time. `nostr restore` then silently restores the older vault state;
  entries created between the two syncs disappear with no warning
  (`skippedNewerManifests` stays empty because nothing was *skipped* — the wrong manifest
  simply sorted first).
- **Evidence:** `js/packages/cli/test/nostr.test.ts` — "syncs the vault to the relay and
  restores after local destruction" fails intermittently (reproduced 1 in 4 runs on this
  machine: the restore returned only the earlier test's `pre-sync` entry). This flake is
  not the environment; it is the bug.
- **Impact:** Silent loss of recent entries on restore. Most likely in scripted or
  automated sync flows that publish twice quickly; also gives a relay a small window to
  serve the older of two same-second snapshots with full deniability.
- **Recommendation:** Add a monotonic sequence number inside the (signed) manifest JSON and
  use it as the secondary sort key; alternatively detect a `created_at` tie among
  assemblable manifests and either merge both or surface the ambiguity to the caller. The
  fix must land on the Python side too, or the two implementations will disagree on which
  snapshot is "latest."

### M-2 (Medium) — Config-level password policy is ignored; same entry derives different passwords in TS vs Python — **FIXED 2026-08-18**

- **Where:** `js/packages/core/src/derive/password.ts:53-64` (`resolvePolicy` hardcodes
  defaults); `js/packages/cli/src/secrets.ts:43-49` (only the entry's own `policy` block is
  passed).
- **What:** Python builds its `PasswordGenerator` with
  `policy=self.config_manager.get_password_policy()` (`src/seedpass/core/manager.py:2033`)
  and merges the entry's `policy` block *over that config base*
  (`manager.py:3167-3201`). The TS port merges the entry block over hardcoded defaults
  (`min_* = 2`, specials on). The per-profile config keys (`min_uppercase`, `min_digits`,
  …) exist in the TS config (`configFile.ts` mirrors them) but are never read by
  derivation.
- **Impact:** Any Python profile whose config policy differs from the defaults derives
  **different passwords** in the TS port for entries that carry no explicit policy block.
  To the user this presents as wrong passwords / apparent data loss after migration. Users
  with default config are unaffected.
- **Recommendation:** Thread the profile config's policy fields into
  `materializeSecret`/`generatePassword` as the base policy before applying the entry's
  overrides, and add a cross-implementation fixture with a non-default config policy —
  the current parity suite does not cover this case, which is why it passed.
- **Fix (2026-08-18):** `materializeSecret` takes a `basePolicy` option and merges the
  entry's block over it. All three callers supply the profile config's policy:
  `program.ts` via `basePolicyForOptions` (which reads the config beside the index when
  `--vault` names one directly), `agent.ts` via `loadConfig(join(appDir, fingerprint))`,
  and the TUI via a new `sessionSecret` helper that every menu path now goes through, so
  a future call site cannot silently omit the base. `util generate-password` is
  deliberately unchanged and now documents itself as profile-less: it has no entry and no
  profile, so its flags are the whole policy.
- **Evidence:** `js/packages/cli/test/passwordPolicy.test.ts` — four cases against values
  computed by the Python implementation (config-only v2, entry-overrides-one-field v2,
  config-only v1, and exclude_ambiguous), each also asserted *unequal* to the value the
  pre-fix code produced. Mutation-verified: dropping `basePolicy` from the merge in
  `secrets.ts` turns all four red.

### L-1 (Low) — BIP-85 app-32 path is shared across password, SSH, and PGP derivation

- **Where:** `derive/ssh.ts:47-49`, `derive/pgp.ts:171-175`, `derive/password.ts:175` — all
  three derive from `m/83696968'/32'/{index}'`.
- **What (verified end-to-end):**
  - `ssh@N` and `pgp@N` take the first 32 bytes of the same HMAC-SHA512 digest → **the
    same Ed25519 private key**, byte for byte.
  - `password@N` takes 64 bytes of that digest → the same-index SSH/PGP private key **is
    the first half of the password's input entropy** (the password itself remains safe:
    256 unknown bits survive, and PBKDF2 is one-way — but this violates key-separation
    hygiene, and SSH keys are exactly the kind of secret that gets exported and used).
- **Reachability:** The TS creation path cannot produce the collision — an entry's
  derivation index equals its vault id (`entryOps.ts:270/275, 418/423`), ids are unique
  (`insert` throws on overwrite), and the persisted watermark (`e3b1325`) prevents id
  reuse. It **is** reachable through data: the schema accepts any nonnegative `index` on
  ssh/pgp entries (`schema/entries.ts:78-106`), so Python-created vaults, imported
  backups, and sync merges can carry `ssh@N` and `pgp@N` with equal indices, and the TS
  port will faithfully derive identical keys.
- **Status:** The ssh/pgp collision is a documented known limit shared with Python
  (`docs/agent_security_model.md`). The password-entropy-prefix relationship extends that
  documented finding and does not appear in the docs.
- **Recommendation:** Protocol-level fix (both implementations, versioned): domain-separate
  the three uses — different app numbers or an HKDF step keyed by entry kind. Short term:
  document the password-prefix relationship alongside the existing known limit, and warn
  on import/merge when two entries of different kinds share an app-32 index.

### L-2 (Low) — Concurrent same-id creation on two replicas silently discards one entry at merge

- **Where:** `js/packages/core/src/sync/merge.ts:347-365` (per-id last-writer-wins).
- **What:** The allocation watermark is per-replica. Two devices working offline can both
  allocate id N; the merge resolves per id by timestamp-then-hash, and the losing entry is
  silently replaced — no conflict is recorded or surfaced. Because an id is a permanent
  BIP-85 derivation coordinate, the surviving entry of a different kind may derive related
  key material (see L-1).
- **Impact:** Silent entry loss under a realistic multi-device workflow. Inherent to the
  deterministic-CRDT design and matched by Python (parity-frozen), so this is a design
  finding, not a divergence.
- **Recommendation:** Surface it: the merge already computes everything needed to detect
  "both sides created different-kind entries at the same id" — report those ids in the
  sync/restore summary instead of resolving silently. A protocol-level fix (replica-scoped
  id ranges or random ids) would need coordination with Python.

### L-3 (Low) — Tombstone retention cap enables deletion replay (documented; confirmed)

- **Where:** `merge.ts:17, 405-416` — `TOMBSTONE_RETENTION_CAP = 2048`, oldest evicted.
- **What:** After 2048 deletions, older tombstones are dropped; merging a stale replica or
  an old relay snapshot then resurrects entries the user deleted. Documented as a known
  protocol limit shared with Python; confirmed present and correctly implemented as
  specified.
- **Recommendation:** None beyond the docs' own roadmap; consider counting evictions and
  warning the user when the cap has actually trimmed history.

### L-4 (Low) — Inert settings: the TUI confirms behavior that does not exist — **FIXED 2026-08-18**

- **Where:** `tui/menus.ts:1482-1489` (`additional_backup_path` — the TUI replies
  "Additional backups will be written to X" but no code path ever writes a backup there);
  `tui/menus.ts:1012` (`quick_unlock_enabled` — a toggle with no effect); also stored but
  unused: `backup_interval`, `pin_hash`, `nostr_max_retries`, `nostr_retry_delay`
  (`configFile.ts:26-47`).
- **Impact:** `additional_backup_path` is the harmful one: a user can reasonably believe a
  second copy of their vault exists when it does not — false assurance in a disaster-
  recovery feature. The rest are cosmetic.
- **Note:** This class of bug is known here — commits `135a626`, `933cad3`, `a698255`
  fixed three other inert settings. These are the stragglers.
- **Recommendation:** Either implement them or have the menu say plainly "not available in
  this build," the pattern already used for QR codes and the semantic index.

### L-5 (Low) — Token `label_regex` is unanchored: substring semantics widen token scope — **RESOLVED 2026-08-18 (documented; matches Python)**

- **Where:** `agent.ts:248-255` (`tokenMaySee` uses bare `RegExp.test`); surfaced at
  `program.ts:1318` (`--label-regex`).
- **What:** A token issued with `--label-regex prod` matches every label *containing*
  "prod" — including `not-prod-db`. The operator issuing the token is the one most likely
  to be surprised. (Owner-supplied pathological regexes are also unbounded, but the owner
  can only ReDoS their own daemon — noted, not scored.)
- **Recommendation:** Anchor the pattern (`^(?:${re})$`) or document substring semantics
  loudly in `--label-regex` help and `capabilities()`. Match Python's behavior, whichever
  it is, and add it to the parity matrix.

### L-6 (Low) — Exec allowlist constrains the command word, not its arguments — **DOCUMENTED 2026-08-18**

- **Where:** `agent.ts:337-349`; execution in `sinks.ts:102-121`.
- **What:** `exec_allowlist` compares only the first token. A use-scoped holder may pass
  arbitrary arguments to an allowlisted binary. Sink children inherit the *daemon's*
  stdio, not the caller's, and get a scrubbed env — good — but the child's 1-bit exit code
  is returned per use, and an argument-flexible binary (anything with an output-file or
  network flag) can move `SEEDPASS_SECRET` somewhere the token holder can read.
- **Status:** The docs already state "use can become reveal without an exec allowlist";
  this finding is that the allowlist's containment is weaker than an operator would
  assume even *with* it.
- **Recommendation:** Document that allowlisted binaries must be chosen as if the token
  holder controls their argv; longer term, allow full argv templates in the allowlist
  (`["ssh-add", "-"]`) rather than bare command words.

### L-7 (Low) — Daemon uses wire-supplied `fingerprint` as a path component without format validation — **FIXED 2026-08-18**

- **Where:** `agent.ts:209, 298, 554` (`join(appDir, fingerprint, ...)`); `put` at
  `agent.ts:633-652` accepts any string.
- **What:** The CLI layer validates fingerprints (`appDir.ts:82-92`,
  `/^[0-9A-F]{16}$/`) before they touch a path; the daemon does not. Every reaching path
  first requires the fingerprint to be in `held`, and only the owner-gated `put` populates
  `held` — so exploitation requires the owner capability, i.e. an attacker who has already
  won under the documented same-uid model. Defense-in-depth gap only.
- **Recommendation:** Call `assertValidFingerprint` in the daemon's `put` handler and also
  verify `generateFingerprint(mnemonic) === fingerprint`, which additionally catches an
  honest mismatch corrupting the audit-log location.

### L-8 (Low) — Plaintext backup import is not bound to a profile — **FIXED 2026-08-18**

- **Where:** `program.ts:1549-1606` (`vault import`), `tui/menus.ts:1432-1459`
  (`importDatabase`); wrapper schema in `core/src/vault/portableBackup.ts`.
- **What:** Encrypted (`seed-only`) backups are implicitly seed-bound — decryption fails
  under the wrong profile. Plaintext (`encryption_mode: "none"`) backups carry a
  `fingerprint` field that is **never compared** to the target profile. A plaintext backup
  of vault A imports cleanly into profile B; every derived entry (passwords, SSH, PGP,
  seeds) then silently produces *different* secrets than the originals.
- **Also:** the CLI detects encryption mode with a regex over the raw file text
  (`program.ts:1560`) rather than parsing the JSON. It is not exploitable (JSON string
  escaping prevents a false match), but it is fragile; parse the wrapper instead.
- **Recommendation:** Compare `wrapper.fingerprint` to the target profile's fingerprint
  and require an explicit override on mismatch, in both the CLI and TUI paths.

---

## Informational notes

- **I-1 — Agent socket framing decodes chunks independently.** `agent.ts:699-723` builds
  the line buffer with per-chunk `toString("utf8")`; a multibyte UTF-8 character split
  across TCP chunks corrupts that request (non-ASCII labels are legal). Use
  `string_decoder`. Separately, pipelined requests on one connection get replies in
  completion order with no request ids; the bundled `AgentClient` opens one connection per
  request and is unaffected, but a future client (the planned browser extension) could
  misattribute replies. Consider serializing per-connection handling or adding ids.
- **I-2 — v1 password generation has modulo bias** (`password.ts:179-183`,
  `byte % alphabet.length` over a ~94-char alphabet). Parity-frozen forever by design; v2
  fixed it with rejection sampling. Worth stating in the security docs so it is a known
  property, not a rediscovery.
- **I-3 — Fingerprint normalization is stronger than Python's.** `fingerprint.ts` hashes
  the fully canonicalized mnemonic (NFKD, internal whitespace collapsed); Python's
  `fingerprint.py` uses `strip().lower()` only. A phrase with doubled internal spaces
  produces *different profile identities* across implementations. Edge case; add a parity
  fixture or align Python.
- **I-4 — `token-issue` coerces `name` and `label_regex` with `String()`**
  (`agent.ts:498, 503`) while other wire fields are shape-checked; an array arrives as
  `"a,b"`. Harmless today; shape-check for consistency.
- **I-5 — Token lookup compares secret hashes non-constant-time** (`agent.ts:233-236`).
  Comparing SHA-256 digests of a high-entropy secret; not practically exploitable. The
  owner capability check does use `timingSafeEqual`.
- **I-6 — TOTP index derivation from imported data:** a malformed `index` on an existing
  totp entry makes `nextTotpIndex` return NaN and the subsequent derivation throw
  (`entryOps.ts:117-123`) — a loud failure, not a corruption; noted only.

---

## What was checked and found sound

The following areas were read in full and are called out because they are load-bearing —
and correct:

- **AEAD/vault crypto** (`aead.ts`, `payload.ts`, `fernet.ts`): AES-256-GCM with fresh
  random 12-byte nonces per call; V2/legacy Fernet decrypt-only with HMAC verified before
  decryption using a constant-time compare (which also forecloses a CBC padding oracle);
  format dispatch mirrors Python exactly.
- **Key derivation** (`indexKey.ts`, `passwordKdf.ts`, `bip85.ts`): HKDF-SHA256 with
  domain separation; KDF parameters read from disk are bounded (`KDF_LIMITS`) so a
  tampered kdf block cannot hang the process or allocate gigabytes; mnemonics are
  canonicalized before both validation and derivation; profile KDF default is 200k
  PBKDF2 iterations matching Python (an earlier-session concern about a 100k default was
  wrong — 100k is only a legacy *fallback candidate* on decrypt).
- **Agent daemon** (`agent.ts`): owner ops gated on a capability file outside the app dir
  (0600, `wx`, under `XDG_RUNTIME_DIR`); token auth happens *before* vault decryption
  (closes an enumeration oracle and a CPU-burn probe); missing entry vs. constraint denial
  are indistinguishable; `Object.hasOwn` blocks `__proto__` lookups; TOTP timestamps are
  clamped to ±120 s for token callers; NaN-TTL coercion rejected; connection and
  line-length caps; socket created under a restrictive umask before chmod.
- **Audit log** (`audit.ts`): HMAC chain plus a signed length-pinning head, with exactly
  one crash-skew record tolerated; a missing or mismatched head fails both verification
  and *append*, so truncation cannot be laundered. Honest limits documented in-file.
- **Sinks** (`sinks.ts`): secrets via env or stdin, never argv; child env is an allowlist
  (secrets, tokens, and socket paths do not leak into sink children); clipboard auto-clear
  compares before wiping; EPIPE from an early-exiting child cannot crash the daemon.
- **Relay sync transport** (`events.ts`, `relay.ts`, `snapshot.ts`): every fetched event
  is re-verified against the *requested filter* (authors pinned to the profile's own
  pubkey — relays are not trusted to honor filters), signature-verified, well-formedness
  checked with correct `created_at` type discipline; decompression bombs are killed
  mid-stream against explicit byte budgets; relay downgrade (withholding a chunk) is
  detected and reported via `skippedNewerManifests`; delta replay across snapshot lineages
  is blocked by client-side `#e`-tag re-checking.
- **Merge determinism** (`canonical.ts`, `merge.ts`): CPython-exact canonical JSON
  (ensure_ascii, float repr, code-point key sort) with loud rejection of unsafe integers;
  null-prototype maps make `__proto__` an ordinary key on both entries and tombstones.
- **Filesystem discipline** (`vaultFile.ts`, `appDir.ts`): atomic writes via `wx` temp +
  fsync + rename + directory fsync, short-write loop, fchmod-on-handle (not path);
  fingerprints validated before becoming path components; recursive profile delete
  re-verifies containment; lock files carry owner tokens and are stolen only from
  demonstrably dead pids.
- **CLI egress policy** (`program.ts`, `refs.ts`, TUI): reference-first output with an
  *allowlist* metadata redactor (unknown fields become `has_*` flags — the right polarity
  for loose schemas); plaintext egress is confined to explicitly named commands; token
  mode cannot escalate to owner (`SEEDPASS_TOKEN` blocks mnemonic resolution); new-seed
  generation refuses to write a phrase into a pipe; TUI database export is always
  encrypted (plaintext export exists only behind the CLI's explicit `--plaintext`);
  secret-bearing file writes go through fresh-0600-inode atomic writes with overwrite
  confirmation.
- **Supply chain**: runtime deps are exactly noble/scure crypto + commander + zod, pinned
  by a lockfile with integrity hashes and installed `--frozen-lockfile` in CI; CI runs
  typecheck, tests, a standalone-bundle smoke test, an npm-pack install test, `pnpm audit`,
  and generates a CycloneDX SBOM; the shipped artifact is a single non-minified esbuild
  bundle with a SHA-256 sidecar; official BIP-85 spec vectors run directly against the
  core (`ecff57e`).

## Known limits (documented, verified to match the code)

Per `docs/agent_security_model.md`, and confirmed accurate against this commit: a same-uid
attacker wins (capability file, ptrace); seeds/secrets are not scrubbed from JS memory;
`use` becomes `reveal` without an exec allowlist (and see L-6 for the allowlist's own
limits); the capability file exists on disk for the daemon's lifetime; tombstone replay
(L-3) and the ssh/pgp index collision (L-1) are shared with Python.

## Baseline

```
pnpm -r typecheck   # clean
pnpm -r test        # core: 234/234 pass (jsdom env: 230 pass, 4 skipped)
                    # cli:  157/158 pass — 1 flaky failure = finding M-1
```

---

## Remediation status (2026-08-18, after the audit)

| Finding | State | Where |
|---|---|---|
| M-1 sync tie-break | **open** | needs a signed-manifest sequence number in both implementations |
| M-2 config password policy | fixed | `secrets.ts` `basePolicy`; `test/passwordPolicy.test.ts` |
| L-1 shared BIP-85 app-32 path | open | protocol change, both implementations |
| L-2 concurrent same-id creation | open | surface at merge rather than change it |
| L-3 tombstone replay | open (documented) | as the docs' own roadmap has it |
| L-4 inert settings | fixed | `backups.ts` ports BackupManager's write side; Quick Unlock now says it is unimplemented |
| L-5 unanchored `label_regex` | resolved as-is | matches Python's `re.search`; documented in help, `capabilities()`, the parity matrix, and pinned by tests |
| L-6 exec allowlist scope | documented | help, `capabilities().tokens.exec_allowlist_semantics`, enforcement-point comment |
| L-7 unvalidated `fingerprint` in `put` | fixed | format + seed-match checks in `agent.ts` |
| L-8 unbound plaintext import | fixed | fingerprint binding in CLI and TUI; `parseBackupWrapper` replaces the regex sniff |

Every fix above is mutation-verified: the guard or hook is disabled, the
matching tests are confirmed red, and the change is restored. A passing suite
was not treated as evidence on its own.

Still outstanding, and unchanged by this round: no GPT-family review has run.
Findings from one model family are one perspective, not independence.
