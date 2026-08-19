# SeedPass TODO

This file tracks the remaining work from the latest bug search and security evaluation.

## Entropy audit (2026-07-31)

[`docs/entropy_audit_2026-07-31.md`](docs/entropy_audit_2026-07-31.md) — RNG and
randomness-integration audit. **No predictable-fallback defect:** every non-deterministic secret
uses `os.urandom` / `secrets`, and the `random` module is not imported anywhere in non-test source.

**Read the compatibility constraint in that document before touching
`core/password_generation.py`.** Passwords are never stored — they are re-derived on demand from
`(seed, index, length, policy, gen_version)`. Entries now carry `gen_version`, and an absent field
means v1. **The rule is permanent: never alter the output of a version that already exists in the
wild.** v1 is frozen; a fix that changes derivation goes into a new version, never into an old one.
`src/tests/test_entropy_integrity.py` enforces this with 18 v1 vectors — a failure there is never
"update the expected value".

- [x] **M4 (done)** — v1 password vectors frozen, plus fail-closed RNG tests, in
      `src/tests/test_entropy_integrity.py` (26 tests, inside the `--determinism-only` CI gate).
      18 vectors cover every policy and both sides of the 32-byte stream-wrap boundary.
      Mutation-verified: removing `_balance_distribution` (M1), altering the `DeterministicStream`
      wrap (M3) and changing the character mapping (M2) each turn all 18 red; adding a
      hash-of-timestamp fallback to `generate_bip85_seed` turns the fail-closed test red.
      **M1/M2/M3 are now safe to attempt.**
- [x] **L1 (done)** — deleted the dead HKDF block in `_derive_password_entropy`, dropped the three
      now-unused imports (`HKDF`, `hashes`, `default_backend`), and corrected the docstrings that
      named HKDF instead of PBKDF2. Verified as a negative control: all 18 v1 vectors stayed green,
      confirming the harness does not produce false alarms on behaviour-preserving edits.
- [x] **M1 / M2 / M3 (done)** — password generation is now versioned. `gen_version` defaults to 1
      everywhere, so existing entries and every untouched caller keep deriving v1 byte-identically;
      new password entries are stamped `gen_version: 2`. v2 drops the forced equal-quarters class
      quota (M1), draws by rejection sampling (M2) from an unbounded HMAC-expanded stream (M3), and
      enforces only the policy minima — choosing donor positions from classes that have a surplus,
      so raising one minimum can no longer break another.

      Measured at length 16 over 200 samples: v1 produced **1** distinct class composition, v2
      produces **82**. Per-character entropy 6.42 → 6.53 bits against a 6.555 ceiling. Chi-square
      96.1 (df=93) confirms the modulo bias is gone; lag-32 repeat rate sits within one standard
      error of chance, confirming the repeating pad is gone.
- [ ] **Opt-in upgrade UX for existing entries** — a per-entry action that re-derives at v2, with a
      confirmation making the consequence unmissable ("this changes the password; update it at the
      site first"). Never bulk-migrate. Until this ships, existing entries stay on v1 by design.
- [x] **L2 (done)** — `generate_bip85_seed(words_num=...)` accepts 12 or 24 and rejects anything
      else; threaded through `create_profile_from_generated_seed`. Default stays 12 so existing
      profiles and callers are unaffected.
- [x] **L3 (done for the RNG path)** — `os.urandom(32)` moved outside the try block in
      `generate_bip85_seed`, so no handler can stand between the entropy draw and the caller, and
      the redundant duplicate `except Exception` is gone. A test asserts the `OSError` arrives as
      the same object that was thrown, which is only true if nothing repackaged it.
- [x] **L4 (code fixes done)** — `torch/` temp filename now uses `randomBytes(8)`; the
      `Math.random` value misnamed `nonce` in `relay-health.mjs` is now `probeSuffix` from
      `randomBytes(6)`.
- [ ] **⚠️ Decision needed: `torch/_backups/` holds 5240 tracked files** across six dated
      snapshots. Untracking is a large deletion, so it is not an audit side effect. Costs today:
      duplicates every security grep hit, and bare `node --test` in `torch/` discovers them and
      fails 18 tests from stale snapshot code (`npm test` uses explicit paths, so CI is unaffected).
      Separately: `torch/` has no `test/` directory in the repo, so its `npm test` cannot run as
      written.
- [x] **L5 (done)** — `dependency-audit.yml` generates and uploads a CycloneDX SBOM from
      `requirements.lock`. Verified with the real tool: CycloneDX 1.6, 96 components, crypto chain
      recorded at exact versions.

The remaining broad `except Exception` handlers in `password_generation.py` wrap deterministic
derivation with no RNG in it and re-raise rather than substituting; they belong to the Robustness
item further down, not to this audit.

## Security

- [ ] Complete checklist item #8 (Supply chain and release integrity):
  - run one tagged release through `.github/workflows/release-integrity.yml` and link evidence in `docs/security_readiness_checklist.md`
  - resolve or formally time-box/own the `GHSA-wj6h-64fc-37mp` exception (`docs/supply_chain_release_integrity.md`)
  - enforce release/tag protections requiring `Release Integrity` + dependency audit checks
  - publish maintainer/consumer verification runbook (checksum + cosign verification with expected issuer/identity) ✅ `docs/release_verification_runbook.md`
- [ ] Upgrade vulnerable runtime dependencies in lockfiles and packaging inputs:
  - `aiohttp` -> `>=3.13.3`
  - `cryptography` -> `>=46.0.5`
  - `starlette` -> `>=0.49.1`
  - `python-multipart` -> `>=0.0.22`
  - `urllib3` -> `>=2.6.3`
  - `pynacl` -> `>=1.6.2`
  - `pillow` -> `>=12.1.1`
  - `orjson`, `pyasn1`, `cbor2` and other `pip-audit` findings
- [ ] Regenerate `requirements.lock` after upgrades and re-run the full test suite.
- [ ] Re-run `pip-audit -r requirements.lock` and ensure zero actionable runtime vulnerabilities.
- [ ] Evaluate the `Crypto.*` imports in `src/seedpass/core/password_generation.py` and either:
  - keep `pycryptodome` intentionally with explicit documentation, or
  - migrate RSA generation to `cryptography` APIs.

## Robustness

- [ ] Replace broad `except Exception: pass` blocks with explicit exceptions + logging:
  - `src/main.py`
  - `src/seedpass/core/manager.py`
  - `src/seedpass/core/menu_handler.py`
- [ ] Add telemetry-safe logs for swallowed error paths without exposing secrets.
- [ ] Harden startup/restore prompt flows against `EOFError` / cancellation loops:
  - startup options (`Continue` / `Restore from backup`)
  - restore-backup fingerprint/path prompts
  - ensure graceful return-to-menu instead of process-level failure.

## Tests To Add

- [ ] Add deterministic tests for `derive_pgp_key(..., key_type="rsa")` covering:
  - stable output across repeated runs
  - key fingerprint format and validity
- [ ] Add API rate-limit tests for:
  - per-client isolation
  - window expiry behavior
  - restart/reset behavior after `start_server()`
- [ ] Add API import tests for boundary conditions:
  - exactly-at-limit upload size
  - malformed multipart payload
  - invalid JSON body for path-based import
- [ ] Add regression tests for manager notification/logging fallback paths currently guarded by broad exception handling.

## Documentation

- [ ] Document API import upload limit (`SEEDPASS_MAX_IMPORT_BYTES`) in user docs.
- [ ] Add a security maintenance section describing dependency-audit cadence and update policy.

## TypeScript port (`port/typescript-web-extension`)

Branch state as of 2026-08-17: core + CLI + interactive TUI are feature-complete
for daily use and cross-verified against Python on every change. What follows is
everything still open, in the order it should be tackled.

### Blockers before real secrets

- [ ] **Independent security review of the TypeScript branch.** Review
      strategy (decided 2026-08-18): two AI families plus vectors, because
      they fail differently. (1) `/code-review ultra` — **blocked**: PR #989
      spans main→port including beta's 150 commits (6795 files/720k lines),
      over ultra's size limit; fallback options are a review-only PR
      containing just the `js/` tree against main, or a narrower local-diff
      target. (2) A GPT-family pass (Codex) over the four ranked targets in
      the PR body, briefed to REFUTE the security claims in file comments,
      not summarize them. (3) Third-party ground truth where possible: the
      official BIP-85 spec vectors now run directly against the TS core
      (test/bip85SpecVectors.test.ts; Python has had them all along), which
      closes the both-implementations-agree-and-are-both-wrong hole for the
      root derivation. Triage rule for findings: flagged by both families =
      almost certainly real; flagged by one = verify against code, arbiter
      is a reproduction test or the cross-impl suite, never the author's
      opinion alone. No one but the
      authoring agent has read this code. Two earlier review rounds on this
      project each found criticals that self-review missed, so a green suite and
      an author's sign-off are not evidence of much. Scope it to
      `js/packages/core/src/crypto`, `js/packages/core/src/derive`, and
      `js/packages/cli/src/agent.ts` first: a derivation bug does not throw, it
      quietly produces a secret that cannot be recovered. Blocks the merge below.
- [ ] **Fix the findings from the 2026-08-17 self-review** (next section). Do
      these before handing the branch to an outside reviewer so their time goes
      on what an author cannot see.

### Findings from the 2026-08-17 self-review

Found by reading and probing, not by the suite — all 128 CLI tests passed
before and after each was confirmed. Ordered by severity.

- [x] **(fixed 2026-08-17)** **The agent can be left holding a parent seed
      forever, after reporting failure.** `AgentDaemon.handle`'s `put` writes to `this.held` *before*
      awaiting the audit append. A non-numeric `ttl` makes `expiresAt` NaN; the
      audit write then throws on the non-finite number, so the caller is told
      the unlock failed — but the seed is resident, `expire()`'s
      `held.expiresAt <= now` is false forever, and no audit record exists
      saying the vault was ever unlocked. Confirmed: `owner-mnemonic` returned
      the full phrase 3.5s after a "failed" put on an agent with a 1s TTL.
      Fix: validate `ttl`/`uses`/`expires_at` as finite positive integers at the
      daemon boundary, and order every op so state is committed only after its
      audit record lands. The CLI's `parseIntOption` already blocks this path,
      which is exactly why the daemon must not rely on it — `agent.ts:1-22`
      states the CLI is untrusted, and the browser extension will be the next
      thing speaking this protocol.
- [x] **(fixed 2026-08-17)** **A `use`-scoped token holder can kill the agent
      and drop every held seed.** `stdinSink` writes to `child.stdin` with no `error` listener, so a
      command that exits before draining stdin raises an unhandled EPIPE.
      Confirmed as an uncaught exception inside the agent process via a
      `use-sink` request naming `/bin/true`; `main.ts` installs no
      `uncaughtException` handler, so the real `agent start` process exits.
      The exec allowlist does not help — any allowlisted command that exits
      early does it. This is the least-privileged principal in the model taking
      down the enforcement point. Fix: handle `stdin` errors the way
      `feedClipboardTool` already does, and treat EPIPE as a delivery failure.
- [x] **(fixed 2026-08-17)** **Secrets sent to the clipboard are never cleared.** Python's
      `copy_to_clipboard(text, timeout)` starts a timer and clears the clipboard
      if the value is unchanged; the TypeScript `clipboardSink` just writes and
      returns. `clipboard_clear_delay: 45` is in the default config, is
      settable, and is read by nothing. This makes TUI **Secret Mode** — whose
      entire purpose is to route secrets away from the screen — strictly less
      safe than Python's, because it parks them on a session-wide clipboard
      indefinitely.
- [x] **(fixed 2026-08-17)** **`kdf_iterations` is inert.** Settings displays it, stores it, and tells
      the user "use Change password to re-wrap this profile's seed at the new
      strength". `changePassword` takes an `iterations` parameter and the TUI
      never passes it, and `createProfile` hardcodes
      `DEFAULT_PBKDF2_ITERATIONS`. Raising it changes nothing anywhere. Either
      wire it through both paths or remove the setting — a security control that
      silently does nothing is worse than an absent one.
- [x] **(fixed 2026-08-17)** **`inactivity_timeout` is inert.** Stored, displayed, settable as Settings
      item 12, enforced nowhere. Python's TUI locks the vault after it lapses;
      the TypeScript TUI leaves an unattended terminal unlocked indefinitely.
- [x] **(fixed 2026-08-17)** **TUI file exports do not get the 0600 they claim.** `menus.ts` writes
      document exports, database exports and the 2FA export with
      `writeFile(..., {mode: 0o600})`. `mode` applies only at creation, so
      writing over an existing 0644 file leaves it 0644 — verified. The 2FA
      export is every TOTP secret in the vault in plaintext, and its comment
      asserts the 0600. The CLI already does this correctly with `atomicWrite`
      (fresh inode + rename, symlink-safe) and explains why; the TUI regressed
      it. The TUI exports also silently overwrite, where the CLI requires
      `--overwrite`.
- [x] **(fixed 2026-08-17)** **Audit-log truncation detection is defeated by deleting one more file.**
      `AuditLog.verify` skips the count check entirely when `audit.log.head` is
      absent, so removing the head and truncating the log verifies clean. The
      head sits beside the log with the same permissions, so anyone who can
      alter one can remove the other. The doc comment claims the head "pins the
      expected length" against exactly this attack. Either require the head once
      the log exists, or keep it somewhere the log's writer cannot reach.
- [x] **(fixed 2026-08-17)** **Unvalidated token constraint shapes.** `token-issue` casts `kinds` and
      `scopes` without checking they are arrays. `kinds: "totp"` makes
      `Array.includes` become `String.includes`, turning an exact kind match into
      a substring match — inert today only because no SeedPass kind is a
      substring of another. `scopes: "reveal"` throws a raw TypeError back to
      the caller. Owner-gated, so this is hardening, not a live hole.
- [x] **(fixed 2026-08-17)** **Dead code that reads as a control.** `authorize()`'s `if (entry)` branch
      is never reached (both call sites omit the argument; the real check is
      `tokenMaySee`), and `sinkEnv`'s `FORBIDDEN_ENV` delete loop runs against an
      allowlist that never contains those keys. Both look like defenses on
      inspection. Remove them or make them load-bearing.
- [x] **(resolved 2026-08-17: confirmed deliberate, documented in authorize())** **A denied entry lookup still burns a token use.** `resolveForToken`
      consumes a use at pre-auth, before the entry is known, so probing for
      non-existent ids exhausts a token. That ordering is deliberate
      anti-enumeration; confirm it is the trade wanted and write it down.

### Findings from the 2026-08-18 independent audit

Full report: [`js/SECURITY_AUDIT.md`](js/SECURITY_AUDIT.md) (Fable 5, line-by-line read
of every non-test source file at `e9d8908`). Verdict: no criticals or highs. This is one
AI family; the GPT-family pass in the blocker above is still outstanding and is what makes
the review independent in the sense that matters.

- [x] **(fixed 2026-08-18) M-2 — the profile config's password policy was ignored.**
      Python bases derivation on `config_manager.get_password_policy()` and merges the
      entry's `policy` block over it; the port merged the entry block over hardcoded
      defaults and never read the config. Any profile with a non-default policy therefore
      derived **different passwords** in TS than in Python, for every entry — reaching the
      user as a wrong password, i.e. as data loss, with nothing failing anywhere.
      `materializeSecret` now takes a `basePolicy`; the CLI, the agent and the TUI all
      supply the profile config's policy, the TUI through a `sessionSecret` helper so no
      menu path can omit it. Evidence:
      `js/packages/cli/test/passwordPolicy.test.ts`, four cases against Python-computed
      values, each also asserted unequal to the pre-fix output; mutation-verified (drop
      `basePolicy` from the merge and all four go red).
- [x] **(fixed 2026-08-19) M-1 — restore could return a stale snapshot when two syncs
      landed in the same second.** Manifests now carry `published_ms`, a monotonic
      publication timestamp inside the signed JSON, and both implementations order by it.
      Python additionally stopped delegating "which snapshot is newest" to the relay (it
      asked for `limit(1)` and restored whatever came back). Backwards compatible: a
      manifest without the field orders at the start of its `created_at` second. The nostr
      CLI test went from ~1-in-4 failures to 6/6 clean runs.
      **Found while fixing:** Python's `publish_delta` republishes the manifest and needed
      the field too (without it the manifest carrying the newest `delta_since` sorted below
      the snapshot it superseded, so readers fetched deltas from a stale watermark), and
      raising the fetch limit turned a vestigial fallback loop into a live downgrade path —
      now it skips relay noise but refuses to reach past the newest manifest that parses.
- [x] **(mitigated 2026-08-19) L-1 — BIP-85 app-32 is shared across password, SSH and PGP.**
      Detection shipped in both implementations (`findDerivationCollisions` /
      `find_derivation_collisions`), wired into import, `--inspect`, restore's merge, the
      TUI, and a new `util check-derivation`. The lead test in each derives the keys and
      compares bytes, so the claim is verified rather than asserted.
      **The derivation change is deliberately deferred**, see the v2 design below.
- [x] **(surfaced 2026-08-19) L-2 / L-3 — merge-level loss that is silent rather than
      wrong.** Both implementations gained an optional `MergeReport`: same-id conflicts
      (naming the kept and discarded entries) and a count of tombstones evicted at the
      retention cap. `nostr restore` reports both. The resolution itself is unchanged —
      it is frozen for parity — and the collector is write-only, asserted in both
      implementations, because if observing could change the outcome it would be a
      divergence rather than an observation.
      **Found while fixing:** Python's `merge_index_payloads` mutated its `current`
      argument (shallow copy sharing the nested entries dict), and an existing idempotency
      test was passing only because of that aliasing.

### L-1 v2 derivation: designed, deliberately not yet implemented

Domain-separate the three app-32 uses so `ssh@N`, `pgp@N` and `password@N` stop
sharing key material. Sketch, for whoever picks this up:

- Keep v1 exactly as it is, forever — existing SSH keys are on servers and in
  forges, existing PGP keys are published. Nothing already derived may change.
- Add `derivation_version` to ssh/pgp entries, absent meaning 1, exactly as
  `gen_version` works for passwords. New entries are stamped 2.
- v2 takes the app-32 entropy and applies one HMAC-SHA256 step with a
  kind-specific info string (`seedpass:v2:ssh`, `seedpass:v2:pgp`,
  `seedpass:v2:password`). Prefer this over new BIP-85 app numbers, which risk
  colliding with future registrations.
- Land it in both implementations in one change, with cross-impl fixtures, and
  an opt-in per-entry upgrade action — never a bulk migration. The same
  "this changes the key; rotate it at the server first" confirmation the
  password v2 upgrade needs.

**Sequencing:** this is a new derivation path, and this project's own rule is
that a derivation bug does not throw — it quietly produces a secret that
cannot be recovered. Adding one immediately before the first outside review
inverts the point of the review. Do it after.
- [x] **(fixed 2026-08-18) L-4 — inert settings, and the unported subsystem behind them.**
      `additional_backup_path` was stored, confirmed by the TUI ("Additional backups will
      be written to X") and used by nothing — false assurance in a disaster-recovery
      feature. The cause was bigger than the setting: Python's `BackupManager` was not
      ported at all, so `backup_interval` was dead for the same reason. New
      `js/packages/cli/src/backups.ts` ports the write side — every committed mutation
      snapshots the encrypted index to `<profile>/backups/entries_db_backup_<ts>.json.enc`
      at 0600 and mirrors it to the configured second location as
      `<fingerprint>_<name>`, filenames matching Python byte for byte so both
      implementations share one backup directory. Two documented deviations: the interval
      throttle reads the newest snapshot on disk rather than Python's in-memory
      `_last_backup_time` (every CLI command is its own process, so an in-memory counter
      would leave `backup_interval` inert for CLI use), and a failed mirror is surfaced
      rather than swallowed. Quick Unlock stays in the menu for item-order parity but now
      says it is unimplemented — in Python the flag never changed unlocking either, it
      writes an audit entry and raises a security finding.
      **Not ported:** `restore_latest_backup` (nothing in the TUI offers it; `vault import`
      and `nostr restore` cover recovery), and `nostr_max_retries` / `nostr_retry_delay`
      remain stored-but-unused.
- [x] **(resolved 2026-08-18) L-5 — `label_regex` is unanchored.** Left as-is deliberately:
      Python matches with `re.search`, so anchoring the TS side alone would make one token
      mean two different things depending on which implementation holds it, and would
      silently narrow every token already issued. Now stated in `--label-regex` help,
      reported as `capabilities().tokens.label_regex_semantics`, explained at the
      enforcement point, recorded in `docs/typescript_port_compatibility_matrix.md`, and
      pinned by tests asserting an unanchored token sees BOTH `prod` and `not-prod-db`.
- [x] **(documented 2026-08-18) L-6 — exec allowlist covers the command word, not argv.**
      The token holder writes the arguments and the child gets the secret in its
      environment, so an allowlisted binary with an output-file or network flag returns the
      secret to its caller. Documented in help, `capabilities()`, and at the check itself.
      Argument-level containment means allowlisting full argv templates instead of command
      words — a token-format change that has to land in both implementations together, so
      it stays a backlog item rather than a quiet divergence.
- [x] **(fixed 2026-08-18) L-7 — daemon `put` accepted any string as a fingerprint.**
      Now requires 16 uppercase hex *and* that the fingerprint belongs to the supplied
      seed. Ordered after the ttl check on purpose: deriving a fingerprint runs the BIP-39
      KDF, and a malformed ttl should not pay for it.
- [x] **(fixed 2026-08-18) L-8 — plaintext backup import was not bound to a profile.**
      A seed-only backup is implicitly seed-bound; a plaintext one imports into any profile
      and is then re-derived from the *target* seed, so every password, SSH key, PGP key and
      seed silently differs from what the backup was taken to preserve, with nothing
      erroring. CLI and TUI now compare the wrapper's fingerprint to the target and require
      an explicit override (`--allow-fingerprint-mismatch`, or a confirmation in the TUI);
      `vault import --inspect` reports the backup's fingerprint and encryption mode. The
      CLI also stops deciding encryption mode by regex over the raw file —
      `parseBackupWrapper` reads the envelope instead.

### Cutover

- [ ] Fold the CLI bundle's `.sha256` into the `release-integrity` signing
      workflow (the remaining item of cutover gate 6).
- [ ] Merge to `main` and move the Python implementation to `legacy/`. Blocked
      by the independent review above. **Merge-day checklist** (do these in
      the same window, so main never advertises a stale product):
  - [ ] **README rewrite, TS-first.** Install = the `seedpass-js` bundle;
        features/architecture describe the TypeScript implementation; the
        Python content moves to `legacy/README.md` with a pointer. The 🚧
        bridge section added 2026-08-18 comes out (it exists precisely
        because the rewrite would have been premature before review).
  - [ ] **Landing page (`landing/`).** Install command switches off the
        Python `install.sh` (or install.sh itself learns to install the TS
        bundle); features/architecture copy updated; main/beta branch toggle
        reconsidered (post-cleanup there is one line of development); drop
        the `_pgbackup`/`_pginfo` Pinegrow artifacts. Verify where the live
        site deploys from before assuming edits take effect.
  - [ ] **Docs triage.** Python-era planning docs (the 14 bannered
        2026-08-18: tui_v2/v3, index0/atlas, semantic) move under
        `docs/legacy/` or keep their banners; living docs (vault/identity
        spec, migration guide, security model, cutover plan) stay top-level;
        `docs/README.md`/index updated to say which is which.
  - [ ] **Branch/repo hygiene.** Fast-forward or delete `beta` (it is fully
        contained in the merged history); revisit `dependabot.yml` (its pip
        entries target the retiring Python deps); CHANGELOG entry for the
        cutover.
  - [ ] **CI.** `python-ci`/`tests`/`briefcase` workflows follow the Python
        code to `legacy/` (or are scoped down); `ts-parity` and
        `release-integrity` become the primary gates.

### Unbuilt milestones

- [ ] **Milestone 6 (static/PWA web app)** and **Milestone 7 (browser
      extension)** of `docs/typescript_web_extension_port_plan.md` are not
      started — `js/packages/` holds `core`, `cli` and `test-vectors` only. The
      branch is named for a web extension that does not exist yet; the CLI was
      the proving ground for the core.
- [ ] **Decide whether the `api` (FastAPI) surface gets a TypeScript port at
      all.** It is currently excluded from cutover gate 5 as "a separate
      surface, not vault behavior", and the session agent (unix socket, 0600,
      scoped tokens) covers agent automation without binding a port — a smaller
      attack surface for a process holding unlocked seeds. `src/seedpass/api.py`
      is 2093 lines and much of it hangs off features that are deliberately not
      ported (high-risk partitions, agent job profiles, recovery split,
      semantic). A faithful port means porting those first; the genuinely useful
      subset is entry CRUD, search, lock/unlock and config. Options: leave it
      Python-only, port the subset, or drop it. Decide before the extension
      lands, since the extension needs *some* transport.

## Shared vault/identity spec (BitLogin groundwork)

- [x] **(done 2026-08-18)** Entry-id allocation watermark — ids are never
      reused after deletion; `_sync_meta.next_index`, merged as max, in both
      implementations with cross-impl parity. The precondition for "account
      #N" as a recovery coordinate.
- [x] **(done 2026-08-18)** `docs/seedpass_vault_identity_spec.md` — v1 draft
      extracted from working code: canonicalization, containers, derivation
      table, the two index namespaces, allocation rule, interop rules
      (preservation, namespacing, no-translation-table, round-trip
      conformance), capability profiles, sync/backup, and an honest gap
      ledger.
- [x] **(done 2026-08-18)** Unknown-kind passthrough (spec §8.2/§12) — TS
      parses unrecognized kinds as opaque records (verbatim, excluded from
      typed operations, malformed KNOWN kinds still fail); CLI listing
      redacts foreign fields as `has_*` and reveal refuses cleanly; Python
      tolerance pinned by test. Discovered en route: Python backfills base
      defaults on foreign records where TS carries verbatim — a benign but
      real canonicalization divergence, now in the spec gap ledger, to align
      before foreign kinds actually sync.
- [x] **(done 2026-08-18)** Round-trip conformance check as CI (spec §8.6) —
      cross-impl Phase L: a vault holding a foreign record (unknown kind,
      trap fields, nested data) plus an unknown top-level index key survives
      Python→TS→Python read-modify-write byte-for-byte; allocation skips the
      foreign id; TS refuses to reveal it. Landing it forced the
      normalization decision: Python's legacy renames now skip unknown kinds
      (they would have reinterpreted foreign data — verified: the old code
      turns a foreign `blacklisted` string into our `archived` flag, and
      Phase L catches it). 38/38 cross-impl checks.

## Post-BitLogin and backup/UX ideas (logged 2026-08-18)

- [ ] **Capsule unlock ("sign in with BitLogin")** — spec §11.1 added with
      the flow and the two normative rules (independence: an unlocking key
      must not derive from the vault it unlocks; rank: a managed identity
      must never unlock the root that provisioned it). Implementation is
      post-BitLogin by definition: it slots in as a fourth seed resolver
      (env → agent → capsule → password) plus a capsule file format, zero
      core-crypto changes. Scope first release to delegated org subtrees;
      personal vaults keep password-primary with capsule as opt-in for
      self-custodial keys.
- [ ] **Blossom server support for index backups** — store the encrypted
      snapshot as a single content-addressed blob on N Blossom servers
      (auth-signed by the existing app-1237 sync identity), with the relay
      manifest pointing at blob hash + server list. Keeps relay sync as-is
      (deltas + coordination, works today); Blossom removes the chunking
      ceiling that big vaults (documents!) hit on relays. Needs: manifest
      field tolerance check in both implementations, retention/mirror
      policy, and the same metadata-leakage analysis as relays (a pubkey's
      blob list is public).
- [x] **(phase 1 done 2026-08-18)** **`.seedpass` file extension** — CLI
      `vault export <dir>` and the TUI database export generate
      `seedpass-<fingerprint>-<date>.seedpass`; extensionless TUI input gets
      the suffix; explicit paths are used exactly as typed (scripts
      unaffected); imports never cared about extensions. Zero byte-format
      change. Remaining (deliberately later): phase 2 format_version 2 with
      a magic header (versioned, both implementations), and OS file
      association + icon from `logo/svg/` (XDG MIME via install.sh, registry
      via install.ps1) — installer work, after #34/#36.

## CI health (noticed 2026-08-18 while preparing PR #989)

- [ ] **ts-parity was red for 33 straight runs** on an environment-coupling
      bug local runs masked (`vault import --vault` demanded a default
      profile; fixed in cf433e3 with a hermetic SEEDPASS_APP_DIR in the CLI
      test harness). Standing lesson: CI results were never checked because
      local suites were green — check the workflow dashboard when a branch
      is long-lived.
- [ ] **Pre-existing red checks on PR #989, not yet diagnosed** (they
      predate this week's work): `tests` workflow failures on macOS
      (3.10/3.11/3.12), the `briefcase` macOS build, and the Netlify
      docs-seedpass deploy preview. All Python/docs-site era. Triage before
      merge so #989's required checks are meaningful — either fix or
      explicitly scope them out of the merge gate.
