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

### NEXT — open items as of 2026-08-20

TypeScript is the implementation going forward; Python is now the reference
oracle the port is validated against, not the product. That reframes some of
what follows, and each item says which side it is on. Detail for every entry
is further down this file.

**P0 — a TypeScript-only product cannot ship with these open**

1. **The session agent does not run on Windows.** `listen EACCES`: Node needs
   a named pipe there, not a filesystem path. No `seedpass agent` means no
   held seeds, no tokens, no high-risk sessions and no sink delivery. NOT a
   path substitution — the agent's access control IS the socket's 0600 mode,
   so this is a security design decision about what replaces it. Four test
   files are excluded on Windows meanwhile.
2. **Are vault files protected from other users on Windows?** Ten `0600`
   assertions across both languages are now skipped there, including the
   vault index and the semantic index, which hold secrets. Windows has no
   POSIX mode bits; these files inherit directory ACLs instead. Either verify
   the inherited ACL is user-scoped and assert THAT, or set one explicitly.

**P1 — security decisions, each needing a call rather than a fix**

3. **An unencrypted portable backup is unauthenticated**, and import accepts
   it silently. Its checksum and fingerprint both live in the same
   attacker-supplied file. Python behaves identically, so this is a shared
   design property — whatever is decided has to land on both sides.
4. **The API's settable config keys are a superset of Python's.** Deliberate
   (TypeScript can set the password-policy keys Python's API cannot), but it
   IS a divergence: a client setting a policy key succeeds here and gets 400
   there. Widen Python or document the surfaces as non-identical.

**P2 — correctness and coverage**

5. **`src/nostr/client.py` needs migrating to nostr-sdk 0.44+.** Pinned at
   `<0.44` because 0.44 removed `NostrSigner.keys` and changed `Client`'s
   constructor. Oracle-side: it has to keep working for parity testing.
6. **`textual` is an undeclared dependency**, so the entire TUI test surface
   skips on Linux and macOS and has been passing by not running. Decide
   whether the TUI is supported or optional — and note that if Python is
   retiring, this may resolve by deletion rather than by fixing.
7. **`manager.py` sits 0.74 points above its coverage floor**, and its
   uncovered half is interactive prompt handling. Raising it honestly means
   extracting logic out of the `input()` loops.
8. **A nested export path answers 500 instead of a refusal.** `atomicWrite`
   does not create parent directories; the path is caller-supplied, so this
   should be a 400 naming the missing directory.
9. **The JavaScript SBOM needs a pnpm-native generator.** The old step used
   the npm tool against a pnpm workspace and never produced anything.

**P3 — now cheap, given today's results**

10. **Promote the reproducible-build check from experiment to required.** All
    three platforms produced a byte-identical bundle
    (`4915bb47…`), so the invariant holds. Remove
    `continue-on-error` from the `reproducible` job in ts-platform.yml.
11. **The path filters do nothing for PR #989, and small branches are the
    fix.** Verified 2026-08-20: a commit touching only TODO.md still fired
    all five workflows, because these are `pull_request` events and GitHub
    evaluates `paths` against the WHOLE PR diff — and #989 spans main→port,
    so every filter matches every time. Push events do filter correctly (a
    js-only commit triggered just the two TypeScript workflows).

    So the filters pay off only once the PR is small. Develop on short-lived
    branches based on `port/typescript-web-extension`, open a small PR
    against that branch, and update #989 at checkpoints rather than on every
    experimental commit. That, not more filtering, is what stops thirteen
    jobs running for a docs edit.
12. **Slim ts-parity.yml.** Its `parity` job now duplicates ts-platform's
    Ubuntu work (typecheck, tests, build, smoke, pack). Left alone
    deliberately so a new workflow and a restructure did not land together;
    safe to do now that ts-platform is green on all three.

### Blockers before real secrets

- [~] **Independent security review — restated, since there is no third party.**
      The point of the gate was catching what the author cannot see, which
      needs an oracle that is not the author's judgement rather than another
      person. Progress and what remains:
      - [x] **Differential fuzzing vs Python** (`scripts/differential_fuzz.py`),
            ~10,000 cases over canonical JSON, password derivation, the sync
            CRDT, index0, recovery shares, the semantic index and entry
            hashing. Found a real defect: integral floats hash differently in
            the two implementations, silently, which could make two clients
            converge to different vaults. Also found — via mutation testing
            turned on the fuzzer itself — that it could not reach the
            tombstone or subject caps; fixed and re-verified.
      - [x] **Wire the fuzzer and `cross_impl_check.py` into CI.** Done —
            `.github/workflows/ts-parity.yml` runs both: `cross-implementation`
            and `differential-fuzz` (three fixed seeds for bisectable
            regressions, plus one exploratory seed derived from the run id so
            the explored input space grows instead of freezing).
      - [x] **Mutation testing in CI**, added 2026-08-19 as
            `.github/workflows/mutation-testing.yml`. Weekly rather than
            per-push: a full sweep is ~1 hour, and what it measures ("would
            the suite notice if a security check broke?") drifts with test
            and check changes, not with every commit. The script now exits 1
            on a survivor and 2 on a target that generated no mutants, so
            "not measured" cannot report as "clean". The job also fails if
            any mutation is left in the tree at the end.
      - [x] **Systematic mutation testing** of the security-critical modules
            that have NO differential oracle because Python has no
            equivalent: the session agent, the API HTTP layer, high-risk
            session handling, sinks. Done 2026-08-19 via
            `scripts/mutation_test.py`. All seven targets sweep to ZERO
            survivors: 234 mutants, 149 killed, 85 non-compiling. Re-run with
            `.venv/bin/python scripts/mutation_test.py --target all`; it is
            slow (~25s/mutant) so use `--offset/--limit` to slice it, and
            never run it unattended — it writes deliberately broken security
            code into the tree while it works, guarded by
            `.mutation-test-running`.

            It found real gaps rather than confirming the suite. The largest:
            the high-risk expiry rule was written in two places that masked
            each other's mutations, and one of the two was unreachable dead
            code; a token's `kinds` restriction was entirely untested; the
            API would delete the profile it was serving; `token-issue` would
            mint a token for a profile the agent never held; an empty
            high-risk factor was refused in both implementations and tested
            in neither.

            Three blind spots in the harness itself mattered as much as the
            findings, and each was found by fixing the one before it:

            1. It only mutated block-form guards, so every one-line
               `if (cond) return ...;` — how most load-bearing checks are
               written — was invisible. `src/highRisk.ts` generated zero
               mutants and printed as a clean sweep.
            2. A target generating no mutants reported identically to a clean
               one. It now reports NOT MEASURED, and that reporting caught
               the next blind spot on its first run against a new target.
            3. Selection was by an auth vocabulary (token, scope, expire), so
               `src/configFile.ts` — whose validators are the API's only
               defence against nonsense being written permanently into an
               encrypted file — generated nothing. Guards are now selected by
               whether their body REFUSES, vocabulary or not. That took the
               corpus from 132 mutants to 234 and found real gaps in every
               target it touched.

            The recurring shape across the whole sweep: two code paths both
            refuse, so only the REASON or the BOUNDARY is observable, and
            nothing observed either. A 500 where a 404 belongs, "your
            envelope is corrupt" where "you never set one up" belongs, an
            approval scoping check that refused everything, a denied request
            returning 0 and printing as "0 profiles locked" while the seeds
            stayed resident.
      - [ ] **DECISION TO RECORD: the API's settable config keys are a
            superset of Python's.** Python's `update_config` allowlists 8
            keys; the TypeScript route now allowlists 23, because it can set
            the password-policy keys (`min_uppercase`, `exclude_ambiguous`
            and friends) that this implementation honours and Python's API
            does not expose. Matching Python exactly would mean deleting
            working behaviour to reproduce a limitation, so the divergence is
            deliberate — but it IS a divergence, and a client that sets a
            policy key succeeds here and gets 400 there. Either widen
            Python's allowlist or document the API surfaces as
            non-identical; do not quietly leave it as an accident.
            (Found 2026-08-19 during the adversarial pass.)
      - [x] **Adversarial pass over TS-only surfaces**, framed as "what does
            this trust?" rather than "is this correct?" — the framing that
            finds trust-boundary bugs rather than logic bugs. Done
            2026-08-19. What held up, so a later pass need not re-derive it:

            - The agent socket bounds its input (512KB/line, 64 connections)
              and validates op/cap/token/fingerprint/id/sink as strings
              before comparing them.
            - The exec allowlist is checked with `parseCommandSpec` on the
              SAME array the spawn later parses, so there is no double-parse
              gap. Every malformed `command` shape fails closed. Containment
              is "which binary", never "what it does" — already documented at
              the call site.
            - CORS is exact-match against an allowlist that is empty by
              default, echoes only allowlisted origins, and sets `Vary`.
            - No path is ever built from ENTRY data; the one caller-supplied
              path (document export) goes through `resolveWithinProfile`.
            - Prototype-pollution-shaped writes (`obj[key] = value` over
              parsed JSON) exist in the merge path, but merge input is
              encrypted under the index key, so producing one requires the
              seed already.

            It found one real defect — the config API accepting any key and
            any value, fixed in the same session — and one property worth
            recording rather than unilaterally changing, below.
      - [ ] **Migrate `src/nostr/client.py` to nostr-sdk 0.44+.** The
            dependency is pinned `>=0.43,<0.44` because 0.44 removed
            `NostrSigner`'s constructors — `NostrSigner.keys(...)`, which
            client.py:107 calls — and changed `Client`'s constructor, which
            client.py:108 uses. Verified against 0.45.0: `NostrSigner` is left
            with only `get_public_key`, `sign_event` and the nip04/nip44
            methods, and `Client.__init__` takes no arguments.

            This surfaced as CI red while the Tests workflow stayed green,
            because the two install from different lockfiles and they had
            drifted: `poetry.lock` held 0.43.0, `requirements.lock` had
            resolved to 0.45.0 under the old unbounded `>=0.43`. Both are now
            on the 0.43 line and agree. There is no advisory against 0.43, so
            the bound costs nothing today — but it is a bound, and the
            migration touches signing and client setup, so it wants doing
            deliberately with the sync round-trip re-validated against a real
            relay rather than folded into unrelated work.
            (Found 2026-08-20 on the first CI run of this branch.)
      - [x] **Two TUI tests still fail on Windows, and only Windows ever runs
            them.** RESOLVED — and they were right. The tests were not
            POSIX-assuming; the APP was. `parse_palette_command` used
            `shlex.split`, which defaults to POSIX mode where a backslash is
            an escape character, so on Windows
            `C:\Users\me\exports` became `C:Usersmeexports` and every
            palette command taking a path — doc-export, export-field,
            db-export, db-import, parent-seed-backup, totp-export — wrote to a
            mangled relative path or nowhere, while telling the user it had
            worked. Both palettes now share `split_palette_args`, which takes
            an explicit `windows` flag so BOTH branches are tested from either
            platform. Original wording kept below for the record. Surfaced 2026-08-20 once the Tests workflow could report a
            Windows failure at all (see below). Four failed; two were literal
            `/tmp/...` comparisons against paths the app echoes
            platform-normalized, and those are fixed by deriving the expected
            string from `Path` — a no-op on POSIX, verified locally.

            The remaining two need a Windows host and are deliberately not
            patched blind:

            - `test_tui2_textual_copy_command_for_core_and_advanced_fields`
              raises FileNotFoundError reading back an `export-field nsec`
              target that was never written.
            - `test_tui2_textual_palette_notes_tags_fields_and_doc_export`
              asserts False after `doc-export`.

            Both depend on palette argument parsing and file writing on
            Windows. Guessing at either would mean changing a test to match an
            assumption rather than a behaviour, so they are left red and
            named.

            Note how this interacts with the textual item below: because
            textual is undeclared, these tests SKIP on Linux and macOS and run
            only on Windows, which is the one platform they were not written
            for. Declaring textual would make them run where they were
            written, which is probably the first move.
      - [ ] **`src/seedpass/core/manager.py` sits two tenths of a point above
            its coverage floor.** 60.74% against a 60.00% threshold on Linux,
            59.80% on Windows — which is why the floor is now measured on
            Linux only (see `scripts/run_ci_tests.sh`): the module holds
            POSIX-only paths that cannot execute on Windows, and Windows runs
            MORE tests, not fewer, so the gap is unreachable code rather than
            absent tests.

            That is the right call for the gate and not a substitute for the
            real problem, which is that a 2970-statement module central to the
            application is 60% covered with no headroom. The uncovered blocks
            are almost entirely the interactive `input()`/`print()` menu
            handlers, so raising the number means either testing prompt flows
            (brittle, low value) or extracting the logic out of the prompt
            loops so it can be tested without them. The second is the real
            work.
            (Recorded 2026-08-20.)
      - [ ] **THE SESSION AGENT DOES NOT RUN ON WINDOWS.** Found 2026-08-20,
            the first time the JavaScript suite executed there: four test
            files die in `beforeAll` with
            `listen EACCES ... \agent.sock`. Node on Windows requires a named
            pipe (`\\.\pipe\name`) for `server.listen(path)`; a filesystem
            path is not a valid endpoint. Nothing about the daemon works
            there — no `seedpass agent`, so no held seeds, no tokens, no
            high-risk sessions, no sink delivery.

            This is not a path substitution. The agent's ACCESS CONTROL is the
            socket's 0600 mode: the trust boundary is "only this user can
            connect", enforced by the filesystem. Named pipes have their own
            ACL model, so supporting Windows means answering what the 0600
            was buying and how to buy it again — a security design question,
            and it should be decided rather than improvised.

            Until then the four files are excluded on Windows in
            js/packages/cli/vitest.config.ts, with the reason written there.
            With TypeScript becoming the only implementation this is a
            shipping decision: either the agent gains a Windows transport, or
            SeedPass documents the daemon as POSIX-only and the Windows CLI
            works without it.
      - [ ] **Are vault files protected from other users on Windows?**
            SCOPE GREW 2026-08-20: this is no longer two Python tests. When
            the JavaScript suite first ran on Windows, eight more `0600`
            assertions failed for the same reason — the vault index itself,
            index backups, the parent-seed phrase file, job profiles, the
            recovery-drill key and log, 2FA exports, and the semantic index,
            which holds stored secrets. All are now guarded by
            `NO_POSIX_PERMISSIONS` in js/packages/cli/test/helpers/platform.ts
            with the reason attached.

            Skipping states the gap, it does not close it. With TypeScript
            becoming the only implementation, "are the user's secrets
            protected from other accounts on Windows" is a shipping question,
            not a test-suite question. Either verify the inherited ACL is
            user-scoped and assert THAT on Windows, or set an explicit ACL and
            assert it.
            `test_atomic_write_permissions` and
            `test_index_files_are_not_readable_by_other_users` assert mode
            0o600 and are now skipped on Windows, because POSIX mode bits do
            not exist there -- `os.chmod` toggles a read-only flag and
            `st_mode` reads back 0o666. Skipped rather than relaxed on
            purpose: a weakened assertion would answer the question falsely.

            The question itself is open and worth answering. On Windows these
            files inherit directory ACLs rather than carrying an explicit
            owner-only mode, and the semantic index in particular holds
            stored secrets. Either verify the inherited ACL is user-scoped
            and assert THAT on Windows, or set an explicit ACL and assert it.
            (Recorded 2026-08-20.)
      - [ ] **`textual` is an undeclared dependency, so the entire TUI test
            surface has never run in CI.** It appears in neither
            `[tool.poetry.dependencies]`, `[tool.poetry.extras]`, nor the dev
            group, so no environment built from the lockfile has it. Every
            TUI test therefore begins `pytest.importorskip("textual")` and
            SKIPS — v2 action matrix, parity scenarios, keyboard stress,
            textual interactions, and now v3 parity. They have been passing
            by not running.

            The check meant to notice this cannot: `seedpass tui2 --check`
            uses `importlib.util.find_spec` and reports
            `status: "unavailable"` with a zero exit, so the CI smoke step
            passes whether or not the TUI can start. A fresh install from the
            lockfile ships a TUI that does not work, and nothing in CI says
            so.

            Decide which the TUI is: a supported feature, in which case
            declare `textual` and let those tests actually run; or an
            optional extra, in which case declare it as one, and make the
            smoke step assert something that can fail. Do not leave it as a
            dependency nobody declared and tests nobody runs.
            (Found 2026-08-20 while fixing the first CI run of this branch.)
      - [ ] **The JavaScript SBOM needs a pnpm-native generator.** The old
            step invoked `@cyclonedx/cyclonedx-npm --package-lock-only`, which
            is the npm tool and reads `package-lock.json` — a file this pnpm
            workspace does not have. It then swallowed the failure twice over
            (`|| echo "non-fatal"` and `if-no-files-found: warn`), so it
            reported success on every run while its own log said "No files
            were found with the provided path". Removed 2026-08-20 rather than
            pinned, because pinning a tool that cannot read our lockfile fixes
            the wrong problem.

            `pnpm audit --audit-level moderate` remains and does fail on
            findings, so supply-chain checking is not absent — only the bill
            of materials is. The shipped bundle has six production
            dependencies, so a generator over `pnpm list --json` is likely
            simpler and more auditable than another third-party tool, and
            fits the zero-dependency posture of the bundle itself.
      - [ ] **A nested export path answers 500 instead of a refusal.**
            `POST /api/v1/entry/:id/document/export` with
            `{"path": "exports/nested/secret.txt"}` fails with an opaque
            "internal error": `atomicWrite` does not create parent
            directories, by design. The path is caller-supplied, so this
            should be a 400 naming the missing directory — a 500 tells the
            caller the server broke when they simply named somewhere that
            does not exist. Small; left out of the commit that found it
            because that commit was about the traversal guard.
            (Found 2026-08-19 during the mutation sweep.)
      - [ ] **DECISION TO RECORD: an unencrypted portable backup is
            unauthenticated, and import accepts it silently.** With
            `encryption_mode: "none"` the payload is used verbatim; the
            checksum that "verifies" it and the `fingerprint` that passes the
            profile check both live in the same attacker-supplied file, so
            they detect corruption and nothing else. A `seed-only` backup is
            genuinely authenticated (Fernet HMAC under a seed-derived key —
            only the seed holder could have produced it), and import treats
            the two identically. `POST /api/v1/vault/import` REPLACES the
            vault, so a user talked into restoring a hostile file gets an
            attacker-chosen index whole: entries that look like theirs, with
            stored values the attacker knows.

            Python does exactly the same thing (`portable_backup.py`, the
            `PortableMode.NONE` branch), so this is a shared design property
            and NOT a port defect — which is also why it is recorded here
            instead of being fixed on one side. Options, cheapest first:
            report `encryption_mode` in the import response so the caller can
            see what it got; require an explicit opt-in for `none` the way
            the fingerprint mismatch already does; or drop the mode. Any of
            them has to land in both implementations together.
            (Found 2026-08-19 during the adversarial pass.)
      Original note follows.
- [ ] **(superseded by the above) Independent security review of the TypeScript branch.** Review
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
- [x] **(done 2026-08-17/18) Fix the findings from the 2026-08-17
      self-review** (next section) — all ten closed, plus all seven findings
      from the 2026-08-18 independent audit (`js/SECURITY_AUDIT.md`). The
      branch is ready to hand to an outside reviewer: their time now goes on
      what an author cannot see.

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
- [x] **(ported 2026-08-19) index0/atlas.** The per-vault activity ledger is
      now computed rather than carried verbatim: events are appended on every
      mutation from all three surfaces, checkpoints and canonical views
      rebuild, and `mergeIndexPayloads` merges both sides by default (it used
      to keep the local block, so a restore discarded the remote's history).
      Hashes and merge results are byte-identical to Python's, verified
      against fixtures and end to end on a live vault.
      **Two Python quirks are replicated on purpose** — `str(None)` == "None"
      in required fields, and a stored integrity_hash is preserved even when
      it disagrees — because diverging would change which events exist, not
      just how they hash. Both are documented at the code.
      **One deliberate design difference:** events are derived by diffing at
      the mutation funnel rather than emitted per call site, because a
      call-site emitter can be forgotten and a silently incomplete ledger
      reads as "nothing happened".
- [x] **(ported 2026-08-19) Agent job profiles and recovery split.** Shares
      interoperate in both directions, verified on a live parent-seed split.
      Job profiles bind to a policy stamp byte-compatible with Python's
      (including `ensure_ascii`). Drill logs are HMAC-chained like the audit
      log. See the recovery-split security finding above.
      **Every Python API endpoint now has a TypeScript equivalent.**
- [x] **(ported 2026-08-19) High-risk partitions and approval gates.** Both
      file formats byte-compatible with Python and verified in both
      directions. The unlock session diverges deliberately — see the security
      finding above. `agent high-risk factor-set/status/unlock/lock/migrate`,
      `agent approval issue/list/revoke`, and the /api/v1/high-risk routes.
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

### Ported on 2026-08-19

- [x] **CLI gap closure** — `vault stats`, `vault change-password`,
      `vault reveal-parent-seed`, `entry export-totp`, `config
      toggle-secret-mode`, `config toggle-offline`, `api stop`. Passwords and
      tokens come from the environment, never argv. `reveal-parent-seed`
      follows `fingerprint create`'s egress rule: it refuses to print into a
      pipe.
- [x] **QR codes in the TUI** — byte mode, versions 1-40, all four EC levels,
      zero dependencies. The block-structure table was extracted
      programmatically from the reference library rather than transcribed, and
      the tests compare every module against it. One documented divergence:
      mask SELECTION, because the reference scores candidates with their
      format modules blanked (a symbol that is not legal); all eight masks are
      valid, so the tests pin the mask and check the selection rule
      separately. Secret Mode suppresses the code — a QR is the secret in a
      form a camera reads across a room.
- [x] **Semantic (retrieval) index** — it was never vector search; it is
      Jaccard overlap over tokenized metadata, which is why it was portable.
      Ported to core, the CLI (`semantic build/status/search`) and the API.
      **Two Python defects found and fixed while porting:** the index wrote
      stored secrets to a plaintext 0664 file beside the encrypted vault, and
      entry 0 — the first entry any profile creates — was silently
      unsearchable. See the security note below.

### Security note: the semantic index leaked secrets (fixed 2026-08-19)

`SemanticIndex._extract_text` appended a `key_value` entry's `value` — the
stored secret — and `build()` wrote it to `semantic_index/records.json` in the
clear, plus a tokenized copy that leaked it just as well. The file was created
at the process umask (0664 on a default install), next to a vault that is
encrypted and 0600. Anything able to read the profile directory — a backup, a
sync client, another user on a shared machine — obtained the secret without
the master password.

Exposure is limited to profiles that actually built an index (it is opt-in and
off by default), but **any such index on disk still contains the secrets**:
the fix does not rewrite existing files. `MODEL_ID` is bumped to
`seedpass-token-overlap-v2` so a stale index is identifiable — `semantic
status` reporting v1 means "rebuild this, it holds secrets".

- [x] **(done 2026-08-19) Stale index files are deleted on first touch.**
      Both implementations check the manifest's `model_id` whenever they read
      an index, and remove records + manifest if it predates the fix, so the
      plaintext does not sit there waiting for a user to notice a version
      string. Safe because the index is a derived cache rebuilt in
      milliseconds. A manifest that cannot be read is NOT treated as stale —
      "cannot tell" must not mean "delete it", or a corrupt-manifest read
      would throw away a good index.

### Security finding: recovery-split shares were derived from the secret (fixed 2026-08-19)

`agent_recovery._coef` derived every polynomial coefficient by HMAC-ing the
secret, so the whole share set was a deterministic function of it. Shamir's
defining property is that a sub-threshold set of shares is
information-theoretically independent of the secret — deriving the
coefficients from the secret destroys it, because a single share becomes an
offline verifier: guess a secret, re-run the split, compare. Demonstrated
recovering `hunter2` from one share of five at threshold three.

Second consequence: re-splitting produced byte-identical shares, so a leaked
share could never be rotated out without changing the secret itself.

Fixed by drawing coefficients from `secrets`, hoisted out of the per-share
loop (they had been recomputed per share, which only worked because they were
deterministic). **The share format is unchanged and `recover_secret` is
untouched**, so old shares keep recovering and both implementations
interoperate — a real security property at zero interop cost.

- [ ] **Consider re-splitting any secrets shared before this fix.** Old shares
      still recover correctly, so nothing is broken; but shares generated by
      the old code remain a guessing oracle for whoever holds one, and are not
      rotatable. Only worth acting on where a share may have been exposed, or
      where the secret has low entropy.

### Security finding: Python's high-risk unlock puts the partition key on disk

Found 2026-08-19 while porting the feature, and verified empirically.

`agent_high_risk_unlock.json` records the live session's `partition_key_tag`,
and `high_risk_partition_store._fernet_for_tag` derives the partition file's
encryption key from exactly that value. So while a session is live, the
high-risk partition decrypts from disk alone with **no factor**, for anything
that can read `APP_DIR` — and the session file lives in the same directory as
the key envelope, so being able to read one implies being able to read the
other.

That is the guarantee the partition exists to provide: ssh/pgp/seed/nostr
entries are the kinds judged to need a SECOND factor beyond the master
password, and during an unlock they effectively need none.

It is inherent to on-disk session state in a CLI with no resident process:
"unlocked for a TTL without re-supplying the factor" means the key must be
recoverable by the next process, and here that is the filesystem. Encrypting
the session under the master password or the seed does not help — then the
password alone reaches the partition, which is the thing the second factor is
supposed to prevent.

`grant_high_risk_unlock` now documents this at the point it happens. The
TypeScript port keeps the tag in the session agent's memory instead and never
writes it (asserted by a test that scans every file in the app directory).

- [ ] **Decide the Python fix.** Two real options, both product decisions:
      (a) drop the session model and require the factor per operation, or
      (b) give Python a resident agent for this (the TS agent already is one).
      Interim guidance is in the docstring: short TTLs, `high-risk-lock` when
      finished, treat read access to APP_DIR as equivalent to holding the
      factor.

### Unbuilt milestones

- [ ] **Milestone 6 (static/PWA web app)** and **Milestone 7 (browser
      extension)** of `docs/typescript_web_extension_port_plan.md` are not
      started — `js/packages/` holds `core`, `cli` and `test-vectors` only. The
      branch is named for a web extension that does not exist yet; the CLI was
      the proving ground for the core.
      **Transport is no longer a blocker for this:** the API is ported, so an
      extension has something to talk to. The remaining question is whether a
      browser should reach the API over loopback at all, or whether the
      extension should embed the core directly — decide before starting M7.
- [x] **(done 2026-08-19) The `api` surface is ported.** `seedpass-js api
      start` serves /api/v1 on `node:http` with no framework — the CLI ships
      one audited bundle with an empty production dependency list, and a web
      framework in a seed-holding process would be the largest supply-chain
      change in the project. Loopback unless `--allow-remote`; bearer token
      printed once; routes that produce plaintext also require the master
      password header; body cap, rate limit, and a tighter unlock-attempt
      budget that returns 429 even for the right password once spent.
      Verified end to end that Python, the TS CLI and the TS API derive the
      same secret for the same entry. Routes belonging to unported subsystems
      answer 501 naming the feature, not 404.
- [ ] ~~Decide whether the `api` (FastAPI) surface gets a TypeScript port at
      all.~~ (superseded by the above) It is currently excluded from cutover gate 5 as "a separate
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

- [x] **(addressed 2026-08-19) CI is now watched and the fuzzer runs in it.**
      `scripts/differential_fuzz.py` is wired into ts-parity with three fixed
      seeds (deterministic, bisectable) plus one derived from the run id, so
      the explored input space grows over time. `cross_impl_check.py` was
      already there — an earlier note in this file claiming otherwise was
      wrong.
- [ ] **ts-parity was red for 33 straight runs** on an environment-coupling
      bug local runs masked (`vault import --vault` demanded a default
      profile; fixed in cf433e3 with a hermetic SEEDPASS_APP_DIR in the CLI
      test harness). Standing lesson: CI results were never checked because
      local suites were green — check the workflow dashboard when a branch
      is long-lived.
- [x] **(diagnosed and mostly fixed 2026-08-19) Red checks on PR #989.**
      Pulled the actual logs rather than guessing. Three distinct causes, not
      one:
      - **CI / dependency scan** — genuinely red for a good reason:
        `pip-audit` found 100 known vulnerabilities across 15 packages,
        including `cryptography` itself. **Fixed**: floors raised, lock and
        `poetry.lock` regenerated, audit now clean. The stubborn one was
        `starlette`, pinned `<0.48` for a FastAPI constraint that no longer
        exists (fastapi 0.141 requires `>=0.46` unbounded), which had been
        holding seven advisories open.
      - **Tests, every OS and Python version** — `black --check` found 28
        unformatted files, part pre-existing, part from this session.
        **Fixed**, with fixtures regenerated afterwards to prove no hashed
        value moved.
      - **Installer Smoke, Windows only** — NOT fixed, and needs a decision.
        `portalocker` pulls `pywin32` on Windows; `pip-compile` runs on Linux
        and drops the Windows-only marker, so `pywin32` never reaches
        `requirements.lock`. The Windows installer installs with
        `--require-hashes`, which then refuses the unpinned transitive
        `pywin32>=226`. Naming it in `src/requirements.txt` with a
        `sys_platform == "win32"` marker does NOT work — pip-compile on Linux
        drops it again — and hand-editing the lock is futile because four
        workflows regenerate it.
- [ ] **Decide how to produce a multi-platform lock** (blocks Windows
      installer smoke). Options: run `pip-compile` on a Windows runner and
      commit a second `requirements-windows.lock`; move to a resolver that
      does platform-independent locking (uv); or drop `--require-hashes` on
      Windows, which trades supply-chain integrity for a green check and is
      the wrong trade. Note this affects only the Python installer, which is
      the implementation being retired.
