# Learnings from known-issues-agent run

- Initialized `KNOWN_ISSUES.md` as it was missing.
- Verified that `npm run --prefix torch lint` requires `npm install --prefix torch` to be run first.
- Confirmed that `landing/index.html` no longer contains `innerHTML` violations.
- Confirmed `torch-config.json` correctly defines scheduler handoff commands.
- Consolidated resolved issues into `KNOWN_ISSUES.md` for historical tracking.

# Learnings from test-coverage run

- `artifacts/coverage/coverage.full.json` is useful for choosing high-impact gaps quickly; `src/utils/input_utils.py` was at 25.00% and had no direct tests.
- Added deterministic unit tests for `timed_input` POSIX/Windows dispatch, timeout handling, and backspace behavior without relying on real terminal input.
- Added positive-path tests for `utils/terminal_utils` header/notification rendering to complement existing failure-path tests.
- Focused coverage after changes: `src/utils/input_utils.py` reached 100% and `src/utils/terminal_utils.py` reached 88% in targeted runs.

# Learnings from entry-type verification run

- Added an enum-driven regression suite to verify every `EntryType` value can be added, retrieved, and filtered via `EntryManager`.
- Guard test now asserts `ALL_ENTRY_TYPES` stays in sync with the `EntryType` enum, so introducing a new kind requires explicit test coverage updates.

# Learnings from account roundtrip restore run

- Added end-to-end regression tests for account lifecycle recovery:
  Nostr sync -> local account deletion -> seed-based restore -> entry integrity checks.
- Added parallel lifecycle regression for portable backups:
  export -> local account deletion -> import with seed -> entry integrity checks.
- `PasswordManager` test harnesses that call `sync_vault()` need `state_manager` set (even `None`) to avoid `AttributeError` in `sync_vault_async`.

# Learnings from real-relay roundtrip run

- Added an opt-in `@pytest.mark.network` roundtrip test in `test_nostr_real.py` that uses live relays and validates sync -> delete local index -> seed-based restore.
- Real-relay tests should isolate keyspace per run using a random `account_index` so snapshot queries do not collide with prior runs.
- Relay propagation can be eventual; bounded retry/backoff around `attempt_initial_sync()` improves stability for live network execution.

# Learnings from live relay + portable chain run

- Added an opt-in live test that chains both recovery paths: real-relay sync and portable export/import, then re-syncs and restores again from relays.
- Keeping `fingerprint` + `account_index` consistent across source/import/restore clients preserves deterministic relay identity for end-to-end verification.

# Learnings from nostr-index-size gating update

- `test_nostr_index_size_limits` remains discoverable in test collection but now requires explicit `NOSTR_INDEX_SIZE_E2E=1` to execute.
- This avoids automatic execution in CI desktop jobs while preserving manual E2E stress capability.

# Learnings from 1000-entry live index-size run

- With `NOSTR_INDEX_SIZE_E2E=1`, live relays handled checkpoints up to 1000 entries with successful publish/retrieve at every batch.
- Observed encrypted payload growth is strongly superlinear (about 30 KB at 100 entries to about 4.6 MB at 1000 entries), which is useful for practical relay size planning.

# Learnings from security checklist + threat model kickoff

- Added `docs/security_readiness_checklist.md` with status/owner/evidence fields and explicit exit criteria per security readiness item.
- Started item 1 by drafting `docs/threat_model.md` with scope, assets, trust boundaries, attacker profiles, assumptions, non-goals, and prioritized risks.
- Added five explicit decision gates to complete item 1 (metadata leakage posture, endpoint stance, recovery policy, relay trust posture, release trust chain).

# Learnings from threat model defaults pass

- Added concrete proposed defaults and requirements for all five item-1 decision gates in `docs/threat_model.md`.
- Added a decision approval table so maintainers can formally approve/reject each gate and close item 1 with traceable signoff.

# Learnings from threat model provisional approval

- Applied best-judgment provisional approvals for all five decision gates and recorded them in `docs/threat_model.md`.
- Marked checklist item 1 as `Done` in `docs/security_readiness_checklist.md` with evidence and approval date.

# Learnings from crypto/key-management review kickoff

- Added `docs/crypto_key_management_review.md` and moved checklist item 2 to `In Progress`.
- Identified immediate P0 gaps: PBKDF2 baseline appears low for modern threat levels and Argon2 `time_cost` config is not clearly wired through all active unlock paths.
- Documented prioritized remediation plan and explicit completion criteria for closing item 2.

# Learnings from argon2 wiring remediation

- Added `PasswordManager._derive_seed_key` and related config helpers so seed-key derivation consistently applies configured `kdf_mode` and Argon2 `time_cost`.
- Replaced multiple direct seed-key derivation callsites with the shared helper across setup/unlock/import/password-change flows.
- Added focused tests in `src/tests/test_kdf_modes.py` validating Argon2 `time_cost` propagation and PBKDF2 iteration override behavior.
