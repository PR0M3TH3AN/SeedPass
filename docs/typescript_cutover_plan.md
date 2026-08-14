# TypeScript Cutover Plan

Goal: promote the TypeScript implementation to `main` and retire the Python
implementation to legacy/reference status.

This document is the gate list. Nothing here is a schedule — each item is a
condition that must be demonstrably true, with the evidence named. Until every
P0 gate is green, Python remains the normative reference
(`docs/typescript_web_extension_port_plan.md` §6).

## Status summary

| Gate | State |
|---|---|
| Deterministic artifact parity | green |
| Vault + backup format compatibility | green |
| Cross-implementation profile interop | green |
| Sync protocol parity | green |
| Agent security model | green (TS ahead of Python) |
| Feature parity for daily use | partial |
| Packaging + release | not started |
| Migration + rollback story | not started |

## P0 gates (must be green to cut over)

1. **Deterministic artifacts match byte-for-byte.**
   Evidence: `js/packages/core/test/parity.test.ts` against fixtures
   regenerated from Python by `scripts/generate_ts_port_fixtures.py`; the
   `fixture-drift` CI job proves the committed fixtures come from the
   committed generator. **Green.**

2. **Each implementation opens the other's profiles.**
   Evidence: `scripts/cross_impl_check.py` phases A/B — Python creates a
   profile, TS reads it and unlocks with the master password; TS creates a
   profile, Python decrypts the parent seed and index and derives identical
   secrets. Runs in CI. **Green.**

3. **Portable backups interoperate both directions.**
   Evidence: cross-impl phase C, including Python's checksum verification of
   a TS-written export. **Green.**

4. **Sync protocol is compatible.**
   Evidence: event ids cross-verified against rust-nostr fixtures; snapshot
   chunking/manifest/delta parity; live relay round trip in
   `js/packages/core/test/relay.test.ts`. **Green.**
   Remaining: a live Python-publishes → TS-restores test through one relay
   (currently each side is tested against the shared protocol, not against
   the other end to end).

5. **Feature parity for real daily use.** **Partial.** Missing:
   - SSH and PGP key material (entries round-trip; derivation not ported)
   - document import/export commands
   - index schema migrations 0→3 (TS refuses old indexes rather than
     migrating them — safe, but a Python user with an old profile is stuck)
   - `semantic` and `api` command groups (deliberately deferred; decide
     whether they block cutover or ship post-cutover)

6. **Packaging and distribution exist.** Not started. Needs: an installable
   artifact (npm bin, single-file build, or both), checksums and signatures
   matching the release-integrity workflow, and updated install docs.

7. **Migration guide and rollback.** Not started. Needs: a documented path
   for existing users (in practice "point the TS CLI at your existing
   `~/.seedpass`", which gate 2 already proves works), a pre-migration
   backup step, and a tested rollback to the Python implementation from a
   migrated profile.

## Non-gates (explicitly not blocking)

- Web app, browser extension, desktop app — these are new surfaces, not
  parity requirements.
- `_system.index0` / atlas content merge — Python-derived state, recomputed
  on load; TS deliberately does not emit it and refuses to merge populated
  index0 rather than corrupt it.
- TUI v2/v3 — the plan explicitly does not port these; terminal UX is the
  CLI plus any future interactive mode.

## Cutover mechanics (once gates are green)

1. Tag the final Python release and branch it as `legacy/python`.
2. Merge `port/typescript-web-extension` into `main`.
3. Move the Python tree under `legacy/` in-repo (keep it runnable — it is
   the reference implementation for fixtures and the cross-impl suite, both
   of which must keep running in CI after cutover).
4. Update `README.md`, `AGENTS.md`, and the installer to the TS entry point.
5. Keep `scripts/generate_ts_port_fixtures.py` and
   `scripts/cross_impl_check.py` green in CI — they are the regression net
   that makes the legacy tree worth keeping.

## Post-cutover posture

The Python implementation stays in the repository and in CI as the
compatibility oracle, not as a shipped product. If a future change makes the
two diverge, the cross-impl suite fails and the change is wrong until proven
otherwise.
