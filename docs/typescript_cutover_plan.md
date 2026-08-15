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
| Feature parity for daily use | green for daily use; 3 scoped exclusions |
| Packaging + release | green |
| Migration + rollback story | green |

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
   `js/packages/core/test/relay.test.ts`, plus a live end-to-end round trip
   in cross-impl phase F: Python publishes a snapshot through a real relay
   and the TS CLI restores it with secrets intact. **Green.**

5. **Feature parity for real daily use.** **Green for daily use**, with
   three scoped exclusions that are documented rather than hidden:
   - **PGP RSA keys** — unsupported by design. PyCryptodome's seeded prime
     search is not reproducible, so TS refuses the key type instead of
     deriving a different key. ed25519 PGP is at byte-for-byte parity.
   - **`semantic`** (local vector search) — a derived index that can be
     rebuilt; plan §8.5 rates it P2.
   - **`api`** (FastAPI server) — a separate surface, not vault behavior.

   Recommendation: none of the three blocks cutover. Each is a bounded,
   named gap with the Python implementation still available for it, and the
   migration guide tells users exactly that. Revisit if a real profile is
   found to depend on RSA PGP entries.

   Everything else is ported and cross-verified: all nine entry kinds,
   create/modify/archive/links, document import/export, both key
   derivations, schema migrations 0→4, sync, backups, profiles and config.

6. **Packaging and distribution exist.** **Green.**
   `js/packages/cli/build.mjs` bundles the CLI into one self-contained ESM
   file with no runtime dependencies beyond Node 22, emits a `.sha256`
   beside it, and is wired into `@seedpass/cli` as `bin` + `prepack` so
   `npm install` and `npm pack` both produce a working command. CI builds
   the bundle, smoke-tests it from a directory with no `node_modules`
   (version, capabilities, profile creation, entry creation, reveal), and
   uploads it as an artifact. Install instructions live in
   `js/packages/cli/README.md`.
   Remaining for a tagged release: fold the bundle checksum into the
   existing `release-integrity` signing workflow.

7. **Migration guide and rollback.** **Green.**
   `docs/typescript_migration_guide.md` covers the (empty) migration path,
   a pre-migration backup, rehearsing against a copy via `SEEDPASS_APP_DIR`,
   the two behavioral differences users will notice (explicit unlock,
   reference-first output), the three known exclusions, and seed-only
   recovery. Rollback is proven, not asserted: cross-impl phase K drives a
   profile through the TS CLI — creating several entry kinds, editing,
   archiving — then checks Python reopens it, sees every change, derives the
   same secrets, and can still write to it.

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
