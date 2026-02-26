**Protocol Research Findings**: The codebase uses `bip_utils` and `nostr_sdk` correctly. However, `BIP85` implementation uses `app_no=2` for symmetric key derivation, which is non-standard (usually `128` or `0`). A regression test `src/tests/test_bip85_compliance.py` was added to document and monitor this behavior.

# Memory Update - 2026-02-26

## What was done
- Ran TORCH update and doctor checks for this repository.
- Preferred dedicated `torch/` install path first, then fell back to repo-root updater flow.

## Key findings
- `npx --prefix torch --no-install torch-lock update --force` failed with:
  - `src and dest cannot be the same /home/user/Documents/GitHub/SeedPass/torch/src`
- Repo-root flow succeeded:
  - `npx --no-install torch-lock update --force`
  - `npx --no-install torch-lock doctor` reported `7 passed, 0 warned, 0 failed`.

## Operational note
- In this repo, when `torch-lock update` is run with `--prefix torch`, path resolution can collide on `torch/src`.
- If that occurs, running the updater from repo root is a reliable fallback.

## Resolution Applied - 2026-02-26
- Implemented same-path guards in `torch/src/ops.mjs`:
  - `copyDir(src, dest)` now skips when `path.resolve(src) === path.resolve(dest)`.
  - `copyFile(src, dest, ...)` now skips no-op self-copy operations for identical resolved paths.
- This aligns with upstream TORCH fix notes for self-hosted installs where package root equals install target.

## Validation After Fix
- `npx --prefix torch --no-install torch-lock update --force` now succeeds (no `src and dest cannot be the same` error).
- Update created backup: `torch/_backups/backup_2026-02-26T13-45-30-661Z`.
- `npx --prefix torch --no-install torch-lock doctor` reports: `7 passed, 0 warned, 0 failed`.

## Operator Context Note (Adam)
- `bitvid` is a different project Adam is working on.
- If a prompt context references `bitvid` instead of `SeedPass`, treat it as a likely working-directory mismatch.
- In that case, ask Adam to confirm whether the active directory/repo is correct before making changes.
