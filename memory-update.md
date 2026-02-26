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
