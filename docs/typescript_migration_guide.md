# Migrating from Python SeedPass to the TypeScript CLI

Short version: there is no migration step. The TypeScript CLI reads and
writes the same `~/.seedpass` profiles as the Python implementation. Point it
at your existing directory and it works.

This document exists to say exactly what that means, what to back up first,
and how to go back if you want to.

## What is shared

Both implementations use the same on-disk layout, the same key derivations,
and the same Nostr sync protocol:

- `~/.seedpass/fingerprints.json` and per-profile directories
- `parent_seed.enc` (PBKDF2 or Argon2id, whichever your profile uses)
- `seedpass_entries_db.json.enc` and `seedpass_config.json.enc`
- portable backups (`format_version` 1)
- Nostr manifests, snapshot chunks and deltas (kinds 30070/30071/30072)

Every one of those is verified on each change by
`scripts/cross_impl_check.py`. See `docs/typescript_port_compatibility_matrix.md`
for what is covered and what is not.

## Before you start

Take a backup you can restore without either implementation:

```bash
# A portable, encrypted export (readable by both implementations)
seedpass vault export --file ~/seedpass-pre-migration.seedpass

# Plus a copy of the raw profile directory
cp -a ~/.seedpass ~/.seedpass.backup-$(date +%Y%m%d)
```

Keep your seed phrase available. It is the ultimate recovery path: with the
seed and a relay snapshot you can rebuild a profile from nothing.

## Trying it without touching your real vault

`SEEDPASS_APP_DIR` redirects everything to a scratch directory, so you can
rehearse against a copy:

```bash
cp -a ~/.seedpass /tmp/seedpass-trial
export SEEDPASS_APP_DIR=/tmp/seedpass-trial
seedpass-js fingerprint list
seedpass-js entry list
seedpass-js entry reveal <some-label>   # compare against `seedpass entry get`
```

Comparing a few revealed secrets against the Python CLI is the most direct
confirmation that the two agree about *your* vault, not just the test vaults.

## Switching over

```bash
unset SEEDPASS_APP_DIR                  # back to ~/.seedpass
seedpass-js agent start &               # once per login session
export SEEDPASS_PASSWORD='...'          # or a leading space to skip shell history
seedpass-js vault unlock --ttl 900
seedpass-js entry list
```

Two differences from the Python CLI worth knowing:

1. **Unlocking is explicit.** Python prompts inside a long-running process;
   the TypeScript CLI is one command per invocation, so a session agent holds
   the unlocked seed with a TTL. `vault lock` (or letting the TTL lapse)
   drops it.
2. **Output is reference-first.** Listing and searching never print secret
   values; `entry reveal` does. This is deliberate — see the README section
   on scoped tokens for why it matters when an agent is driving.

## Rolling back

Nothing needs undoing. A profile that the TypeScript CLI has created,
modified, archived, linked or synced is still an ordinary SeedPass profile:

```bash
seedpass entry list        # the Python CLI, same profile
```

This is enforced, not assumed: cross-impl phase K drives a profile through
the TypeScript CLI (creating entries of several kinds, editing one, archiving
another) and then asserts that Python reopens it, sees every change, derives
the same secrets, and can still write to it.

The one thing to know: an old Python build cannot read a profile whose index
schema has been upgraded. Both implementations write schema version 4 today,
so this only applies if you jump backwards several releases.

## What the TypeScript CLI does not do yet

- PGP **RSA** keys. ed25519 PGP keys are at byte-for-byte parity; RSA
  generation is not reproducible, so the TypeScript port refuses rather than
  deriving a different key. Keep the Python implementation for RSA entries.
- The `semantic` (vector search) and `api` (FastAPI server) command groups.
- Python's v2 and v3 TUIs. Interactive mode follows the **legacy (v1)** menu
  tree instead, which is the one `seedpass --legacy-tui` opens.
- Two legacy-TUI items are stubs that say so when selected: Semantic Index
  (not part of this build) and QR code display (no QR encoder here; it offers
  the underlying value instead). Script checksum verification covers the
  Python source tree and is replaced by the bundle's `.sha256`.

If you rely on any of those, run both: they operate on the same profile.

## Interactive mode

```bash
seedpass-js            # opens the vault; asks for your master password
```

It unlocks the same way the CLI does: `SEEDPASS_MNEMONIC` if set, then the
session agent, then a password prompt.

The menus mirror Python's legacy TUI item for item, in the same order and
under the same numbers, so the sequences you already know still work — `7`
then `1` is still Settings then Profiles. A blank line goes back; a blank
line at the main menu exits.

```
  1. Add Entry          5. Modify an Existing Entry
  2. Retrieve Entry     6. 2FA Codes
  3. Search Entries     7. Settings
  4. List Entries       8. List Archived
```

Entry details list metadata only, with stored secrets shown as `has_*`
flags. `S` shows a secret and `C` copies it — the two actions whose purpose
is to produce one. Turning on **Secret Mode** (Settings 15) sends both to the
clipboard instead of the screen, as it does in Python.

Piped or redirected, the bare command prints the help instead — there is no
terminal to drive.

## Starting fresh (no existing vault)

If you have no seed yet, `fingerprint create` generates one — 32 bytes of OS
entropy through BIP-85, the same construction Python uses:

```bash
export SEEDPASS_APP_DIR=~/.seedpass
export SEEDPASS_PASSWORD='a master password'
seedpass-js fingerprint create --name personal --words 24 --out ~/seed.txt
```

The phrase is written to a `0600` file, and an existing file is never
overwritten. `--show` prints it to stdout instead; on an interactive terminal
neither flag is needed.

**Where the phrase goes is a deliberate choice, not a default.** When stdout
is not a terminal the command refuses to generate anything rather than write
your only copy of the seed into a pipe — a CI log, a captured transcript, an
AI agent's context. Nothing is created in that case, so there is no
half-made profile to clean up.

Write the phrase down offline and delete the file. It is the only way to
recover the vault: everything else is derived from it, and SeedPass keeps no
copy you can read without it.

## Recovering from nothing

With only your seed phrase and a relay that has your snapshot:

```bash
export SEEDPASS_APP_DIR=~/.seedpass
export SEEDPASS_MNEMONIC='your words'
export SEEDPASS_PASSWORD='a new master password'   # can differ from before
seedpass-js fingerprint add --name recovered
seedpass-js nostr add-relay wss://your.relay
seedpass-js nostr restore
```

The profile fingerprint derives from the seed, so it comes back identical,
and deterministic entries re-derive to the same secrets. This path is
verified end to end in the cross-implementation suite.
