# SeedPass Advanced CLI and API Documentation

## Overview

Welcome to the **Advanced CLI and API Documentation** for **SeedPass**, a secure, deterministic password manager built on Bitcoin's BIP‑85 standard. This guide is designed for power users, developers, and system administrators who wish to leverage the full capabilities of SeedPass through the command line for scripting, automation, and integration.

SeedPass uses a `noun-verb` command structure (e.g., `seedpass entry get <query>`) for a clear, scalable, and discoverable interface. You can explore the available actions for any command group with the `--help` flag (for example, `seedpass entry --help`).

The commands in this document reflect the Typer-based CLI shipped with SeedPass. Each command accepts the optional `--fingerprint` flag to operate on a specific seed profile.

---

## Table of Contents

1. [Global Options](#global-options)
2. [Command Group Reference](#command-group-reference)
   - [Entry Commands](#entry-commands)
   - [Vault Commands](#vault-commands)
   - [Nostr Commands](#nostr-commands)
   - [Config Commands](#config-commands)
   - [Fingerprint Commands](#fingerprint-commands)
   - [Utility Commands](#utility-commands)
   - [API Commands](#api-commands)
3. [Detailed Command Descriptions](#detailed-command-descriptions)
4. [API Integration](#api-integration)
5. [Usage Guidelines](#usage-guidelines)

---

## Global Options

These options can be used with any command.

| Flag | Description |
| :--- | :--- |
| `--fingerprint <fp>` | Specify which seed profile to use. If omitted, the most recently used profile is selected. |
| `--help`, `-h` | Display help information for a command or subcommand. |

---

## Command Group Reference

### Entry Commands

Manage individual entries within a vault.

| Action | Command | Examples |
| :--- | :--- | :--- |
| List entries | `entry list` | `seedpass entry list --sort label` |
| Search for entries | `entry search` | `seedpass entry search "GitHub"` |
| Retrieve an entry's secret (password or TOTP code) | `entry get` | `seedpass entry get "GitHub"` |
| Add a password entry | `entry add` | `seedpass entry add Example --length 16` |
| Add a TOTP entry | `entry add-totp` | `seedpass entry add-totp Email --secret JBSW...` |
| Add an SSH key entry | `entry add-ssh` | `seedpass entry add-ssh Server --index 0` |
| Add a PGP key entry | `entry add-pgp` | `seedpass entry add-pgp Personal --user-id me@example.com` |
| Add a Nostr key entry | `entry add-nostr` | `seedpass entry add-nostr Chat` |
| Add a seed phrase entry | `entry add-seed` | `seedpass entry add-seed Backup --words 24` |
| Add a key/value entry | `entry add-key-value` | `seedpass entry add-key-value "API Token" --key api --value abc123` |
| Add a managed account entry | `entry add-managed-account` | `seedpass entry add-managed-account Trading` |
| Modify an entry | `entry modify` | `seedpass entry modify 1 --key new --value updated` |
| Archive an entry | `entry archive` | `seedpass entry archive 1` |
| Unarchive an entry | `entry unarchive` | `seedpass entry unarchive 1` |
| Export all TOTP secrets | `entry export-totp` | `seedpass entry export-totp --file totp.json` |
| Show all TOTP codes | `entry totp-codes` | `seedpass entry totp-codes` |

### Vault Commands

Manage the entire vault for a profile.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Export the vault | `vault export` | `seedpass vault export --file backup.json` |
| Import a vault | `vault import` | `seedpass vault import --file backup.json` *(also syncs with Nostr)* |
| Change the master password | `vault change-password` | `seedpass vault change-password` |
| Lock the vault | `vault lock` | `seedpass vault lock` |
| Show profile statistics | `vault stats` | `seedpass vault stats` |
| Reveal or back up the parent seed | `vault reveal-parent-seed` | `seedpass vault reveal-parent-seed --file backup.enc` |

### Nostr Commands

Interact with the Nostr network for backup and synchronization.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Sync with relays | `nostr sync` | `seedpass nostr sync` |
| Get public key | `nostr get-pubkey` | `seedpass nostr get-pubkey` |

### Config Commands

Manage profile‑specific settings.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Get a setting value | `config get` | `seedpass config get kdf_iterations` |
| Set a setting value | `config set` | `seedpass config set backup_interval 3600` |
| Toggle offline mode | `config toggle-offline` | `seedpass config toggle-offline` |

### Fingerprint Commands

Manage seed profiles (fingerprints).

| Action | Command | Examples |
| :--- | :--- | :--- |
| List all profiles | `fingerprint list` | `seedpass fingerprint list` |
| Add a profile | `fingerprint add` | `seedpass fingerprint add` |
| Remove a profile | `fingerprint remove` | `seedpass fingerprint remove <fp>` |
| Switch profile | `fingerprint switch` | `seedpass fingerprint switch <fp>` |

### Utility Commands

Miscellaneous helper commands.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Generate a password | `util generate-password` | `seedpass util generate-password --length 24` |
| Verify script checksum | `util verify-checksum` | `seedpass util verify-checksum` |
| Update script checksum | `util update-checksum` | `seedpass util update-checksum` |

If you see a startup warning about a script checksum mismatch,
run `seedpass util update-checksum` or choose "Generate Script Checksum"
from the Settings menu to update the stored value.

### API Commands

Run or stop the local HTTP API.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Start the API | `api start` | `seedpass api start --host 0.0.0.0 --port 8000` |
| Stop the API | `api stop` | `seedpass api stop` |

---

## Detailed Command Descriptions

### `entry` Commands

- **`seedpass entry list`** – List entries in the vault, optionally sorted or filtered.
- **`seedpass entry search <query>`** – Search across labels, usernames, URLs and notes.
- **`seedpass entry get <query>`** – Retrieve the password or TOTP code for one matching entry, depending on the entry's type.
- **`seedpass entry add <label>`** – Create a new password entry. Use `--length` to set the password length and optional `--username`/`--url` values.
- **`seedpass entry add-totp <label>`** – Create a TOTP entry. Use `--secret` to import an existing secret or `--index` to derive from the seed.
- **`seedpass entry add-ssh <label>`** – Create an SSH key entry derived from the seed.
- **`seedpass entry add-pgp <label>`** – Create a PGP key entry. Provide `--user-id` and `--key-type` as needed.
- **`seedpass entry add-nostr <label>`** – Create a Nostr key entry for decentralised chat.
- **`seedpass entry add-seed <label>`** – Store a derived seed phrase. Use `--words` to set the word count.
 - **`seedpass entry add-key-value <label>`** – Store arbitrary data with `--key` and `--value`.
- **`seedpass entry add-managed-account <label>`** – Store a BIP‑85 derived account seed.
- **`seedpass entry modify <id>`** – Update an entry's fields. For key/value entries you can change the label, key and value.
- **`seedpass entry archive <id>`** – Mark an entry as archived so it is hidden from normal lists.
- **`seedpass entry unarchive <id>`** – Restore an archived entry.
- **`seedpass entry export-totp --file <path>`** – Export all stored TOTP secrets to a JSON file.
- **`seedpass entry totp-codes`** – Display all current TOTP codes with remaining time.

Example retrieving a TOTP code:

```bash
$ seedpass entry get "email"
[##########----------] 15s
Code: 123456
```

### Viewing Entry Details

Picking an entry from `entry list` or `entry search` displays its metadata first
so you can review the label, username and notes. Sensitive fields are hidden
until you confirm you want to reveal them. After showing the secret, the details
view offers the same actions as `entry get`—edit the entry, archive it or show
QR codes for supported types.

### `vault` Commands

- **`seedpass vault export`** – Export the entire vault to an encrypted JSON file.
- **`seedpass vault import`** – Import a vault from an encrypted JSON file and automatically sync via Nostr.
- **`seedpass vault change-password`** – Change the master password used for encryption.
- **`seedpass vault lock`** – Clear sensitive data from memory and require reauthentication.
- **`seedpass vault stats`** – Display statistics about the active seed profile.
- **`seedpass vault reveal-parent-seed`** – Print the parent seed or write an encrypted backup with `--file`.

### `nostr` Commands

- **`seedpass nostr sync`** – Perform a two‑way sync with configured Nostr relays.
- **`seedpass nostr get-pubkey`** – Display the Nostr public key for the active profile.

### `config` Commands

- **`seedpass config get <key>`** – Retrieve a configuration value such as `kdf_iterations`, `backup_interval`, `inactivity_timeout`, `secret_mode_enabled`, `clipboard_clear_delay`, `additional_backup_path`, `relays`, `quick_unlock`, `nostr_max_retries`, `nostr_retry_delay`, or password policy fields like `min_uppercase`.
- **`seedpass config set <key> <value>`** – Update a configuration option. Example: `seedpass config set kdf_iterations 200000`. Use keys like `min_uppercase`, `min_lowercase`, `min_digits`, `min_special`, `nostr_max_retries`, `nostr_retry_delay`, or `quick_unlock` to adjust settings.
- **`seedpass config toggle-secret-mode`** – Interactively enable or disable Secret Mode and set the clipboard delay.
- **`seedpass config toggle-offline`** – Enable or disable offline mode to skip Nostr operations.

### `fingerprint` Commands

- **`seedpass fingerprint list`** – List available profiles by fingerprint.
- **`seedpass fingerprint add`** – Create a new seed profile.
- **`seedpass fingerprint remove <fp>`** – Delete the specified profile.
- **`seedpass fingerprint switch <fp>`** – Switch the active profile.

### `util` Commands

- **`seedpass util generate-password`** – Generate a strong password of the requested length.
- **`seedpass util verify-checksum`** – Verify the SeedPass script checksum.
- **`seedpass util update-checksum`** – Regenerate the script checksum file.

---

## API Integration

SeedPass provides a small REST API for automation. Run `seedpass api start` to launch the server. The command prints a one‑time token which clients must include in the `Authorization` header.

Set the `SEEDPASS_CORS_ORIGINS` environment variable to a comma‑separated list of allowed origins when you need cross‑origin requests:

```bash
SEEDPASS_CORS_ORIGINS=http://localhost:3000 seedpass api start
```

Shut down the server with `seedpass api stop`.

---

## Usage Guidelines

- Use the `--help` flag for details on any command.
- Set a strong master password and regularly export encrypted backups.
- Adjust configuration values like `kdf_iterations`, `backup_interval`, `inactivity_timeout`, `secret_mode_enabled`, `nostr_max_retries`, `nostr_retry_delay`, or `quick_unlock` through the `config` commands.
- Customize password complexity with `config set min_uppercase 3`, `config set min_digits 4`, and similar commands.
- `entry get` is script‑friendly and can be piped into other commands.
