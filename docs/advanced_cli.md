# SeedPass Advanced CLI and API Documentation

## Overview

Welcome to the **Advanced CLI and API Documentation** for **SeedPass**, a secure, deterministic password manager built on Bitcoin's BIP‑85 standard. This guide is designed for power users, developers, and system administrators who wish to leverage the full capabilities of SeedPass through the command line for scripting, automation, and integration.

SeedPass uses a `noun-verb` command structure (e.g., `seedpass entry get <query>`) for a clear, scalable, and discoverable interface. You can explore the available actions for any command group with the `--help` flag (for example, `seedpass entry --help`).

> **Note:** These commands describe planned functionality. The advanced CLI is not yet part of the stable release but will follow the current SeedPass design of fingerprint-based profiles and a local API for secure integrations.

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
3. [Detailed Command Descriptions](#detailed-command-descriptions)
4. [Planned API Integration](#planned-api-integration)
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
| Add a new entry | `entry add` | `seedpass entry add --type password --label "GitHub" --username "user" --length 20` |
| Retrieve an entry's secret | `entry get` | `seedpass entry get "GitHub"` |
| List entries | `entry list` | `seedpass entry list --sort label` |
| Search for entries | `entry search` | `seedpass entry search "GitHub"` |
| Modify an entry | `entry modify` | `seedpass entry modify "GitHub" --notes "New note"` |
| Delete an entry | `entry delete` | `seedpass entry delete "GitHub"` |

### Vault Commands

Manage the entire vault for a profile.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Export the vault | `vault export` | `seedpass vault export --file backup.json` |
| Import a vault | `vault import` | `seedpass vault import --file backup.json` |
| Change master password | `vault changepw` | `seedpass vault changepw` |

### Nostr Commands

Interact with the Nostr network for backup and synchronization.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Sync with relays | `nostr sync` | `seedpass nostr sync` |
| Get public key | `nostr get-pubkey` | `seedpass nostr get-pubkey` |
| Manage relays | `nostr relays` | `seedpass nostr relays --add wss://relay.example.com` |

### Config Commands

Manage profile‑specific settings.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Get a setting value | `config get` | `seedpass config get inactivity_timeout` |
| Set a setting value | `config set` | `seedpass config set secret_mode true` |

### Fingerprint Commands

Manage seed profiles (fingerprints).

| Action | Command | Examples |
| :--- | :--- | :--- |
| Add a new profile | `fingerprint add` | `seedpass fingerprint add` |
| List all profiles | `fingerprint list` | `seedpass fingerprint list` |
| Remove a profile | `fingerprint remove` | `seedpass fingerprint remove <FP>` |
| Set active profile | `fingerprint use` | `seedpass fingerprint use <FP>` |

### Utility Commands

Miscellaneous helper commands.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Generate a password | `util generate-password` | `seedpass util generate-password --length 24` |
| Verify script checksum | `util verify-checksum` | `seedpass util verify-checksum` |

---

## Detailed Command Descriptions

### `entry` Commands

- **`seedpass entry add`** – Add a new entry. Use `--type` to specify `password`, `totp`, `ssh`, `pgp`, `nostr`, `key-value`, or `managed-account`.
- **`seedpass entry get <query>`** – Retrieve the primary secret for one matching entry.
- **`seedpass entry list`** – List entries in the vault, optionally sorted or filtered.
- **`seedpass entry search <query>`** – Search across labels, usernames, URLs, and notes.
- **`seedpass entry modify <query>`** – Update fields on an existing entry. Use `--archive` to hide or `--restore` to un‑archive.
- **`seedpass entry delete <query>`** – Permanently delete an entry after confirmation.

### `vault` Commands

- **`seedpass vault export`** – Export the entire vault to an encrypted JSON file.
- **`seedpass vault import`** – Import entries from an exported file, replacing the current vault after creating a backup.
- **`seedpass vault changepw`** – Interactively change the master password for the current profile.

### `nostr` Commands

- **`seedpass nostr sync`** – Perform a two‑way sync with configured Nostr relays.
- **`seedpass nostr get-pubkey`** – Display the Nostr public key for the active profile.
- **`seedpass nostr relays`** – Manage the relay list (`--list`, `--add`, `--remove`, `--reset`).

### `config` Commands

- **`seedpass config get <key>`** – Retrieve a configuration value such as `inactivity_timeout`, `secret_mode`, or `auto_sync`.
- **`seedpass config set <key> <value>`** – Set a configuration value for the active profile.

### `fingerprint` Commands

- **`seedpass fingerprint add`** – Add a new seed profile (interactive or via `--import-seed`).
- **`seedpass fingerprint list`** – List available profiles by fingerprint.
- **`seedpass fingerprint remove <FP>`** – Delete a profile and its data after confirmation.
- **`seedpass fingerprint use <FP>`** – Make the given fingerprint active in the current shell session.

### `util` Commands

- **`seedpass util generate-password`** – Generate a strong password of the requested length.
- **`seedpass util verify-checksum`** – Verify the program checksum for integrity.

---

## Planned API Integration

The advanced CLI will act as a client for a locally hosted REST API. Starting the API loads the vault into memory after prompting for the master password and prints a temporary API key. Third‑party clients include this key in the `Authorization` header when calling endpoints such as `GET /api/v1/entry?query=GitHub`. The server automatically shuts down after a period of inactivity or when `seedpass api stop` is run.

---

## Usage Guidelines

- Use the `--help` flag for details on any command.
- Set a strong master password and regularly export encrypted backups.
- Adjust configuration values like `inactivity_timeout` or `secret_mode` through the `config` commands.
- `entry get` is script‑friendly and can be piped into other commands.
