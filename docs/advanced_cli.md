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
| Retrieve an entry's secret | `entry get` | `seedpass entry get "GitHub"` |

### Vault Commands

Manage the entire vault for a profile.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Export the vault | `vault export` | `seedpass vault export --file backup.json` |

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
| Get a setting value | `config get` | `seedpass config get inactivity_timeout` |

### Fingerprint Commands

Manage seed profiles (fingerprints).

| Action | Command | Examples |
| :--- | :--- | :--- |
| List all profiles | `fingerprint list` | `seedpass fingerprint list` |

### Utility Commands

Miscellaneous helper commands.

| Action | Command | Examples |
| :--- | :--- | :--- |
| Generate a password | `util generate-password` | `seedpass util generate-password --length 24` |

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
- **`seedpass entry get <query>`** – Retrieve the primary secret for one matching entry.

### `vault` Commands

- **`seedpass vault export`** – Export the entire vault to an encrypted JSON file.

### `nostr` Commands

- **`seedpass nostr sync`** – Perform a two‑way sync with configured Nostr relays.
- **`seedpass nostr get-pubkey`** – Display the Nostr public key for the active profile.

### `config` Commands

- **`seedpass config get <key>`** – Retrieve a configuration value such as `inactivity_timeout`, `secret_mode`, or `auto_sync`.

### `fingerprint` Commands

- **`seedpass fingerprint list`** – List available profiles by fingerprint.

### `util` Commands

- **`seedpass util generate-password`** – Generate a strong password of the requested length.

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
- Adjust configuration values like `inactivity_timeout` or `secret_mode` through the `config` commands.
- `entry get` is script‑friendly and can be piped into other commands.
