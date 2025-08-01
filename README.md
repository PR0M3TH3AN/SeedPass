# SeedPass

![SeedPass Logo](https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/refs/heads/main/logo/png/SeedPass-Logo-03.png)

**SeedPass** is a secure password generator and manager built on **Bitcoin's BIP-85 standard**. It uses deterministic key derivation to generate **passwords that are never stored**, but can be easily regenerated when needed. By integrating with the **Nostr network**, SeedPass compresses your encrypted vault and splits it into 50 KB chunks. Each chunk is published as a parameterised replaceable event (`kind 30071`), with a manifest (`kind 30070`) describing the snapshot and deltas (`kind 30072`) capturing changes between snapshots. This allows secure password recovery across devices without exposing your data.

[Tip Jar](https://nostrtipjar.netlify.app/?n=npub16y70nhp56rwzljmr8jhrrzalsx5x495l4whlf8n8zsxww204k8eqrvamnp)

---

**⚠️ Disclaimer**

This software was not developed by an experienced security expert and should be used with caution. There may be bugs and missing features. Each vault chunk is limited to 50 KB and SeedPass periodically publishes a new snapshot to keep accumulated deltas small. The security of the program's memory management and logs has not been evaluated and may leak sensitive information. Loss or exposure of the parent seed places all derived passwords, accounts, and other artifacts at risk.

---
### Supported OS

✔ Windows 10/11 • macOS 12+ • Any modern Linux  
SeedPass now uses the `portalocker` library for cross-platform file locking. No WSL or Cygwin required.

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Create a Virtual Environment](#2-create-a-virtual-environment)
  - [3. Activate the Virtual Environment](#3-activate-the-virtual-environment)
  - [4. Install Dependencies](#4-install-dependencies)
- [Usage](#usage)
  - [Running the Application](#running-the-application)
  - [Managing Multiple Seeds](#managing-multiple-seeds)
    - [Additional Entry Types](#additional-entry-types)
  - [Recovery](#recovery)
- [Building a standalone executable](#building-a-standalone-executable)
- [Packaging with Briefcase](#packaging-with-briefcase)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features

- **Deterministic Password Generation:** Utilize BIP-85 for generating deterministic and secure passwords.
- **Encrypted Storage:** All seeds, login passwords, and sensitive index data are encrypted locally.
- **Nostr Integration:** Post and retrieve your encrypted password index to/from the Nostr network.
- **Chunked Snapshots:** Encrypted vaults are compressed and split into 50 KB chunks published as `kind 30071` events with a `kind 30070` manifest and `kind 30072` deltas. The manifest's `delta_since` field stores the UNIX timestamp of the latest delta event.
- **Automatic Checksum Generation:** The script generates and verifies a SHA-256 checksum to detect tampering.
- **Multiple Seed Profiles:** Manage separate seed profiles and switch between them seamlessly.
- **Nested Managed Account Seeds:** SeedPass can derive nested managed account seeds.
- **Interactive TUI:** Navigate through menus to add, retrieve, and modify entries as well as configure Nostr settings.
- **SeedPass 2FA:** Generate TOTP codes with a real-time countdown progress bar.
- **2FA Secret Issuance & Import:** Derive new TOTP secrets from your seed or import existing `otpauth://` URIs.
- **Export 2FA Codes:** Save all stored TOTP entries to an encrypted JSON file for use with other apps.
- **Display TOTP Codes:** Show all active 2FA codes with a countdown timer.
- **Optional External Backup Location:** Configure a second directory where backups are automatically copied.
- **Auto-Lock on Inactivity:** Vault locks after a configurable timeout for additional security.
- **Quick Unlock:** Optionally skip the password prompt after verifying once.
- **Secret Mode:** When enabled, newly generated and retrieved passwords are copied to your clipboard and automatically cleared after a delay.
- **Tagging Support:** Organize entries with optional tags and find them quickly via search.
- **Manual Vault Export/Import:** Create encrypted backups or restore them using the CLI or API.
- **Parent Seed Backup:** Securely save an encrypted copy of the master seed.
- **Manual Vault Locking:** Instantly clear keys from memory when needed.
- **Vault Statistics:** View counts for entries and other profile metrics.
- **Change Master Password:** Rotate your encryption password at any time.
- **Checksum Verification Utilities:** Verify or regenerate the script checksum.
- **Relay Management:** List, add, remove or reset configured Nostr relays.
- **Offline Mode:** Disable all Nostr communication for local-only operation.


A small on-screen notification area now shows queued messages for 10 seconds
before fading.

## Architecture Overview

SeedPass follows a layered design. The **`seedpass.core`** package exposes the
`PasswordManager` along with service classes (e.g. `VaultService` and
`EntryService`) that implement the main API used across interfaces.
The command line tool in **`seedpass.cli`** is a thin adapter built with Typer
that delegates operations to this API layer.

The BeeWare desktop interface lives in **`seedpass_gui.app`** and can be
started with either `seedpass-gui` or `python -m seedpass_gui`. It reuses the
same service objects to unlock the vault, list entries and search through them.

An optional browser extension can communicate with the FastAPI server exposed by
`seedpass.api` to manage entries from within the browser.

```mermaid
graph TD
    core["seedpass.core"]
    cli["CLI"]
    api["FastAPI server"]
    gui["BeeWare GUI"]
    ext["Browser Extension"]

    cli --> core
    gui --> core
    api --> core
    ext --> api
```

See `docs/ARCHITECTURE.md` for details.

## Prerequisites

- **Python 3.8+** (3.11 or 3.12 recommended): Install Python from [python.org](https://www.python.org/downloads/) and be sure to check **"Add Python to PATH"** during setup. Using Python 3.13 is currently discouraged because some dependencies do not ship wheels for it yet, which can cause build failures on Windows unless you install the Visual C++ Build Tools.  
  *Windows only:* Install the [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and select the **C++ build tools** workload.

## Installation

### Quick Installer

Use the automated installer to download SeedPass and its dependencies in one step.
The scripts also install the correct BeeWare backend for your platform automatically.
If the GTK `gi` bindings are missing, the installer attempts to install the
necessary system packages using `apt`, `yum`, `pacman`, or Homebrew.

**Linux and macOS:**
```bash
bash -c "$(curl -sSL https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/main/scripts/install.sh)"
```
*Install the beta branch:*
```bash
bash -c "$(curl -sSL https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/main/scripts/install.sh)" _ -b beta
```
Make sure the command ends right after `-b beta` with **no trailing parenthesis**.

**Windows (PowerShell):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; $scriptContent = (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/main/scripts/install.ps1'); & ([scriptblock]::create($scriptContent))
```
Before running the script, install **Python 3.11** or **3.12** from [python.org](https://www.python.org/downloads/windows/) and tick **"Add Python to PATH"**. You should also install the [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **C++ build tools** workload so dependencies compile correctly.  
The Windows installer will attempt to install Git automatically if it is not already available. It also tries to install Python 3 using `winget`, `choco`, or `scoop` when Python is missing and recognizes the `py` launcher if `python` isn't on your PATH. If these tools are unavailable you'll see a link to download Python directly from <https://www.python.org/downloads/windows/>. When Python 3.13 or newer is detected without the Microsoft C++ build tools, the installer now attempts to download Python 3.12 automatically so you don't have to compile packages from source.

**Note:** If this fallback fails, install Python 3.12 manually or install the [Microsoft Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and rerun the installer.

#### Windows Nostr Sync Troubleshooting

When backing up or restoring from Nostr on Windows, a few issues are common:

* **Event loop errors** – Messages like `RuntimeError: Event loop is closed` usually mean the async runtime failed to initialize. Running SeedPass with `--verbose` provides more detail about which coroutine failed.
* **Permission problems** – If you see `Access is denied` when writing to `~/.seedpass`, launch your terminal with "Run as administrator" so the app can create files in your profile directory.
* **Missing dependencies** – Ensure `websockets` and other requirements are installed inside your virtual environment:

  ```bash
  pip install websockets
  ```

Using increased log verbosity helps diagnose sync issues and confirm that the WebSocket connections to your configured relays succeed.
### Uninstall

Run the matching uninstaller if you need to remove a previous installation or clean up an old `seedpass` command:

**Linux and macOS:**
```bash
bash -c "$(curl -sSL https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/main/scripts/uninstall.sh)"
```
If you see a warning that an old executable couldn't be removed, delete the file manually.

**Windows (PowerShell):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; $scriptContent = (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/main/scripts/uninstall.ps1'); & ([scriptblock]::create($scriptContent))
```

### Manual Setup

Follow these steps to set up SeedPass on your local machine.

1. **Clone the Repository**

   ```bash
   git clone https://github.com/PR0M3TH3AN/SeedPass.git
   cd SeedPass
   ```

2. **Create a Virtual Environment**

   ```bash
   python3 -m venv venv
   ```

3. **Activate the Virtual Environment**

   - **Linux/macOS:**
     ```bash
     source venv/bin/activate
     ```
   - **Windows:**
     ```bash
     venv\Scripts\activate
     ```

4. **Install Dependencies**

   ```bash
   python -m pip install --upgrade pip
   python -m pip install -r src/requirements.txt
   python -m pip install -e .
   ```
// 🔧 merged conflicting changes from codex/locate-command-usage-issue-in-seedpass vs beta
After reinstalling, run `which seedpass` on Linux/macOS or `where seedpass` on Windows to confirm the command resolves to your virtual environment's `seedpass` executable.

#### Linux Clipboard Support

On Linux, `pyperclip` relies on external utilities like `xclip` or `xsel`. SeedPass will attempt to install **xclip** automatically if neither tool is available. If the automatic installation fails, you can install it manually:

```bash
sudo apt-get install xclip
```

## Quick Start

After installing dependencies and activating your virtual environment, install the package in editable mode so the `seedpass` command is available:

```bash
python -m pip install -e .
```


You can then launch SeedPass and create a backup:

```bash
# Start the application (interactive TUI)
seedpass

# Export your index
seedpass export --file "~/seedpass_backup.json"

# Later you can restore it
seedpass import --file "~/seedpass_backup.json"

# Quickly find or retrieve entries
seedpass search "github"
seedpass search --tags "work,personal"
seedpass get "github"
# Retrieve a TOTP entry
seedpass entry get "email"
# The code is printed and copied to your clipboard

# Sort or filter the list view
seedpass list --sort label
seedpass list --filter totp
# Generate a password with the safe character set defined by `SAFE_SPECIAL_CHARS`
seedpass util generate-password --length 20 --special-mode safe --exclude-ambiguous

# Use the **Settings** menu to configure an extra backup directory
# on an external drive.
```

For additional command examples, see [docs/advanced_cli.md](docs/advanced_cli.md). Details on the REST API can be found in [docs/api_reference.md](docs/api_reference.md).

### Getting Started with the GUI

SeedPass also ships with a simple BeeWare desktop interface. Launch it from
your virtual environment using any of the following commands:

```bash
seedpass gui
python -m seedpass_gui
seedpass-gui
```

Only `toga-core` and the headless `toga-dummy` backend are included by default.
The quick installer automatically installs the correct BeeWare backend so the
GUI works out of the box. If you set up SeedPass manually, install the backend
for your platform:

```bash
# Linux
pip install toga-gtk

# If you see build errors about "cairo" on Linux, install the cairo
# development headers using your package manager, e.g.:
sudo apt-get install libcairo2 libcairo2-dev

# Windows
pip install toga-winforms

# macOS
pip install toga-cocoa
```

The GUI works with the same vault and configuration files as the CLI.

```mermaid
graph TD
    core["seedpass.core"]
    cli["CLI"]
    api["FastAPI server"]
    gui["BeeWare GUI"]
    ext["Browser Extension"]

    cli --> core
    gui --> core
    api --> core
    ext --> api
```

### Vault JSON Layout

The encrypted index file `seedpass_entries_db.json.enc` begins with `schema_version` `2` and stores an `entries` map keyed by entry numbers.

```json
{
  "schema_version": 2,
  "entries": {
    "0": {
      "label": "example.com",
      "length": 8,
      "type": "password",
      "notes": ""
    }
  }
}
```

> **Note**
>
> Opening a vault created by older versions automatically converts the legacy
> `seedpass_passwords_db.json.enc` (Fernet) to AES-GCM as
> `seedpass_entries_db.json.enc`. The original file is kept with a `.fernet`
> extension.
> The same migration occurs for a legacy `parent_seed.enc` encrypted with
> Fernet: it is transparently decrypted, re-encrypted with AES-GCM and the old
> file saved as `parent_seed.enc.fernet`.

## Usage

After successfully installing the dependencies, install the package with:

```bash
python -m pip install -e .
```

Once installed, launch the interactive TUI with:

```bash
seedpass
```

You can also run directly from the repository with:

```bash
python src/main.py
```

You can explore other CLI commands using:

```bash
seedpass --help
```

If this command displays `usage: main.py` instead of the Typer help output, an old `seedpass` executable is still on your `PATH`. Remove it with `pip uninstall seedpass` or delete the stale launcher and rerun:

```bash
python -m pip install -e .
```
// 🔧 merged conflicting changes from codex/locate-command-usage-issue-in-seedpass vs beta
You can confirm which executable will run with:

```bash
which seedpass  # or 'where seedpass' on Windows
```

For a full list of commands see [docs/advanced_cli.md](docs/advanced_cli.md). The REST API is described in [docs/api_reference.md](docs/api_reference.md).

### Running the Application

1. **Start the Application:**

   ```bash
   seedpass
   ```
   *(or `python src/main.py` when running directly from the repository)*

2. **Follow the Prompts:**

   - **Seed Profile Selection:** If you have existing seed profiles, you'll be prompted to select one or add a new one.
   - **Enter Your Password:** This password is crucial as it is used to encrypt and decrypt your parent seed and seed index data.
   - **Select an Option:** Navigate through the menu by entering the number corresponding to your desired action.

   Example menu:

   ```bash
   Select an option:
   1. Add Entry
   2. Retrieve Entry
   3. Search Entries
   4. List Entries
   5. Modify an Existing Entry
   6. 2FA Codes
   7. Settings

   Enter your choice (1-7) or press Enter to exit:
   ```

When choosing **Add Entry**, you can now select from:

- **Password**
- **2FA (TOTP)**
- **SSH Key**
- **Seed Phrase**
- **Nostr Key Pair**
- **PGP Key**
- **Key/Value**
- **Managed Account**

### Adding a 2FA Entry

1. From the main menu choose **Add Entry** and select **2FA (TOTP)**.
2. Pick **Make 2FA** to derive a new secret from your seed or **Import 2FA** to paste an existing `otpauth://` URI or secret.
3. Provide a label for the account (for example, `GitHub`).
4. SeedPass automatically chooses the next available derivation index when deriving.
5. Optionally specify the TOTP period and digit count.
6. SeedPass displays the URI and secret, along with a QR code you can scan to import it into your authenticator app.

### Modifying a 2FA Entry

1. From the main menu choose **Modify an Existing Entry** and enter the index of the 2FA code you want to edit.
2. SeedPass will show the current label, period, digit count, and archived status.
3. Enter new values or press **Enter** to keep the existing settings.
4. When retrieving a 2FA entry you can press **E** to edit the label, period or digit count, or **A** to archive/unarchive it.
5. The updated entry is saved back to your encrypted vault.
6. Archived entries are hidden from lists but can be viewed or restored from the **List Archived** menu.
7. When editing an archived entry you'll be prompted to restore it after saving your changes.

### Using Secret Mode

When **Secret Mode** is enabled, SeedPass copies newly generated and retrieved passwords directly to your clipboard instead of displaying them on screen. The clipboard clears automatically after the delay you choose.

1. From the main menu open **Settings** and select **Toggle Secret Mode**.
2. Choose how many seconds to keep passwords on the clipboard.
3. Generate or retrieve an entry and SeedPass will confirm the password was copied.

### Viewing Entry Details

Selecting an item from **List Entries** or **Search Entries** first displays the
entry's metadata such as the label, username, tags and notes. Passwords, seed
phrases and other sensitive fields remain hidden until you choose to reveal
them. When you opt to show the secret, the details view presents the same action
menu as **Retrieve Entry** so you can edit, archive or display QR codes for the
entry.

### Additional Entry Types

SeedPass supports storing more than just passwords and 2FA secrets. You can also create entries for:
- **SSH Key** – deterministically derive an Ed25519 key pair for servers or git hosting platforms.
- **Seed Phrase** – store only the BIP-85 index and word count. The mnemonic is regenerated on demand.
- **PGP Key** – derive an OpenPGP key pair from your master seed.
- **Nostr Key Pair** – store the index used to derive an `npub`/`nsec` pair for Nostr clients. When you retrieve one of these entries, SeedPass can display QR codes for the keys. The `npub` is wrapped in the `nostr:` URI scheme so any client can scan it, while the `nsec` QR is shown only after a security warning.
- **Key/Value** – store a simple key and value for miscellaneous secrets or configuration data.
- **Managed Account** – derive a child seed under the current profile. Loading a managed account switches to a nested profile and the header shows `<parent_fp> > Managed Account > <child_fp>`. Press Enter on the main menu to return to the parent profile.

The table below summarizes the extra fields stored for each entry type. Every entry includes a `label`, while only password entries track a `url`.

| Entry Type      | Extra Fields                                                                                                                                         |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| Password        | `username`, `url`, `length`, `archived`, optional `notes`, optional `custom_fields` (may include hidden fields), optional `tags`                       |
| 2FA (TOTP)      | `index` or `secret`, `period`, `digits`, `archived`, optional `notes`, optional `tags`                                                                 |
| SSH Key         | `index`, `archived`, optional `notes`, optional `tags`                                                                                                |
| Seed Phrase     | `index`, `word_count` *(mnemonic regenerated; never stored)*, `archived`, optional `notes`, optional `tags`                                            |
| PGP Key         | `index`, `key_type`, `archived`, optional `user_id`, optional `notes`, optional `tags`                                                                 |
| Nostr Key Pair  | `index`, `archived`, optional `notes`, optional `tags`                                                                                                |
| Key/Value       | `key`, `value`, `archived`, optional `notes`, optional `custom_fields`, optional `tags`                                                                       |
| Managed Account | `index`, `word_count`, `fingerprint`, `archived`, optional `notes`, optional `tags`                                                                   |

### Managing Multiple Seeds

SeedPass allows you to manage multiple seed profiles (previously referred to as "fingerprints"). Each seed profile has its own parent seed and associated data, enabling you to compartmentalize your passwords.

- **Add a New Seed Profile:**
  1. From the main menu, select **Settings** then **Profiles** and choose "Add a New Seed Profile".
  2. Choose to paste in a full seed, enter one word at a time, or generate a new seed.
  3. If you enter the seed word by word, each word is hidden with `*` and the screen refreshes after every entry for clarity. SeedPass then shows the completed phrase for confirmation so you can fix any mistakes before it is stored.
  4. If generating a new seed, you'll be provided with a 12-word BIP-85 seed phrase. **Ensure you write this down and store it securely.**

- **Switch Between Seed Profiles:**
  1. From the **Profiles** menu, select "Switch Seed Profile".
  2. You'll see a list of available seed profiles.
  3. Enter the number corresponding to the seed profile you wish to switch to.
  4. Enter the master password associated with that seed profile.

- **List All Seed Profiles:**
  In the **Profiles** menu, choose "List All Seed Profiles" to view all existing profiles.
- **Set Seed Profile Name:**
  In the **Profiles** menu, choose "Set Seed Profile Name" to assign an optional
  label to the currently selected profile. The name is stored locally and shown
  alongside the fingerprint in menus.

**Note:** The term "seed profile" is used to represent different sets of seeds you can manage within SeedPass. This provides an intuitive way to handle multiple identities or sets of passwords.

### Configuration File and Settings

SeedPass keeps per-profile settings in an encrypted file named `seedpass_config.json.enc` inside each profile directory under `~/.seedpass/`. This file stores your chosen Nostr relays and the optional settings PIN. New profiles start with the following default relays:

```
wss://relay.snort.social
wss://nostr.oxtr.dev
wss://relay.primal.net
```

You can manage your relays and sync with Nostr from the **Settings** menu:

1. From the main menu choose `6` (**Settings**).
2. Select `2` (**Nostr**) to open the Nostr submenu.
3. Choose `1` to back up your encrypted index to Nostr.
4. Select `2` to restore the index from Nostr.
5. Choose `3` to view your current relays.
6. Select `4` to add a new relay URL.
7. Choose `5` to remove a relay by number.
8. Select `6` to reset to the default relay list.
9. Choose `7` to display your Nostr public key.
10. Select `8` to return to the Settings menu.

Back in the Settings menu you can:

- Select `3` to change your master password.
- Choose `4` to verify the script checksum.
- Select `5` to generate a new script checksum.
- Choose `6` to back up the parent seed.
- Select `7` to export the database to an encrypted file.
- Choose `8` to import a database from a backup file.
- Select `9` to export all 2FA codes.
- Choose `10` to set an additional backup location. A backup is created immediately after the directory is configured.
- Select `11` to set the PBKDF2 iteration count used for encryption.
- Choose `12` to change the inactivity timeout.
- Select `13` to lock the vault and require re-entry of your password.
- Select `14` to view seed profile stats. The summary lists counts for passwords, TOTP codes, SSH keys, seed phrases, and PGP keys. It also shows whether both the encrypted database and the script itself pass checksum validation.
- Choose `15` to toggle Secret Mode and set the clipboard clear delay.
- Select `16` to toggle Offline Mode and disable Nostr synchronization.
- Choose `17` to toggle Quick Unlock for skipping the password prompt after the first unlock.
Press **Enter** at any time to return to the main menu.
You can adjust these settings directly from the command line:

```bash
seedpass config set kdf_iterations 200000
seedpass config set backup_interval 3600
seedpass config set quick_unlock true
seedpass config set nostr_max_retries 2
seedpass config set nostr_retry_delay 1
```

The default configuration uses **50,000** PBKDF2 iterations. Increase this value for stronger password hashing or lower it for faster startup (not recommended). Offline Mode skips all Nostr communication, keeping your data local until you re-enable syncing. Quick Unlock stores a hashed copy of your password in the encrypted config so that after the initial unlock, subsequent operations won't prompt for the password until you exit the program. Avoid enabling Quick Unlock on shared machines.

### Recovery

If you previously backed up your vault to Nostr you can restore it during the
initial setup:

1. Start SeedPass and choose option **4** when prompted to set up a seed.
2. Paste your BIP-85 seed phrase when asked.
3. SeedPass initializes the profile and attempts to download the encrypted vault
   from the configured relays.
4. A success message confirms the vault was restored. If no data is found a
   failure message is shown and a new empty vault is created.

## Running Tests

SeedPass includes a small suite of unit tests located under `src/tests`. **Before running `pytest`, be sure to install the test requirements.** Activate your virtual environment and run `pip install -r src/requirements.txt` to ensure all testing dependencies are available. Then run the tests with **pytest**. Use `-vv` to see INFO-level log messages from each passing test:

```bash
pip install -r src/requirements.txt
pytest -vv
```

### Exploring Nostr Index Size Limits

`test_nostr_index_size.py` demonstrates how SeedPass rotates snapshots after too many delta events. Each chunk is limited to 50 KB, so the test gradually grows the vault to observe when a new snapshot is triggered. Use the `NOSTR_TEST_DELAY` environment variable to control the delay between publishes when experimenting with large vaults.

```bash
pytest -vv -s -n 0 src/tests/test_nostr_index_size.py --desktop --max-entries=1000
```

### Generating a Test Profile

Use the helper script below to populate a profile with sample entries for testing:

```bash
python scripts/generate_test_profile.py --profile demo_profile --count 100
```

The script determines the fingerprint from the generated seed and stores the
vault under `~/.seedpass/tests/<fingerprint>`. SeedPass only looks for profiles
in `~/.seedpass/`, so move or copy the fingerprint directory out of the `tests`
subfolder (or adjust `APP_DIR` in `constants.py`) if you want to load it with
the main application. The fingerprint is printed after creation and the
encrypted index is published to Nostr. Use that same seed phrase to load
SeedPass. The app checks Nostr on startup and pulls any newer snapshot so your
vault stays in sync across machines. If no snapshot exists or the download
cannot be decrypted (for example when using a brand-new seed), SeedPass
automatically initializes an empty index instead of exiting.

### Automatically Updating the Script Checksum

SeedPass stores a SHA-256 checksum for the main program in `~/.seedpass/seedpass_script_checksum.txt`. To keep this value in sync with the source code, install the pre-push git hook:

```bash
pre-commit install -t pre-push
```

After running this command, every `git push` will execute `scripts/update_checksum.py`, updating the checksum file automatically.

If the checksum file is missing, generate it manually:

```bash
python scripts/update_checksum.py
```

If SeedPass prints a "script checksum mismatch" warning on startup, regenerate
the checksum with `seedpass util update-checksum` or select "Generate Script
Checksum" from the Settings menu.

To run mutation tests locally, generate coverage data first and then execute `mutmut`:

```bash
pytest --cov=src src/tests
python -m mutmut run --paths-to-mutate src --tests-dir src/tests --runner "python -m pytest -q" --use-coverage --no-progress
python -m mutmut results
```

Mutation testing is disabled in the GitHub workflow due to reliability issues and should be run on a desktop environment instead.
## Development Workflow

1. Install all development dependencies:
```bash
pip install -r src/requirements.txt
```

2. When `src/runtime_requirements.txt` changes, rerun:
```bash
scripts/vendor_dependencies.sh
```
Commit the updated `src/vendor/` directory. The application automatically adds this folder to `sys.path` so the bundled packages are found.

3. Before committing, format and test the code:
```bash
black .
pytest
```


## Building a standalone executable

1. Run the vendoring script to bundle runtime dependencies:

```bash
scripts/vendor_dependencies.sh
```

2. Build the binary with PyInstaller:

```bash
pyinstaller SeedPass.spec
```

You can also produce packaged installers for the GUI with BeeWare's Briefcase:

```bash
briefcase build
```

Pre-built installers are published for each `seedpass-gui` tag. Visit the
project's **Actions** or **Releases** page on GitHub to download the latest
package for your platform.

The standalone executable will appear in the `dist/` directory. This process works on Windows, macOS and Linux but you must build on each platform for a native binary.

## Packaging with Briefcase

For step-by-step instructions see [docs/docs/content/01-getting-started/05-briefcase.md](docs/docs/content/01-getting-started/05-briefcase.md).

Install Briefcase and create a platform-specific scaffold:

```bash
python -m pip install briefcase
briefcase create
```

Build and run the packaged GUI:

```bash
briefcase build
briefcase run
```

You can also launch the GUI directly with `seedpass gui` or `seedpass-gui`.


## Security Considerations

**Important:** The password you use to encrypt your parent seed is also required to decrypt the seed index data retrieved from Nostr. **It is imperative to remember this password** and be sure to use it with the same seed, as losing it means you won't be able to access your stored index. Secure your 12-word seed **and** your master password.

- **Backup Your Data:** Regularly back up your encrypted data and checksum files to prevent data loss.
- **Backup the Settings PIN:** Your settings PIN is stored in the encrypted configuration file. Keep a copy of this file or remember the PIN, as losing it will require deleting the file and reconfiguring your relays.
- **Protect Your Passwords:** Do not share your master password or seed phrases with anyone and ensure they are strong and unique.
- **Revealing the Parent Seed:** The `vault reveal-parent-seed` command and `/api/v1/parent-seed` endpoint print your seed in plain text. Run them only in a secure environment.
- **No PBKDF2 Salt Needed:** SeedPass deliberately omits an explicit PBKDF2 salt. Every password is derived from a unique 512-bit BIP-85 child seed, which already provides stronger per-password uniqueness than a conventional 128-bit salt.
- **Checksum Verification:** Always verify the script's checksum to ensure its integrity and protect against unauthorized modifications.
- **Potential Bugs and Limitations:** Be aware that the software may contain bugs and lacks certain features. Snapshot chunks are capped at 50 KB and the client rotates snapshots after enough delta events accumulate. The security of memory management and logs has not been thoroughly evaluated and may pose risks of leaking sensitive information.
- **Multiple Seeds Management:** While managing multiple seeds adds flexibility, it also increases the responsibility to secure each seed and its associated password.
- **No PBKDF2 Salt Required:** SeedPass deliberately omits an explicit PBKDF2 salt. Every password is derived from a unique 512-bit BIP-85 child seed, which already provides stronger per-password uniqueness than a conventional 128-bit salt.
- **Default KDF Iterations:** New profiles start with 50,000 PBKDF2 iterations. Adjust this with `seedpass config set kdf_iterations`.
- **KDF Iteration Caution:** Lowering `kdf_iterations` makes password cracking easier, while a high `backup_interval` leaves fewer recent backups.
- **Offline Mode:** When enabled, SeedPass skips all Nostr operations so your vault stays local until syncing is turned back on.
- **Quick Unlock:** Stores a hashed copy of your password in the encrypted config so you only need to enter it once per session. Avoid this on shared computers.

## Contributing

Contributions are welcome! If you have suggestions for improvements, bug fixes, or new features, please follow these steps:

1. **Fork the Repository:** Click the "Fork" button on the top right of the repository page.
1. **Create a Branch:** Create a new branch for your feature or bugfix.
   ```bash
   git checkout -b feature/YourFeatureName
   ```
1. **Commit Your Changes:** Make your changes and commit them with clear messages.
   ```bash
   git commit -m "Add feature X"
   ```
1. **Push to GitHub:** Push your changes to your forked repository.
   ```bash
   git push origin feature/YourFeatureName
   ```
1. **Create a Pull Request:** Navigate to the original repository and create a pull request describing your changes.

## License

This project is licensed under the [MIT License](LICENSE). See the [LICENSE](LICENSE) file for details.

## Contact

For any questions, suggestions, or support, please open an issue on the [GitHub repository](https://github.com/PR0M3TH3AN/SeedPass/issues) or contact the maintainer directly on [Nostr](https://primal.net/p/npub15jnttpymeytm80hatjqcvhhqhzrhx6gxp8pq0wn93rhnu8s9h9dsha32lx).

---

*Stay secure and keep your passwords safe with SeedPass!*
