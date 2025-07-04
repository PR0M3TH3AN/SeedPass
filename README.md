# SeedPass

![SeedPass Logo](https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/refs/heads/main/logo/png/SeedPass-Logo-03.png)

**SeedPass** is a secure password generator and manager built on **Bitcoin's BIP-85 standard**. It uses deterministic key derivation to generate **passwords that are never stored**, but can be easily regenerated when needed. By integrating with the **Nostr network**, SeedPass compresses your encrypted vault and splits it into 50 KB chunks. Each chunk is published as a parameterised replaceable event (`kind 30071`), with a manifest (`kind 30070`) describing the snapshot and deltas (`kind 30072`) capturing changes between snapshots. This allows secure password recovery across devices without exposing your data.

[Tip Jar](https://nostrtipjar.netlify.app/?n=npub16y70nhp56rwzljmr8jhrrzalsx5x495l4whlf8n8zsxww204k8eqrvamnp)

---

**⚠️ Disclaimer**

This software was not developed by an experienced security expert and should be used with caution. There may be bugs and missing features. Each vault chunk is limited to 50 KB and SeedPass periodically publishes a new snapshot to keep accumulated deltas small. The security of the program's memory management and logs has not been evaluated and may leak sensitive information.

---
### Supported OS

✔ Windows 10/11 • macOS 12+ • Any modern Linux  
SeedPass now uses the `portalocker` library for cross-platform file locking. No WSL or Cygwin required.


## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Create a Virtual Environment](#2-create-a-virtual-environment)
  - [3. Activate the Virtual Environment](#3-activate-the-virtual-environment)
  - [4. Install Dependencies](#4-install-dependencies)
- [Usage](#usage)
  - [Running the Application](#running-the-application)
  - [Managing Multiple Seeds](#managing-multiple-seeds)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Roadmap](#roadmap)

## Features

- **Deterministic Password Generation:** Utilize BIP-85 for generating deterministic and secure passwords.
- **Encrypted Storage:** All seeds, login passwords, and sensitive index data are encrypted locally.
- **Nostr Integration:** Post and retrieve your encrypted password index to/from the Nostr network.
- **Chunked Snapshots:** Encrypted vaults are compressed and split into 50 KB chunks published as `kind 30071` events with a `kind 30070` manifest and `kind 30072` deltas.
- **Automatic Checksum Generation:** The script generates and verifies a SHA-256 checksum to detect tampering.
- **Multiple Seed Profiles:** Manage separate seed profiles and switch between them seamlessly.
- **Interactive TUI:** Navigate through menus to add, retrieve, and modify entries as well as configure Nostr settings.
- **SeedPass 2FA:** Generate TOTP codes with a real-time countdown progress bar.
- **2FA Secret Issuance & Import:** Derive new TOTP secrets from your seed or import existing `otpauth://` URIs.
- **Export 2FA Codes:** Save all stored TOTP entries to an encrypted JSON file for use with other apps.
- **SSH Key & Seed Derivation:** Generate deterministic SSH keys and new BIP-39 seed phrases from your master seed.
- **Optional External Backup Location:** Configure a second directory where backups are automatically copied.
- **Auto‑Lock on Inactivity:** Vault locks after a configurable timeout for additional security.
- **Secret Mode:** Copy retrieved passwords directly to your clipboard and automatically clear it after a delay.

## Prerequisites

- **Python 3.8+**: Ensure you have Python installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

## Installation

Follow these steps to set up SeedPass on your local machine.

### 1. Clone the Repository

First, clone the SeedPass repository from GitHub:

```bash
git clone https://github.com/PR0M3TH3AN/SeedPass.git
```

Navigate to the project directory:

```bash
cd SeedPass
```

### 2. Create a Virtual Environment

It's recommended to use a virtual environment to manage your project's dependencies. Create a virtual environment named `venv`:

```bash
python3 -m venv venv
```

### 3. Activate the Virtual Environment

Activate the virtual environment using the appropriate command for your operating system.

- **On Linux and macOS:**

  ```bash
  source venv/bin/activate
  ```

- **On Windows:**

  ```bash
  venv\Scripts\activate
  ```

Once activated, your terminal prompt should be prefixed with `(venv)` indicating that the virtual environment is active.

### 4. Install Dependencies

Install the required Python packages and build dependencies using `pip`:

```bash
pip install --upgrade pip
pip install -r src/requirements.txt
```

#### Linux Clipboard Support

On Linux, `pyperclip` relies on external utilities like `xclip` or `xsel`.
SeedPass will attempt to install **xclip** automatically if neither tool is
available. If the automatic installation fails, you can install it manually:

```bash
sudo apt-get install xclip
```

## Quick Start

After installing dependencies and activating your virtual environment, launch
SeedPass and create a backup:

```bash
# Start the application
python src/main.py

# Export your index
seedpass export --file "~/seedpass_backup.json"

# Later you can restore it
seedpass import --file "~/seedpass_backup.json"

# Quickly find or retrieve entries
seedpass search "github"
seedpass get "github"
seedpass totp "email"
# The code is printed and copied to your clipboard

# Sort or filter the list view
seedpass list --sort website
seedpass list --filter totp

# Use the **Settings** menu to configure an extra backup directory
# on an external drive.
```

### Vault JSON Layout

The encrypted index file `seedpass_entries_db.json.enc` begins with `schema_version` `2` and stores an `entries` map keyed by entry numbers.

```json
{
  "schema_version": 2,
  "entries": {
    "0": {
      "website": "example.com",
      "length": 8,
      "type": "password",
      "notes": ""
    }
  }
}
```


## Usage

After successfully installing the dependencies, you can run SeedPass using the following command:

```bash
python src/main.py
```

### Running the Application

1. **Start the Application:**

    ```bash
    python src/main.py
    ```

2. **Follow the Prompts:**

   - **Seed Profile Selection:** If you have existing seed profiles, you'll be prompted to select one or add a new one.
   - **Enter Your Password:** This password is crucial as it is used to encrypt and decrypt your parent seed and seed index data.
   - **Select an Option:** Navigate through the menu by entering the number corresponding to your desired action.

   Example menu:

   ```
   Select an option:
   1. Add Entry
   2. Retrieve Entry
   3. Search Entries
   4. Modify an Existing Entry
   5. 2FA Codes
   6. Settings
   7. Exit

   Enter your choice (1-7):
  ```

   When choosing **Add Entry**, you can now select **Password**, **2FA (TOTP)**,
   **SSH Key**, or **BIP-39 Seed**.

### Adding a 2FA Entry

1. From the main menu choose **Add Entry** and select **2FA (TOTP)**.
2. Pick **Make 2FA** to derive a new secret from your seed or **Import 2FA** to paste an existing `otpauth://` URI or secret.
3. Provide a label for the account (for example, `GitHub`).
4. SeedPass automatically chooses the next available derivation index when deriving.
5. Optionally specify the TOTP period and digit count.
6. SeedPass will display the URI and secret so you can add it to your authenticator app.

### Modifying a 2FA Entry

1. From the main menu choose **Modify an Existing Entry** and enter the index of the 2FA code you want to edit.
2. SeedPass will show the current label, period, digit count, and blacklist status.
3. Enter new values or press **Enter** to keep the existing settings.
4. The updated entry is saved back to your encrypted vault.

### Using Secret Mode

When **Secret Mode** is enabled, SeedPass copies retrieved passwords directly to your clipboard instead of displaying them on screen. The clipboard clears automatically after the delay you choose.

1. From the main menu open **Settings** and select **Toggle Secret Mode**.
2. Choose how many seconds to keep passwords on the clipboard.
3. Retrieve an entry and SeedPass will confirm the password was copied.


### Managing Multiple Seeds

SeedPass allows you to manage multiple seed profiles (previously referred to as "fingerprints"). Each seed profile has its own parent seed and associated data, enabling you to compartmentalize your passwords.

- **Add a New Seed Profile:**
  - From the main menu, select **Settings** then **Profiles** and choose "Add a New Seed Profile".
  - Choose to enter an existing seed or generate a new one.
  - If generating a new seed, you'll be provided with a 12-word BIP-85 seed phrase. **Ensure you write this down and store it securely.**

- **Switch Between Seed Profiles:**
  - From the **Profiles** menu, select "Switch Seed Profile".
  - You'll see a list of available seed profiles.
  - Enter the number corresponding to the seed profile you wish to switch to.
  - Enter the master password associated with that seed profile.

- **List All Seed Profiles:**
  - In the **Profiles** menu, choose "List All Seed Profiles" to view all existing profiles.

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

* Select `3` to change your master password.
* Choose `4` to verify the script checksum.
* Select `5` to generate a new script checksum.
* Choose `6` to back up the parent seed.
* Select `7` to export the database to an encrypted file.
* Choose `8` to import a database from a backup file.
* Select `9` to export all 2FA codes.
* Choose `10` to set an additional backup location.
* Select `11` to change the inactivity timeout.
* Choose `12` to lock the vault and require re-entry of your password.
* Select `13` to view seed profile stats.
* Choose `14` to toggle Secret Mode and set the clipboard clear delay.
* Select `15` to return to the main menu.

## Running Tests

SeedPass includes a small suite of unit tests located under `src/tests`. After activating your virtual environment and installing dependencies, run the tests with **pytest**. Use `-vv` to see INFO-level log messages from each passing test:


```bash
pip install -r src/requirements.txt
pytest -vv
```

### Exploring Nostr Index Size Limits

`test_nostr_index_size.py` demonstrates how SeedPass rotates snapshots after too many delta events.
Each chunk is limited to 50 KB, so the test gradually grows the vault to observe
when a new snapshot is triggered. Use the `NOSTR_TEST_DELAY` environment
variable to control the delay between publishes when experimenting with large vaults.

```bash
pytest -vv -s -n 0 src/tests/test_nostr_index_size.py --desktop --max-entries=1000
```

### Automatically Updating the Script Checksum

SeedPass stores a SHA-256 checksum for the main program in `~/.seedpass/seedpass_script_checksum.txt`.
To keep this value in sync with the source code, install the pre‑push git hook:

```bash
pre-commit install -t pre-push
```

After running this command, every `git push` will execute `scripts/update_checksum.py`,
updating the checksum file automatically.

If the checksum file is missing, generate it manually:

```bash
python scripts/update_checksum.py
```

To run mutation tests locally, generate coverage data first and then execute `mutmut`:

```bash
pytest --cov=src src/tests
python -m mutmut run --paths-to-mutate src --tests-dir src/tests --runner "python -m pytest -q" --use-coverage --no-progress
python -m mutmut results
```

Mutation testing is disabled in the GitHub workflow due to reliability issues and should be run on a desktop environment instead.

## Security Considerations

**Important:** The password you use to encrypt your parent seed is also required to decrypt the seed index data retrieved from Nostr. **It is imperative to remember this password** and be sure to use it with the same seed, as losing it means you won't be able to access your stored index. Secure your 12-word seed **and** your master password.

- **Backup Your Data:** Regularly back up your encrypted data and checksum files to prevent data loss.
- **Backup the Settings PIN:** Your settings PIN is stored in the encrypted configuration file. Keep a copy of this file or remember the PIN, as losing it will require deleting the file and reconfiguring your relays.
- **Protect Your Passwords:** Do not share your master password or seed phrases with anyone and ensure they are strong and unique.
- **No PBKDF2 Salt Needed:** SeedPass deliberately omits an explicit PBKDF2 salt. Every password is derived from a unique 512-bit BIP-85 child seed, which already provides stronger per-password uniqueness than a conventional 128-bit salt.
- **Checksum Verification:** Always verify the script's checksum to ensure its integrity and protect against unauthorized modifications.
- **Potential Bugs and Limitations:** Be aware that the software may contain bugs and lacks certain features. Snapshot chunks are capped at 50 KB and the client rotates snapshots after enough delta events accumulate. The security of memory management and logs has not been thoroughly evaluated and may pose risks of leaking sensitive information.
- **Multiple Seeds Management:** While managing multiple seeds adds flexibility, it also increases the responsibility to secure each seed and its associated password.
- **No PBKDF2 Salt Required:** SeedPass deliberately omits an explicit PBKDF2 salt. Every password is derived from a unique 512-bit BIP-85 child seed, which already provides stronger per-password uniqueness than a conventional 128-bit salt.

## Contributing

Contributions are welcome! If you have suggestions for improvements, bug fixes, or new features, please follow these steps:

1. **Fork the Repository:** Click the "Fork" button on the top right of the repository page.

2. **Create a Branch:** Create a new branch for your feature or bugfix.

   ```bash
   git checkout -b feature/YourFeatureName
   ```

3. **Commit Your Changes:** Make your changes and commit them with clear messages.

   ```bash
   git commit -m "Add feature X"
   ```

4. **Push to GitHub:** Push your changes to your forked repository.

   ```bash
   git push origin feature/YourFeatureName
   ```

5. **Create a Pull Request:** Navigate to the original repository and create a pull request describing your changes.

## License

This project is licensed under the [MIT License](LICENSE). See the [LICENSE](LICENSE) file for details.

## Contact

For any questions, suggestions, or support, please open an issue on the [GitHub repository](https://github.com/PR0M3TH3AN/SeedPass/issues) or contact the maintainer directly on [Nostr](https://primal.net/p/npub15jnttpymeytm80hatjqcvhhqhzrhx6gxp8pq0wn93rhnu8s9h9dsha32lx).

---

*Stay secure and keep your passwords safe with SeedPass!*

---

## Roadmap

### Overview

The SeedPass roadmap outlines a structured development plan divided into distinct phases. Each phase focuses on specific areas, prioritizing core functionalities and security before expanding into advanced CLI features and integrations. This approach ensures that SeedPass remains a secure, reliable, and user-friendly CLI-based password management tool while accommodating the new method of individual entry management.

---

### Phase 1: Core Functionality and Security Enhancements

**Goal:** Establish a robust foundation with individual entry management, secure seed handling, and seamless Nostr integration.

[see the docs](https://github.com/PR0M3TH3AN/SeedPass/blob/main/docs/json_entries.md) 

1. **Configuration File Management** *(implemented)*
   - **Description:** Implement a configuration file to store user-specific settings, starting with user-determined Nostr relays.
   - **Implementation Steps:**
     - Create a `config.yaml` or `config.json` file in the SeedPass data directory.
     - Define a structure to store user configurations, starting with a list of Nostr relay URLs.
    - Allow users to add, remove, and manage an unlimited number of Nostr relays through the CLI or configuration file.
    - Ensure the configuration file is securely stored and encrypted if necessary.
    - The Nostr client loads its relay list from this encrypted file. New accounts start with the default relays until you update the settings.

2. **Individual JSON File Management**
   - **Separate Entry Files:**
     - **Description:** Modify the application to create and manage each entry as a separate JSON file within a designated directory.
     - **Implementation Steps:**
       - Define a standardized naming convention for entry files (e.g., `entry_<entry_num>.json`).
       - Update CRUD (Create, Read, Update, Delete) operations to handle individual files.
   - **Backup Directory Structure:**
     - **Description:** Implement a backup system that saves previous versions of each entry in a separate backup folder.
     - **Implementation Steps:**
       - Create a `backups/` directory within the SeedPass data folder.
       - Upon modifying an entry, save the previous version in `backups/entry_<entry_num>_v<version>.json`.
       - Implement rollback functionality to restore from backups if needed.

3. **Enhanced JSON Schema Integration** *(implemented)*
   - **Description:** Adopt the new JSON schema for all entry types, ensuring consistency and flexibility.
   - **Implementation Steps:**
     - Update existing entries to conform to the new schema.
     - Ensure that new kinds adhere to the defined structure, facilitating future expansions.

4. **Nostr Integration Enhancements** *(implemented)*
   - **Description:** Improve Nostr integration by changing the posting mechanism and enabling efficient synchronization.
   - **Implementation Steps:**
     - **Selective Posting:**
       - Modify the Nostr posting mechanism to only post new or updated entries instead of the entire index.
     - **Index Reconstruction:**
       - On the first run, build the index from Nostr posts based on timestamps to ensure the correct and complete database retrieval.
       - Implement logic to check for existing posts on the specified `npub` account and synchronize accordingly.
     - **Configuration Integration:**
       - Utilize the newly added configuration file to manage Nostr relays and synchronization settings.

5. **Backup and Restore Index Option** *(implemented)*
   - **Description:** Provide users with the ability to backup and restore the index, offering flexibility in backup locations.
   - **Implementation Steps:**
     - Introduce CLI commands such as `backup-index` and `restore-index`.
     - Allow users to choose the backup location via CLI prompts or by specifying a path in the configuration file.
     - Ensure backups can be saved to external drives, remote folders, or other user-defined locations.
     - Validate the integrity of backups during the restore process.

6. **Security Enhancements**
   - **"Secret" Mode (Clipboard-Only Password Retrieval)** *(implemented)*
     - **Description:** Introduce a "secret" mode where passwords are copied directly to the clipboard rather than displayed on the screen upon retrieval.
     - **Features:**
       - **Toggle Setting:** Allow users to enable or disable "secret" mode.
       - **Clipboard Integration:** Ensure passwords are copied securely to the clipboard when "secret" mode is active.
       - **User Feedback:** Notify users that the password has been copied to the clipboard.
      - **Settings Menu:** Toggle this mode under `Settings -> Toggle Secret Mode` and set how long the clipboard is retained.
   - **Two-Factor Security Model with Random Index Generation**
     - **Description:** Create a robust two-factor security system using a master seed and master password combination, enhanced with random index generation for additional security.
     - **Key Features:**
       - **Random Index Generation:** Generate cryptographically secure random numbers for each new password index.
       - **Master Seed Management:** Keep the master seed in cold storage/offline, acting as the primary key for password generation.
       - **Master Password System:** Store the master password in memory/brain only, required to decrypt indices and access accounts.
       - **Protection Layers:** Ensure seed and password compromise protection through encrypted indices and secure storage.
       - **Security Verification:** Implement checks to ensure neither factor can be bypassed and verify the randomness quality of index generation.

7. **Comprehensive Testing and Security Auditing**
   - **Unit Tests:** Develop tests for individual functions and modules to ensure they work as intended.
   - **Integration Tests:** Test the interaction between different modules, especially for features like automatic Nostr posting and seed recovery.
   - **Security Audits:** Conduct regular code reviews and security assessments to identify and mitigate vulnerabilities.

8. **Managed Users’ Data Loading**
   - **Summary:** Enable the master seed holder to load and manage the seeds, passwords, and Nostr accounts of dependent users. This allows centralized management of multiple accounts, ensuring secure synchronization and control over multiple users' data.

---

### Phase 2: Enhanced Security and Data Management

**Goal:** Strengthen security features and improve data management capabilities with the new individual entry system.

1. **Advanced Data Fields and New Kinds**
   - **Description:** Utilize the flexible JSON schema to introduce advanced data fields and new kinds.
   - **Implementation Steps:**
     - Define additional fields for existing kinds as needed.
     - Introduce new kinds (e.g., `cryptocurrency_wallet`) following the established schema.
   
2. **Family Password Management**
   - **Description:** Enable management of multiple password sets for family members using individual entry files.
   - **Features:**
     - **Segregated Access:** Allow users to create and manage separate password sets for different family members.
     - **Additional Security Layers:** Implement MFA or role-based access for managing family members' accounts.
     - **User-Friendly CLI Commands:** Develop intuitive CLI commands to handle family member password sets efficiently.

3. **Easy BIP39 Seed Generation for Various Use Cases** *(implemented)*
   - **Description:** Provide an easy method for generating new BIP39 seeds for different purposes, such as cryptocurrency wallets.
   - **Features:**
     - **Seed Generation:** Ensure seeds are generated securely and comply with BIP39 standards.
     - **User Guidance:** Offer CLI instructions on securely handling and storing generated seeds.

4. **Nostr Public/Private Key Pair Generation** *(implemented)*
   - **Description:** Allow users to generate new Nostr public/private key pairs within the application.
   - **Features:**
     - **Secure Key Generation:** Ensure key pairs are generated securely and tied to specific index entries.
     - **Seamless Integration:** Integrate key pair management with existing Nostr functionalities.
     - **Security Advisories:** Inform users about best practices for managing multiple Nostr identities and the risks of using the same seed across different identities.

---

### Phase 3: Advanced CLI Functionalities

**Goal:** Develop a sophisticated Command-Line Interface (CLI) tailored for the individual entry system, enhancing automation and customization.

[see the docs](https://github.com/PR0M3TH3AN/SeedPass/blob/main/docs/advanced_cli.md) 

1. **Advanced CLI Commands for Entry Management**
   - **Description:** Introduce CLI commands to create, read, update, delete, and backup individual entries.
   - **Implementation Steps:**
     - Implement commands such as `add-entry`, `view-entry`, `update-entry`, `delete-entry`, and `backup-entry`.
     - Ensure commands support specifying entry kinds and associated data fields.

2. **Custom Relays Configuration via CLI**
   - **Description:** Allow users to specify custom Nostr relays for each entry or globally.
   - **Implementation Steps:**
     - Introduce CLI options to add, remove, or list relays.
     - Ensure entries are posted to the specified relays upon creation or update.

3. **Secure Clipboard Operations**
   - **Description:** Ensure clipboard operations are secure and temporary.
   - **Features:**
     - **Clear Clipboard After Duration:** Automatically clear the clipboard after a set duration (e.g., 30 seconds) to prevent unauthorized access.
     - **User Notifications:** Inform users when the clipboard is cleared.
     - **Graceful Failure Handling:** Manage cases where clipboard operations fail without disrupting the user experience.

---

### Phase 4: Data Management Enhancements and Integrations

**Goal:** Further improve data management capabilities and integrate with other platforms using the individual entry system.

1. **Additional Integrations**
   - **Description:** Expand integrations with other platforms and services, leveraging individual entry management.
   - **Implementation Steps:**
     - Integrate with cryptocurrency wallets, productivity tools, and other services.
     - Ensure each integration corresponds to separate entries, maintaining modularity.

2. **Scalability Enhancements**
   - **Description:** Optimize the application to handle a growing number of individual entries without performance degradation.
   - **Features:**
     - **Indexing Mechanisms:** Implement indexing for quick retrieval of entries.
     - **Optimized File Storage:** Improve file storage and access patterns for efficiency.

---

### Phase 5: Documentation, Testing, and Finalization

**Goal:** Ensure comprehensive documentation, robust testing, and finalize the application for release with the new entry management system.

1. **Provide Comprehensive Documentation**
   - **User Guide:** Create detailed documentation covering installation, setup, usage, and troubleshooting via CLI help commands and external documentation files.
   - **CLI Help:** Ensure that each CLI command includes descriptive help messages accessible via commands like `--help`.
   - **Developer Documentation:** Document the codebase to assist future development and maintenance efforts, including contribution guidelines and code structure explanations.
   - **Guidelines for Adding New Kinds:** Document the process and standards for introducing new `kind` types.

2. **Enhance Logging and Monitoring**
   - **Granular Logging:** Implement detailed logs for successful operations and warnings/errors for issues, including timestamps, action types, and relevant metadata.
   - **Log Rotation:** Use Python's `logging.handlers` module or external libraries to manage log rotation and prevent log files from growing indefinitely.
   - **Log Unknown Kinds:** Ensure logs capture instances of unknown `kind` types for future handling.

3. **Ensure Comprehensive Testing**
   - **Unit Tests:** Write tests for individual functions and modules to ensure they work as intended.
   - **Integration Tests:** Test the interaction between different modules, especially for features like automatic Nostr posting and seed recovery.
   - **User Acceptance Testing (UAT):** Engage a group of users to test the CLI tool and provide feedback on usability and functionality.
   - **Automate Extensibility Tests:** Incorporate tests that verify the application's behavior with both known and unknown `kind` types.

4. **Prioritize Security Best Practices**
   - **Sensitive Data Handling:** Ensure that all sensitive data (e.g., seed phrases, encryption keys) are handled securely in memory and during storage.
   - **Encryption Standards:** Use industry-standard encryption algorithms and key derivation functions.
   - **Regular Audits:** Periodically review and audit the codebase for potential security vulnerabilities.
   - **Secure Handling of All Kinds:** Ensure that security measures are uniformly applied across all `kind` types.

---

### Future Phases (Beyond Initial Roadmap)

1. **Continuous Improvement and Feature Expansion**
   - **Description:** Respond to user feedback and implement additional features based on emerging needs.
   - **Examples:** Integrate biometric authentication, expand to mobile platforms, or introduce collaborative password management features.

2. **Scalability and Performance Optimization**
   - **Description:** Optimize application performance for large datasets and enhance scalability for a growing user base.
   - **Features:**
     - **Performance Tuning:** Improve response times and resource usage.
     - **Scalability Enhancements:** Ensure the application can handle an increasing number of users and data entries without degradation in performance.

