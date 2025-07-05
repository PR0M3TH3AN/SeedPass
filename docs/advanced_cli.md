# Advanced CLI Commands Documentation

## Overview

The **Advanced CLI Commands** document provides an in-depth guide to the various command-line functionalities available in **SeedPass**, a secure password manager built on Bitcoin's BIP-85 standard. Designed for power users and developers, this guide outlines each command's purpose, usage, options, and examples to facilitate efficient and effective password management through the CLI.

---

## Table of Contents

1. [Command Reference](#command-reference)
2. [Detailed Command Descriptions](#detailed-command-descriptions)
   - [1. Add a New Password Entry](#1-add-a-new-password-entry)
   - [2. Retrieve a Password Entry](#2-retrieve-a-password-entry)
   - [3. Modify an Existing Entry](#3-modify-an-existing-entry)
   - [4. Delete an Entry](#4-delete-an-entry)
   - [5. List All Entries](#5-list-all-entries)
   - [6. Search for a Password Entry](#6-search-for-a-password-entry)
   - [7. Get a Password by Query](#7-get-a-password-by-query)
   - [8. Display a TOTP Code](#8-display-a-totp-code)
   - [9. Export Passwords to a File](#9-export-passwords-to-a-file)
   - [10. Import Passwords from a File](#8-import-passwords-from-a-file)
   - [11. Display Help Information](#9-display-help-information)
   - [12. Display Application Version](#10-display-application-version)
   - [13. Change Master Password](#11-change-master-password)
   - [14. Enable Auto-Lock](#12-enable-auto-lock)
   - [15. Disable Auto-Lock](#13-disable-auto-lock)
   - [16. Generate a Strong Password](#14-generate-a-strong-password)
   - [17. Verify Script Checksum](#15-verify-script-checksum)
   - [18. Post Encrypted Snapshots to Nostr](#16-post-encrypted-snapshots-to-nostr)
   - [19. Retrieve from Nostr](#17-retrieve-from-nostr)
   - [20. Display Nostr Public Key](#18-display-nostr-public-key)
   - [21. Set Custom Nostr Relays](#19-set-custom-nostr-relays)
   - [22. Enable "Secret" Mode](#20-enable-secret-mode)
   - [23. Batch Post Snapshot Deltas to Nostr](#21-batch-post-snapshot-deltas-to-nostr)
   - [24. Show All Passwords](#22-show-all-passwords)
   - [23. Add Notes to an Entry](#23-add-notes-to-an-entry)
   - [24. Add Tags to an Entry](#24-add-tags-to-an-entry)
   - [25. Search by Tag or Title](#25-search-by-tag-or-title)
   - [26. Automatically Post Deltas to Nostr After Edit](#26-automatically-post-deltas-to-nostr-after-edit)
   - [27. Initial Setup Prompt for Seed Generation/Import](#27-initial-setup-prompt-for-seed-generationimport)
3. [Notes on New CLI Commands](#notes-on-new-cli-commands)

---

## Command Reference

The following table provides a quick reference to all available advanced CLI commands in SeedPass, including their actions, command syntax, short and long flags, and example usages.

| **Action**                                | **Command**            | **Short Flag** | **Long Flag**                     | **Example Command**                                                                                                                                                                              |
|-------------------------------------------|------------------------|----------------|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Add a new password entry                  | `add`                  | `-A`           | `--add`                           | `seedpass add --title "GitHub" --url "https://github.com" --username "john_doe" --email "john@example.com" --notes "Primary GitHub account" --tags "work,development" --length 20`                  |
| Retrieve a password entry                 | `retrieve`             | `-R`           | `--retrieve`                      | `seedpass retrieve --index 3` or `seedpass retrieve --title "GitHub"`                                                                                                                           |
| Modify an existing entry                  | `modify`               | `-M`           | `--modify`                        | `seedpass modify --index 3 --title "GitHub Pro" --notes "Updated to pro account" --tags "work,development,pro" --length 22`                                                                        |
| Delete an entry                           | `delete`               | `-D`           | `--delete`                        | `seedpass delete --index 3`                                                                                                                                                                       |
| List all entries                          | `list`                 | `-L`           | `--list`                          | `seedpass list --sort label`                                                                                                                                                                                    |
| Search for a password entry               | `search`               | `-S`           | `--search`                        | `seedpass search "GitHub"`                                                                                                                                                                 |
| Get password from query                   | `get`                  |           |                                   | `seedpass get "GitHub"`
| Display a TOTP code                       | `totp`                 |           |                                   | `seedpass totp "email"`
|                                           |                        |           |                                   | `seedpass list --filter totp`
| Export passwords to a file                | `export`               | `-E`           | `--export`                        | `seedpass export --file "backup_passwords.json"`                                                                                                                                                   |
| Import passwords from a file              | `import`               | `-I`           | `--import`                        | `seedpass import --file "backup_passwords.json"`                                                                                                                                                   |
| Display help information                  | `help`                 | `-H`           | `--help`                          | `seedpass help`                                                                                                                                                                                    |
| Display application version               | `version`              | `-V`           | `--version`                       | `seedpass version`                                                                                                                                                                                 |
| Change master password                    | `changepw`             | `-C`           | `--changepw`                      | `seedpass changepw --new "NewSecureP@ssw0rd!"`                                                                                                                                                      |
| Enable auto-lock                          | `autolock --enable`    | `-AL`          | `--auto-lock --enable`            | `seedpass autolock --enable --timeout 10`                                                                                                                                                          |
| Disable auto-lock                         | `autolock --disable`   | `-DL`          | `--auto-lock --disable`           | `seedpass autolock --disable`                                                                                                                                                                      |
| Generate a strong password                | `generate`             | `-G`           | `--generate`                      | `seedpass generate --length 20`                                                                                                                                                                    |
| Verify script checksum                    | `verify`               | `-V`           | `--verify`                        | `seedpass verify`                                                                                                                                                                                  |
| Post encrypted snapshots to Nostr             | `post`                 | `-P`           | `--post`                          | `seedpass post` |
| Retrieve snapshots from Nostr                 | `get-nostr`            | `-GN`          | `--get-nostr`                     | `seedpass get-nostr` |
| Display Nostr public key                  | `show-pubkey`          | `-K`           | `--show-pubkey`                   | `seedpass show-pubkey`                                                                                                                                                                             |
| Set Custom Nostr Relays                   | `set-relays`           | `-SR`          | `--set-relays`                    | `seedpass set-relays --add "wss://relay1.example.com" --add "wss://relay2.example.com"`                                                                                                           |
| Enable "Secret" Mode                      | `set-secret`           | `-SS`          | `--set-secret`                    | `seedpass set-secret --enable` or `seedpass set-secret --disable`                                                                                                                                    |
| Batch Post Snapshot Deltas to Nostr       | `batch-post`           | `-BP`          | `--batch-post`                    | `seedpass batch-post --start 0 --end 9` or `seedpass batch-post --range 10-19` |
| Show All Passwords                        | `show-all`             | `-SA`          | `--show-all`                      | `seedpass show-all`                                                                                                                                                                                |
| Add Notes to an Entry                     | `add-notes`            | `-AN`          | `--add-notes`                     | `seedpass add-notes --index 3 --notes "This is a secured account"`                                                                                                                                  |
| Add Tags to an Entry                      | `add-tags`             | `-AT`          | `--add-tags`                      | `seedpass add-tags --index 3 --tags "personal,finance"`                                                                                                                                              |
| Search by Tag or Title                    | `search-by`            | `-SB`          | `--search-by`                     | `seedpass search-by --tag "work"` or `seedpass search-by --title "GitHub"`                                                                                                                          |
| Automatically Post Deltas After Edit      | `auto-post`            | `-AP`          | `--auto-post`                     | `seedpass auto-post --enable` or `seedpass auto-post --disable` |
| Initial Setup Prompt for Seed Generation/Import | `setup`                | `-ST`          | `--setup`                         | `seedpass setup`                                                                                                                                                                                   |

---

## Detailed Command Descriptions

### 1. Add a New Password Entry

**Command:** `add`  
**Short Flag:** `-A`  
**Long Flag:** `--add`  

**Description:**  
Adds a new password entry to the password manager. This command allows users to specify various attributes of the password entry, including title, URL, username, email, notes, tags, and desired password length.

**Usage Example:**
```bash
seedpass add --title "GitHub" --url "https://github.com" --username "john_doe" --email "john@example.com" --notes "Primary GitHub account" --tags "work,development" --length 20
```

**Options:**
- `--title` (`-T`): The title or name of the service.
- `--url` (`-U`): The URL of the service.
- `--username` (`-UN`): The username associated with the account.
- `--email` (`-E`): The email address linked to the account.
- `--notes` (`-N`): Additional notes or comments about the account.
- `--tags` (`-TG`): Comma-separated tags for categorization.
- `--length` (`-L`): Desired length of the generated password.

---

### 2. Retrieve a Password Entry

**Command:** `retrieve`  
**Short Flag:** `-R`  
**Long Flag:** `--retrieve`  

**Description:**  
Retrieves a password entry based on either its index or title. This allows users to access specific passwords without browsing through all entries.

**Usage Examples:**
```bash
seedpass retrieve --index 3
seedpass retrieve --title "GitHub"
```

**Options:**
- `--index` (`-I`): The numerical index of the password entry.
- `--title` (`-T`): The title of the password entry.

---

### 3. Modify an Existing Entry

**Command:** `modify`  
**Short Flag:** `-M`  
**Long Flag:** `--modify`  

**Description:**  
Modifies an existing password entry. Users can update various attributes of the entry, such as title, notes, tags, and password length.

**Usage Example:**
```bash
seedpass modify --index 3 --title "GitHub Pro" --notes "Updated to pro account" --tags "work,development,pro" --length 22
```

**Options:**
- `--index` (`-I`): The numerical index of the password entry to modify.
- `--title` (`-T`): New title for the password entry.
- `--notes` (`-N`): Updated notes or comments.
- `--tags` (`-TG`): Updated comma-separated tags.
- `--length` (`-L`): New desired password length.

---

### 4. Delete an Entry

**Command:** `delete`  
**Short Flag:** `-D`  
**Long Flag:** `--delete`  

**Description:**  
Deletes a password entry from the password manager based on its index.

**Usage Example:**
```bash
seedpass delete --index 3
```

**Options:**
- `--index` (`-I`): The numerical index of the password entry to delete.

---

### 5. List All Entries

**Command:** `list`  
**Short Flag:** `-L`  
**Long Flag:** `--list`  

**Description:**  
Lists all password entries stored in the password manager. You can sort the output by index, label, or username and filter by entry type.

**Usage Example:**
```bash
seedpass list --sort label
seedpass list --filter totp
```

---

### 6. Search for a Password Entry

**Command:** `search`  
**Short Flag:** `-S`  
**Long Flag:** `--search`  

**Description:**  
Searches for password entries based on a query string, allowing users to find specific entries without knowing their exact titles or indices.

**Usage Example:**
```bash
seedpass search "GitHub"
```

**Options:**
- `<query>`: The search string to look for in titles, usernames, URLs or notes.

---

### 7. Get a Password by Query

**Command:** `get`

**Description:**
Searches for a password entry and immediately prints the generated password when exactly one match is found.

**Usage Example:**
```bash
seedpass get "GitHub"
```

---

### 8. Display a TOTP Code

**Command:** `totp`

**Description:**
Looks up a TOTP entry by query and prints the current code. The code is also copied to your clipboard if possible.

**Usage Example:**
```bash
seedpass totp "email"
```

---

### 9. Export Passwords to a File

---

### 7. Export Passwords to a File

**Command:** `export`  
**Short Flag:** `-E`  
**Long Flag:** `--export`  

**Description:**  
Exports password entries to a specified file in JSON format, enabling users to back up their data or transfer it to another system.

**Usage Example:**
```bash
seedpass export --file "backup_passwords.json"
```

**Options:**
- `--file` (`-F`): The destination file path for the exported data. If omitted, the export
  is saved to the current profile's `exports` directory under `~/.seedpass/<profile>/exports/`.

---

### 8. Import Passwords from a File

**Command:** `import`  
**Short Flag:** `-I`  
**Long Flag:** `--import`  

**Description:**  
Imports password entries from a specified JSON file into the password manager, allowing users to restore backups or migrate data.

**Usage Example:**
```bash
seedpass import --file "backup_passwords.json"
```

**Options:**
- `--file` (`-F`): The source file path containing the password entries to import.

---

### 9. Display Help Information

**Command:** `help`  
**Short Flag:** `-H`  
**Long Flag:** `--help`  

**Description:**  
Displays help information for SeedPass commands, providing users with guidance on available options and usage patterns.

**Usage Example:**
```bash
seedpass help
```

---

### 10. Display Application Version

**Command:** `version`  
**Short Flag:** `-V`  
**Long Flag:** `--version`  

**Description:**  
Displays the current version of the SeedPass application, helping users verify their installed version or check for updates.

**Usage Example:**
```bash
seedpass version
```

---

### 11. Change Master Password

**Command:** `changepw`  
**Short Flag:** `-C`  
**Long Flag:** `--changepw`  

**Description:**  
Allows users to change the master password used to encrypt and decrypt their password entries, enhancing account security.

**Usage Example:**
```bash
seedpass changepw --new "NewSecureP@ssw0rd!"
```

**Options:**
- `--new` (`-N`): The new master password to set.

---

### 12. Enable Auto-Lock

**Command:** `autolock --enable`  
**Short Flag:** `-AL`  
**Long Flag:** `--auto-lock --enable`  

**Description:**  
Enables the auto-lock feature, which automatically locks the password manager after a specified period of inactivity, enhancing security.

**Usage Example:**
```bash
seedpass autolock --enable --timeout 10
```

**Options:**
- `--enable`: Flag to enable the auto-lock feature.
- `--timeout` (`-T`): The duration (in minutes) of inactivity before auto-lock is triggered.

---

### 13. Disable Auto-Lock

**Command:** `autolock --disable`  
**Short Flag:** `-DL`  
**Long Flag:** `--auto-lock --disable`  

**Description:**  
Disables the auto-lock feature, preventing the password manager from automatically locking after inactivity.

**Usage Example:**
```bash
seedpass autolock --disable
```

---

### 14. Generate a Strong Password

**Command:** `generate`  
**Short Flag:** `-G`  
**Long Flag:** `--generate`  

**Description:**  
Generates a strong, random password of specified length, aiding users in creating secure credentials.

**Usage Example:**
```bash
seedpass generate --length 20
```

**Options:**
- `--length` (`-L`): The desired length of the generated password.

---

### 15. Verify Script Checksum

**Command:** `verify`  
**Short Flag:** `-V`  
**Long Flag:** `--verify`  

**Description:**  
Verifies the integrity of the SeedPass script by checking its checksum, ensuring that the code has not been tampered with.

**Usage Example:**
```bash
seedpass verify
```

---

### 16. Post Encrypted Snapshots to Nostr

**Command:** `post`  
**Short Flag:** `-P`  
**Long Flag:** `--post`  

**Description:**  
Posts encrypted snapshot chunks of the index to the Nostr network, followed by compact delta events for subsequent changes. This approach enables reliable backups and efficient synchronization across devices.

**Usage Example:**
```bash
seedpass post
```

---

### 17. Retrieve from Nostr

**Command:** `get-nostr`  
**Short Flag:** `-GN`  
**Long Flag:** `--get-nostr`  

**Description:**  
Retrieves the encrypted snapshot chunks and any delta events from the Nostr network, allowing users to reconstruct the latest index on a new device.

**Usage Example:**
```bash
seedpass get-nostr
```

---

### 18. Display Nostr Public Key

**Command:** `show-pubkey`  
**Short Flag:** `-K`  
**Long Flag:** `--show-pubkey`  

**Description:**  
Displays the user's Nostr public key (npub), which is used for identifying their account on the Nostr network.

**Usage Example:**
```bash
seedpass show-pubkey
```

---

### 19. Set Custom Nostr Relays

**Command:** `set-relays`  
**Short Flag:** `-SR`  
**Long Flag:** `--set-relays`  

**Description:**  
Allows users to specify custom Nostr relays for publishing their encrypted backup snapshots, providing flexibility and control over data distribution.
Relay URLs are stored in an encrypted configuration file located in `~/.seedpass/<fingerprint>/seedpass_config.json.enc` and loaded each time the Nostr client starts. New accounts use the following default relays until changed:

```
wss://relay.snort.social
wss://nostr.oxtr.dev
wss://relay.primal.net
```

**Usage Example:**
```bash
seedpass set-relays --add "wss://relay1.example.com" --add "wss://relay2.example.com"
```

**Options:**
- `--add`: Adds a new relay URL to the list of custom relays.

---

### 20. Enable "Secret" Mode

**Command:** `set-secret`  
**Short Flag:** `-SS`  
**Long Flag:** `--set-secret`  

**Description:**  
Enables or disables "secret" mode, where retrieved passwords are copied directly to the clipboard instead of being displayed on the screen, enhancing security.

**Usage Examples:**
```bash
seedpass set-secret --enable
seedpass set-secret --disable
```

**Options:**
- `--enable`: Activates "secret" mode.
- `--disable`: Deactivates "secret" mode.

You can also enable or disable secret mode from the interactive Settings menu by selecting **Toggle Secret Mode**.

---

### 21. Batch Post Snapshot Deltas to Nostr

**Command:** `batch-post`  
**Short Flag:** `-BP`  
**Long Flag:** `--batch-post`  

**Description:**  
Posts a specified range of snapshot delta events to the Nostr network in batches, ensuring efficient and manageable data transmission.

**Usage Examples:**
```bash
seedpass batch-post --start 0 --end 9
seedpass batch-post --range 10-19
```

**Options:**
- `--start` (`-S`): The starting index of the batch.
- `--end` (`-E`): The ending index of the batch.
- `--range` (`-R`): Specifies a range in the format `start-end`.

---

### 22. Show All Passwords

**Command:** `show-all`  
**Short Flag:** `-SA`  
**Long Flag:** `--show-all`  

**Description:**  
Displays all stored password entries along with their associated index numbers, titles, and tags, providing a comprehensive view for management purposes.

**Usage Example:**
```bash
seedpass show-all
```

---

### 23. Add Notes to an Entry

**Command:** `add-notes`  
**Short Flag:** `-AN`  
**Long Flag:** `--add-notes`  

**Description:**  
Adds or updates notes for a specific password entry, allowing users to include additional information or comments.

**Usage Example:**
```bash
seedpass add-notes --index 3 --notes "This is a secured account"
```

**Options:**
- `--index` (`-I`): The numerical index of the password entry.
- `--notes` (`-N`): The notes or comments to add.

---

### 24. Add Tags to an Entry

**Command:** `add-tags`  
**Short Flag:** `-AT`  
**Long Flag:** `--add-tags`  

**Description:**  
Adds or updates tags for a specific password entry, enabling better categorization and organization.

**Usage Example:**
```bash
seedpass add-tags --index 3 --tags "personal,finance"
```

**Options:**
- `--index` (`-I`): The numerical index of the password entry.
- `--tags` (`-TG`): Comma-separated tags to add.

---

### 25. Search by Tag or Title

**Command:** `search-by`  
**Short Flag:** `-SB`  
**Long Flag:** `--search-by`  

**Description:**  
Allows users to search for password entries based on specific tags or titles, enhancing the ability to locate entries quickly.

**Usage Examples:**
```bash
seedpass search-by --tag "work"
seedpass search-by --title "GitHub"
```

**Options:**
- `--tag` (`-T`): The tag to search for.
- `--title` (`-Ti`): The title to search for.

---

### 26. Automatically Post Deltas to Nostr After Edit

**Command:** `auto-post`  
**Short Flag:** `-AP`  
**Long Flag:** `--auto-post`  

**Description:**  
Enables or disables the automatic posting of snapshot delta events to the Nostr network whenever an edit occurs, ensuring real-time backups.

**Usage Examples:**
```bash
seedpass auto-post --enable
seedpass auto-post --disable
```

**Options:**
- `--enable`: Activates automatic posting.
- `--disable`: Deactivates automatic posting.

---

### 27. Initial Setup Prompt for Seed Generation/Import

**Command:** `setup`  
**Short Flag:** `-ST`  
**Long Flag:** `--setup`  

**Description:**  
Guides users through the initial setup process, allowing them to choose between generating a new seed or importing an existing one. This command also handles the encryption of the seed and the creation of a profile.

**Usage Example:**
```bash
seedpass setup
```

**Features to Implement:**
- **Seed Choice Prompt:** Asks users whether they want to generate a new seed or import an existing one.
- **Encryption of Seed:** Uses the user-selected password to encrypt the seed, whether generated or imported.
- **Profile Creation:** Upon first login, automatically generates a profile and checks for existing snapshot data that can be pulled and decrypted.

---

## CLI Commands for Managing Fingerprints

SeedPass provides a set of Command-Line Interface (CLI) commands to facilitate the management of fingerprints. These commands allow users to import, remove, list, and switch between fingerprints efficiently.

### 1. List All Fingerprints

**Command:**

```bash
seedpass fingerprint list
```

**Description:**

Displays all available fingerprints stored in the `~/.seedpass/` directory.

**Example Output:**

```
Available Fingerprints:
1. A1B2C3D4
2. E5F6G7H8
3. I9J0K1L2
```

### 2. Import a New Seed

**Command:**

```bash
seedpass fingerprint import
```

**Description:**

Guides the user through the process of importing a new seed, which automatically generates a corresponding fingerprint.

**Steps:**

1. **Choose Seed Option:**
   - **Generate:** SeedPass can generate a new seed.
   - **Import:** Users can import an existing seed by entering their 12-word mnemonic phrase.

2. **Provide Seed Details:**
   - If importing, enter the 12-word mnemonic phrase.
   - If generating, SeedPass creates a new seed complying with BIP-39 standards.

3. **Set Password:**
   - Enter a strong password to encrypt the seed and associated data.

4. **Confirmation:**
   - SeedPass generates the fingerprint and creates the corresponding directory structure.

**Example:**

```bash
seedpass fingerprint import
```

### 3. Remove an Existing Fingerprint

**Command:**

```bash
seedpass fingerprint remove <fingerprint_id>
```

**Description:**

Removes a specified fingerprint and deletes all associated data.

**Parameters:**

- `<fingerprint_id>`: The identifier of the fingerprint to remove (e.g., `A1B2C3D4`).

**Example:**

```bash
seedpass fingerprint remove A1B2C3D4
```

**Confirmation Prompt:**

```
Are you sure you want to remove A1B2C3D4? This action cannot be undone. (y/n):
```

### 4. Switch Active Fingerprint

**Command:**

```bash
seedpass fingerprint switch <fingerprint_id>
```

**Description:**

Switches the active fingerprint to the specified one, loading its data for use.

**Parameters:**

- `<fingerprint_id>`: The identifier of the fingerprint to activate.

**Example:**

```bash
seedpass fingerprint switch E5F6G7H8
```

### 5. View Current Active Fingerprint

**Command:**

```bash
seedpass fingerprint current
```

**Description:**

Displays the currently active fingerprint.

**Example Output:**

```
Current Active Fingerprint:
A1B2C3D4
```

### 6. Rename a Fingerprint

**Command:**

```bash
seedpass fingerprint rename <old_fingerprint_id> <new_fingerprint_id>
```

**Description:**

Renames an existing fingerprint for better identification.

**Parameters:**

- `<old_fingerprint_id>`: The current identifier of the fingerprint.
- `<new_fingerprint_id>`: The new desired identifier.

**Example:**

```bash
seedpass fingerprint rename A1B2C3D4 PersonalProfile
```

*Note: Renaming does not affect the underlying seed data but provides a more recognizable identifier for the user.*

---

## Notes on New CLI Commands

1. **Automatically Post Deltas to Nostr After Edit (`auto-post`):**
   - **Purpose:** Enables or disables the automatic posting of snapshot deltas to Nostr whenever an edit occurs.
   - **Usage Examples:**
     - Enable auto-post: `seedpass auto-post --enable`
     - Disable auto-post: `seedpass auto-post --disable`

2. **Initial Setup Prompt for Seed Generation/Import (`setup`):**
   - **Purpose:** Guides users through the initial setup process, allowing them to choose between generating a new seed or importing an existing one.
   - **Features to Implement:**
     - **Seed Choice Prompt:** Ask users whether they want to generate a new seed or import an existing one.
     - **Encryption of Seed:** Use the user-selected password to encrypt the seed, whether generated or imported.
     - **Profile Creation:** Upon first login, automatically generate a profile and check for existing snapshot data that can be pulled and decrypted.
   - **Usage Example:** `seedpass setup`

3. **Advanced CLI Enhancements:**
   - **Toggle "Secret" Mode via CLI:**
     - **Description:** Allows users to enable or disable "secret" mode directly through the CLI.
     - **Usage Examples:**
       - Enable secret mode: `seedpass set-secret --enable`
       - Disable secret mode: `seedpass set-secret --disable`
   
   - **Initial Seed Setup Flow:**
     - **Description:** When running `seedpass setup`, prompts users to either enter an existing seed or generate a new one, followed by password creation for encryption.
     - **Usage Example:** `seedpass setup`
   
   - **Automatic Profile Generation and Snapshot Retrieval:**
     - **Description:** During the initial setup or first login, generates a profile and attempts to retrieve and decrypt any existing snapshots and deltas from Nostr.
     - **Usage Example:** `seedpass setup` (handles internally)

---

## Usage Guidelines

- **Help Commands:** For detailed information on any command, use the help flag. For example:
  ```bash
  seedpass add --help
  ```
  
- **Consistent Flag Usage:** Use either the short flag or the long flag as per your preference, but maintain consistency for readability.
  
- **Security Considerations:**  
  - Always use strong, unique master passwords.
  - Regularly back up your encrypted index.
  - Enable auto-lock to enhance security.
  - Be cautious when using the `export` and `import` commands to handle sensitive data securely.
  
- **Nostr Integration:**  
  - Ensure that your Nostr relays are reliable and secure.
  - Regularly verify your Nostr public key and manage relays through the `set-relays` command.

---

## Conclusion

This **Advanced CLI Commands Documentation** serves as a comprehensive guide for utilizing SeedPass's full suite of command-line functionalities. By understanding and effectively leveraging these commands, users can manage their passwords securely and efficiently, ensuring both ease of use and robust security measures.

For further assistance or to contribute to the development of SeedPass, please refer to the [Contributing Guidelines](CONTRIBUTING.md) or open an issue on the [GitHub Repository](https://github.com/PR0M3TH3AN/SeedPass/issues).

---