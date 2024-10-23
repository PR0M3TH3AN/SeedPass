# Fingerprint-Based Backup and Local Storage in SeedPass

## Table of Contents

1. [Introduction](#introduction)
2. [Overview](#overview)
3. [Fingerprint Generation](#fingerprint-generation)
4. [Directory Structure](#directory-structure)
5. [Data Encryption and Security](#data-encryption-and-security)
6. [Managing Fingerprints](#managing-fingerprints)
7. [Loading and Switching Fingerprints at Startup](#loading-and-switching-fingerprints-at-startup)
8. [Backup and Restore Procedures](#backup-and-restore-procedures)
9. [CLI Commands for Managing Fingerprints](#cli-commands-for-managing-fingerprints)
10. [Security Considerations](#security-considerations)
11. [Use Cases](#use-cases)
12. [FAQs](#faqs)
13. [Conclusion](#conclusion)

---

## Introduction

**SeedPass** is a secure password generator and manager leveraging Bitcoin's BIP-85 standard and integrated with the Nostr network for seamless password recovery across devices. To enhance the security and manageability of multiple seeds and user profiles, SeedPass introduces a **Fingerprint-Based Backup and Local Storage Structure**. This document provides a comprehensive guide on how this system operates, ensuring secure identification, storage, and management of seed data without exposing sensitive information.

---

## Overview

The fingerprint-based system in SeedPass serves as a unique identifier for each seed and user profile. By utilizing a one-way hashing function, SeedPass generates fingerprints that securely represent seeds without revealing any sensitive details. This mechanism allows users to manage multiple seeds efficiently, ensuring organized storage and easy retrieval while maintaining high security standards.

### Key Objectives

- **Secure Identification:** Use one-way fingerprints to uniquely identify seeds and user profiles without exposing sensitive information.
- **Organized Storage:** Implement a structured directory system that segregates data based on fingerprints.
- **Scalability:** Allow users to manage multiple fingerprints seamlessly, facilitating the handling of various seeds and profiles.
- **Enhanced Security:** Ensure all sensitive data is encrypted and protected within each fingerprint directory.

---

## Fingerprint Generation

### What is a Fingerprint?

In the context of SeedPass, a **fingerprint** is a unique identifier generated from a seed using a one-way hashing function. It acts as an alias for the seed, enabling the system to reference and manage seeds without directly exposing them.

### How is the Fingerprint Generated?

1. **Seed Input:** The user provides a seed, typically a 12-word BIP-39 mnemonic phrase.
2. **Hashing Function:** SeedPass applies a cryptographic one-way hashing function (e.g., SHA-256) to the seed to produce a fixed-length hash.
3. **Truncation and Formatting:** The resulting hash is truncated and formatted to create a human-readable fingerprint (e.g., `fingerprint01`, `fingerprint02`).

### Example

```python
import hashlib

def generate_fingerprint(seed):
    # Convert seed to bytes
    seed_bytes = seed.encode('utf-8')
    
    # Generate SHA-256 hash of the seed
    hash_digest = hashlib.sha256(seed_bytes).hexdigest()
    
    # Truncate and format the fingerprint (e.g., first 8 characters)
    fingerprint = f"fingerprint{hash_digest[:8]}"
    
    return fingerprint

# Example usage
seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
fingerprint = generate_fingerprint(seed)
print(fingerprint)  # Output: fingerprinte9a1b2c3
```

*Note: The actual implementation may use more sophisticated methods to ensure uniqueness and security.*

---

## Directory Structure

The fingerprint-based system organizes data into separate directories based on the generated fingerprints. This structure ensures that each seed's data is isolated, encrypted, and easily manageable.

### Root Directory

All fingerprint directories reside within the `~/.seedpass` directory in the user's home folder.

```
~/.seedpass/
```

### Fingerprint Directories

Each fingerprint corresponds to its own directory containing all related data and backups.

```
~/.seedpass/
├── fingerprint01/
│   ├── parent_seed.enc
│   ├── backups/
│   │   ├── passwords_db_backup_1729556583.json.enc
│   │   ├── passwords_db_backup_1729556584.json.enc
│   │   └── passwords_db_backup_1729556684.json.enc
│   ├── seedpass_passwords_checksum.txt
│   ├── seedpass_passwords_db_checksum.txt
│   └── seedpass_passwords_db.json
├── fingerprint02/
│   ├── parent_seed.enc
│   ├── backups/
│   │   ├── passwords_db_backup_1729556585.json.enc
│   │   └── passwords_db_backup_1729556685.json.enc
│   ├── seedpass_passwords_checksum.txt
│   ├── seedpass_passwords_db_checksum.txt
│   └── seedpass_passwords_db.json
└── fingerprint03/
    └── ...
```

### Directory Components

- **`parent_seed.enc`**: Encrypted file containing the parent seed associated with the fingerprint.
- **`backups/`**: Directory storing encrypted backups of the passwords database with timestamped filenames.
- **`seedpass_passwords_checksum.txt`**: Checksum file for verifying the integrity of the passwords script.
- **`seedpass_passwords_db_checksum.txt`**: Checksum file for verifying the integrity of the passwords database.
- **`seedpass_passwords_db.json`**: Encrypted JSON file containing the actual passwords database.

---

## Data Encryption and Security

### Encryption Standards

All sensitive data within each fingerprint directory is encrypted using industry-standard encryption algorithms (e.g., AES-256). Encryption ensures that even if unauthorized access to the files occurs, the data remains unreadable without the appropriate decryption key.

### Encryption Process

1. **Key Derivation:** SeedPass derives an encryption key from the user's password using a key derivation function (e.g., PBKDF2, Argon2).
2. **Data Encryption:** The derived key encrypts the sensitive files (`parent_seed.enc`, `seedpass_passwords_db.json`, etc.).
3. **Secure Storage:** Encrypted files are stored within the respective fingerprint directories, ensuring data isolation and protection.

### Decryption Process

1. **User Authentication:** Upon startup or when accessing a specific fingerprint, the user provides their password.
2. **Key Derivation:** SeedPass derives the encryption key using the same key derivation function and parameters.
3. **Data Decryption:** The encrypted files are decrypted in-memory for use by the application.

*Note: The encryption and decryption processes are transparent to the user but crucial for maintaining data security.*

---

## Managing Fingerprints

SeedPass allows users to manage multiple fingerprints, enabling the handling of various seeds and user profiles. This section outlines how to add, remove, and switch between different fingerprints.

### Adding a New Fingerprint

1. **Generate or Import a Seed:**
   - **Generate:** SeedPass can generate a new BIP-39 seed for the user.
   - **Import:** Users can import an existing seed by entering their 12-word mnemonic phrase.

2. **Generate Fingerprint:**
   - SeedPass generates a unique fingerprint using the one-way hashing method described earlier.

3. **Create Directory Structure:**
   - A new directory corresponding to the fingerprint is created within `~/.seedpass/`.
   - All relevant files (`parent_seed.enc`, `backups/`, etc.) are initialized and encrypted.

4. **Confirmation:**
   - SeedPass confirms the successful addition of the new fingerprint and its associated data.

### Removing a Fingerprint

1. **Select Fingerprint:**
   - Users choose the fingerprint they wish to remove from the list of existing fingerprints.

2. **Confirmation:**
   - SeedPass prompts the user to confirm the removal to prevent accidental deletions.

3. **Deletion:**
   - The selected fingerprint directory and all its contents are securely deleted from the local storage.

*Warning: Removing a fingerprint permanently deletes all associated data. Ensure backups are available before proceeding.*

### Switching Between Fingerprints

1. **List Available Fingerprints:**
   - SeedPass displays a list of all existing fingerprints stored in `~/.seedpass/`.

2. **Select Fingerprint:**
   - Users choose the desired fingerprint to activate.

3. **Load Data:**
   - SeedPass decrypts and loads the data from the selected fingerprint directory for use within the application.

*Note: Users can manage and switch between multiple fingerprints to handle different seeds or profiles as needed.*

---

## Loading and Switching Fingerprints at Startup

SeedPass is designed to handle multiple fingerprints seamlessly upon startup. This section explains the process of loading available fingerprints and allowing users to select or manage their data.

### Startup Process

1. **Initialization:**
   - SeedPass initializes and scans the `~/.seedpass/` directory for available fingerprint directories.

2. **Fingerprint Detection:**
   - All directories matching the `fingerprintXX` naming convention are identified as valid fingerprints.

3. **User Prompt:**
   - SeedPass presents a list of detected fingerprints and prompts the user to select one for activation.
   - Alternatively, users can choose to add a new fingerprint during startup.

4. **Authentication:**
   - Upon selection, SeedPass requests the user's password to decrypt the corresponding `parent_seed.enc` and other encrypted files.

5. **Data Loading:**
   - Once authenticated, SeedPass loads the decrypted data into memory, making it available for password management operations.

### Managing Fingerprints at Startup

- **Add New Fingerprint:** Users can choose to add a new fingerprint if they wish to manage an additional seed or profile.
- **Remove Existing Fingerprint:** Users can opt to remove an existing fingerprint during startup if it's no longer needed.
- **Switch Fingerprint:** Users can switch to a different fingerprint without restarting the application by accessing the fingerprint management CLI commands.

---

## Backup and Restore Procedures

Ensuring data integrity and availability is paramount. SeedPass provides robust backup and restore mechanisms within each fingerprint directory.

### Automated Backups

- **Backup Directory:** Each fingerprint directory contains a `backups/` folder where encrypted backups of the passwords database are stored.
- **Backup Files:** Backups are named using a timestamp format to ensure uniqueness and facilitate easy retrieval (e.g., `passwords_db_backup_1729556583.json.enc`).

### Creating Backups

1. **Triggering a Backup:**
   - Backups are automatically created upon significant changes, such as adding, updating, or deleting entries.
   - Users can also manually initiate a backup via CLI commands.

2. **Backup Process:**
   - The current state of `seedpass_passwords_db.json` is encrypted and saved as a new backup file within the `backups/` directory.
   - A checksum file (`seedpass_passwords_db_checksum.txt`) is updated to verify the integrity of the database.

### Restoring from Backups

1. **Accessing Backups:**
   - Users can list available backups within the `backups/` directory to identify the desired backup version.

2. **Selecting a Backup:**
   - Choose the specific backup file to restore (e.g., `passwords_db_backup_1729556583.json.enc`).

3. **Decryption and Restoration:**
   - SeedPass decrypts the selected backup file using the derived encryption key.
   - The decrypted data replaces the current `seedpass_passwords_db.json` file.
   - The associated checksum files are updated accordingly.

4. **Verification:**
   - SeedPass verifies the integrity of the restored data using the checksum files to ensure successful restoration.

*Note: Restoring a backup overwrites the current database. Ensure that you intend to revert to the selected backup before proceeding.*

---

## CLI Commands for Managing Fingerprints

SeedPass provides a set of Command-Line Interface (CLI) commands to facilitate the management of fingerprints. These commands allow users to add, remove, list, and switch between fingerprints efficiently.

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
1. fingerprinte9a1b2c3
2. fingerprint4d5e6f7g
3. fingerprint8h9i0j1k
```

### 2. Add a New Fingerprint

**Command:**

```bash
seedpass fingerprint add
```

**Description:**

Guides the user through the process of adding a new fingerprint by either generating a new seed or importing an existing one.

**Steps:**

1. **Choose Seed Option:**
   - Generate a new seed.
   - Import an existing seed.

2. **Provide Seed Details:**
   - If importing, enter the 12-word mnemonic phrase.
   - If generating, SeedPass creates a new seed complying with BIP-39 standards.

3. **Set Password:**
   - Enter a strong password to encrypt the seed and associated data.

4. **Confirmation:**
   - SeedPass generates the fingerprint and creates the corresponding directory structure.

### 3. Remove an Existing Fingerprint

**Command:**

```bash
seedpass fingerprint remove <fingerprint_id>
```

**Description:**

Removes a specified fingerprint and deletes all associated data.

**Parameters:**

- `<fingerprint_id>`: The identifier of the fingerprint to remove (e.g., `fingerprinte9a1b2c3`).

**Example:**

```bash
seedpass fingerprint remove fingerprinte9a1b2c3
```

**Confirmation Prompt:**

```
Are you sure you want to remove fingerprinte9a1b2c3? This action cannot be undone. (y/n):
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
seedpass fingerprint switch fingerprint4d5e6f7g
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
fingerprinte9a1b2c3
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
seedpass fingerprint rename fingerprinte9a1b2c3 fingerprintPersonal
```

*Note: Renaming does not affect the underlying seed data but provides a more recognizable identifier for the user.*

---

## Security Considerations

Implementing a fingerprint-based backup and local storage system introduces several security measures to protect sensitive seed data. However, it's crucial to adhere to best practices to maintain the integrity and confidentiality of the information.

### 1. One-Way Hashing for Fingerprints

- **Purpose:** Ensures that fingerprints cannot be reverse-engineered to obtain the original seed.
- **Implementation:** Use cryptographic one-way hashing functions (e.g., SHA-256) with salting to generate unique fingerprints.

### 2. Encryption of Sensitive Files

- **Encryption Standards:** Utilize robust encryption algorithms like AES-256.
- **Key Management:** Derive encryption keys from user passwords using secure key derivation functions (e.g., PBKDF2, Argon2) with appropriate salting and iteration counts.
- **In-Memory Security:** Handle decrypted data securely in memory, minimizing exposure to potential memory scraping attacks.

### 3. Secure Password Handling

- **Password Strength:** Encourage users to create strong, unique passwords for encrypting their seeds.
- **Password Storage:** Never store user passwords in plaintext. Only use them to derive encryption keys in-memory.

### 4. Access Control

- **File Permissions:** Set strict file permissions on the `~/.seedpass/` directory and its contents to prevent unauthorized access.
  - **Example (Unix-based systems):**
    ```bash
    chmod 700 ~/.seedpass
    chmod 600 ~/.seedpass/*/*.enc
    ```
- **User Authentication:** Require user authentication (password entry) before allowing access to any seed-related operations.

### 5. Backup Security

- **Encrypted Backups:** Ensure all backup files are encrypted using the same encryption standards as primary data.
- **Backup Integrity:** Use checksum files to verify the integrity of backup data, preventing tampering or corruption.

### 6. Secure Fingerprint Management

- **Non-Reversible Identification:** Since fingerprints are derived using one-way functions, even if a fingerprint is exposed, it cannot be used to recover the original seed.
- **Unique Identifiers:** Ensure that each fingerprint is unique to prevent collisions and potential confusion between different seeds.

### 7. Regular Security Audits

- **Code Reviews:** Conduct regular code reviews to identify and fix potential vulnerabilities.
- **Dependency Management:** Keep all dependencies up-to-date to mitigate risks from known vulnerabilities in third-party libraries.

### 8. User Education

- **Best Practices:** Inform users about the importance of securing their passwords and maintaining backups.
- **Warning on Sensitive Actions:** Provide clear warnings when users perform sensitive operations like removing fingerprints or restoring from backups.

---

## Use Cases

### 1. Managing Multiple User Profiles

**Scenario:** A user wants to manage separate password databases for personal and work-related accounts.

**Implementation:**

1. **Add Fingerprint:** Create two fingerprints (`fingerprintPersonal`, `fingerprintWork`) corresponding to each profile.
2. **Manage Separately:** Each fingerprint directory contains its own `seedpass_passwords_db.json`, ensuring data isolation.
3. **Switch Profiles:** Easily switch between personal and work profiles using CLI commands.

### 2. Seed Recovery and Redundancy

**Scenario:** A user wants to ensure they can recover their password database in case of data loss.

**Implementation:**

1. **Backup Fingerprints:** Regularly backup the `backups/` directories within each fingerprint folder.
2. **Store Backups Securely:** Keep encrypted backups in multiple secure locations (e.g., external drives, cloud storage with encryption).
3. **Restore Process:** Use SeedPass CLI commands to restore from backups if the primary data is compromised.

### 3. Sharing Seed Data Across Devices

**Scenario:** A user wants to access their password database from multiple devices securely.

**Implementation:**

1. **Fingerprint Identification:** Each device recognizes fingerprints without accessing the actual seeds.
2. **Encrypted Data Transfer:** Transfer encrypted `seedpass_passwords_db.json` files between devices using secure channels.
3. **Authentication:** Each device decrypts the data using the user's password, maintaining data security across platforms.

---

## FAQs

### 1. **Can fingerprints be customized?**

**Answer:** While fingerprints are generated using a one-way hashing function to ensure uniqueness and security, users can assign recognizable names to fingerprints (e.g., `fingerprintPersonal`, `fingerprintWork`) during the renaming process to facilitate easier identification.

### 2. **What happens if I forget my password?**

**Answer:** If you forget your password, SeedPass cannot decrypt your encrypted data, including seeds and password databases. It's crucial to remember your password or securely store it using reliable password management practices.

### 3. **Is the fingerprint reversible to obtain the original seed?**

**Answer:** No. Fingerprints are generated using one-way hashing functions, making it computationally infeasible to reverse-engineer the original seed from the fingerprint.

### 4. **Can I have multiple fingerprints with the same seed?**

**Answer:** While technically possible, it's not recommended to have multiple fingerprints pointing to the same seed as it could lead to confusion and redundant data management. Each fingerprint should uniquely correspond to a distinct seed.

### 5. **How secure are the backups stored in the `backups/` directory?**

**Answer:** Backups within the `backups/` directory are encrypted using the same encryption standards as primary data. Additionally, their integrity is verified using checksum files, ensuring that only authentic and untampered backups are restored.

---

## Conclusion

The **Fingerprint-Based Backup and Local Storage Structure** in SeedPass significantly enhances the application's security and manageability. By leveraging one-way hashing for fingerprint generation and implementing a structured, encrypted directory system, SeedPass ensures that users can securely manage multiple seeds and profiles without compromising sensitive information. This system not only provides organized storage and easy retrieval but also lays a robust foundation for future scalability and feature expansions.

By adhering to best security practices and offering intuitive CLI commands for fingerprint management, SeedPass empowers users to maintain control over their password data with confidence and ease.
