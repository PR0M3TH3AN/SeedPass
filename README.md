# SeedPass

![SeedPass Logo](https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/refs/heads/main/logo/png/SeedPass-Logo-03.png)

**SeedPass** is a secure password generator and manager built on **Bitcoin's BIP-85 standard**. It uses deterministic key derivation to generate **passwords that are never stored**, but can be easily regenerated when needed. By integrating with the **Nostr network**, SeedPass ensures that your passwords are safe and accessible across devices. The index for retrieving each password is securely stored on Nostr relays, allowing seamless password recovery on multiple devices without compromising security.

---

**⚠️ Disclaimer**

This software was not developed by an experienced security expert and should be used with caution. There may be bugs and missing features. For instance, the maximum size of the index before the Nostr backup starts to have problems is unknown. Additionally, the security of the program's memory management and logs has not been evaluated and may leak sensitive information.

---

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
- **Checksum Verification:** Ensure the integrity of the script with checksum verification.
- **Multiple Seed Profiles:** Manage multiple seed profiles and switch between them seamlessly.
- **User-Friendly CLI:** Simple command-line interface for easy interaction.

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

- **On Windows:** (Note: SeedPass currently does not support Windows)

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
   1. Generate a New Password and Add to Index
   2. Retrieve a Password from Index
   3. Modify an Existing Entry
   4. Verify Script Checksum
   5. Post Encrypted Index to Nostr
   6. Retrieve Encrypted Index from Nostr
   7. Display Nostr Public Key (npub)
   8. Backup/Reveal Parent Seed
   9. Switch Seed Profile
   10. Add a New Seed Profile
   11. Remove an Existing Seed Profile
   12. List All Seed Profiles
   13. Exit

   Enter your choice (1-13):
   ```

### Managing Multiple Seeds

SeedPass allows you to manage multiple seed profiles (previously referred to as "fingerprints"). Each seed profile has its own parent seed and associated data, enabling you to compartmentalize your passwords.

- **Add a New Seed Profile:**
  - Select option `10` from the main menu.
  - Choose to enter an existing seed or generate a new one.
  - If generating a new seed, you'll be provided with a 12-word BIP-85 seed phrase. **Ensure you write this down and store it securely.**

- **Switch Between Seed Profiles:**
  - Select option `9` from the main menu.
  - You'll see a list of available seed profiles.
  - Enter the number corresponding to the seed profile you wish to switch to.
  - Enter the master password associated with that seed profile.

- **List All Seed Profiles:**
  - Select option `12` from the main menu to view all existing seed profiles.

**Note:** The term "seed profile" is used to represent different sets of seeds you can manage within SeedPass. This provides an intuitive way to handle multiple identities or sets of passwords.

## Running Tests

SeedPass includes a small suite of unit tests. After activating your virtual environment and installing dependencies, run the tests with **pytest**:

```bash
pip install -r src/requirements.txt
pytest
```

## Security Considerations

**Important:** The password you use to encrypt your parent seed is also required to decrypt the seed index data retrieved from Nostr. **It is imperative to remember this password** and be sure to use it with the same seed, as losing it means you won't be able to access your stored index. Secure your 12-word seed **and** your master password.

- **Backup Your Data:** Regularly back up your encrypted data and checksum files to prevent data loss.
- **Protect Your Passwords:** Do not share your master password or seed phrases with anyone and ensure they are strong and unique.
- **Checksum Verification:** Always verify the script's checksum to ensure its integrity and protect against unauthorized modifications.
- **Potential Bugs and Limitations:** Be aware that the software may contain bugs and lacks certain features. The maximum size of the password index before encountering issues with Nostr backups is unknown. Additionally, the security of memory management and logs has not been thoroughly evaluated and may pose risks of leaking sensitive information.
- **Multiple Seeds Management:** While managing multiple seeds adds flexibility, it also increases the responsibility to secure each seed and its associated password.

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

1. **Configuration File Management**
   - **Description:** Implement a configuration file to store user-specific settings, starting with user-determined Nostr relays.
   - **Implementation Steps:**
     - Create a `config.yaml` or `config.json` file in the SeedPass data directory.
     - Define a structure to store user configurations, starting with a list of Nostr relay URLs.
     - Allow users to add, remove, and manage an unlimited number of Nostr relays through the CLI or configuration file.
     - Ensure the configuration file is securely stored and encrypted if necessary.

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

3. **Enhanced JSON Schema Integration**
   - **Description:** Adopt the new JSON schema for all entry types, ensuring consistency and flexibility.
   - **Implementation Steps:**
     - Update existing entries to conform to the new schema.
     - Ensure that new kinds adhere to the defined structure, facilitating future expansions.

4. **Nostr Integration Enhancements**
   - **Description:** Improve Nostr integration by changing the posting mechanism and enabling efficient synchronization.
   - **Implementation Steps:**
     - **Selective Posting:**
       - Modify the Nostr posting mechanism to only post new or updated entries instead of the entire index.
     - **Index Reconstruction:**
       - On the first run, build the index from Nostr posts based on timestamps to ensure the correct and complete database retrieval.
       - Implement logic to check for existing posts on the specified `npub` account and synchronize accordingly.
     - **Configuration Integration:**
       - Utilize the newly added configuration file to manage Nostr relays and synchronization settings.

5. **Backup and Restore Index Option**
   - **Description:** Provide users with the ability to backup and restore the index, offering flexibility in backup locations.
   - **Implementation Steps:**
     - Introduce CLI commands such as `backup-index` and `restore-index`.
     - Allow users to choose the backup location via CLI prompts or by specifying a path in the configuration file.
     - Ensure backups can be saved to external drives, remote folders, or other user-defined locations.
     - Validate the integrity of backups during the restore process.

6. **Security Enhancements**
   - **"Secret" Mode (Clipboard-Only Password Retrieval)**
     - **Description:** Introduce a "secret" mode where passwords are copied directly to the clipboard rather than displayed on the screen upon retrieval.
     - **Features:**
       - **Toggle Setting:** Allow users to enable or disable "secret" mode.
       - **Clipboard Integration:** Ensure passwords are copied securely to the clipboard when "secret" mode is active.
       - **User Feedback:** Notify users that the password has been copied to the clipboard.
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

3. **Easy BIP39 Seed Generation for Various Use Cases**
   - **Description:** Provide an easy method for generating new BIP39 seeds for different purposes, such as cryptocurrency wallets.
   - **Features:**
     - **Seed Generation:** Ensure seeds are generated securely and comply with BIP39 standards.
     - **User Guidance:** Offer CLI instructions on securely handling and storing generated seeds.

4. **Nostr Public/Private Key Pair Generation**
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

