# SeedPass

![SeedPass Logo](https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/refs/heads/main/logo/png/SeedPass-Logo-03.png)

**SeedPass** is a secure password generator and manager built on **Bitcoin's BIP-85 standard**. It uses deterministic key derivation to generate **passwords that are never stored**, but can be easily regenerated when needed. By integrating with the **Nostr network**, SeedPass ensures that your passwords are safe and accessible across devices. The index for retrieving each password is securely stored on Nostr relays, allowing seamless password recovery on multiple devices without compromising security.

---

**⚠️ Disclaimer**

This software was not developed by an experienced security expert and should be used with caution. There are likely many bugs and missing features. For instance, the maximum size of the index before the Nostr backup starts to have problems is unknown. Additionally, the security of the program's memory management and logs have not been evaluated and may leak sensitive information.

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
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Roadmap](#roadmap)

## Features

- **Deterministic Password Generation:** Utilize BIP-85 for generating deterministic and secure passwords.
- **Encrypted Storage:** All seeds, login passwords and sensitive index data are encrypted locally.
- **Nostr Integration:** Post and retrieve your encrypted password index to/from the Nostr network.
- **Checksum Verification:** Ensure the integrity of the script with checksum verification.
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
cd SeedPass/src
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

- **On Windows:** (This app doesent currently work on Windows)
  
  ```bash
  venv\Scripts\activate
  ```

Once activated, your terminal prompt should be prefixed with `(venv)` indicating that the virtual environment is active.

### 4. Install Dependencies

Install the required Python packages and build dependencies using `pip`:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

After successfully installing the dependencies, you can run SeedPass using the following command:

```bash
python main.py
```

### Running the Application

1. **Start the Application:**
   
   ```bash
   python main.py
   ```

2. **Follow the Prompts:**
   
   - **Enter Your Password:** This password is crucial as it is used to decrypt your parent seed and, subsequently, your seed index data from Nostr.
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
   8. Exit
   
   Enter your choice (1-8):
   ```

## Security Considerations

**Important:** The password you use to decrypt your parent seed is also required to decrypt the seed index data retrieved from Nostr. **It is imperative to remember this password** and be sure to use it with the same seed, as losing it means you won't be able to access your stored index. Secure your 12 word seed AND your login password.

- **Backup Your Data:** Regularly back up your encrypted data and checksum files to prevent data loss.
- **Protect Your Password:** Do not share your decryption password with anyone and ensure it's strong and unique.
- **Checksum Verification:** Always verify the script's checksum to ensure its integrity and protect against unauthorized modifications.
- **Potential Bugs and Limitations:** Be aware that the software may contain bugs and lacks certain features. The maximum size of the password index before encountering issues with Nostr backups is unknown. Additionally, the security of memory management and logs has not been thoroughly evaluated and may pose risks of leaking sensitive information.

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

The SeedPass roadmap outlines a structured development plan divided into distinct phases. Each phase focuses on specific areas, prioritizing core functionalities and security before expanding into advanced CLI features and integrations. This approach ensures that SeedPass remains a secure, reliable, and user-friendly CLI-based password management tool.

---

### Phase 1: Core Functionality and Security

**Goal:** Establish a solid foundation with essential password management features, secure seed handling, and robust Nostr integration.

1. **Cross-Platform Compatibility**
   - **Add Windows-Supported File Locking**
     - **Description:** Implement a cross-platform file locking mechanism to ensure safe concurrent file access across different operating systems.
     - **Approach:** Utilize a library like [`portalocker`](https://pypi.org/project/portalocker/) to replace the current `fcntl`-based locking system.

2. **Security Enhancements**
   - **Add Parent Seed Recovery**
     - **Description:** Develop a secure method for users to recover their parent seed if lost.
     - **Features:**
       - **Recovery Phrase:** Allow users to generate and store a recovery phrase or backup file.
       - **Multi-Factor Authentication (MFA):** Integrate MFA to enhance the security of the recovery process.
       - **Encrypted Storage:** Ensure that recovery data is encrypted and stored securely.

   - **Add "Secret" Mode (Clipboard-Only Password Retrieval)**
     - **Description:** Introduce a "secret" mode where passwords are copied directly to the clipboard rather than displayed on the screen upon retrieval.
     - **Features:**
       - **Toggle Setting:** Allow users to enable or disable "secret" mode.
       - **Clipboard Integration:** Ensure passwords are copied securely to the clipboard when "secret" mode is active.
       - **User Feedback:** Notify users that the password has been copied to the clipboard.

   - **Implement Two-Factor Security Model with Random Index Generation**
     - **Description:** Create a robust two-factor security system using a master seed and master password combination, enhanced with random index generation for additional security.
     - **Key Features:**
       - **Random Index Generation:** Generate cryptographically secure random numbers for each new password index.
       - **Master Seed Management:** Keep the master seed in cold storage/offline, acting as the primary key for password generation.
       - **Master Password System:** Store the master password in memory/brain only, required to decrypt indices and access accounts.
       - **Protection Layers:** Ensure seed and password compromise protection through encrypted indices and secure storage.
       - **Security Verification:** Implement checks to ensure neither factor can be bypassed and verify the randomness quality of index generation.

3. **Nostr Integration Enhancements**
   - **Add Option for Custom Relays**
     - **Description:** Provide users with the ability to select or configure specific Nostr relays for publishing their encrypted backup index.
     - **Features:**
       - **User Configuration:** Allow users to input or select preferred relay URLs via CLI commands.
       - **Validation:** Ensure specified relays are active and support necessary protocols.
       - **Fallback Mechanism:** Allow users to add multiple relays for redundancy in case some become unavailable.

   - **Implement Smart Batching System for Index Updates**
     - **Description:** Manage the synchronization of password indices across devices by segmenting the encrypted JSON index into manageable chunks for Nostr transmission.
     - **Features:**
       - **Batch Structure:** Include metadata such as total batch count, sequence position, and checksums.
       - **Reconstruction Protocol:** Collect batches with matching timestamps, verify checksums, and reconstruct the complete index.
       - **Conflict Management:** Use timestamp-based precedence and checksum validation to handle conflicts.
       - **Error Handling:** Implement mechanisms to recover from partial updates, network interruptions, and corrupt batches.
       - **Optimization Features:** Use differential updates, batch prioritization, and compression to enhance performance.

   - **Automatically Post Index to Nostr After Every Edit**
     - **Description:** Automate the process of updating Nostr relays whenever modifications to the password index occur.
     - **Features:**
       - **Hook Integration:** Detect changes and trigger posting via hooks in relevant modules.
       - **Error Handling:** Manage failed posts without disrupting the user's workflow.
       - **User Notifications:** Inform users of the backup status after each edit (e.g., success, failure).

4. **User Onboarding and Initialization**
   - **Seed Initialization on First Run**
     - **Description:** Prompt users to either enter an existing seed or generate a new one during the first run.
     - **Features:**
       - **Prompt Options:** Ask users if they want to input an existing seed or generate a new one.
       - **Seed Generation:** Ensure generated seeds comply with BIP-39 standards.
       - **Encryption:** Securely encrypt the seed using the user's chosen password.
       - **Confirmation:** Confirm the successful initialization and encryption of the seed.
       - **Error Handling:** Manage scenarios where seed generation or encryption fails, providing clear feedback to the user.

5. **Comprehensive Testing and Security Auditing**
   - **Unit Tests:** Develop tests for individual functions and modules to ensure they work as intended.
   - **Integration Tests:** Test the interaction between different modules, especially for features like automatic Nostr posting and seed recovery.
   - **Security Audits:** Conduct regular code reviews and security assessments to identify and mitigate vulnerabilities.

---

### Phase 2: Enhanced Security and Data Management

**Goal:** Strengthen security features and improve data management capabilities for better scalability and user satisfaction.

1. **Enhanced Data Fields**
   - **Add "Notes" Field**
     - **Description:** Allow users to add supplementary information or comments to each password entry.
   - **Add "Tags" Field**
     - **Description:** Enable categorization and easier organization of passwords through tagging.
   - **Rename "Website" Field to "Title"**
     - **Description:** Generalize the naming convention to accommodate non-website entries, such as application logins or system credentials.

2. **Add Family Password Management**
   - **Description:** Enable users to manage multiple sets of passwords for their entire family, including kids or elderly parents, from a single interface.
   - **Features:**
     - **Segregated Access:** Allow users to create and manage separate password sets for different family members.
     - **Additional Security Layers:** Implement MFA or role-based access for managing family members' accounts.
     - **User-Friendly CLI Commands:** Develop intuitive CLI commands to handle family member password sets efficiently.

3. **Add Easy BIP39 Seed Generation for Various Use Cases**
   - **Description:** Provide an easy method for generating new BIP39 seeds for different purposes, such as cryptocurrency wallets.
   - **Features:**
     - **Seed Generation:** Ensure seeds are generated securely and comply with BIP39 standards.
     - **User Guidance:** Offer CLI instructions on securely handling and storing generated seeds.

4. **Add Nostr Public/Private Key Pair Generation**
   - **Description:** Allow users to generate new Nostr public/private key pairs within the application.
   - **Features:**
     - **Secure Key Generation:** Ensure key pairs are generated securely and tied to specific index entries.
     - **Seamless Integration:** Integrate key pair management with existing Nostr functionalities.
     - **Security Advisories:** Inform users about best practices for managing multiple Nostr identities and the risks of using the same seed across different identities.

---

### Phase 3: Advanced CLI Functionalities

**Goal:** Develop a sophisticated Command-Line Interface (CLI) for power users and developers, enhancing automation and customization capabilities.

1. **Develop an Advanced CLI Mode with Enhanced Functionalities**
   - **Features:**
     - **Custom Relays Configuration:** Allow users to specify a custom set of Nostr relays for publishing their backup index via CLI commands.
     - **Batch Posting:** Enable the CLI to handle the segmentation of index entries into batches of 10 for Nostr posts.
     - **Toggle "Secret" Mode via CLI:** Provide CLI commands to enable or disable "secret" mode for clipboard-only password retrieval.
     - **Automated Nostr Posting:** Ensure that any edit to the index automatically triggers a post to Nostr.
     - **Initial Setup Enhancements:** Implement CLI commands to handle the first-time user experience, including seed generation/import and initial Nostr profile creation.

2. **Use a Robust CLI Framework**
   - **Description:** Transition to a robust CLI framework like [`click`](https://click.palletsprojects.com/) or [`Typer`](https://typer.tiangolo.com/) for better maintainability and scalability.
   - **Benefits:**
     - Simplifies the creation of complex CLI commands and subcommands.
     - Enhances readability and maintainability of CLI code.
     - Provides built-in help and documentation features.

3. **Implement Secure Clipboard Operations**
   - **Description:** Ensure that clipboard operations are secure and temporary.
   - **Features:**
     - **Clear Clipboard After Duration:** Automatically clear the clipboard after a set duration (e.g., 30 seconds) to prevent unauthorized access.
     - **User Notifications:** Inform users when the clipboard is cleared.
     - **Graceful Failure Handling:** Manage cases where clipboard operations fail without disrupting the user experience.

---

### Phase 4: Data Management Enhancements and Integrations

**Goal:** Further improve data management capabilities and integrate with other platforms for expanded functionality.

1. **Add Nostr Public/Private Key Pair Generation**
   - **Description:** Allow users to generate new Nostr public/private key pairs within the application.
   - **Features:**
     - **Secure Key Pair Generation:** Ensure key pairs are generated securely and tied to specific index entries.
     - **Seamless Integration:** Integrate key pair management with existing Nostr functionalities.
     - **Security Advisories:** Inform users about best practices for managing multiple Nostr identities and the risks of using the same seed across different identities.

2. **Additional Integrations**
   - **Description:** Expand integrations with other platforms and services as needed.
   - **Examples:**
     - **Cryptocurrency Wallets:** Integrate with wallets like Bitcoin/Cashu or Atomic Wallet for seamless seed management.
     - **Productivity Tools:** Integrate with tools like AnyType for enhanced password and data management.

---

### Phase 5: Documentation, Testing, and Finalization

**Goal:** Ensure comprehensive documentation, robust testing, and finalize the application for release.

1. **Provide Comprehensive Documentation**
   - **User Guide:** Create detailed documentation covering installation, setup, usage, and troubleshooting via CLI help commands and external documentation files.
   - **CLI Help:** Ensure that each CLI command includes descriptive help messages accessible via commands like `--help`.
   - **Developer Documentation:** Document the codebase to assist future development and maintenance efforts, including contribution guidelines and code structure explanations.

2. **Enhance Logging and Monitoring**
   - **Granular Logging:** Implement detailed logs for successful operations and warnings/errors for issues, including timestamps, action types, and relevant metadata.
   - **Log Rotation:** Use Python's `logging.handlers` module or external libraries to manage log rotation and prevent log files from growing indefinitely.

3. **Ensure Comprehensive Testing**
   - **Unit Tests:** Write tests for individual functions and modules to ensure they work as intended.
   - **Integration Tests:** Test the interaction between different modules, especially for features like automatic Nostr posting and seed recovery.
   - **User Acceptance Testing (UAT):** Engage a group of users to test the CLI tool and provide feedback on usability and functionality.

4. **Prioritize Security Best Practices**
   - **Sensitive Data Handling:** Ensure that all sensitive data (e.g., seed phrases, encryption keys) are handled securely in memory and during storage.
   - **Encryption Standards:** Use industry-standard encryption algorithms and key derivation functions.
   - **Regular Audits:** Periodically review and audit the codebase for potential security vulnerabilities.

---

### Future Phases (Beyond Initial Roadmap)

1. **Continuous Improvement and Feature Expansion**
   - **Description:** Respond to user feedback and implement additional features based on emerging needs.
   - **Examples:** Integrate with new platforms, add support for biometric authentication, or expand to mobile platforms.

2. **Scalability and Performance Optimization**
   - **Description:** Optimize application performance for large datasets and enhance scalability for a growing user base.
   - **Features:**
     - **Performance Tuning:** Improve response times and resource usage.
     - **Scalability Enhancements:** Ensure the application can handle an increasing number of users and data entries without degradation in performance.