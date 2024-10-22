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

## **To-Do List**

### **1. Cross-Platform Compatibility**
- **Add Windows-Supported File Locking**
  - **Description:** Implement a file locking mechanism compatible with Windows to ensure that the application can safely handle concurrent file access across different operating systems.
  - **Suggested Approach:** Consider using a cross-platform library like [`portalocker`](https://pypi.org/project/portalocker/) to replace the current `fcntl`-based locking system.

### **2. Security Enhancements**
- **Add Parent Seed Recovery**
  - **Description:** Develop a secure method for users to recover their parent seed in case it is lost or forgotten.
  - **Suggested Features:**
    - **Recovery Phrase:** Allow users to generate and store a recovery phrase or backup file.
    - **Multi-Factor Authentication (MFA):** Integrate MFA to enhance the security of the recovery process.
    - **Encrypted Storage:** Ensure that recovery data is encrypted and stored securely.

- **Add "Secret" Mode (Clipboard-Only Password Retrieval)**
  - **Description:** Introduce a "secret" mode where passwords are copied directly to the clipboard rather than displayed on the screen upon retrieval. This mode should be a setting the user can toggle on or off.
  - **Suggested Features:**
    - **Toggle Setting:** Allow users to enable or disable "secret" mode.
    - **Clipboard Integration:** Ensure passwords are copied securely to the clipboard when "secret" mode is active.
    - **User Feedback:** Notify users that the password has been copied to the clipboard.

### **3. User Interface & Experience Improvements**
- **Show All Passwords**
  - **Description:** Introduce a "Show All" option that displays all stored passwords along with their associated index entries.
  - **Benefits:** Provides users with a comprehensive view of their password entries for easier management.

- **Export to CSV**
  - **Description:** Implement functionality to export index numbers and generated passwords within a specified index range to a CSV file.
  - **Purpose:** Facilitates bulk password recovery in scenarios where index data is lost.
  - **Security Consideration:** Ensure that exported CSV files are handled securely, possibly by encrypting them or warning users about the risks.

### **4. Data Management Enhancements**
- **Add "Notes" Field**
  - **Description:** Introduce a "Notes" field for each password entry to allow users to add supplementary information or comments.
  - **Use Cases:** Users can store additional details like password creation date, usage guidelines, or any other relevant notes.

- **Add "Tags" Field**
  - **Description:** Add a "Tags" field to each entry to enable categorization and easier organization of passwords.
  - **Benefits:** Allows users to group related passwords, making retrieval and management more efficient.

- **Rename "Website" Field to "Title"**
  - **Description:** Change the existing "Website" field to "Title" to provide a more flexible and generalized naming convention.
  - **Advantages:** Accommodates entries that may not be directly tied to a website, such as application logins or system credentials.

### **5. Search and Retrieval Features**
- **Implement Search by Tag or Title**
  - **Description:** Develop search functionality that allows users to locate password entries based on associated tags or titles.
  - **Features to Consider:**
    - **Keyword Search:** Enable partial and case-insensitive searches.
    - **Filter Options:** Allow users to filter search results based on multiple tags or specific criteria.
    - **Advanced Search:** Incorporate Boolean operators (AND, OR, NOT) for more precise searches.

### **6. Nostr Integration Enhancements**
- **Add Option for Users to Specify Custom Set of Relays for Publishing Backup Index**
  - **Description:** Provide users with the ability to select or configure specific Nostr relays where their encrypted backup index will be published.
  - **Benefits:** Enhances flexibility and control over where backups are distributed, allowing users to choose trusted relays or optimize for performance and reliability.
  - **Suggested Approach:**
    - **User Interface:** Add settings in the application where users can input or select preferred relay URLs.
    - **Validation:** Implement validation to ensure that the specified relays are active and support the necessary protocols.
    - **Fallback Mechanism:** Allow users to add multiple relays to ensure redundancy in case some relays become unavailable.

- **Modify JSON Index Nostr Post to Publish 10 Index Items Max per Post**
  - **Description:** Adjust the mechanism for posting the JSON index to Nostr by limiting each post to a maximum of 10 index items (e.g., index 0-9, 10-19). This segmentation ensures that each Nostr post remains small and manageable.
  - **Benefits:**
    - **Efficiency:** Smaller posts reduce the risk of exceeding size limits and improve the speed of data transmission.
    - **Scalability:** Facilitates handling larger databases by allowing the index to be pieced together from multiple posts rather than relying on a single large file.
    - **Reliability:** Enhances the robustness of data retrieval by distributing the index across multiple posts, reducing the impact of potential data corruption in any single post.

<<<<<<< Updated upstream
- **Automatically Post Index to Nostr After Every Edit**
  - **Description:** Implement an automated process where any modification to the password index triggers an immediate update to the Nostr relays.
  - **Benefits:**
    - **Real-Time Backups:** Ensures that backups are always up-to-date with the latest changes.
    - **Data Consistency:** Minimizes the risk of discrepancies between local data and Nostr backups.
  - **Suggested Approach:**
    - **Hook Integration:** Integrate hooks in the `EntryManager` or relevant modules to detect changes and trigger posting.
    - **Error Handling:** Implement robust error handling to manage failed posts without disrupting the user's workflow.
    - **User Notifications:** Inform users of the backup status after each edit (e.g., success, failure).
=======
- **Post Index to Nostr Automatically After Every Edit**
  - **Description:** Implement a feature where every time the password index is edited (add, modify, delete), the updated index is automatically posted to Nostr.
  - **Benefits:** Ensures that backups are always up-to-date without requiring manual intervention.
  - **Suggested Approach:**
    - **Event Hooking:** Integrate hooks in the EntryManager or relevant modules to trigger the post operation after any edit.
    - **Error Handling:** Implement robust error handling to manage scenarios where posting to Nostr fails, ensuring data integrity.
    - **User Notifications:** Inform users about the success or failure of automatic posts to maintain transparency.

- **Generate Nostr Profile on First Login and Retrieve Existing Index Data**
  - **Description:** When a user logs in for the first time using the parent seed, generate a Nostr profile and check if there are existing index data notes that can be retrieved and decrypted.
  - **Benefits:** Allows users to seamlessly recover their password index from existing Nostr posts, enhancing data portability and redundancy.
  - **Suggested Approach:**
    - **Profile Generation:** Automate the creation of a Nostr profile linked to the user's parent seed.
    - **Data Retrieval:** Implement logic to search for existing encrypted index data across specified relays.
    - **Decryption and Integration:** Decrypt retrieved data and integrate it into the local index, ensuring no duplication or data conflicts.
    - **User Feedback:** Provide clear messages about the status of profile creation and data retrieval processes.
>>>>>>> Stashed changes

### **7. Advanced CLI Mode**
- **Develop an Advanced CLI Mode with Enhanced Functionalities**
  - **Description:** Create a more sophisticated Command-Line Interface (CLI) mode that supports advanced operations beyond the basic functionalities.
  - **Included Features:**
    - **Custom Relays Configuration:** Allow users to specify a custom set of Nostr relays for publishing their backup index.
    - **Batch Posting:** Enable the CLI to handle the segmentation of index entries into batches of 10 for Nostr posts.
    - **Toggle "Secret" Mode:** Provide CLI commands to enable or disable "secret" mode for clipboard-only password retrieval.
<<<<<<< Updated upstream
    - **Automated Nostr Posting:** Ensure that any edit to the index automatically triggers a post to Nostr.
    - **Initial Setup Enhancements:** Implement features to handle the first-time user experience, including seed generation/import and initial Nostr profile creation.
=======
    - **Automatic Nostr Posting:** Automatically post updated indexes to Nostr after any edit operation.
    - **Nostr Profile Generation and Data Retrieval:** Handle the generation of Nostr profiles and retrieval of existing index data upon first login.
    - **Seed Initialization:** Allow users to choose between entering an existing seed or generating a new one during the first run.
>>>>>>> Stashed changes
  - **Suggested Approach:**
    - **Command Structure:** Design intuitive commands and flags to manage advanced settings.
    - **User Feedback:** Ensure that the CLI provides clear feedback and confirmations for advanced operations.
    - **Error Handling:** Implement robust error handling to manage issues specific to advanced functionalities.

### **8. User Onboarding and Initialization**
- **Seed Initialization on First Run**
  - **Description:** When the user runs the program for the first time, prompt them to either enter an existing seed or generate a new one. Use the chosen password to encrypt the seed, whether it's user-provided or program-generated.
  - **Benefits:** Provides flexibility and security during the initial setup, catering to both new users and those migrating from other password managers.
  - **Suggested Features:**
    - **Prompt Options:** Ask users if they want to input an existing seed or generate a new one.
    - **Seed Generation:** If generating a new seed, ensure it's compliant with BIP-39 standards.
    - **Encryption:** Securely encrypt the seed using the user's chosen password.
    - **Confirmation:** Confirm the successful initialization and encryption of the seed.
    - **Error Handling:** Manage scenarios where seed generation or encryption fails, providing clear feedback to the user.

### **9. Use a Robust CLI Framework**
- **Suggested Libraries:** [`argparse`](https://docs.python.org/3/library/argparse.html), [`click`](https://click.palletsprojects.com/), or [`Typer`](https://typer.tiangolo.com/).
- **Benefits:**
  - Simplifies the creation of complex CLI commands and subcommands.
  - Enhances readability and maintainability of CLI code.
  - Provides built-in help and documentation features.

### **10. Implement Secure Clipboard Operations**
- **Library Suggestion:** [`pyperclip`](https://pypi.org/project/pyperclip/) for cross-platform clipboard access.
- **Security Consideration:**
  - Clear the clipboard after a set duration (e.g., 30 seconds) to prevent unauthorized access.
  - Notify users when the clipboard is cleared.
  - Handle cases where clipboard operations fail gracefully.

### **11. Enhance Logging and Monitoring**
- **Granular Logging:**
  - Log detailed information for successful operations and warnings/errors for issues.
  - Include timestamps, action types, and relevant metadata.
- **Log Rotation:**
  - Implement log rotation to prevent log files from growing indefinitely.
  - Use Python's `logging.handlers` module or external libraries for managing log rotation.

### **12. Ensure Comprehensive Testing**
- **Unit Tests:**
  - Write tests for individual functions and modules to ensure they work as intended.
- **Integration Tests:**
  - Test the interaction between different modules, especially for features like automatic Nostr posting and seed recovery.
- **User Acceptance Testing (UAT):**
  - Engage a group of users to test the application and provide feedback on usability and functionality.

### **13. Prioritize Security Best Practices**
- **Sensitive Data Handling:**
  - Ensure that all sensitive data (e.g., seed phrases, encryption keys) are handled securely in memory and during storage.
- **Encryption Standards:**
  - Use industry-standard encryption algorithms and key derivation functions.
- **Regular Audits:**
  - Periodically review and audit the codebase for potential security vulnerabilities.

### **14. Provide Comprehensive Documentation**
- **User Guide:**
  - Create detailed documentation covering installation, setup, usage, and troubleshooting.
- **CLI Help:**
  - Ensure that each CLI command includes descriptive help messages.
- **Developer Documentation:**
  - Document the codebase to assist future development and maintenance efforts.

---

<<<<<<< Updated upstream
## **Advanced CLI Commands**

| **Action**                                | **Command**            | **Short Flag** | **Long Flag**                     | **Example Command**                                                                                                                                                                              |
|-------------------------------------------|------------------------|----------------|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Add a new password entry                  | `add`                  | `-A`           | `--add`                           | `passmgr add --title "GitHub" --url "https://github.com" --username "john_doe" --email "john@example.com" --notes "Primary GitHub account" --tags "work,development" --length 20`                        |
| Retrieve a password entry                 | `retrieve`             | `-R`           | `--retrieve`                      | `passmgr retrieve --index 3` or `passmgr retrieve --title "GitHub"`                                                                                                                             |
| Modify an existing entry                  | `modify`               | `-M`           | `--modify`                        | `passmgr modify --index 3 --title "GitHub Pro" --notes "Updated to pro account" --tags "work,development,pro" --length 22`                                                                          |
| Delete an entry                           | `delete`               | `-D`           | `--delete`                        | `passmgr delete --index 3`                                                                                                                                                                       |
| List all entries                          | `list`                 | `-L`           | `--list`                          | `passmgr list`                                                                                                                                                                                    |
| Search for a password entry               | `search`               | `-S`           | `--search`                        | `passmgr search --query "GitHub"`                                                                                                                                                                 |
| Export passwords to a file                | `export`               | `-E`           | `--export`                        | `passmgr export --file "backup_passwords.json"`                                                                                                                                                   |
| Import passwords from a file              | `import`               | `-I`           | `--import`                        | `passmgr import --file "backup_passwords.json"`                                                                                                                                                   |
| Display help information                  | `help`                 | `-H`           | `--help`                          | `passmgr help`                                                                                                                                                                                    |
| Display application version               | `version`              | `-V`           | `--version`                       | `passmgr version`                                                                                                                                                                                 |
| Change master password                    | `changepw`             | `-C`           | `--changepw`                      | `passmgr changepw --new "NewSecureP@ssw0rd!"`                                                                                                                                                      |
| Enable auto-lock                          | `autolock --enable`    | `-AL`          | `--auto-lock --enable`            | `passmgr autolock --enable --timeout 10`                                                                                                                                                          |
| Disable auto-lock                         | `autolock --disable`   | `-DL`          | `--auto-lock --disable`           | `passmgr autolock --disable`                                                                                                                                                                      |
| Generate a strong password                | `generate`             | `-G`           | `--generate`                      | `passmgr generate --length 20`                                                                                                                                                                    |
| Verify script checksum                    | `verify`               | `-V`           | `--verify`                        | `passmgr verify`                                                                                                                                                                                  |
| Post encrypted index to Nostr             | `post`                 | `-P`           | `--post`                          | `passmgr post`                                                                                                                                                                                    |
| Retrieve from Nostr                       | `get-nostr`            | `-GN`          | `--get-nostr`                     | `passmgr get-nostr`                                                                                                                                                                               |
| Display Nostr public key                  | `show-pubkey`          | `-K`           | `--show-pubkey`                   | `passmgr show-pubkey`                                                                                                                                                                             |
| **Set Custom Nostr Relays**               | `set-relays`           | `-SR`          | `--set-relays`                    | `passmgr set-relays --add "wss://relay1.example.com" --add "wss://relay2.example.com"`                                                                                                           |
| **Enable "Secret" Mode**                   | `set-secret`           | `-SS`          | `--set-secret`                    | `passmgr set-secret --enable` or `passmgr set-secret --disable`                                                                                                                                    |
| **Batch Post Index Items to Nostr**        | `batch-post`           | `-BP`          | `--batch-post`                    | `passmgr batch-post --start 0 --end 9` or `passmgr batch-post --range 10-19`                                                                                                                       |
| **Show All Passwords**                     | `show-all`             | `-SA`          | `--show-all`                      | `passmgr show-all`                                                                                                                                                                                |
| **Add Notes to an Entry**                  | `add-notes`            | `-AN`          | `--add-notes`                     | `passmgr add-notes --index 3 --notes "This is a secured account"`                                                                                                                                  |
| **Add Tags to an Entry**                   | `add-tags`             | `-AT`          | `--add-tags`                      | `passmgr add-tags --index 3 --tags "personal,finance"`                                                                                                                                              |
| **Search by Tag or Title**                 | `search-by`            | `-SB`          | `--search-by`                     | `passmgr search-by --tag "work"` or `passmgr search-by --title "GitHub"`                                                                                                                          |
| **Automatically Post Index to Nostr After Edit** | `auto-post`            | `-AP`          | `--auto-post`                     | `passmgr auto-post --enable` or `passmgr auto-post --disable`                                                                                                                                    |
| **Initial Setup Prompt for Seed Generation/Import** | `setup`                | `-ST`          | `--setup`                         | `passmgr setup`                                                                                                                                                                                   |

=======
| **Action**                                | **Command**            | **Short Flag** | **Long Flag**                     | **Example Command**                                                                                                                                                                             |
|-------------------------------------------|------------------------|----------------|-----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Add a new password entry                  | `add`                  | `-A`           | `--add`                           | `passmgr add --title "GitHub" --url "https://github.com" --username "john_doe" --email "john@example.com" --notes "Primary GitHub account" --tags "work,development" --length 20`                       |
| Retrieve a password entry                 | `retrieve`             | `-R`           | `--retrieve`                      | `passmgr retrieve --index 3` or `passmgr retrieve --title "GitHub"`                                                                                                                             |
| Modify an existing entry                  | `modify`               | `-M`           | `--modify`                        | `passmgr modify --index 3 --title "GitHub Pro" --notes "Updated to pro account" --tags "work,development,pro" --length 22`                                                                          |
| Delete an entry                           | `delete`               | `-D`           | `--delete`                        | `passmgr delete --index 3`                                                                                                                                                                      |
| List all entries                          | `list`                 | `-L`           | `--list`                          | `passmgr list`                                                                                                                                                                                   |
| Search for a password entry               | `search`               | `-S`           | `--search`                        | `passmgr search --query "GitHub"`                                                                                                                                                                |
| Export passwords to a file                | `export`               | `-E`           | `--export`                        | `passmgr export --file "backup_passwords.json"`                                                                                                                                                  |
| Import passwords from a file              | `import`               | `-I`           | `--import`                        | `passmgr import --file "backup_passwords.json"`                                                                                                                                                  |
| Display help information                  | `help`                 | `-H`           | `--help`                          | `passmgr help`                                                                                                                                                                                   |
| Display application version               | `version`              | `-V`           | `--version`                       | `passmgr version`                                                                                                                                                                                |
| Change master password                    | `changepw`             | `-C`           | `--changepw`                      | `passmgr changepw --new "NewSecureP@ssw0rd!"`                                                                                                                                                     |
| Enable auto-lock                          | `autolock --enable`    | `-AL`          | `--auto-lock --enable`            | `passmgr autolock --enable --timeout 10`                                                                                                                                                         |
| Disable auto-lock                         | `autolock --disable`   | `-DL`          | `--auto-lock --disable`           | `passmgr autolock --disable`                                                                                                                                                                     |
| Generate a strong password                | `generate`             | `-G`           | `--generate`                      | `passmgr generate --length 20`                                                                                                                                                                   |
| Verify script checksum                    | `verify`               | `-V`           | `--verify`                        | `passmgr verify`                                                                                                                                                                                 |
| Post encrypted index to Nostr             | `post`                 | `-P`           | `--post`                          | `passmgr post`                                                                                                                                                                                   |
| Retrieve from Nostr                       | `get-nostr`            | `-GN`          | `--get-nostr`                     | `passmgr get-nostr`                                                                                                                                                                              |
| Display Nostr public key                  | `show-pubkey`          | `-K`           | `--show-pubkey`                   | `passmgr show-pubkey`                                                                                                                                                                            |
| **Set Custom Nostr Relays**               | `set-relays`           | `-SR`          | `--set-relays`                    | `passmgr set-relays --add "wss://relay1.example.com" --add "wss://relay2.example.com"`                                                                                                          |
| **Enable "Secret" Mode**                   | `set-secret`           | `-SS`          | `--set-secret`                    | `passmgr set-secret --enable` or `passmgr set-secret --disable`                                                                                                                                |
| **Batch Post Index Items to Nostr**        | `batch-post`           | `-BP`          | `--batch-post`                    | `passmgr batch-post --start 0 --end 9` or `passmgr batch-post --range 10-19`                                                                                                                    |
| **Show All Passwords**                     | `show-all`             | `-SA`          | `--show-all`                      | `passmgr show-all`                                                                                                                                                                               |
| **Add Notes to an Entry**                  | `add-notes`            | `-AN`          | `--add-notes`                     | `passmgr add-notes --index 3 --notes "This is a secured account"`                                                                                                                               |
| **Add Tags to an Entry**                   | `add-tags`             | `-AT`          | `--add-tags`                      | `passmgr add-tags --index 3 --tags "personal,finance"`                                                                                                                                             |
| **Search by Tag or Title**                 | `search-by`            | `-SB`          | `--search-by`                     | `passmgr search-by --tag "work"` or `passmgr search-by --title "GitHub"`                                                                                                                         |
| **Initialize Seed (First Run)**            | `init-seed`            | `-IS`          | `--init-seed`                     | `passmgr init-seed --generate` or `passmgr init-seed --import "your-existing-seed-phrase"`                                                                                                       |
| **Generate Nostr Profile and Retrieve Data** | `setup-nostr`          | `-SN`          | `--setup-nostr`                   | `passmgr setup-nostr`                                                                                                                                                                             |
    
>>>>>>> Stashed changes
---

### **Notes on New CLI Commands**

1. **Automatically Post Index to Nostr After Edit (`auto-post`):**
   - **Purpose:** Enables or disables the automatic posting of the index to Nostr whenever an edit occurs.
   - **Usage Examples:**
     - Enable auto-post: `passmgr auto-post --enable`
     - Disable auto-post: `passmgr auto-post --disable`

2. **Initial Setup Prompt for Seed Generation/Import (`setup`):**
   - **Purpose:** Guides users through the initial setup process, allowing them to choose between generating a new seed or importing an existing one.
   - **Features to Implement:**
     - **Seed Choice Prompt:** Ask users whether they want to generate a new seed or import an existing one.
     - **Encryption of Seed:** Use the user-selected password to encrypt the seed, whether generated or imported.
     - **Nostr Profile Creation:** Upon first login, automatically generate a Nostr profile and check for existing index data notes that can be pulled and decrypted.
   - **Usage Example:** `passmgr setup`

<<<<<<< Updated upstream
3. **Advanced CLI Enhancements:**
   - **Toggle "Secret" Mode via CLI:**
     - **Description:** Allow users to enable or disable "secret" mode directly through the CLI.
     - **Usage Examples:**
       - Enable secret mode: `passmgr set-secret --enable`
       - Disable secret mode: `passmgr set-secret --disable`
   
   - **Initial Seed Setup Flow:**
     - **Description:** When running `passmgr setup`, prompt users to either enter an existing seed or generate a new one, followed by password creation for encryption.
     - **Usage Example:** `passmgr setup`
   
   - **Automatic Nostr Profile Generation and Index Retrieval:**
     - **Description:** During the initial setup or first login, generate a Nostr profile and attempt to retrieve and decrypt any existing index data from Nostr.
     - **Usage Example:** `passmgr setup` (handles internally)
=======
3. **Batch Post Index Items to Nostr (`batch-post`):**
   - **Purpose:** Publishes segments of the index (e.g., 10 items per post) to Nostr to manage large databases efficiently.
   - **Usage Examples:**
     - Post indexes 0-9: `passmgr batch-post --start 0 --end 9`
     - Post indexes 10-19: `passmgr batch-post --range 10-19`

4. **Show All Passwords (`show-all`):**
   - **Purpose:** Displays all stored passwords along with their index entries.
   - **Usage Example:** `passmgr show-all`

5. **Add Notes to an Entry (`add-notes`):**
   - **Purpose:** Adds or updates the "Notes" field for a specific password entry.
   - **Usage Example:** `passmgr add-notes --index 3 --notes "This is a secured account"`

6. **Add Tags to an Entry (`add-tags`):**
   - **Purpose:** Adds or updates the "Tags" field for a specific password entry.
   - **Usage Example:** `passmgr add-tags --index 3 --tags "personal,finance"`

7. **Search by Tag or Title (`search-by`):**
   - **Purpose:** Enables searching for password entries based on tags or titles.
   - **Usage Examples:**
     - Search by tag: `passmgr search-by --tag "work"`
     - Search by title: `passmgr search-by --title "GitHub"`

8. **Initialize Seed (First Run) (`init-seed`):**
   - **Purpose:** Handles the initial setup of the seed during the first run of the application, allowing users to either generate a new seed or import an existing one.
   - **Usage Examples:**
     - Generate a new seed: `passmgr init-seed --generate`
     - Import an existing seed: `passmgr init-seed --import "your-existing-seed-phrase"`

9. **Generate Nostr Profile and Retrieve Data (`setup-nostr`):**
   - **Purpose:** Automates the generation of a Nostr profile upon the first login and retrieves any existing encrypted index data from specified relays.
   - **Usage Example:** `passmgr setup-nostr`

---


>>>>>>> Stashed changes
