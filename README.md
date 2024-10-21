# SeedPass

![SeedPass Logo](https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/refs/heads/main/SeedPass%20Logo/png/SeedPass-Logo-03.png)



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
---
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
