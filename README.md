# SeedPass

![SeedPass Logo](https://github.com/PR0M3TH3AN/SeedPass/raw/main/assets/logo.png)

SeedPass is a **BIP-85 Deterministic Password Generator** that securely generates, stores, and manages your passwords. Leveraging deterministic key derivation and integration with the Nostr network, SeedPass ensures your passwords are both robust and accessible across devices.

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
- **Encrypted Storage:** All passwords and sensitive data are encrypted locally.
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
cd SeedPass
```

### 2. Create a Virtual Environment

It's recommended to use a virtual environment to manage your project's dependencies. Create a virtual environment named `venv`:

```bash
python -m venv venv
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
pip install -r requirements.txt
```

**Note:** If your project has any additional build dependencies or uses tools like `setup.py` or `pyproject.toml`, ensure you follow those specific instructions as well.

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

   - **Enter Your Password:** This password is crucial as it is used to decrypt your parent seed and, subsequently, your password index from Nostr.
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

**Important:** The password you use to decrypt your parent seed is also required to decrypt the password index retrieved from Nostr. **It is imperative to remember this password**, as losing it means you won't be able to access your stored passwords. Consider using a secure method to store and remember your 12 word seed AND your password.

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
