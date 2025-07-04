# Repository Guidelines

This project is written in **Python**. Follow these instructions when working with the code base.

## Running Tests

1. Set up a virtual environment and install dependencies:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r src/requirements.txt
   ```

2. Run the test suite using **pytest**:

   ```bash
   pytest
   ```

   Currently the test folder is located in `src/tests/`. New tests should be placed there so `pytest` can discover them automatically.

## Style Guidelines

- Adhere to **PEP 8** conventions (4‑space indentation, descriptive names, docstrings).
- Use [**black**](https://black.readthedocs.io/) to format Python files before committing:

  ```bash
  black .
  ```

- Optionally run **flake8** or another linter to catch style issues.

## Security Practices

- Never commit seed phrases, passwords, private keys, or other sensitive data.
- Use environment variables or local configuration files (ignored by Git) for secrets.
- Review code for potential information leaks (e.g., verbose logging) before submitting.

Following these practices helps keep the code base consistent and secure.

## Integrating New Entry Types

SeedPass supports multiple `kind` values in its JSON entry files. When adding a
new `kind` (for example, SSH keys or BIP‑39 seeds) use the checklist below:

1. **Menu Updates** – Extend the CLI menus in `main.py` so "Add Entry" offers
   choices for the new types and retrieval operations handle them properly. The
   current main menu looks like this:

   ```
   Select an option:
   1. Add Entry
   2. Retrieve Entry
   3. Search Entries
   4. Modify an Existing Entry
   5. 2FA Codes
   6. Settings
   7. Exit
   ```

2. **JSON Schema** – Each entry file must include a `kind` field describing the
   entry type. Add new values (`ssh`, `seed`, etc.) as needed and implement
   handlers so older kinds continue to work.

3. **Best Practices** – When introducing a new `kind`, follow the modular
   architecture guidelines from `docs/json_entries.md`:
   - Use clear, descriptive names.
   - Keep handler code for each `kind` separate.
   - Validate required fields and gracefully handle missing data.
   - Add regression tests to ensure backward compatibility.

This procedure keeps the UI consistent and ensures new data types integrate
smoothly with existing functionality.
