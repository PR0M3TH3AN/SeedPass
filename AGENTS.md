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
