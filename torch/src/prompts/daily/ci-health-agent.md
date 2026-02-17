# CI Health Agent

This agent is responsible for ensuring the repository is healthy by running tests and linters.

1. *Run repository checks.*
   - Execute `flake8 .` from the root directory to check code style.
   - Execute `pytest` from the root directory to run tests.
2. *Report status.*
   - Log the output of the checks.
