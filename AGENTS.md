# Repository Guidelines

## Overstory Ecosystem
This project is part of the **Overstory** multi-agent development ecosystem. When asked to "update Overstory" or work on the ecosystem, these are the relevant repositories:

- **[Overstory](https://github.com/jayminwest/overstory)** — The coordinator. Orchestrates multi-agent workflows across worktrees.
- **[Mulch](https://github.com/jayminwest/mulch)** — Structured expertise/memory system for agents.
- **[Canopy](https://github.com/jayminwest/canopy)** — Prompt management system for agents.
- **[Seeds](https://github.com/jayminwest/seeds)** — Git-native issue tracker for agents.
- **[os-eco](https://github.com/jayminwest/os-eco)** — The entire Overstory ecosystem (meta-repo/docs).

This project is written in **Python**. Follow these instructions when working with the code base.

## Installation Quickstart for AI Agents

### Prerequisites

Ensure the system has the required build tools and Python headers. Examples:

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y \
    build-essential \
    libffi-dev \
    pkg-config \
    python3.11-dev \
    curl \
    git

# CentOS/RHEL
sudo yum install -y gcc gcc-c++ libffi-devel pkgconfig python3-devel curl git

# macOS
brew install python@3.11 libffi pkg-config git
```

### Installation

Run the installer script to fetch the latest release:

```bash
# Stable release
bash -c "$(curl -sSL https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/main/scripts/install.sh)"

# Beta branch
bash -c "$(curl -sSL https://raw.githubusercontent.com/PR0M3TH3AN/SeedPass/main/scripts/install.sh)" _ -b beta
```

### Environment Layout

- Virtual environment: `~/.seedpass/app/venv/`
- Entry point: `~/.seedpass/app/src/main.py`

### Verification

```bash
cd ~/.seedpass/app && source venv/bin/activate
cd src && python main.py --version  # Expected: SeedPass v[version]
```

### Running SeedPass

```bash
cd ~/.seedpass/app && source venv/bin/activate
cd src && python main.py
```

## Planning & Strategy

Before starting work, AI agents must consult the following documents to align with the current project trajectory:

1.  **[Dev Control Center](docs/dev_control_center.md)**: The single source of truth for current priorities and "what to do next."
2.  **[TUI v2 Execution Plan](docs/tui_v2_integration_execution_plan_2026-03-02.md)**: The active roadmap for the TUI v2 mockup parity and hardening phase.

<!-- mulch:start -->
## Project Expertise (Mulch)
<!-- mulch-onboard-v:1 -->

This project uses [Mulch](https://github.com/jayminwest/mulch) for structured expertise management.

**At the start of every session**, run:
```bash
mulch prime
```

This injects project-specific conventions, patterns, decisions, and other learnings into your context.
Use `mulch prime --files src/foo.ts` to load only records relevant to specific files.

**Before completing your task**, review your work for insights worth preserving — conventions discovered,
patterns applied, failures encountered, or decisions made — and record them:
```bash
mulch record <domain> --type <convention|pattern|failure|decision|reference|guide> --description "..."
```

Link evidence when available: `--evidence-commit <sha>`, `--evidence-bead <id>`

Run `mulch status` to check domain health and entry counts.
Run `mulch --help` for full usage.
Mulch write commands use file locking and atomic writes — multiple agents can safely record to the same domain concurrently.

### Before You Finish

1. Discover what to record:
   ```bash
   mulch learn
   ```
2. Store insights from this work session:
   ```bash
   mulch record <domain> --type <convention|pattern|failure|decision|reference|guide> --description "..."
   ```
3. Validate and commit:
   ```bash
   mulch sync
   ```
<!-- mulch:end -->

<!-- seeds:start -->
## Issue Tracking (Seeds)
<!-- seeds-onboard-v:1 -->

This project uses [Seeds](https://github.com/jayminwest/seeds) for git-native issue tracking.

**At the start of every session**, run:
```
sd prime
```

This injects session context: rules, command reference, and workflows.

**Quick reference:**
- `sd ready` — Find unblocked work
- `sd create --title "..." --type task --priority 2` — Create issue
- `sd update <id> --status in_progress` — Claim work
- `sd close <id>` — Complete work
- `sd sync` — Sync with git (run before pushing)

### Before You Finish
1. Close completed issues: `sd close <id>`
2. File issues for remaining work: `sd create --title "..."`
3. Sync and push: `sd sync && git push`
<!-- seeds:end -->

<!-- canopy:start -->
## Prompt Management (Canopy)
<!-- canopy-onboard-v:1 -->

This project uses [Canopy](https://github.com/jayminwest/canopy) for git-native prompt management.

**At the start of every session**, run:
```
cn prime
```

This injects prompt workflow context: commands, conventions, and common workflows.

**Quick reference:**
- `cn list` — List all prompts
- `cn render <name>` — View rendered prompt (resolves inheritance)
- `cn emit --all` — Render prompts to files
- `cn update <name>` — Update a prompt (creates new version)
- `cn sync` — Stage and commit .canopy/ changes

**Do not manually edit emitted files.** Use `cn update` to modify prompts, then `cn emit` to regenerate.
<!-- canopy:end -->

## Running Tests

SeedPass maintains a comprehensive test infrastructure. Agents should use the central inventory as a guide:

1.  **[Test Infrastructure Inventory](docs/TEST_INVENTORY.md)**: A complete index of all unit, integration, UI, and determinism tests.

### Quick Start: Running Tests

1. Set up a virtual environment and install dependencies:
...
   ```bash
   pytest
   ```

   For a full CI-equivalent run (highly recommended before any PR), use:
   ```bash
   bash scripts/run_ci_tests.sh
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

## Deterministic Artifact Generation

- All generated artifacts (passwords, keys, TOTP secrets, etc.) must be fully deterministic across runs and platforms.
- Randomness is only permitted for security primitives (e.g., encryption nonces, in-memory keys) and must never influence derived artifacts.

## Legacy Index Migration

- Always provide a migration path for index archives and import/export routines.
- Support older SeedPass versions whose indexes lacked salts or password-based encryption by detecting legacy formats and upgrading them to the current schema.
- Ensure migrations unlock older account indexes and allow Nostr synchronization.
- Add regression tests covering these migrations whenever the index format or encryption changes.


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
   architecture guidelines from `docs/entry_types.md`:
   - Use clear, descriptive names.
   - Keep handler code for each `kind` separate.
   - Validate required fields and gracefully handle missing data.
   - Add regression tests to ensure backward compatibility.

This procedure keeps the UI consistent and ensures new data types integrate
smoothly with existing functionality.


## Repo memory

Curated agent memory lives in `.agents/` (index: `.agents/MEMORY.md`). Read it
before substantive work. Propose additions as files in `.agents/proposals/`;
trusted memory under `.agents/memory/` changes only through reviewed commits.
Code, tests, and configuration always outrank memory.
