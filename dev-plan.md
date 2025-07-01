### SeedPass Road-to-1.0 — Detailed Development Plan

*(Assumes today = 1 July 2025, team of 1-3 devs, weekly release cadence)*

| Phase                                | Goal                                                                      | Key Deliverables                                                                                                                                                                                                                                                                                                                                                                      | Target Window             |
| ------------------------------------ | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| **0 – Vision Lock-in**               | Be explicit about where you’re going so every later trade-off is easy.    | • 2-page “north-star” doc covering product scope, security promises, platforms, and **“CLI is source of truth”** principle. <br>• Public roadmap Kanban board.                                                                                                                                                                                                                        | **Week 0**                |
| **1 – Package-ready Codebase**       | Turn loose `src/` tree into a pip-installable library + console script.   | • `pyproject.toml` with PEP-621 metadata, `setuptools-scm` dynamic version. <br>• Restructure to `seedpass/` (or keep `src/` but list `packages = ["seedpass"]`). <br>• Entry-point: `seedpass = "seedpass.main:cli"`. <br>• Dev extras: `pytest-cov`, `ruff`, `mypy`, `pre-commit`. <br>• Split pure business logic from I/O (e.g., encryption, BIP-85, vault ops) so GUI can reuse. | **Weeks 0-2**             |
| **2 – Local Quality Net**            | Fail fast before CI runs.                                                 | • `make test` / `tox` quick matrix (3.10–3.12). <br>• 90 % line coverage gate. <br>• Static checks in pre-commit (black, ruff, mypy).                                                                                                                                                                                                                                                 | **Weeks 1-3**             |
| **3 – CI / Release Automation**      | One Git tag → everything ships.                                           | • GitHub Actions matrix (Ubuntu, macOS, Windows). <br>• Steps: install → unit tests →  build wheels (`python -m build`) → PyInstaller one-file artefacts → upload to Release. <br>• Secrets for PyPI / code-signing left empty until 1.0.                                                                                                                                             | **Weeks 2-4**             |
| **4 – OS-Native Packages**           | Users can “apt install / brew install / flatpak install / download .exe”. | **Linux** • `stdeb` → `.deb`, `reprepro` mini-APT repo.  <br>**Flatpak** • YAML manifest + GitHub Action to build & push to Flathub beta repo. <br>**Windows** • PyInstaller `--onefile` → NSIS installer. <br>**macOS** • Briefcase → notarised `.pkg` or `.dmg` (signing cert later).                                                                                               | **Weeks 4-8**             |
| **5 – Experimental GUI Track**       | Ship a GUI **without** slowing CLI velocity.                              | • Decide stack (recommend **Textual** first; upgrade later to Toga or PySide). <br>• Create `seedpass.gui` package calling existing APIs; flag with `--gui`. <br>• Feature flag via env var `SEEDPASS_GUI=1` or CLI switch. <br>• Separate workflow that builds GUI artefacts, but does **not** block CLI releases.                                                                   | **Weeks 6-12** (parallel) |
| **6 – Plugin / Extensibility Layer** | Keep core slim while allowing future features.                            | • Define `entry_points={"seedpass.plugins": …}`. <br>• Document simple example plugin (e.g., custom password rule). <br>• Load plugins lazily to avoid startup cost.                                                                                                                                                                                                                  | **Weeks 10-14**           |
| **7 – Security & Hardening**         | Turn security assumptions into guarantees before 1.0                      | • SAST scan (Bandit, Semgrep). <br>• Threat-model doc: key-storage, BIP-85 determinism, Nostr backup flow. <br>• Repro-build check for PyInstaller artefacts. <br>• Signed releases (Sigstore, minisign).                                                                                                                                                                             | **Weeks 12-16**           |
| **8 – 1.0 Launch Prep**              | Final polish + docs.                                                      | • User manual (MkDocs, `docs.seedpass.org`). <br>• In-app `--check-update` hitting GitHub API. <br>• Blog post & template release notes.                                                                                                                                                                                                                                              | **Weeks 16-18**           |

---

### Ongoing Practices to Keep Development Nimble

| Practice                | What to do                                                                                  |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| **Dynamic versioning**  | Keep `version` dynamic via `setuptools-scm` / `hatch-vcs`; tag and push – nothing else.     |
| **Trunk-based dev**     | Short-lived branches, PRs < 300 LOC; merge when tests pass.                                 |
| **Feature flags**       | `seedpass.config.is_enabled("X")` so unfinished work can ship dark.                         |
| **Fast feedback loops** | Local editable install; `invoke run --watch` (or `uvicorn --reload` for GUI) to hot-reload. |
| **Weekly beta release** | Even during heavy GUI work, cut “beta” tags weekly; real users shake out regressions early. |

---

### First 2-Week Sprint (Concrete To-Dos)

1. **Bootstrap packaging**

   ```bash
   pip install --upgrade pip build setuptools_scm
   poetry init   # if you prefer Poetry, else stick with setuptools
   ```

   Add `pyproject.toml`, move code to `seedpass/`.

2. **Console entry-point**
   In `seedpass/__main__.py` add `from .main import cli; cli()`.

3. **Editable dev install**
   `pip install -e .[dev]` → run `seedpass --help`.

4. **Set up pre-commit**
   `pre-commit install` with ruff + black + mypy hooks.

5. **GitHub Action skeleton** (`.github/workflows/ci.yml`)

   ```yaml
   jobs:
     test:
       strategy:
         matrix: os: [ubuntu-latest, windows-latest, macos-latest]
         python-version: ['3.12', '3.11']
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-python@v5
           with: {python-version: ${{ matrix.python-version }}}
         - run: pip install --upgrade pip
         - run: pip install -e .[dev]
         - run: pytest -n auto
   ```

6. **Smoke PyInstaller locally**
   `pyinstaller --onefile seedpass/main.py` – fix missing data/hooks; check binary runs.

When that’s green, cut tag `v0.1.0-beta` and let CI build artefacts automatically.

---

### Choosing the GUI Path (decision by Week 6)

| If you value…                      | Choose                       |
| ---------------------------------- | ---------------------------- |
| Terminal-first UX, live coding     | **Textual (Rich-TUI)**       |
| Native look, single code base      | **Toga / Briefcase**         |
| Advanced widgets, designer tooling | **PySide-6 / Qt for Python** |

Prototype one screen (vault list + “Add” dialog) and benchmark bundle size + startup time with PyInstaller before committing.

---

## Recap

* **Packaging & CI first** – lets every future feature ride an established release train.
* **GUI lives in its own layer** – CLI stays stable; dev cycles remain quick.
* **Security & signing** land after functionality is stable, before v1.0 marketing push.

Follow the phase table, keep weekly betas flowing, and you’ll reach a polished, installer-ready, GUI-enhanced 1.0 in roughly four months without sacrificing day-to-day agility.
