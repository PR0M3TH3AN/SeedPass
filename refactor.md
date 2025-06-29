# SeedPass v2 Roadmap — CLI → Desktop GUI

> **Guiding principles**
>
> 1. **Core-first** – a headless, testable Python package (`seedpass.core`) that is 100 % GUI-agnostic.
> 2. **Thin adapters** – CLI, GUI, and future mobile layers merely call the core API.
> 3. **Stateless UI** – all persistence lives in core services; UI never touches vault files directly.
> 4. **Parity at every step** – CLI must keep working while GUI evolves.

---

## Phase 0 • Tooling Baseline

| #   | Task                                                                                           | Rationale                         |
| --- | ---------------------------------------------------------------------------------------------- | --------------------------------- |
| 0.1 | ✅ **Adopt `poetry`** (or `hatch`) for builds & dependency pins.                                | Single-source version + lockfile. |
| 0.2 | ✅ **GitHub Actions**: lint (ruff), type-check (mypy), tests (pytest -q), coverage gate ≥ 85 %. | Prevent regressions.              |
| 0.3 | ✅ Pre-commit hooks: ruff –fix, black, isort.                                                   | Uniform style.                    |

---

## Phase 1 • Finalize Core Refactor (CLI still primary)

> *Most of this is already drafted – here’s what must ship before GUI work starts.*

| #   | Component                                                                     | Must-have work                                                             |
| --- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| 1.1 | **`kinds.py` registry + per-kind handler modules**                            | import-safe; handler signature `(data,fingerprint,**svc)`                  |
| 1.2 | **`StateManager`**                                                            | JSON file w/ fcntl lock<br>keys: `last_bip85_idx`, `last_sync_ts`          |
| 1.3 | **Checksum inside entry metadata**                                            | `sha256(json.dumps(data,sort_keys=True))`                                  |
| 1.4 | **Replaceable Nostr events** (kind 31111, `d` tag = `"{kindtag}{entry_num}"`) | publish/update/delete tombstone                                            |
| 1.5 | **Per-entry `EntryManager` / `BackupManager`**                                | Save / load / backup / restore individual encrypted files                  |
| 1.6 | **CLI rewritten with Typer**                                                  | Typer commands map 1-to-1 with core service methods; preserves colours.    |
| 1.7 | **Legacy index migration command**                                            | `seedpass migrate-legacy` – idempotent, uses `add_entry()` under the hood. |
| 1.8 | **bcrypt + NFKD master password hash**                                        | Stored per fingerprint.                                                    |

> **Exit-criteria:** end-to-end flow (`add → list → sync → restore`) green in CI and covered by tests.

---

## Phase 2 • Core API Hardening (prep for GUI)

| #   | Task                                      | Deliverable                                                                                                 |
| --- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| 2.1 | **Public Service Layer** (`seedpass.api`) | Facade classes:<br>`VaultService`, `ProfileService`, `SyncService` – *no* CLI / UI imports.                 |
| 2.2 | **Thread-safe gate**                      | Re-entrancy locks so GUI threads can call core safely.                                                      |
| 2.3 | **Fast in-process event bus**             | Simple `pubsub.py` (observer pattern) for GUI to receive progress callbacks (e.g. sync progress, long ops). |
| 2.4 | **Docstrings + pydantic models**          | Typed request/response objects → eases RPC later (e.g. REST, gRPC).                                         |
| 2.5 | **Library packaging**                     | `python -m pip install .` gives importable `seedpass`.                                                      |

---

## Phase 3 • Desktop GUI MVP

| #   | Decision                                  | Notes                                                                                                                |
| --- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| 3.0 | **Framework: PySide 6 (Qt 6)**            | ✓ LGPL, ✓ native look, ✓ Python-first, ✓ WebEngine if needed.                                                        |
| 3.1 | **Process model**                         | *Same* process; GUI thread ↔ core API via signals/slots.<br>(If we outgrow this, swap to a local gRPC server later.) |
| 3.2 | **UI Skeleton (milestone “Hello Vault”)** |                                                                                                                      |
| –   | `LoginWindow`                             | master-password prompt → opens default profile                                                                       |
| –   | `VaultWindow`                             | sidebar (Profiles, Entries, Backups) + stacked views                                                                 |
| –   | `EntryTableView`                          | QTableView bound to `VaultService.list_entries()`                                                                    |
| –   | `EntryEditorDialog`                       | Add / Edit forms – field set driven by `kinds.py`                                                                    |
| –   | `SyncStatusBar`                           | pulse animation + last-sync timestamp                                                                                |
| 3.3 | **Icons / theming**                       | Start with Qt-built-in icons; later swap to SVG set.                                                                 |
| 3.4 | **Packaging**                             | `PyInstaller --onefile` for Win / macOS / Linux AppImage; GitHub Actions matrix build.                               |
| 3.5 | **GUI E2E tests**                         | PyTest + pytest-qt (QtBot) smoke flows; run headless in CI (Xvfb).                                                   |

> **Stretch option:** wrap the same UI in **Tauri** later for a lighter binary (\~5 MB), reusing the core API through a local websocket RPC.

---

## Phase 4 • Unified Workflows & Coverage

| #   | Task                                                                                    |
| --- | --------------------------------------------------------------------------------------- |
| 4.1 | Extend GitHub Actions to build GUI artifacts on every tag.                              |
| 4.2 | Add synthetic coverage for GUI code paths (QtBot).                                      |
| 4.3 | Nightly job: spin up headless GUI, run `sync` against test relay, assert no exceptions. |

---

## Phase 5 • Future-Proofing (post-GUI v1)

| Idea                       | Sketch                                                                                    |
| -------------------------- | ----------------------------------------------------------------------------------------- |
| **Background daemon**      | Optional `seedpassd` exposing Unix socket + JSON-RPC; both CLI & GUI become thin clients. |
| **Hardware-wallet unlock** | Replace master password with HWW + SLIP-39 share; requires PyUSB bridge.                  |
| **Mobile companion app**   | Reuse core via BeeWare or Flutter FFI; sync over Nostr only (no local vault).             |
| **End-to-end test farm**   | dedicated relay docker-compose + pytest-subprocess to fake flaky relays.                  |

---

## Deliverables Checklist

* [ ] Core refactor merged, tests ≥ 85 % coverage
* [ ] `seedpass` installs and passes `python -m seedpass.cli --help`
* [ ] `seedpass-gui` binary opens vault, lists entries, adds & edits, syncs
* [ ] GitHub Actions builds binaries for Win/macOS/Linux on tag
* [ ] `docs/ARCHITECTURE.md` diagrams core ↔ CLI ↔ GUI layers

When the above are ✅ we can ship `v2.0.0-beta.1` and invite early desktop testers.

---

### 🔑 Key Takeaways

1. **Keep all state & crypto in the core package.**
2. **Expose a clean Python API first – GUI is “just another client.”**
3. **Checksum + replaceable Nostr events give rock-solid sync & conflict handling.**
4. **Lock files and StateManager prevent index reuse and vault corruption.**
5. **The GUI sprint starts only after Phase 1 + 2 are fully green in CI.**

