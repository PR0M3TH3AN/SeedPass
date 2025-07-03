---

# SeedPass Feature Back‑Log (v2)

> **Encryption invariant**   Everything at rest **and** in export remains cipher‑text that ultimately derives from the **profile master‑password + parent seed**. No unencrypted payload leaves the vault.
>
> **Surface rule**   UI layers (CLI, GUI, future mobile) may *display* decrypted data **after** user unlock, but must never write plaintext to disk or network.

---

## Track vocabulary

| Label        | Meaning                                                                        |
| ------------ | ------------------------------------------------------------------------------ |
| **Core API** | `seedpass.api`  – headless services consumed by CLI / GUI                      |
| **Profile**  | A fingerprint‑scoped vault:   parent‑seed + hashed pw + entries                |
| **Entry**    | One encrypted JSON blob on disk plus Nostr snapshot chunks and delta events |
| **GUI MVP**  | Desktop app built with PySide 6 announced in the v2 roadmap                    |

---

## Phase A  •  Core‑level enhancements (blockers for GUI)

|  Prio  | Feature                            | Notes                                                                                                                                                                              |
| ------ | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  🔥    | **Encrypted Search API**           | • `VaultService.search(query:str, *, kinds=None) -> List[EntryMeta]`  <br>• Decrypt *only* whitelisted meta‑fields per `kind` (title, username, url, tags) for in‑memory matching. |
|  🔥    | **Rich Listing / Sort / Filter**   | • `list_entries(sort_by="updated", kind="note")`  <br>• Sorting by `title` must decrypt that field on‑the‑fly.                                                                     |
|  🔥    | **Custom Relay Set (per profile)** | • `StateManager.state["relays"]: List[str]`  <br>• CRUD CLI commands & GUI dialog.  <br>• `NostrClient` reads from state at instantiation.                                         |
|  ⚡     | **Session Lock & Idle Timeout**    | • Config `SESSION_TIMEOUT` (default 15 min).  <br>• `AuthGuard` clears in‑memory keys & seeds.  <br>• CLI `seedpass lock` + GUI menu “Lock vault”.                                 |

**Exit‑criteria** : All functions green in CI, consumed by both CLI (Typer) *and* a minimal Qt test harness.

---

## Phase B  •  Data Portability (encrypted only)

|  Prio  | Feature                              | Notes                                                                                                                                                                                        |                                                                                                                     |
| ------ | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
|  ⭐     | **Encrypted Profile Export**         | • CLI `seedpass export --out myprofile.enc`  <br>• Serialise *encrypted* entry files → single JSON wrapper → `EncryptionManager.encrypt_data()`  <br>• Always require active profile unlock. |                                                                                                                     |
|  ⭐     | **Encrypted Profile Import / Merge** | • CLI \`seedpass import myprofile.enc \[--strategy skip                                                                                                                                      | overwrite-newer]`  <br>• Verify fingerprint match before ingest.  <br>• Conflict policy pluggable; default `skip\`. |

---

## Phase C  •  Advanced secrets & sync

|  Prio  | Feature                      | Notes                                                                                                                                          |
| ------ | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
|  ◇     | **TOTP entry kind**          | • `kind="totp_secret"`  fields: title, issuer, username, secret\_key  <br>• `secret_key` encrypted; handler uses `pyotp` to show current code. |
|  ◇     | **Manual Conflict Resolver** | • When `checksum` mismatch *and* both sides newer than last sync → prompt user (CLI) or modal (GUI).                                           |

---

## Phase D  •  Desktop GUI MVP (Qt 6)

*Features here ride on the Core API; keep UI totally stateless.*

|  Prio  | Feature                  | Notes                                                                                                                                            |
| ------ | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
|  🔥    | **Login Window**         | • Unlock profile with master pw.  <br>• Profile switcher drop‑down.                                                                              |
|  🔥    | **Vault Window**         | • Sidebar (Entries, Search, Backups, Settings).  <br>• `QTableView` bound to `VaultService.list_entries()`  <br>• Sort & basic filters built‑in. |
|  🔥    | **Entry Editor Dialog**  | • Dynamic form driven by `kinds.py`.  <br>• Add / Edit.                                                                                          |
|  ⭐     | **Sync Status Bar**      | • Pulsing icon + last sync timestamp; hooks into `SyncService` bus.                                                                              |
|  ◇     | **Relay Manager Dialog** | • CRUD & ping test per relay.                                                                                                                    |

*Binary packaging (PyInstaller matrix build) is already tracked in the roadmap and is not duplicated here.*

---

## Phase E  •  Later / Research

• Hardware‑wallet unlock (SLIP‑39 share)
• Background daemon (`seedpassd` + gRPC)
• Mobile companion (Flutter FFI)
• Federated search across multiple profiles

---

**Reminder:**  *No plaintext exports, no on‑disk temp files, and no writing decrypted data to Nostr.*  Everything funnels through the encryption stack or stays in memory for the current unlocked session only.
