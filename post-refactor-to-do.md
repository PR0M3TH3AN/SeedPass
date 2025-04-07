Okay, acknowledging the strict requirement that **exported data must remain encrypted and ultimately depend on the master seed/password for decryption**, here is a prioritized feature list to-do:

---

## SeedPass Feature To-Do List

**Key Constraint:** All data storage and export mechanisms must ensure data remains encrypted. Access to usable, decrypted information must always require the user's Master Password for the specific profile (which in turn decrypts the Parent Seed or the necessary keys derived from it). *Plaintext export for migration to other tools is explicitly excluded by this constraint.*

---

### **Phase 1: High Priority (Core Usability & Control)**

1.  **Search Functionality (Encrypted Search)**
    *   **Goal:** Allow users to quickly find specific entries without manually listing all of them.
    *   **Key Implementation Steps:**
        *   Add a "Search Entries" option to the main CLI menu.
        *   Implement search logic in `PasswordManager`:
            *   Iterate through all local entry files (`entry_manager.list_all_entry_nums()` -> `entry_manager.load_entry()`).
            *   For each entry, decrypt *only the necessary searchable fields* defined per `kind` (e.g., 'title', 'username', 'url', 'tags'). **Do NOT decrypt passwords/secrets for searching.**
            *   Perform case-insensitive substring matching on the decrypted searchable fields against the user's query.
            *   Display a list of matching entries (e.g., `EntryNum: Title (Kind)`).
            *   Allow the user to select a search result to view its full details (triggering the appropriate handler which *will* decrypt sensitive data for display only).
    *   **Encryption Consideration:** Only non-secret metadata fields are decrypted *during the search process*. Sensitive data remains encrypted until explicitly requested for display via the entry handler.
    *   **Priority:** High

2.  **Custom Nostr Relays (Per Profile)**
    *   **Goal:** Allow users to specify which Nostr relays to use for synchronization for each profile, enhancing reliability and privacy.
    *   **Key Implementation Steps:**
        *   Modify `StateManager` to load/save a `relays: List[str]` field in `seedpass_state.json`. Default to `constants.DEFAULT_RELAYS` if not present.
        *   Add options to the "Manage Profiles" sub-menu:
            *   `View Relays`: Display current relays for the active profile.
            *   `Add Relay`: Prompt user for a relay URL and add it to the list.
            *   `Remove Relay`: Display current relays with numbers, prompt user to select one for removal.
            *   `Set Default Relays`: Reset the list to `constants.DEFAULT_RELAYS`.
        *   Update `NostrClient.__init__` to read the relay list from `StateManager` for the current profile.
        *   Ensure `StateManager._save_state()` is called after modifications.
    *   **Encryption Consideration:** Relay list itself is not sensitive and stored in plaintext within the profile's state file.
    *   **Priority:** High

3.  **Entry Listing with Sorting & Filtering**
    *   **Goal:** Provide more organized ways to view local entries beyond just retrieving a single one by number.
    *   **Key Implementation Steps:**
        *   Enhance the "List / Retrieve Entries" option or create a dedicated "List Entries" option.
        *   Load all local entries (`password_manager.list_all_entries()`).
        *   Add sub-prompts or flags for:
            *   **Sorting:** By Entry Number (default), Title (requires decrypting 'title'), Kind, Last Updated Timestamp.
            *   **Filtering:** By Kind (`--kind note`).
        *   Implement the sorting logic (decrypting 'title' in memory only for sorting purposes).
        *   Implement the filtering logic.
        *   Display the formatted, sorted, and/or filtered list.
    *   **Encryption Consideration:** Only the 'title' field needs temporary in-memory decryption for sorting by title. All other data remains encrypted until an entry is selected for full display.
    *   **Priority:** High

---

### **Phase 2: Medium Priority (Data Management - Securely)**

4.  **Secure Data Export (Profile Backup)**
    *   **Goal:** Allow users to create a single, encrypted backup file containing *all* entries for a specific profile, suitable for transferring or archiving *within the SeedPass ecosystem*.
    *   **Key Implementation Steps:**
        *   Add an "Export Profile Data" option (requires password confirmation).
        *   Prompt for an output filename (e.g., `seedpass_profile_<fingerprint>_export.json.enc`).
        *   Load all local entries for the current profile.
        *   Construct a JSON object containing a list of all *un-decrypted* (as loaded from disk) entry data structures. Include metadata like export date and profile fingerprint.
        *   Convert this JSON object to bytes.
        *   **Crucially:** Encrypt this *entire byte stream* using the profile's `EncryptionManager` (i.e., using the key derived from the master password).
        *   Save the resulting encrypted blob to the user-specified file.
    *   **Encryption Consideration:** The entire export is a single encrypted blob. It requires the *exact same* SeedPass profile (same seed + master password) to decrypt and import it later. It is **not** interoperable with other tools. This adheres to the "no plaintext export" rule.
    *   **Priority:** Medium

5.  **Secure Data Import (Profile Restore/Merge)**
    *   **Goal:** Allow users to import entries from a previously created secure export file.
    *   **Key Implementation Steps:**
        *   Add an "Import Profile Data" option (requires password confirmation).
        *   Prompt for the path to the encrypted export file (`.json.enc`).
        *   Use the current profile's `EncryptionManager` to decrypt the entire file blob.
        *   Parse the decrypted JSON to get the list of exported entries.
        *   **Crucially:** Verify the fingerprint inside the imported data matches the current profile's fingerprint. Abort if mismatched.
        *   Iterate through the imported entries:
            *   For each imported entry, check if an entry with the same `entry_num` already exists locally.
            *   **Conflict Strategy:** Decide how to handle conflicts (e.g., skip import, overwrite local if import is newer based on timestamp, prompt user). Prompting is safest but less automated. Start with "skip if exists" or "overwrite if newer".
            *   If importing (either new or overwriting):
                *   Validate the `kind` and structure.
                *   Save the encrypted entry data (as provided in the import file) locally using `entry_manager.save_entry()`.
                *   Optionally, post the imported/updated entry to Nostr.
    *   **Encryption Consideration:** Import only works if the current profile's master password can decrypt the export file. Fingerprint matching prevents accidental cross-profile imports. Data remains encrypted until processed by `save_entry`.
    *   **Priority:** Medium

---

### **Phase 3: Lower Priority (Convenience & Advanced)**

6.  **Session Lock / Auto-Timeout**
    *   **Goal:** Enhance security by requiring password re-entry after inactivity or manual locking.
    *   **Key Implementation Steps:**
        *   Track `last_activity_time` within `PasswordManager`. Update it on each successful user action.
        *   Add a configurable `SESSION_TIMEOUT` constant (e.g., 900 seconds for 15 mins).
        *   Before executing sensitive operations (anything requiring decryption/generation), check if `time.time() - last_activity_time > SESSION_TIMEOUT`.
        *   If timed out, clear sensitive in-memory data (`encryption_manager.key = None`, `encryption_manager.fernet = None`, `parent_seed = None`, `bip85 = None`) and prompt for the master password again using `prompt_existing_password`. Re-initialize the necessary components upon success.
        *   Add a "Lock Session" menu option that immediately clears sensitive data and forces password re-entry on the next action.
    *   **Encryption Consideration:** Focuses on clearing in-memory keys/seeds, not on-disk encryption which remains unchanged.
    *   **Priority:** Low

7.  **Additional `Kind` Types (e.g., TOTP)**
    *   **Goal:** Extend SeedPass to securely manage other types of secrets like Time-based One-Time Passwords.
    *   **Key Implementation Steps:**
        *   Define `kind = "totp_secret"` in `kinds.py` with fields like `title`, `issuer`, `username`, `secret_key`.
        *   Ensure `secret_key` is encrypted/base64'd within the `data` payload like other sensitive fields (`stored_password`, `note` content).
        *   Create `handlers/totp_secret_handler.py`.
        *   The handler should decrypt the `secret_key`.
        *   **Decision:** Should it *display* the secret key, or *generate* the current code? Generating is more useful but adds a dependency (`pyotp`) and time sensitivity.
        *   If generating codes: Add `pyotp` to `requirements.txt`. The handler uses `pyotp.TOTP(decrypted_secret_key).now()`. Display the code along with other metadata.
    *   **Encryption Consideration:** The TOTP secret key itself is stored encrypted. Generating the code requires decrypting it in memory temporarily within the handler.
    *   **Priority:** Low

8.  **Enhanced Sync Conflict Resolution (Manual Prompt)**
    *   **Goal:** Provide user control when a sync detects that an entry was modified both locally and on Nostr since the last sync.
    *   **Key Implementation Steps:**
        *   In `PasswordManager.synchronize_with_nostr`: When `local_entry_path.exists()` and `local_checksum != remote_checksum`:
            *   Load the local entry's full data and timestamp.
            *   Compare the `updated_at` timestamp from the local entry's metadata with the `created_at` timestamp of the Nostr event.
            *   If timestamps differ significantly *and* checksums differ, flag as a conflict.
            *   Prompt the user: "Conflict detected for Entry X ('Title'). Keep Local version (updated Y) or Remote version (updated Z)? (L/R/Skip)".
            *   Based on user input, either save the remote version (as currently done), skip the update for this entry, or do nothing (keep local).
    *   **Encryption Consideration:** Requires decrypting local entry metadata (`updated_at`) and comparing with Nostr event metadata (`created_at`). Sensitive data decryption only happens if the user chooses to view details or keep a specific version.
    *   **Priority:** Low

---

### **Phase 4: Future / Major Effort**

9.  **GUI / TUI Implementation**
    *   **Goal:** Provide a more user-friendly interface than the current CLI menu system.
    *   **Key Implementation Steps:** Requires selecting a framework (`curses`, `Tkinter`, `PyQt`, etc.) and redesigning the entire user interaction flow. Major undertaking.
    *   **Encryption Consideration:** No change to the core encryption logic, but requires careful handling of when decrypted data is displayed in GUI widgets.
    *   **Priority:** Future

---