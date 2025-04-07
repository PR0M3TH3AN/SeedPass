Okay, this is a significant refactoring effort! Let's break it down and implement the changes based on your plan and the provided code.

**Phase 1: Create New Files and Basic Structures**

**1. Create `password_manager/kinds.py`:**

```python
# password_manager/kinds.py

import logging
from typing import Dict, Callable, List, Any
from termcolor import colored

# Forward declaration for type hinting if handlers need PasswordManager instance later
# class PasswordManager: pass
# from .encryption import EncryptionManager

logger = logging.getLogger(__name__)

# Placeholder handlers - will be imported properly later
def handle_generated_password(entry_data: Dict[str, Any], fingerprint: str, **kwargs):
    logger.warning("Placeholder handler called for generated_password")
    print(colored(f"Processing Generated Password (Placeholder): {entry_data.get('title')}", "grey"))

def handle_stored_password(entry_data: Dict[str, Any], fingerprint: str, **kwargs):
    logger.warning("Placeholder handler called for stored_password")
    print(colored(f"Processing Stored Password (Placeholder): {entry_data.get('title')}", "grey"))

def handle_note(entry_data: Dict[str, Any], fingerprint: str, **kwargs):
    logger.warning("Placeholder handler called for note")
    print(colored(f"Processing Note (Placeholder): Content length {len(entry_data.get('content', ''))}", "grey"))

# --- Actual KINDS Definition ---
# We'll import real handlers after creating them.

# Define the structure for kinds. Each kind maps to:
# - handler: The function to process/display the entry data.
# - description: User-friendly description for menus.
# - fields: List of expected keys within the 'data' part of an entry.
# - nostr_kind: The Nostr event kind used for this entry type.
# - identifier_tag: The Nostr tag ('d' tag) value prefix for this entry type.
KINDS: Dict[str, Dict[str, Any]] = {
    "generated_password": {
        "handler": handle_generated_password, # Placeholder
        "description": "Generated Password (using BIP-85 index)",
        "fields": ["title", "username", "email", "url", "length", "bip85_index"], # Note: password is not stored, bip85_index is key
        "nostr_kind": 31111, # Example custom kind for SeedPass entries
        "identifier_tag": "seedpass_gp_" # gp for generated password
    },
    "stored_password": {
        "handler": handle_stored_password, # Placeholder
        "description": "Stored Password / Credential",
        "fields": ["title", "username", "password", "url", "notes"], # Password stored encrypted in 'data'
        "nostr_kind": 31111,
        "identifier_tag": "seedpass_sp_" # sp for stored password
    },
    "note": {
        "handler": handle_note, # Placeholder
        "description": "Secure Note",
        "fields": ["title", "content", "tags"],
        "nostr_kind": 31111,
        "identifier_tag": "seedpass_note_"
    },
    # Add new kinds here in the future
}

def get_kind_details(kind_name: str) -> Optional[Dict[str, Any]]:
    """Safely retrieves details for a given kind."""
    return KINDS.get(kind_name)

def get_all_kinds() -> List[str]:
    """Returns a list of all defined kind names."""
    return list(KINDS.keys())

def get_nostr_kind(kind_name: str) -> Optional[int]:
    """Gets the Nostr event kind for a SeedPass kind."""
    details = get_kind_details(kind_name)
    return details.get("nostr_kind") if details else None

def get_identifier_tag_prefix(kind_name: str) -> Optional[str]:
    """Gets the 'd' tag prefix for a SeedPass kind."""
    details = get_kind_details(kind_name)
    return details.get("identifier_tag") if details else None

def get_required_fields(kind_name: str) -> List[str]:
    """Gets the list of required fields for a SeedPass kind."""
    details = get_kind_details(kind_name)
    return details.get("fields", []) if details else []

def get_kind_handler(kind_name: str) -> Optional[Callable]:
    """Gets the handler function for a SeedPass kind."""
    details = get_kind_details(kind_name)
    return details.get("handler") if details else None

```

**2. Create `password_manager/handlers/` directory and `__init__.py`:**

```bash
mkdir -p password_manager/handlers
touch password_manager/handlers/__init__.py
```

**3. Create Handler Files:**

*   **`password_manager/handlers/generated_password_handler.py`:**
    ```python
    # password_manager/handlers/generated_password_handler.py
    import logging
    from typing import Dict, Any
    from termcolor import colored
    # Avoid circular import - PasswordManager/EncryptionManager likely passed in kwargs
    # from ..manager import PasswordManager
    # from ..encryption import EncryptionManager
    # from ..password_generation import PasswordGenerator

    logger = logging.getLogger(__name__)

    def handle_generated_password(entry_data: Dict[str, Any], fingerprint: str, **kwargs):
        """Handles processing/displaying a generated password entry."""
        # Expect PasswordGenerator instance in kwargs for actual generation
        password_generator = kwargs.get("password_generator")
        if not password_generator:
             logger.error("PasswordGenerator not provided to generated_password handler.")
             print(colored("Error: Cannot process generated password - internal setup issue.", "red"))
             return

        title = entry_data.get("title", "N/A")
        username = entry_data.get("username", "")
        email = entry_data.get("email", "")
        url = entry_data.get("url", "")
        length = entry_data.get("length")
        bip85_index = entry_data.get("bip85_index")

        if length is None or bip85_index is None:
            logger.error(f"Missing length or bip85_index for generated password entry: {title}")
            print(colored(f"Error: Incomplete data for generated password '{title}'.", "red"))
            return

        try:
            # Regenerate the password on the fly
            password = password_generator.generate_password(length=length, index=bip85_index)

            print(colored(f"--- Generated Password Entry ---", "cyan"))
            print(colored(f"  Title:    {title}", "cyan"))
            if username: print(colored(f"  Username: {username}", "cyan"))
            if email: print(colored(f"  Email:    {email}", "cyan"))
            if url: print(colored(f"  URL:      {url}", "cyan"))
            print(colored(f"  Length:   {length}", "cyan"))
            print(colored(f"  Index:    {bip85_index}", "cyan"))
            print(colored(f"  Password: {password}", "yellow")) # Display generated password
            print(colored(f"--------------------------------", "cyan"))

        except Exception as e:
            logger.error(f"Failed to generate password for entry {title}: {e}", exc_info=True)
            print(colored(f"Error generating password for '{title}': {e}", "red"))

    ```
*   **`password_manager/handlers/stored_password_handler.py`:**
    ```python
    # password_manager/handlers/stored_password_handler.py
    import logging
    from typing import Dict, Any
    from termcolor import colored
    # from ..encryption import EncryptionManager # Passed in kwargs

    logger = logging.getLogger(__name__)

    def handle_stored_password(entry_data: Dict[str, Any], fingerprint: str, **kwargs):
        """Handles processing/displaying a stored password entry."""
        encryption_manager = kwargs.get("encryption_manager")
        if not encryption_manager:
             logger.error("EncryptionManager not provided to stored_password handler.")
             print(colored("Error: Cannot process stored password - internal setup issue.", "red"))
             return

        title = entry_data.get("title", "N/A")
        username = entry_data.get("username", "")
        encrypted_password_b64 = entry_data.get("password") # Expecting base64 encoded encrypted bytes
        url = entry_data.get("url", "")
        notes = entry_data.get("notes", "")

        if not encrypted_password_b64:
            logger.error(f"Missing encrypted password for stored password entry: {title}")
            print(colored(f"Error: Incomplete data for stored password '{title}'.", "red"))
            return

        try:
            # Decode from base64 then decrypt
            import base64
            encrypted_password_bytes = base64.b64decode(encrypted_password_b64)
            password = encryption_manager.decrypt_data(encrypted_password_bytes).decode('utf-8')

            print(colored(f"--- Stored Password Entry ---", "cyan"))
            print(colored(f"  Title:    {title}", "cyan"))
            if username: print(colored(f"  Username: {username}", "cyan"))
            if url: print(colored(f"  URL:      {url}", "cyan"))
            if notes: print(colored(f"  Notes:    {notes}", "cyan"))
            print(colored(f"  Password: {password}", "yellow")) # Display decrypted password
            print(colored(f"-----------------------------", "cyan"))

        except Exception as e:
            logger.error(f"Failed to decrypt stored password for entry {title}: {e}", exc_info=True)
            print(colored(f"Error decrypting password for '{title}': {e}", "red"))
    ```
*   **`password_manager/handlers/note_handler.py`:**
    ```python
    # password_manager/handlers/note_handler.py
    import logging
    from typing import Dict, Any
    from termcolor import colored
    # from ..encryption import EncryptionManager # Passed in kwargs

    logger = logging.getLogger(__name__)

    def handle_note(entry_data: Dict[str, Any], fingerprint: str, **kwargs):
        """Handles processing/displaying a secure note entry."""
        encryption_manager = kwargs.get("encryption_manager")
        if not encryption_manager:
             logger.error("EncryptionManager not provided to note handler.")
             print(colored("Error: Cannot process note - internal setup issue.", "red"))
             return

        title = entry_data.get("title", "N/A")
        encrypted_content_b64 = entry_data.get("content") # Expecting base64 encoded encrypted bytes
        tags = entry_data.get("tags", [])

        if not encrypted_content_b64:
            logger.error(f"Missing encrypted content for note entry: {title}")
            print(colored(f"Error: Incomplete data for note '{title}'.", "red"))
            return

        try:
            # Decode from base64 then decrypt
            import base64
            encrypted_content_bytes = base64.b64decode(encrypted_content_b64)
            content = encryption_manager.decrypt_data(encrypted_content_bytes).decode('utf-8')

            print(colored(f"--- Secure Note Entry ---", "cyan"))
            print(colored(f"  Title: {title}", "cyan"))
            if tags: print(colored(f"  Tags:  {', '.join(tags)}", "cyan"))
            print(colored(f"  Content:\n{content}", "yellow"))
            print(colored(f"-------------------------", "cyan"))

        except Exception as e:
            logger.error(f"Failed to decrypt note content for entry {title}: {e}", exc_info=True)
            print(colored(f"Error decrypting note '{title}': {e}", "red"))

    ```
*   **Update `password_manager/kinds.py` imports:**
    ```python
    # password_manager/kinds.py
    # ... (other imports)

    # --- Import Real Handlers ---
    from .handlers.generated_password_handler import handle_generated_password
    from .handlers.stored_password_handler import handle_stored_password
    from .handlers.note_handler import handle_note
    # Future handlers can be imported here

    # --- KINDS Definition --- (Use imported handlers now)
    KINDS: Dict[str, Dict[str, Any]] = {
        "generated_password": {
            "handler": handle_generated_password, # Use imported handler
            "description": "Generated Password (using BIP-85 index)",
            "fields": ["title", "username", "email", "url", "length", "bip85_index"],
            "nostr_kind": 31111,
            "identifier_tag": "seedpass_gp_"
        },
        "stored_password": {
            "handler": handle_stored_password, # Use imported handler
            "description": "Stored Password / Credential",
            "fields": ["title", "username", "password", "url", "notes"],
            "nostr_kind": 31111,
            "identifier_tag": "seedpass_sp_"
        },
        "note": {
            "handler": handle_note, # Use imported handler
            "description": "Secure Note",
            "fields": ["title", "content", "tags"],
            "nostr_kind": 31111,
            "identifier_tag": "seedpass_note_"
        },
        # ...
    }
    # ... (rest of the helper functions)
    ```

**4. Create `password_manager/state_manager.py`:**

```python
# password_manager/state_manager.py

import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import fcntl
import os
import traceback

from utils.file_lock import lock_file # Use the existing file lock utility

logger = logging.getLogger(__name__)

class StateManager:
    """Manages persistent state for a fingerprint, like last index and sync time."""

    STATE_FILENAME = "seedpass_state.json"

    def __init__(self, fingerprint_dir: Path):
        self.fingerprint_dir = fingerprint_dir
        self.state_file_path = self.fingerprint_dir / self.STATE_FILENAME
        self._state: Dict[str, Any] = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        """Loads state from the JSON file, returns default if not found or invalid."""
        default_state = {"last_generated_password_index": -1, "last_nostr_sync_time": 0}
        if not self.state_file_path.exists():
            logger.info(f"State file not found for {self.fingerprint_dir.name}. Initializing default state.")
            return default_state

        try:
            with lock_file(self.state_file_path, fcntl.LOCK_SH):
                with open(self.state_file_path, 'r') as f:
                    state = json.load(f)
                    # Ensure essential keys exist
                    for key, default_value in default_state.items():
                        if key not in state:
                            state[key] = default_value
                    logger.debug(f"State loaded for {self.fingerprint_dir.name}")
                    return state
        except (json.JSONDecodeError, IOError, ValueError) as e:
            logger.error(f"Failed to load or parse state file {self.state_file_path}: {e}. Using default state.", exc_info=True)
            return default_state
        except Exception as e:
            logger.error(f"Unexpected error loading state file {self.state_file_path}: {e}. Using default state.", exc_info=True)
            return default_state

    def _save_state(self) -> bool:
        """Saves the current state to the JSON file."""
        try:
            with lock_file(self.state_file_path, fcntl.LOCK_EX):
                with open(self.state_file_path, 'w') as f:
                    json.dump(self._state, f, indent=4)
                os.chmod(self.state_file_path, 0o600) # Ensure permissions
            logger.debug(f"State saved for {self.fingerprint_dir.name}")
            return True
        except IOError as e:
            logger.error(f"Failed to save state file {self.state_file_path}: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Unexpected error saving state file {self.state_file_path}: {e}", exc_info=True)
            return False

    def get_last_generated_password_index(self) -> int:
        """Gets the last used index for generated passwords."""
        # Ensure the key exists, defaulting if necessary
        if "last_generated_password_index" not in self._state:
             self._state["last_generated_password_index"] = -1
        return self._state.get("last_generated_password_index", -1)

    def set_last_generated_password_index(self, index: int) -> bool:
        """Sets the last used index for generated passwords and saves state."""
        if not isinstance(index, int) or index < -1:
             logger.error(f"Invalid index provided to set_last_generated_password_index: {index}")
             return False
        self._state["last_generated_password_index"] = index
        logger.info(f"Setting last generated password index to: {index}")
        return self._save_state()

    def get_next_generated_password_index(self) -> int:
        """Gets the next available index and increments the stored value."""
        current_index = self.get_last_generated_password_index()
        next_index = current_index + 1
        if self.set_last_generated_password_index(next_index):
            return next_index
        else:
            # Handle save failure - maybe raise an exception?
            logger.critical("Failed to save state after incrementing index! Potential index reuse risk.")
            raise RuntimeError("Failed to update state for next generated password index.")

    def get_last_nostr_sync_time(self) -> int:
        """Gets the timestamp of the last successful Nostr sync."""
         # Ensure the key exists, defaulting if necessary
        if "last_nostr_sync_time" not in self._state:
             self._state["last_nostr_sync_time"] = 0
        return self._state.get("last_nostr_sync_time", 0)

    def set_last_nostr_sync_time(self, timestamp: int) -> bool:
        """Sets the timestamp of the last successful Nostr sync and saves state."""
        if not isinstance(timestamp, int) or timestamp < 0:
             logger.error(f"Invalid timestamp provided to set_last_nostr_sync_time: {timestamp}")
             return False
        self._state["last_nostr_sync_time"] = timestamp
        logger.info(f"Setting last Nostr sync time to: {timestamp}")
        return self._save_state()

```

**Phase 2: Refactor `EntryManager` and `BackupManager`**

*   **`password_manager/entry_management.py` (Refactored):**
    ```python
    # password_manager/entry_management.py

    import json
    import logging
    import hashlib
    import sys
    import os
    import shutil
    import time
    import traceback
    import fcntl
    from pathlib import Path
    from typing import Optional, Dict, Any, List

    from termcolor import colored
    from .encryption import EncryptionManager # Keep this
    from utils.file_lock import lock_file # Keep this

    logger = logging.getLogger(__name__)

    class EntryManager:
        """Manages storage and retrieval of individual encrypted entry files."""

        ENTRY_FILENAME_TEMPLATE = "entry_{entry_num}.json.enc"
        ENTRY_CHECKSUM_FIELD = "checksum" # Field within the decrypted JSON metadata

        def __init__(self, encryption_manager: EncryptionManager, fingerprint_dir: Path):
            """
            Initializes the EntryManager.

            :param encryption_manager: The encryption manager instance.
            :param fingerprint_dir: The directory corresponding to the fingerprint.
            """
            self.encryption_manager = encryption_manager
            self.fingerprint_dir = fingerprint_dir
            self.entries_dir = self.fingerprint_dir / 'entries'
            # Ensure the entries directory exists
            self.entries_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"EntryManager initialized for directory {self.entries_dir}")

        def _get_entry_path(self, entry_num: int) -> Path:
            """Constructs the file path for a given entry number."""
            return self.entries_dir / self.ENTRY_FILENAME_TEMPLATE.format(entry_num=entry_num)

        def get_next_entry_num(self) -> int:
            """Determines the next available entry number based on existing files."""
            try:
                existing_entries = list(self.entries_dir.glob('entry_*.json.enc'))
                if not existing_entries:
                    return 0
                entry_nums = []
                for entry_path in existing_entries:
                    try:
                        # Extract number from filename like 'entry_123.json.enc'
                        num_str = entry_path.stem.split('_')[1]
                        entry_nums.append(int(num_str))
                    except (IndexError, ValueError):
                        logger.warning(f"Could not parse entry number from filename: {entry_path.name}")
                return max(entry_nums) + 1 if entry_nums else 0
            except Exception as e:
                logger.error(f"Error determining next entry number: {e}", exc_info=True)
                print(colored(f"Error determining next entry number: {e}", 'red'))
                # Returning 0 might be risky, perhaps raise or exit?
                raise RuntimeError("Could not determine the next entry number.") from e

        def calculate_checksum(self, data_dict: Dict[str, Any]) -> str:
            """Calculates SHA-256 checksum of the provided data dictionary."""
            try:
                # Ensure consistent ordering for checksum calculation
                data_string = json.dumps(data_dict, sort_keys=True).encode('utf-8')
                return hashlib.sha256(data_string).hexdigest()
            except Exception as e:
                logger.error(f"Error calculating checksum: {e}", exc_info=True)
                raise ValueError("Could not calculate checksum for data.") from e

        def save_entry(self, entry_num: int, encrypted_entry_data: bytes) -> bool:
            """Saves the encrypted data for a specific entry number."""
            entry_path = self._get_entry_path(entry_num)
            try:
                with lock_file(entry_path, fcntl.LOCK_EX):
                    with open(entry_path, 'wb') as f:
                        f.write(encrypted_entry_data)
                    os.chmod(entry_path, 0o600) # Ensure permissions
                logger.info(f"Entry {entry_num} saved successfully to {entry_path}.")
                return True
            except IOError as e:
                logger.error(f"Failed to save entry {entry_num} to {entry_path}: {e}", exc_info=True)
                print(colored(f"Error: Failed to save entry {entry_num}: {e}", 'red'))
                return False
            except Exception as e:
                logger.error(f"Unexpected error saving entry {entry_num}: {e}", exc_info=True)
                return False

        def load_entry(self, entry_num: int) -> Optional[Dict[str, Any]]:
            """Loads, decrypts, and returns the entry data for a specific entry number."""
            entry_path = self._get_entry_path(entry_num)
            if not entry_path.exists():
                logger.warning(f"Entry file not found: {entry_path}")
                return None
            try:
                # Use EncryptionManager's decrypt_file which handles locking
                decrypted_data_bytes = self.encryption_manager.decrypt_file(entry_path.relative_to(self.fingerprint_dir))
                entry_dict = json.loads(decrypted_data_bytes.decode('utf-8'))
                logger.debug(f"Entry {entry_num} loaded successfully.")
                return entry_dict
            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode JSON for entry {entry_num} from {entry_path}: {e}", exc_info=True)
                print(colored(f"Error: Corrupted data found for entry {entry_num}.", 'red'))
                return None
            except Exception as e:
                # Includes InvalidToken from decrypt_file
                logger.error(f"Failed to load or decrypt entry {entry_num} from {entry_path}: {e}", exc_info=True)
                # Don't show raw error to user unless needed
                # print(colored(f"Error: Failed to load entry {entry_num}: {e}", 'red'))
                return None

        def get_entry_checksum(self, entry_num: int) -> Optional[str]:
            """Retrieves the stored checksum from within an entry's metadata."""
            entry_data = self.load_entry(entry_num)
            if entry_data:
                checksum = entry_data.get("metadata", {}).get(self.ENTRY_CHECKSUM_FIELD)
                if checksum:
                    return checksum
                else:
                    logger.warning(f"Checksum not found in metadata for entry {entry_num}")
            return None

        def delete_entry_file(self, entry_num: int) -> bool:
            """Deletes the file associated with an entry number."""
            entry_path = self._get_entry_path(entry_num)
            if not entry_path.exists():
                logger.warning(f"Attempted to delete non-existent entry file: {entry_path}")
                return False # Or True, as the state is achieved? Decide consistency.
            try:
                with lock_file(entry_path, fcntl.LOCK_EX): # Lock before deleting
                     entry_path.unlink()
                logger.info(f"Entry file {entry_path} deleted successfully.")
                return True
            except OSError as e:
                logger.error(f"Failed to delete entry file {entry_path}: {e}", exc_info=True)
                print(colored(f"Error: Failed to delete entry file {entry_num}: {e}", 'red'))
                return False
            except Exception as e:
                logger.error(f"Unexpected error deleting entry file {entry_num}: {e}", exc_info=True)
                return False

        def list_all_entry_nums(self) -> List[int]:
             """Lists all available entry numbers by scanning the directory."""
             entry_nums = []
             try:
                 for entry_path in self.entries_dir.glob('entry_*.json.enc'):
                     try:
                         num_str = entry_path.stem.split('_')[1]
                         entry_nums.append(int(num_str))
                     except (IndexError, ValueError):
                         logger.warning(f"Could not parse entry number from filename: {entry_path.name}")
                 return sorted(entry_nums)
             except Exception as e:
                 logger.error(f"Error listing entry numbers: {e}", exc_info=True)
                 return []

        # --- Methods related to the old single index are removed ---
        # remove _load_index, _save_index, add_entry (old), retrieve_entry (old) etc.
        # remove update_checksum (old)
        # remove get_encrypted_index (old)
    ```

*   **`password_manager/backup.py` (Refactored):**
    ```python
    # password_manager/backup.py

    import logging
    import os
    import shutil
    import time
    import traceback
    from pathlib import Path
    import fcntl # Keep fcntl import if used in lock_file
    from typing import List, Optional

    from termcolor import colored
    from utils.file_lock import lock_file

    logger = logging.getLogger(__name__)

    class BackupManager:
        """Handles backups for individual entry files."""

        BACKUP_FILENAME_TEMPLATE = 'entry_{entry_num}_backup_{timestamp}.json.enc'

        def __init__(self, fingerprint_dir: Path):
            """
            Initializes the BackupManager.

            :param fingerprint_dir: The directory corresponding to the fingerprint.
            """
            self.fingerprint_dir = fingerprint_dir
            self.entries_dir = self.fingerprint_dir / 'entries'
            self.backups_dir = self.fingerprint_dir / 'backups'
            self.backups_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"BackupManager initialized for backup directory {self.backups_dir}")

        def _get_entry_path(self, entry_num: int) -> Path:
            """Constructs the original entry file path."""
            return self.entries_dir / f'entry_{entry_num}.json.enc'

        def create_backup_for_entry(self, entry_num: int) -> Optional[Path]:
            """Creates a timestamped backup for a specific entry file."""
            entry_file = self._get_entry_path(entry_num)
            if not entry_file.exists():
                logger.warning(f"Entry {entry_num} file does not exist at {entry_file}. No backup created.")
                print(colored(f"Warning: Entry file {entry_num} does not exist. No backup created.", 'yellow'))
                return None
            try:
                timestamp = int(time.time())
                backup_filename = self.BACKUP_FILENAME_TEMPLATE.format(entry_num=entry_num, timestamp=timestamp)
                backup_file_path = self.backups_dir / backup_filename

                # Lock the source file for reading during copy
                with lock_file(entry_file, fcntl.LOCK_SH):
                    shutil.copy2(entry_file, backup_file_path) # copy2 preserves metadata

                logger.info(f"Backup created for entry {entry_num} at '{backup_file_path}'.")
                print(colored(f"Backup created successfully for entry {entry_num}.", 'green'))
                return backup_file_path
            except Exception as e:
                logger.error(f"Failed to create backup for entry {entry_num}: {e}", exc_info=True)
                print(colored(f"Error: Failed to create backup for entry {entry_num}: {e}", 'red'))
                return None

        def list_backups_for_entry(self, entry_num: int) -> List[Path]:
            """Lists available backup files for a specific entry, sorted by time (newest first)."""
            try:
                backup_pattern = f'entry_{entry_num}_backup_*.json.enc'
                backup_files = sorted(
                    self.backups_dir.glob(backup_pattern),
                    key=lambda x: x.stat().st_mtime,
                    reverse=True
                )
                return backup_files
            except Exception as e:
                logger.error(f"Failed to list backups for entry {entry_num}: {e}", exc_info=True)
                return []

        def list_all_backups(self) -> List[Path]:
             """Lists all backup files, sorted by time (newest first)."""
             try:
                 backup_files = sorted(
                     self.backups_dir.glob('entry_*_backup_*.json.enc'),
                     key=lambda x: x.stat().st_mtime,
                     reverse=True
                 )
                 return backup_files
             except Exception as e:
                 logger.error(f"Failed to list all backups: {e}", exc_info=True)
                 return []

        def display_backups(self, entry_num: Optional[int] = None):
             """Prints available backups to the console."""
             if entry_num is not None:
                 backup_files = self.list_backups_for_entry(entry_num)
                 print(colored(f"Available Backups for Entry {entry_num}:", 'cyan'))
             else:
                 backup_files = self.list_all_backups()
                 print(colored("Available Backups (All Entries):", 'cyan'))

             if not backup_files:
                 logger.info("No backup files available.")
                 print(colored("No backup files available.", 'yellow'))
                 return

             for backup in backup_files:
                 try:
                     creation_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(backup.stat().st_mtime))
                     print(colored(f"- {backup.name} (Created on: {creation_time})", 'cyan'))
                 except Exception as e:
                     logger.warning(f"Could not get stat for backup file {backup.name}: {e}")
                     print(colored(f"- {backup.name} (Error reading time)", "red"))


        def restore_entry_from_backup(self, entry_num: int, backup_filename: str) -> bool:
            """Restores an entry file from a specific backup file."""
            entry_file = self._get_entry_path(entry_num)
            backup_file = self.backups_dir / backup_filename

            # Basic check to ensure the backup filename matches the entry number pattern
            if not backup_filename.startswith(f'entry_{entry_num}_backup_'):
                 logger.error(f"Backup filename '{backup_filename}' does not match entry number {entry_num}.")
                 print(colored("Error: Backup file name does not match the entry number.", 'red'))
                 return False

            if not backup_file.exists():
                logger.error(f"Backup file '{backup_file}' not found.")
                print(colored(f"Error: Backup file '{backup_filename}' not found.", 'red'))
                return False

            try:
                 # Lock the destination file exclusively during restore
                 with lock_file(entry_file, fcntl.LOCK_EX):
                     shutil.copy2(backup_file, entry_file) # copy2 preserves metadata
                 logger.info(f"Entry {entry_num} restored successfully from backup '{backup_filename}'.")
                 print(colored(f"Restored entry {entry_num} from backup '{backup_filename}'.", 'green'))
                 return True
            except Exception as e:
                 logger.error(f"Failed to restore entry {entry_num} from backup '{backup_filename}': {e}", exc_info=True)
                 print(colored(f"Error: Failed to restore entry {entry_num} from backup: {e}", 'red'))
                 return False

        # --- Methods related to the old single index are removed ---
        # Remove restore_latest_backup (old), restore_backup_by_timestamp (old) etc.
    ```

**Phase 3: Refactor `PasswordManager`**

*   **`password_manager/manager.py` (Major Refactoring):**
    ```python
    # password_manager/manager.py

    import sys
    import json
    import logging
    import getpass
    import os
    import base64 # Added
    import uuid   # Added
    from datetime import datetime # Added
    from typing import Optional, Dict, Any, List
    import shutil
    from colorama import Fore, Style # Style Added
    from termcolor import colored

    from .encryption import EncryptionManager
    from .entry_management import EntryManager # Modified Import Path
    from .password_generation import PasswordGenerator
    from .backup import BackupManager # Modified Import Path
    from .state_manager import StateManager # Added
    from .kinds import KINDS, get_kind_details, get_all_kinds, get_required_fields, get_kind_handler # Added
    from utils.key_derivation import derive_key_from_password
    from utils.checksum import calculate_checksum as calculate_script_checksum, verify_checksum as verify_script_checksum # Renamed for clarity
    from utils.password_prompt import prompt_for_password, prompt_existing_password, confirm_action
    from constants import (
        APP_DIR,
        PARENT_SEED_FILE as OLD_PARENT_SEED_FILENAME, # Rename old constant if needed
        SCRIPT_CHECKSUM_FILE,
        MIN_PASSWORD_LENGTH,
        MAX_PASSWORD_LENGTH,
        DEFAULT_PASSWORD_LENGTH,
        DEFAULT_SEED_BACKUP_FILENAME
    )
    import traceback
    import bcrypt
    from pathlib import Path
    from local_bip85.bip85 import BIP85
    from bip_utils import Bip39SeedGenerator
    from utils.fingerprint_manager import FingerprintManager
    from nostr.client import NostrClient

    logger = logging.getLogger(__name__)

    # --- Define constants for new structure ---
    ENTRIES_DIR_NAME = "entries"
    BACKUPS_DIR_NAME = "backups"
    PARENT_SEED_FILENAME = "parent_seed.enc"
    HASHED_PASSWORD_FILENAME = "hashed_password.enc"
    OLD_INDEX_FILENAME = 'seedpass_passwords_db.json.enc' # For migration check

    class PasswordManager:
        """
        Manages password entries, encryption, Nostr sync, and user interaction
        using individual entry files and 'kinds'.
        """

        def __init__(self):
            self.encryption_manager: Optional[EncryptionManager] = None
            self.entry_manager: Optional[EntryManager] = None
            self.password_generator: Optional[PasswordGenerator] = None
            self.backup_manager: Optional[BackupManager] = None
            self.fingerprint_manager: Optional[FingerprintManager] = None
            self.state_manager: Optional[StateManager] = None # Added
            self.parent_seed: Optional[str] = None
            self.bip85: Optional[BIP85] = None
            self.nostr_client: Optional[NostrClient] = None
            self.current_fingerprint: Optional[str] = None # Added for clarity
            self.fingerprint_dir: Optional[Path] = None # Added for clarity
            self.entries_dir: Optional[Path] = None # Added
            self.backups_dir: Optional[Path] = None # Added

            try:
                self.initialize_fingerprint_manager()
                self.setup_parent_seed() # This now includes selecting/adding fingerprint and initializing managers

                # Perform data migration check *after* managers are initialized for the selected fingerprint
                if self.fingerprint_dir: # Ensure fingerprint_dir is set
                     self.migrate_data_if_needed()

                # Initial synchronization with Nostr after setup/migration
                if self.nostr_client:
                    self.synchronize_with_nostr() # Optional: run sync on startup

            except Exception as e:
                 logger.critical(f"Critical error during PasswordManager initialization: {e}", exc_info=True)
                 print(colored(f"FATAL ERROR during startup: {e}. Check logs.", "red", attrs=["bold"]))
                 sys.exit(1)


        def initialize_fingerprint_manager(self):
            """Initializes the FingerprintManager."""
            try:
                self.fingerprint_manager = FingerprintManager(APP_DIR)
                logger.debug("FingerprintManager initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize FingerprintManager: {e}", exc_info=True)
                print(colored(f"Error: Failed to initialize FingerprintManager: {e}", 'red'))
                sys.exit(1)

        def setup_parent_seed(self) -> None:
            """Guides user through selecting or adding a fingerprint and initializes components."""
            fingerprints = self.fingerprint_manager.list_fingerprints()
            if fingerprints:
                self.select_or_add_fingerprint()
            else:
                print(colored("No existing SeedPass profiles (fingerprints) found.", 'yellow'))
                self.handle_new_seed_setup()

            # Ensure initialization happened after selection/creation
            if not self.current_fingerprint or not self.fingerprint_dir or not self.encryption_manager:
                 logger.critical("Fingerprint selection or initialization failed.")
                 print(colored("Error: Could not set up a valid SeedPass profile.", 'red'))
                 sys.exit(1)

        def select_or_add_fingerprint(self):
            """Prompts user to select existing fingerprint or add a new one."""
            try:
                print(colored("\nAvailable SeedPass Profiles (Fingerprints):", 'cyan'))
                fingerprints = self.fingerprint_manager.list_fingerprints()
                for idx, fp in enumerate(fingerprints, start=1):
                    print(colored(f"{idx}. {fp}", 'cyan'))

                print(colored(f"{len(fingerprints) + 1}. Add a new profile (generate or import seed)", 'cyan'))
                print(colored(f"{len(fingerprints) + 2}. Exit", 'cyan'))


                while True:
                    choice_str = input("Select a profile by number or choose an action: ").strip()
                    if not choice_str.isdigit():
                        print(colored("Invalid input. Please enter a number.", 'red'))
                        continue

                    choice = int(choice_str)
                    if 1 <= choice <= len(fingerprints):
                        selected_fingerprint = fingerprints[choice - 1]
                        self.select_fingerprint(selected_fingerprint)
                        break # Exit loop on valid selection
                    elif choice == len(fingerprints) + 1:
                        # Add a new fingerprint
                        new_fingerprint = self.add_new_fingerprint()
                        if new_fingerprint:
                            self.select_fingerprint(new_fingerprint) # Select the newly added one
                        else:
                            print(colored("Failed to add new profile. Exiting.", "red"))
                            sys.exit(1)
                        break # Exit loop
                    elif choice == len(fingerprints) + 2:
                         print(colored("Exiting.", "yellow"))
                         sys.exit(0)
                    else:
                        print(colored("Invalid selection.", 'red'))

            except Exception as e:
                logger.error(f"Error during fingerprint selection: {e}", exc_info=True)
                print(colored(f"Error: Failed to select profile: {e}", 'red'))
                sys.exit(1)

        def add_new_fingerprint(self) -> Optional[str]:
            """Guides user to add a new fingerprint/profile. Returns the new fingerprint or None."""
            try:
                print(colored("\n--- Add New SeedPass Profile ---", "yellow"))
                choice = input("Do you want to (1) Enter an existing 12-word seed or (2) Generate a new 12-word seed? (1/2): ").strip()
                new_fingerprint = None
                if choice == '1':
                    new_fingerprint = self.setup_existing_seed()
                elif choice == '2':
                    new_fingerprint = self.generate_new_seed()
                else:
                    print(colored("Invalid choice.", 'red'))
                    return None # Indicate failure

                if new_fingerprint:
                     # Don't automatically select here, let select_or_add_fingerprint handle it
                     print(colored(f"New profile with fingerprint '{new_fingerprint}' created.", 'green'))
                     return new_fingerprint
                else:
                     return None # Indicate failure

            except Exception as e:
                logger.error(f"Error adding new fingerprint: {e}", exc_info=True)
                print(colored(f"Error: Failed to add new profile: {e}", 'red'))
                return None

        def select_fingerprint(self, fingerprint: str) -> bool:
            """Sets the selected fingerprint as active and initializes all managers."""
            if self.fingerprint_manager.select_fingerprint(fingerprint):
                self.current_fingerprint = fingerprint
                self.fingerprint_dir = self.fingerprint_manager.get_current_fingerprint_dir()
                if not self.fingerprint_dir:
                    print(colored(f"Error: Fingerprint directory for {fingerprint} not found.", 'red'))
                    return False # Indicate failure

                # Setup encryption requires password for the selected fingerprint
                password = prompt_existing_password(f"Enter master password for profile '{fingerprint}': ")
                if not self.setup_encryption_manager(self.fingerprint_dir, password):
                    # setup_encryption_manager now handles verify_password internally
                    print(colored("Password verification failed. Cannot switch profile.", "red"))
                    # Reset state if needed
                    self.current_fingerprint = None
                    self.fingerprint_dir = None
                    self.encryption_manager = None
                    return False # Indicate failure

                # Define entry/backup dirs based on selected fingerprint
                self.entries_dir = self.fingerprint_dir / ENTRIES_DIR_NAME
                self.backups_dir = self.fingerprint_dir / BACKUPS_DIR_NAME
                self.entries_dir.mkdir(parents=True, exist_ok=True) # Ensure they exist
                self.backups_dir.mkdir(parents=True, exist_ok=True)

                # Load parent seed (requires encryption manager)
                if not self.load_parent_seed(self.fingerprint_dir):
                     # Reset state
                     self.current_fingerprint = None
                     self.fingerprint_dir = None
                     self.encryption_manager = None
                     return False # Indicate failure

                # Initialize BIP85 (requires parent seed)
                if not self.initialize_bip85():
                     return False # Indicate failure

                # Initialize other managers (requires encryption_manager, dirs, bip85 etc.)
                if not self.initialize_managers():
                    return False # Indicate failure

                print(colored(f"Profile '{fingerprint}' selected and ready.", 'green'))
                return True
            else:
                print(colored(f"Error: Profile (fingerprint) '{fingerprint}' not found.", 'red'))
                return False

        def setup_encryption_manager(self, fingerprint_dir: Path, password: str) -> bool:
            """Sets up EncryptionManager and verifies password. Returns True on success."""
            try:
                key = derive_key_from_password(password)
                self.encryption_manager = EncryptionManager(key, fingerprint_dir)
                logger.debug(f"EncryptionManager set up for {fingerprint_dir.name}.")

                # Verify password against stored hash
                if not self.verify_password(password):
                    self.encryption_manager = None # Clear invalid manager
                    return False # Indicate failure

                return True # Success
            except Exception as e:
                logger.error(f"Failed to set up EncryptionManager: {e}", exc_info=True)
                print(colored(f"Error: Failed to set up encryption: {e}", 'red'))
                self.encryption_manager = None
                return False

        def load_parent_seed(self, fingerprint_dir: Path) -> bool:
            """Loads and decrypts parent seed. Returns True on success."""
            if not self.encryption_manager:
                 logger.error("Cannot load parent seed: EncryptionManager not initialized.")
                 return False
            try:
                self.parent_seed = self.encryption_manager.decrypt_parent_seed()
                logger.debug(f"Parent seed loaded for profile {self.current_fingerprint}.")
                return True
            except Exception as e:
                # Decrypt_parent_seed already logs and prints errors
                logger.error(f"Failed to load parent seed for {self.current_fingerprint}: {e}", exc_info=False) # Avoid redundant stack trace
                print(colored(f"Error: Could not load the parent seed for this profile.", 'red'))
                self.parent_seed = None
                return False

        def initialize_bip85(self) -> bool:
            """Initializes BIP85 generator. Returns True on success."""
            if not self.parent_seed:
                 logger.error("Cannot initialize BIP85: Parent seed not loaded.")
                 return False
            try:
                seed_bytes = Bip39SeedGenerator(self.parent_seed).Generate()
                self.bip85 = BIP85(seed_bytes)
                logger.debug("BIP-85 initialized successfully.")
                return True
            except Exception as e:
                logger.error(f"Failed to initialize BIP-85: {e}", exc_info=True)
                print(colored(f"Error: Failed to initialize BIP-85: {e}", 'red'))
                self.bip85 = None
                return False

        def initialize_managers(self) -> bool:
            """Initializes EntryManager, PasswordGenerator, BackupManager, StateManager, NostrClient."""
            # Check prerequisites
            if not all([self.encryption_manager, self.fingerprint_dir, self.entries_dir, self.backups_dir, self.parent_seed, self.bip85, self.current_fingerprint]):
                logger.error("Cannot initialize managers: Prerequisites missing.")
                return False

            try:
                # Initialize State Manager first
                self.state_manager = StateManager(self.fingerprint_dir)

                self.entry_manager = EntryManager(
                    encryption_manager=self.encryption_manager,
                    fingerprint_dir=self.fingerprint_dir
                    # entries_dir passed via fingerprint_dir in its init
                )

                self.password_generator = PasswordGenerator(
                    encryption_manager=self.encryption_manager, # Needed for derive_seed_from_mnemonic
                    parent_seed=self.parent_seed,
                    bip85=self.bip85
                )

                self.backup_manager = BackupManager(
                     fingerprint_dir=self.fingerprint_dir
                     # backup_dir passed via fingerprint_dir in its init
                )

                # Initialize NostrClient (ensure NostrClient init is updated)
                self.nostr_client = NostrClient(
                    encryption_manager=self.encryption_manager,
                    fingerprint=self.current_fingerprint,
                    # Pass PasswordManager instance for callbacks if needed by EventHandler
                    # password_manager_ref=self
                )

                logger.debug(f"All managers initialized for profile {self.current_fingerprint}.")
                return True

            except Exception as e:
                logger.error(f"Failed to initialize managers: {e}", exc_info=True)
                print(colored(f"Error: Failed to initialize managers: {e}", 'red'))
                # Clean up partially initialized managers?
                self.state_manager = None
                self.entry_manager = None
                self.password_generator = None
                self.backup_manager = None
                self.nostr_client = None
                return False

        # --- Seed Setup Handlers (Modified) ---

        def handle_new_seed_setup(self) -> None:
            """Handles setup when no profiles exist."""
            print(colored("Welcome to SeedPass! Let's create your first profile.", 'yellow'))
            new_fingerprint = self.add_new_fingerprint() # This handles generate/import choice
            if new_fingerprint:
                 self.select_fingerprint(new_fingerprint) # Select and initialize
            else:
                 print(colored("Failed to create initial profile. Exiting.", "red"))
                 sys.exit(1)


        def setup_existing_seed(self) -> Optional[str]:
            """Handles importing an existing seed phrase."""
            try:
                parent_seed = getpass.getpass(prompt='Enter your 12-word BIP-39 seed phrase: ').strip()
                if not self.validate_bip85_seed(parent_seed):
                    print(colored("Error: Invalid 12-word seed phrase format.", 'red'))
                    return None

                fingerprint = self.fingerprint_manager.add_fingerprint(parent_seed)
                if not fingerprint:
                    print(colored("Error: Failed to add profile for the provided seed (maybe it already exists?).", 'red'))
                    # FingerprintManager logs specific error
                    return None # Could be duplicate or generation failure

                fingerprint_dir = self.fingerprint_manager.get_fingerprint_directory(fingerprint)
                if not fingerprint_dir:
                    print(colored("Error: Failed to create profile directory.", 'red'))
                    # Attempt cleanup?
                    self.fingerprint_manager.remove_fingerprint(fingerprint)
                    return None

                print(colored(f"Profile '{fingerprint}' created. Now set its master password.", 'green'))
                # Need to save the seed and password hash *for this new fingerprint*
                # Temporarily set context to save correctly
                temp_fp_dir = self.fingerprint_dir # Save old context if any
                self.fingerprint_dir = fingerprint_dir
                if not self.save_seed_and_password(parent_seed, fingerprint_dir):
                     print(colored("Error saving seed or password. Rolling back profile creation.", "red"))
                     self.fingerprint_manager.remove_fingerprint(fingerprint) # Cleanup
                     self.fingerprint_dir = temp_fp_dir # Restore context
                     return None
                self.fingerprint_dir = temp_fp_dir # Restore context

                return fingerprint

            except KeyboardInterrupt:
                print(colored("\nOperation cancelled by user.", 'yellow'))
                return None
            except Exception as e:
                 logger.error(f"Error setting up existing seed: {e}", exc_info=True)
                 print(colored(f"Error importing seed: {e}", 'red'))
                 return None


        def generate_new_seed(self) -> Optional[str]:
            """Handles generating a new seed phrase."""
            try:
                new_seed = self.generate_bip85_seed()
                print(colored("\n=== Your New 12-Word Master Seed Phrase ===", 'yellow', attrs=['bold']))
                print(colored(new_seed, 'cyan'))
                print(colored("=============================================", 'yellow', attrs=['bold']))
                print(colored("WRITE THIS DOWN NOW!", 'red', attrs=['blink']))
                print(colored("Store it securely offline. Losing this means losing all derived passwords.", 'red'))
                print(colored("Do not store it digitally unless you understand the risks.", 'red'))

                if not confirm_action("\nHave you securely written down this seed phrase? (Y/N): "):
                    print(colored("Seed generation cancelled. Please run again when ready.", 'yellow'))
                    return None

                fingerprint = self.fingerprint_manager.add_fingerprint(new_seed)
                if not fingerprint:
                    print(colored("Error: Failed to add profile for the new seed.", 'red'))
                    return None

                fingerprint_dir = self.fingerprint_manager.get_fingerprint_directory(fingerprint)
                if not fingerprint_dir:
                    print(colored("Error: Failed to create profile directory.", 'red'))
                    self.fingerprint_manager.remove_fingerprint(fingerprint)
                    return None

                print(colored(f"\nProfile '{fingerprint}' created. Now set its master password.", 'green'))
                 # Temporarily set context to save correctly
                temp_fp_dir = self.fingerprint_dir # Save old context if any
                self.fingerprint_dir = fingerprint_dir
                if not self.save_seed_and_password(new_seed, fingerprint_dir):
                     print(colored("Error saving seed or password. Rolling back profile creation.", "red"))
                     self.fingerprint_manager.remove_fingerprint(fingerprint) # Cleanup
                     self.fingerprint_dir = temp_fp_dir # Restore context
                     return None
                self.fingerprint_dir = temp_fp_dir # Restore context

                return fingerprint

            except KeyboardInterrupt:
                print(colored("\nOperation cancelled by user.", 'yellow'))
                return None
            except Exception as e:
                 logger.error(f"Error generating new seed: {e}", exc_info=True)
                 print(colored(f"Error generating seed: {e}", 'red'))
                 return None

        def save_seed_and_password(self, seed: str, fingerprint_dir: Path) -> bool:
            """Internal helper to prompt for password, save hash, and save encrypted seed."""
            try:
                password = prompt_for_password() # Prompts for new + confirm
                # Derive key and setup temporary encryption manager for saving
                key = derive_key_from_password(password)
                temp_enc_mgr = EncryptionManager(key, fingerprint_dir)

                # Store hashed password within the target fingerprint dir
                if not self._store_hashed_password(password, fingerprint_dir):
                     raise RuntimeError("Failed to store hashed password.")

                # Encrypt and save parent seed within the target fingerprint dir
                temp_enc_mgr.encrypt_parent_seed(seed) # encrypt_parent_seed handles saving to file

                logger.info(f"Seed and password hash saved successfully for profile {fingerprint_dir.name}.")
                return True
            except Exception as e:
                logger.error(f"Failed to encrypt/save seed or password hash for {fingerprint_dir.name}: {e}", exc_info=True)
                # Cleanup potentially created hash file? Difficult to do atomically here.
                return False


        # --- Core Entry Operations (NEW) ---

        def add_entry(self, kind: str, entry_data: Dict[str, Any]) -> Optional[int]:
            """
            Adds a new entry of the specified kind, saves locally, and posts to Nostr.

            :param kind: The type of entry (must exist in KINDS).
            :param entry_data: The data payload for the entry.
            :return: The assigned entry number if successful, None otherwise.
            """
            if not all([self.entry_manager, self.encryption_manager, self.state_manager, self.nostr_client, self.current_fingerprint]):
                logger.error("Cannot add entry: PasswordManager not fully initialized.")
                print(colored("Error: System not ready. Please restart.", "red"))
                return None

            kind_details = get_kind_details(kind)
            if not kind_details:
                logger.error(f"Attempted to add entry with unknown kind: {kind}")
                print(colored(f"Error: Unknown entry type '{kind}'.", "red"))
                return None

            # Add necessary metadata
            entry_num = self.entry_manager.get_next_entry_num()
            timestamp = datetime.utcnow().isoformat() + 'Z'
            checksum = self.entry_manager.calculate_checksum(entry_data) # Checksum of the *data* part

            # Handle bip85 index for generated passwords
            bip85_index = None
            if kind == "generated_password":
                # Check if bip85_index was passed in entry_data (e.g. during migration)
                if "bip85_index" not in entry_data:
                    bip85_index = self.state_manager.get_next_generated_password_index()
                    entry_data["bip85_index"] = bip85_index # Add it to the data part
                    # Recalculate checksum if index was added
                    checksum = self.entry_manager.calculate_checksum(entry_data)
                else:
                    bip85_index = entry_data["bip85_index"]
                    # Ensure state manager is updated if migrating an index higher than current max
                    last_known_index = self.state_manager.get_last_generated_password_index()
                    if bip85_index > last_known_index:
                        self.state_manager.set_last_generated_password_index(bip85_index)


            # Encrypt sensitive fields within entry_data before creating the full entry JSON
            # Example: encrypt 'password' for stored_password, 'content' for note
            if kind == "stored_password" and "password" in entry_data:
                try:
                    pwd_bytes = entry_data["password"].encode('utf-8')
                    encrypted_pwd_bytes = self.encryption_manager.encrypt_data(pwd_bytes)
                    entry_data["password"] = base64.b64encode(encrypted_pwd_bytes).decode('utf-8') # Store as base64 string
                    checksum = self.entry_manager.calculate_checksum(entry_data) # Recalculate checksum
                except Exception as enc_err:
                    logger.error(f"Failed to encrypt password for stored_password entry {entry_num}: {enc_err}", exc_info=True)
                    print(colored("Error encrypting password data.", "red"))
                    return None
            elif kind == "note" and "content" in entry_data:
                 try:
                    content_bytes = entry_data["content"].encode('utf-8')
                    encrypted_content_bytes = self.encryption_manager.encrypt_data(content_bytes)
                    entry_data["content"] = base64.b64encode(encrypted_content_bytes).decode('utf-8') # Store as base64 string
                    checksum = self.entry_manager.calculate_checksum(entry_data) # Recalculate checksum
                 except Exception as enc_err:
                    logger.error(f"Failed to encrypt content for note entry {entry_num}: {enc_err}", exc_info=True)
                    print(colored("Error encrypting note data.", "red"))
                    return None


            # Construct the full entry structure (to be encrypted)
            full_entry = {
                "entry_num": entry_num,
                "fingerprint": self.current_fingerprint,
                "kind": kind,
                "data": entry_data, # Contains potentially pre-encrypted fields
                "timestamp": timestamp, # UTC timestamp of creation/last update
                "metadata": {
                    "created_at": timestamp, # Keep original creation time separate? maybe not needed.
                    "updated_at": timestamp,
                    "checksum": checksum # Checksum of the 'data' part
                }
            }

            # Add bip85_index to top level for generated_password for easier access if needed
            # This is somewhat redundant but might be useful for retrieval/display logic.
            if kind == "generated_password":
                full_entry["bip85_index"] = bip85_index

            try:
                # Encrypt the entire entry structure
                entry_json = json.dumps(full_entry).encode('utf-8')
                encrypted_entry_data = self.encryption_manager.encrypt_data(entry_json)

                # Save the encrypted entry locally
                if not self.entry_manager.save_entry(entry_num, encrypted_entry_data):
                    # EntryManager logs the error
                    print(colored(f"Error: Failed to save entry {entry_num} locally.", 'red'))
                    # Potential rollback needed? Difficult state.
                    return None

                # Create a backup of the newly saved entry
                self.backup_manager.create_backup_for_entry(entry_num)

                # Post the encrypted entry to Nostr
                # Use a unique identifier ('d' tag) for replaceable events
                identifier = f"{kind_details['identifier_tag']}{entry_num}"
                nostr_kind_int = kind_details['nostr_kind']
                self.nostr_client.publish_entry(
                     encrypted_entry_data=encrypted_entry_data, # Already encrypted full entry
                     nostr_kind=nostr_kind_int,
                     d_tag=identifier
                 )

                logger.info(f"Entry {entry_num} (Kind: {kind}, ID: {identifier}) added locally and posted to Nostr.")
                print(colored(f"Entry {entry_num} added successfully.", 'green'))
                return entry_num

            except Exception as e:
                logger.error(f"Failed during final steps of adding entry {entry_num}: {e}", exc_info=True)
                print(colored(f"Error: Failed to complete adding entry {entry_num}: {e}", 'red'))
                # Attempt to clean up the saved file if posting failed?
                # self.entry_manager.delete_entry_file(entry_num) # Risky if Nostr post *did* succeed partially
                return None


        def modify_entry(self, entry_num: int, updated_data_fields: Dict[str, Any]) -> bool:
            """
            Modifies an existing entry, saves locally, and posts update to Nostr.

            :param entry_num: The number of the entry to modify.
            :param updated_data_fields: Dictionary containing only the fields to update within the 'data' part.
            :return: True if successful, False otherwise.
            """
            if not all([self.entry_manager, self.encryption_manager, self.nostr_client]):
                logger.error("Cannot modify entry: PasswordManager not fully initialized.")
                return False

            # Load existing entry
            existing_entry = self.entry_manager.load_entry(entry_num)
            if not existing_entry:
                print(colored(f"Error: Entry {entry_num} not found.", 'red'))
                return False

            kind = existing_entry.get("kind")
            kind_details = get_kind_details(kind)
            if not kind_details:
                 logger.error(f"Cannot modify entry {entry_num}: Unknown kind '{kind}' found in loaded data.")
                 print(colored(f"Error: Cannot modify entry {entry_num} due to corrupted kind.", 'red'))
                 return False

            # Create backup before modifying
            self.backup_manager.create_backup_for_entry(entry_num)

            # Update the 'data' part
            original_data = existing_entry.get("data", {})

            # Decrypt sensitive fields *before* updating if necessary
            # Example: Decrypt 'password' for stored_password, 'content' for note
            if kind == "stored_password" and "password" in original_data:
                try:
                    pwd_b64 = original_data["password"]
                    pwd_bytes = self.encryption_manager.decrypt_data(base64.b64decode(pwd_b64))
                    original_data["password"] = pwd_bytes.decode('utf-8') # Temporarily store decrypted for update logic
                except Exception as dec_err:
                    logger.error(f"Failed to decrypt password for modification in entry {entry_num}: {dec_err}", exc_info=True)
                    print(colored("Error preparing password field for modification.", "red"))
                    return False
            elif kind == "note" and "content" in original_data:
                 try:
                    content_b64 = original_data["content"]
                    content_bytes = self.encryption_manager.decrypt_data(base64.b64decode(content_b64))
                    original_data["content"] = content_bytes.decode('utf-8') # Temporarily store decrypted
                 except Exception as dec_err:
                    logger.error(f"Failed to decrypt content for modification in entry {entry_num}: {dec_err}", exc_info=True)
                    print(colored("Error preparing note content for modification.", "red"))
                    return False

            # Apply the updates from updated_data_fields
            original_data.update(updated_data_fields)

            # Re-encrypt sensitive fields *after* updating
            if kind == "stored_password" and "password" in original_data:
                try:
                    pwd_bytes = original_data["password"].encode('utf-8')
                    encrypted_pwd_bytes = self.encryption_manager.encrypt_data(pwd_bytes)
                    original_data["password"] = base64.b64encode(encrypted_pwd_bytes).decode('utf-8') # Store as base64 string again
                except Exception as enc_err:
                    logger.error(f"Failed to re-encrypt password for stored_password entry {entry_num}: {enc_err}", exc_info=True)
                    print(colored("Error encrypting updated password data.", "red"))
                    return False
            elif kind == "note" and "content" in original_data:
                 try:
                    content_bytes = original_data["content"].encode('utf-8')
                    encrypted_content_bytes = self.encryption_manager.encrypt_data(content_bytes)
                    original_data["content"] = base64.b64encode(encrypted_content_bytes).decode('utf-8') # Store as base64 string again
                 except Exception as enc_err:
                    logger.error(f"Failed to re-encrypt content for note entry {entry_num}: {enc_err}", exc_info=True)
                    print(colored("Error encrypting updated note data.", "red"))
                    return False


            # Update timestamp and recalculate checksum
            new_timestamp = datetime.utcnow().isoformat() + 'Z'
            new_checksum = self.entry_manager.calculate_checksum(original_data)

            # Update the full entry structure
            existing_entry["data"] = original_data # Put potentially re-encrypted data back
            existing_entry["timestamp"] = new_timestamp
            if "metadata" not in existing_entry: existing_entry["metadata"] = {}
            existing_entry["metadata"]["updated_at"] = new_timestamp
            existing_entry["metadata"]["checksum"] = new_checksum

            try:
                 # Encrypt the updated full entry
                 entry_json = json.dumps(existing_entry).encode('utf-8')
                 encrypted_entry_data = self.encryption_manager.encrypt_data(entry_json)

                 # Save locally
                 if not self.entry_manager.save_entry(entry_num, encrypted_entry_data):
                     print(colored(f"Error: Failed to save updated entry {entry_num} locally.", 'red'))
                     return False

                 # Post update to Nostr (as a replaceable event)
                 identifier = f"{kind_details['identifier_tag']}{entry_num}"
                 nostr_kind_int = kind_details['nostr_kind']
                 self.nostr_client.publish_entry(
                     encrypted_entry_data=encrypted_entry_data,
                     nostr_kind=nostr_kind_int,
                     d_tag=identifier
                 )

                 logger.info(f"Entry {entry_num} modified locally and update posted to Nostr.")
                 print(colored(f"Entry {entry_num} updated successfully.", 'green'))
                 return True

            except Exception as e:
                 logger.error(f"Failed during final steps of modifying entry {entry_num}: {e}", exc_info=True)
                 print(colored(f"Error: Failed to complete modifying entry {entry_num}: {e}", 'red'))
                 # Consider attempting to restore the backup?
                 return False


        def delete_entry(self, entry_num: int) -> bool:
            """Deletes an entry locally and posts a deletion marker to Nostr."""
            if not all([self.entry_manager, self.nostr_client]):
                logger.error("Cannot delete entry: PasswordManager not fully initialized.")
                return False

            # Load entry to get kind details for Nostr deletion marker
            entry_data = self.entry_manager.load_entry(entry_num)
            if not entry_data:
                 print(colored(f"Warning: Entry {entry_num} not found locally. Cannot delete.", 'yellow'))
                 # Maybe still try to post deletion to Nostr?
                 # For now, assume local file must exist.
                 return False

            kind = entry_data.get("kind")
            kind_details = get_kind_details(kind)
            if not kind_details:
                logger.warning(f"Cannot determine kind for entry {entry_num} during deletion.")
                # Proceed with file deletion, but maybe skip Nostr?
            else:
                # Create backup before deleting
                self.backup_manager.create_backup_for_entry(entry_num)


            # Delete local file first
            if not self.entry_manager.delete_entry_file(entry_num):
                print(colored(f"Error: Failed to delete local file for entry {entry_num}.", 'red'))
                # Don't post deletion to Nostr if local delete failed
                return False

            # Post deletion marker to Nostr (e.g., Kind 5 event referencing the replaceable event)
            if kind_details:
                 identifier = f"{kind_details['identifier_tag']}{entry_num}"
                 nostr_kind_to_delete = kind_details['nostr_kind']
                 # We need the event ID of the event we want to delete if using Kind 5
                 # Fetching the event ID first might be complex/slow.
                 # Alternative: Publish an empty content replaceable event? Easier.
                 # Let's publish an empty content update for the replaceable event.
                 # Note: Relays might prune empty events faster. Kind 5 is more explicit.
                 # Decision: Publish empty content replaceable event for simplicity now.
                 try:
                     # Create a dummy entry structure with empty data for checksum
                     empty_data_checksum = self.entry_manager.calculate_checksum({})
                     tombstone_entry = {
                        "entry_num": entry_num,
                        "fingerprint": self.current_fingerprint,
                        "kind": kind,
                        "data": {}, # Empty data
                        "timestamp": datetime.utcnow().isoformat() + 'Z',
                        "metadata": {
                           "deleted": True, # Add deletion flag
                           "updated_at": datetime.utcnow().isoformat() + 'Z',
                           "checksum": empty_data_checksum
                         }
                     }
                     entry_json = json.dumps(tombstone_entry).encode('utf-8')
                     encrypted_tombstone_data = self.encryption_manager.encrypt_data(entry_json)

                     self.nostr_client.publish_entry(
                         encrypted_entry_data=encrypted_tombstone_data,
                         nostr_kind=nostr_kind_to_delete,
                         d_tag=identifier,
                         is_deletion=True # Add flag for logging/handling in client
                     )
                     logger.info(f"Deletion marker for entry {entry_num} (ID: {identifier}) posted to Nostr.")

                 except Exception as e:
                      logger.error(f"Failed to post deletion marker to Nostr for entry {entry_num}: {e}", exc_info=True)
                      # Local file is already deleted. Log inconsistency.
                      print(colored(f"Warning: Local entry {entry_num} deleted, but failed to post deletion to Nostr.", 'yellow'))
                      # Still return True as local deletion succeeded? Or False due to incomplete operation?
                      # Let's return True as the primary goal (local deletion) was met.

            print(colored(f"Entry {entry_num} deleted successfully.", 'green'))
            return True


        def list_all_entries(self) -> List[Dict[str, Any]]:
            """Loads all local entries and returns them as a list of dictionaries."""
            if not self.entry_manager: return []
            all_entries = []
            entry_nums = self.entry_manager.list_all_entry_nums()
            for num in entry_nums:
                entry = self.entry_manager.load_entry(num)
                if entry:
                    all_entries.append(entry)
            return all_entries

        def process_entry(self, entry: Dict[str, Any]):
            """
            Processes an individual entry based on its kind using the registered handler.

            :param entry: The entry data dictionary (decrypted).
            """
            if not self.encryption_manager or not self.password_generator:
                 logger.error("Cannot process entry: Required managers not initialized.")
                 return

            try:
                kind = entry.get('kind')
                data = entry.get('data', {})
                fingerprint = entry.get('fingerprint')
                entry_num = entry.get('entry_num', 'N/A')

                handler = get_kind_handler(kind)
                if handler:
                    # Pass necessary components to the handler via kwargs
                    handler_kwargs = {
                        "encryption_manager": self.encryption_manager,
                        "password_generator": self.password_generator,
                        # Add other managers if handlers need them
                    }
                    handler(data, fingerprint, **handler_kwargs)
                    logger.debug(f"Processed entry {entry_num} of kind '{kind}'.")
                else:
                    logger.warning(f"No handler found for kind '{kind}'. Skipping processing for entry {entry_num}.")
                    print(colored(f"Warning: Cannot process entry {entry_num} - unknown type '{kind}'.", "yellow"))

            except Exception as e:
                logger.error(f"Failed to process entry {entry.get('entry_num', 'N/A')}: {e}", exc_info=True)
                print(colored(f"Error processing entry {entry.get('entry_num', 'N/A')}: {e}", 'red'))

        def synchronize_with_nostr(self):
            """Fetches entries from Nostr and updates local storage."""
            if not self.nostr_client or not self.entry_manager or not self.encryption_manager or not self.state_manager:
                logger.error("Cannot synchronize: Required managers not initialized.")
                print(colored("Error: Cannot synchronize with Nostr - system not ready.", "red"))
                return

            print(colored("Synchronizing with Nostr... Please wait.", "yellow"))
            try:
                last_sync_time = self.state_manager.get_last_nostr_sync_time()
                # Fetch events since last sync
                # Modify fetch_all_entries_async in NostrClient to accept a 'since' timestamp
                # Use a reasonable limit initially, might need pagination for huge histories
                nostr_events = self.nostr_client.fetch_all_entries_sync(since=last_sync_time, limit=500) # Sync version

                if nostr_events is None: # Indicates an error during fetch
                    print(colored("Synchronization failed: Could not retrieve data from Nostr.", "red"))
                    return

                if not nostr_events:
                     print(colored("No new entries found on Nostr since last sync.", "green"))
                     # Still update sync time? Yes, confirms we checked.
                     self.state_manager.set_last_nostr_sync_time(int(time.time()))
                     return

                newest_event_time = last_sync_time
                processed_count = 0
                updated_count = 0
                new_count = 0
                deleted_count = 0
                error_count = 0

                # Process newest events first
                for event in sorted(nostr_events, key=lambda e: e.created_at, reverse=True):
                    if event.created_at > newest_event_time:
                        newest_event_time = event.created_at

                    try:
                        encrypted_content_b64 = event.content
                        encrypted_content_bytes = base64.b64decode(encrypted_content_b64)
                        decrypted_content_bytes = self.encryption_manager.decrypt_data(encrypted_content_bytes)
                        entry = json.loads(decrypted_content_bytes.decode('utf-8'))

                        entry_num = entry.get('entry_num')
                        remote_checksum = entry.get('metadata', {}).get('checksum')
                        is_deleted = entry.get('metadata', {}).get('deleted', False) # Check deletion flag

                        if entry_num is None or remote_checksum is None:
                            logger.warning(f"Skipping invalid Nostr event (ID: {event.id}): Missing entry_num or checksum.")
                            error_count += 1
                            continue

                        local_entry_path = self.entry_manager._get_entry_path(entry_num) # Use internal helper

                        if is_deleted:
                             # Handle deletion marker
                             if local_entry_path.exists():
                                 print(colored(f"Processing deletion for entry {entry_num}...", "magenta"))
                                 # Optional: backup before deleting based on sync? Risky.
                                 # self.backup_manager.create_backup_for_entry(entry_num)
                                 if self.entry_manager.delete_entry_file(entry_num):
                                     deleted_count += 1
                                 else:
                                     error_count += 1 # Failed local delete
                             else:
                                 logger.debug(f"Received deletion marker for already deleted/non-existent entry {entry_num}.")
                             continue # Don't process further if deleted


                        # Compare with local version
                        if local_entry_path.exists():
                             local_checksum = self.entry_manager.get_entry_checksum(entry_num)
                             if local_checksum is None: # Error reading local checksum
                                 logger.warning(f"Could not read local checksum for entry {entry_num}. Skipping update check.")
                                 error_count += 1
                                 continue

                             if local_checksum != remote_checksum:
                                 # Remote is newer or different, update local
                                 print(colored(f"Updating entry {entry_num} from Nostr...", "yellow"))
                                 if self.entry_manager.save_entry(entry_num, encrypted_content_bytes):
                                     updated_count += 1
                                     # Optional: process updated entry immediately?
                                     # self.process_entry(entry)
                                 else:
                                     error_count += 1 # Failed local save
                             else:
                                 # Checksums match, no update needed
                                 logger.debug(f"Entry {entry_num} is already up-to-date.")
                        else:
                             # Entry exists on Nostr but not locally, save it
                             print(colored(f"Downloading new entry {entry_num} from Nostr...", "green"))
                             if self.entry_manager.save_entry(entry_num, encrypted_content_bytes):
                                 new_count += 1
                                 # Optional: process new entry immediately?
                                 # self.process_entry(entry)
                             else:
                                 error_count += 1 # Failed local save

                        processed_count +=1

                    except (base64.binascii.Error, json.JSONDecodeError) as decode_err:
                        logger.error(f"Failed to decode/decrypt Nostr event content (ID: {event.id}): {decode_err}")
                        error_count += 1
                    except InvalidToken: # From decryption
                        logger.error(f"Decryption failed for Nostr event content (ID: {event.id}). Invalid key or corrupt data?")
                        error_count += 1
                    except Exception as proc_err:
                        logger.error(f"Unexpected error processing Nostr event (ID: {event.id}): {proc_err}", exc_info=True)
                        error_count += 1

                # Update last sync time to the timestamp of the newest processed event
                # Add a small buffer (1 sec) to avoid missing events published exactly at sync time?
                if newest_event_time > last_sync_time:
                     self.state_manager.set_last_nostr_sync_time(newest_event_time + 1)

                print(colored(f"Synchronization complete. New: {new_count}, Updated: {updated_count}, Deleted: {deleted_count}, Errors: {error_count}", "blue"))

            except Exception as e:
                logger.error(f"Failed to synchronize with Nostr: {e}", exc_info=True)
                print(colored(f"Error: Failed to synchronize with Nostr: {e}", 'red'))


        def migrate_data_if_needed(self):
            """Checks for the old index file and performs migration if found."""
            if not self.fingerprint_dir: return # Should not happen if called correctly

            old_index_path = self.fingerprint_dir / OLD_INDEX_FILENAME
            if not old_index_path.exists():
                logger.info("Old index file not found. Migration not required.")
                return

            print(colored(f"Old index file found for profile {self.current_fingerprint}. Migrating to new format...", "yellow"))

            # Backup the old index file before migration
            try:
                 timestamp = int(time.time())
                 backup_old_index_path = self.backups_dir / f"{OLD_INDEX_FILENAME}.backup_{timestamp}"
                 shutil.copy2(old_index_path, backup_old_index_path)
                 logger.info(f"Backed up old index file to {backup_old_index_path}")
            except Exception as backup_err:
                 logger.error(f"Failed to backup old index file before migration: {backup_err}", exc_info=True)
                 print(colored("Error: Could not back up old data file. Migration aborted.", "red"))
                 return

            try:
                # Load old data (uses EncryptionManager correctly)
                old_data = self.encryption_manager.load_json_data(old_index_path.relative_to(self.fingerprint_dir))
                old_passwords = old_data.get('passwords', {})

                if not old_passwords:
                     print(colored("Old index file is empty or invalid. No entries to migrate.", "yellow"))
                     # Optionally delete the empty/invalid old file?
                     # old_index_path.unlink()
                     return

                migrated_count = 0
                error_count = 0
                print(colored(f"Found {len(old_passwords)} entries in old format. Starting migration...", "cyan"))

                # Iterate through old entries and use add_entry logic
                # Note: old index was string, new entry_num is int
                for old_idx_str, old_entry_data in old_passwords.items():
                    try:
                        old_idx = int(old_idx_str)
                        # Map old fields to new 'generated_password' kind structure
                        new_entry_data = {
                            "title": old_entry_data.get('website', f"Migrated Entry {old_idx}"),
                            "username": old_entry_data.get('username', ''),
                            "email": "", # Old format didn't have email
                            "url": old_entry_data.get('url', ''),
                            "length": old_entry_data.get('length'),
                            "bip85_index": old_idx # Use the old index as the bip85_index
                            # Blacklisted status? Decide how to handle. Maybe add to notes?
                        }
                        # Validate required fields for generated_password
                        if new_entry_data["length"] is None:
                             logger.warning(f"Skipping migration for old index {old_idx}: Missing 'length'. Data: {old_entry_data}")
                             error_count += 1
                             continue

                        # Use the add_entry method which handles saving and posting to nostr
                        result_entry_num = self.add_entry(kind="generated_password", entry_data=new_entry_data)

                        if result_entry_num is not None:
                            migrated_count += 1
                            print(f"  Migrated old index {old_idx} -> new entry {result_entry_num}")
                        else:
                            error_count += 1
                            print(colored(f"  Failed to migrate old index {old_idx}", "red"))
                            # Should we stop migration on first error? Or continue? Let's continue.
                    except ValueError:
                         logger.warning(f"Skipping migration for invalid old index key: {old_idx_str}")
                         error_count += 1
                         continue
                    except Exception as migrate_entry_err:
                         logger.error(f"Error migrating old index {old_idx_str}: {migrate_entry_err}", exc_info=True)
                         error_count += 1
                         print(colored(f"  Error migrating old index {old_idx_str}", "red"))


                print(colored(f"Migration finished. Migrated: {migrated_count}, Errors: {error_count}", "blue"))

                if error_count == 0:
                     # Optionally delete the old index file after successful migration
                     if confirm_action("Migration successful. Delete the old index file? (Y/N): "):
                         try:
                             with lock_file(old_index_path, fcntl.LOCK_EX):
                                  old_index_path.unlink()
                             print(colored("Old index file deleted.", "green"))
                         except Exception as del_err:
                             logger.error(f"Failed to delete old index file {old_index_path}: {del_err}", exc_info=True)
                             print(colored("Error: Failed to delete old index file.", "red"))
                else:
                     print(colored("Migration completed with errors. Please review logs.", "yellow"))
                     print(colored("The old index file has NOT been deleted.", "yellow"))


            except Exception as e:
                logger.error(f"Critical error during data migration: {e}", exc_info=True)
                print(colored(f"Error: Failed to migrate data: {e}. Old data remains.", 'red'))

        # --- Utility Methods (Password Hashing, Seed Validation, etc.) ---

        def validate_bip85_seed(self, seed: str) -> bool:
            """Validates the provided BIP-39 seed phrase (12 words)."""
            try:
                words = seed.split()
                if len(words) == 12: # Basic check
                     # Add bip_utils validation? Bip39MnemonicValidator(seed).IsValid() - needs wordlist
                     return True
                return False
            except Exception:
                 return False

        def generate_bip85_seed(self) -> str:
            """Generates a new 12-word BIP-39 seed phrase."""
            try:
                # Generate entropy suitable for a 12-word mnemonic (128 bits / 16 bytes)
                entropy = os.urandom(16)
                mnemonic = Bip39MnemonicGenerator(Bip39Languages.ENGLISH).FromEntropy(entropy)
                return mnemonic.ToStr()
            except Exception as e:
                logger.error(f"Failed to generate BIP-39 seed: {e}", exc_info=True)
                print(colored(f"Error: Failed to generate seed: {e}", 'red'))
                sys.exit(1)


        def verify_password(self, password: str) -> bool:
            """Verifies provided password against the stored hash for the current fingerprint."""
            if not self.fingerprint_dir:
                 logger.error("Cannot verify password, fingerprint directory not set.")
                 return False
            hashed_password_file = self.fingerprint_dir / HASHED_PASSWORD_FILENAME
            if not hashed_password_file.exists():
                logger.error(f"Hashed password file not found: {hashed_password_file}")
                print(colored("Error: Password hash file missing for this profile.", 'red'))
                return False
            try:
                with lock_file(hashed_password_file, fcntl.LOCK_SH):
                    with open(hashed_password_file, 'rb') as f:
                        stored_hash = f.read()
                # Normalize entered password before checking
                normalized_password = unicodedata.normalize('NFKD', password).strip()
                is_correct = bcrypt.checkpw(normalized_password.encode('utf-8'), stored_hash)
                if is_correct:
                    logger.debug("Password verification successful.")
                else:
                    logger.warning("Password verification failed.")
                return is_correct
            except ValueError as e: # Handle potential bcrypt errors like "invalid salt"
                 logger.error(f"Error during password check (likely invalid hash file): {e}")
                 print(colored("Error: Problem verifying password - hash file might be corrupt.", 'red'))
                 return False
            except Exception as e:
                logger.error(f"Error verifying password: {e}", exc_info=True)
                print(colored(f"Error: Failed to verify password: {e}", 'red'))
                return False

        def _store_hashed_password(self, password: str, fingerprint_dir: Path) -> bool:
            """Hashes and stores password for a specific fingerprint directory."""
            hashed_password_file = fingerprint_dir / HASHED_PASSWORD_FILENAME
            try:
                 # Normalize password before hashing
                 normalized_password = unicodedata.normalize('NFKD', password).strip()
                 hashed = bcrypt.hashpw(normalized_password.encode('utf-8'), bcrypt.gensalt())
                 with lock_file(hashed_password_file, fcntl.LOCK_EX):
                     with open(hashed_password_file, 'wb') as f:
                         f.write(hashed)
                     os.chmod(hashed_password_file, 0o600)
                 logger.info(f"Password hash stored for profile {fingerprint_dir.name}.")
                 return True
            except Exception as e:
                logger.error(f"Failed to store hashed password for {fingerprint_dir.name}: {e}", exc_info=True)
                print(colored(f"Error: Failed to store password hash: {e}", 'red'))
                return False

        # --- CLI Handler Methods (Adapting old ones) ---

        def handle_add_entry_cli(self) -> None:
             """Handles the CLI interaction for adding a new entry."""
             print(colored("\n--- Add New Entry ---", "yellow"))
             available_kinds = get_all_kinds()
             print("Available entry types:")
             for i, kind_name in enumerate(available_kinds):
                  details = get_kind_details(kind_name)
                  print(f"  {i+1}. {kind_name} ({details['description']})")

             while True:
                 try:
                     choice_str = input("Select entry type number: ").strip()
                     choice = int(choice_str) - 1
                     if 0 <= choice < len(available_kinds):
                          selected_kind = available_kinds[choice]
                          break
                     else:
                          print(colored("Invalid selection.", "red"))
                 except ValueError:
                     print(colored("Invalid input. Please enter a number.", "red"))

             print(colored(f"\nAdding new '{selected_kind}' entry...", "cyan"))
             entry_data = {}
             required_fields = get_required_fields(selected_kind)

             # Special handling for generated_password length/index (not prompted here)
             if selected_kind == "generated_password":
                 try:
                     entry_data["title"] = input("Enter Title/Website Name: ").strip()
                     if not entry_data["title"]:
                         print(colored("Title cannot be empty.", "red"))
                         return
                     entry_data["username"] = input("Enter Username (optional): ").strip()
                     entry_data["email"] = input("Enter Email (optional): ").strip()
                     entry_data["url"] = input("Enter URL (optional): ").strip()

                     length_input = input(f'Enter desired password length (default {DEFAULT_PASSWORD_LENGTH}): ').strip()
                     length = DEFAULT_PASSWORD_LENGTH
                     if length_input:
                         length = int(length_input) # Add validation
                         if not (MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH):
                              print(colored(f"Error: Password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}.", 'red'))
                              return
                     entry_data["length"] = length
                     # bip85_index is added automatically by add_entry method

                 except ValueError:
                     print(colored("Invalid length input.", "red"))
                     return

             # Generic prompt for other kinds
             else:
                 for field in required_fields:
                     # Skip password field for stored_password - handle specially
                     if selected_kind == "stored_password" and field == "password":
                         entry_data[field] = getpass.getpass(f"Enter Password for '{entry_data.get('title', 'entry')}': ").strip()
                         # Add confirmation?
                         if not entry_data[field]:
                              print(colored("Password cannot be empty.", "red"))
                              return
                         continue
                     # Skip content field for note - handle specially? Maybe allow multiline?
                     if selected_kind == "note" and field == "content":
                          print(f"Enter {field.capitalize()} (end with 'EOF' on a new line):")
                          lines = []
                          while True:
                              line = input()
                              if line == "EOF":
                                  break
                              lines.append(line)
                          entry_data[field] = "\n".join(lines)
                          continue

                     # Standard prompt
                     prompt_text = f"Enter {field.replace('_', ' ').capitalize()}"
                     if field == "tags" and selected_kind == "note":
                           prompt_text += " (comma-separated)"

                     user_input = input(f"{prompt_text}: ").strip()

                     if field == "tags" and selected_kind == "note":
                          entry_data[field] = [tag.strip() for tag in user_input.split(',') if tag.strip()]
                     else:
                          # Add validation based on field type if needed later
                          entry_data[field] = user_input

             # Add the entry using the main logic
             self.add_entry(selected_kind, entry_data)


        def handle_retrieve_entry_cli(self) -> None:
             """Handles the CLI interaction for retrieving/displaying an entry."""
             print(colored("\n--- Retrieve Entry ---", "yellow"))
             all_entries = self.list_all_entries()
             if not all_entries:
                  print(colored("No entries found locally.", "yellow"))
                  return

             print("Available Entries:")
             # Sort by entry_num for consistent display
             for entry in sorted(all_entries, key=lambda x: x.get("entry_num", -1)):
                  num = entry.get("entry_num", "N/A")
                  kind = entry.get("kind", "Unknown")
                  title = entry.get("data", {}).get("title", "No Title")
                  timestamp = entry.get("timestamp", "No Date")
                  print(f"  {Style.BRIGHT}{num}{Style.RESET_ALL}. {title} ({kind}) - Last Updated: {timestamp}")

             while True:
                 try:
                     choice_str = input("Enter entry number to display: ").strip()
                     entry_num_to_display = int(choice_str)
                     # Find the selected entry
                     selected_entry = next((e for e in all_entries if e.get("entry_num") == entry_num_to_display), None)
                     if selected_entry:
                         print(colored(f"\nDisplaying Entry {entry_num_to_display}:", "blue"))
                         self.process_entry(selected_entry) # Use the handler logic
                         break
                     else:
                         print(colored("Invalid entry number.", "red"))
                 except ValueError:
                     print(colored("Invalid input. Please enter a number.", "red"))
                 except KeyboardInterrupt:
                      print(colored("\nCancelled.", "yellow"))
                      break

        def handle_modify_entry_cli(self) -> None:
             """Handles the CLI interaction for modifying an entry."""
             print(colored("\n--- Modify Entry ---", "yellow"))
             all_entries = self.list_all_entries()
             if not all_entries:
                  print(colored("No entries found locally to modify.", "yellow"))
                  return

             print("Available Entries:")
             for entry in sorted(all_entries, key=lambda x: x.get("entry_num", -1)):
                 num = entry.get("entry_num", "N/A")
                 kind = entry.get("kind", "Unknown")
                 title = entry.get("data", {}).get("title", "No Title")
                 print(f"  {Style.BRIGHT}{num}{Style.RESET_ALL}. {title} ({kind})")

             while True:
                 try:
                     choice_str = input("Enter entry number to modify: ").strip()
                     entry_num_to_modify = int(choice_str)
                     existing_entry = next((e for e in all_entries if e.get("entry_num") == entry_num_to_modify), None)
                     if existing_entry:
                         break
                     else:
                         print(colored("Invalid entry number.", "red"))
                 except ValueError:
                     print(colored("Invalid input. Please enter a number.", "red"))
                 except KeyboardInterrupt:
                     print(colored("\nCancelled.", "yellow"))
                     return # Exit modify handler

             kind = existing_entry.get("kind")
             current_data = existing_entry.get("data", {})
             print(colored(f"\nModifying Entry {entry_num_to_modify} (Kind: {kind}, Title: {current_data.get('title', 'N/A')})", "cyan"))

             # Decrypt sensitive fields for display/editing if needed
             display_data = current_data.copy() # Work on a copy for display/prompting
             if kind == "stored_password" and "password" in display_data:
                 try:
                     pwd_b64 = display_data["password"]
                     pwd_bytes = self.encryption_manager.decrypt_data(base64.b64decode(pwd_b64))
                     display_data["password"] = pwd_bytes.decode('utf-8')
                 except Exception: display_data["password"] = "*** Error Decrypting ***"
             elif kind == "note" and "content" in display_data:
                 try:
                     content_b64 = display_data["content"]
                     content_bytes = self.encryption_manager.decrypt_data(base64.b64decode(content_b64))
                     display_data["content"] = content_bytes.decode('utf-8')
                 except Exception: display_data["content"] = "*** Error Decrypting ***"


             updated_data_fields = {}
             fields_to_modify = get_required_fields(kind)
             # Cannot modify bip85_index or length for generated_password
             if kind == "generated_password":
                  fields_to_modify = [f for f in fields_to_modify if f not in ["length", "bip85_index"]]

             for field in fields_to_modify:
                 current_value = display_data.get(field, "")
                 # Handle special display/prompt for password/content
                 if field == "password" and kind == "stored_password":
                       print(f"Current Password: {'*' * len(current_value) if current_value else 'Not Set'}")
                       new_value = getpass.getpass(f"Enter new Password (leave blank to keep current): ").strip()
                 elif field == "content" and kind == "note":
                       print(f"Current Content:\n---\n{current_value}\n---")
                       print(f"Enter new {field.capitalize()} (leave blank to keep, end with 'EOF' on a new line):")
                       lines = []
                       while True:
                           line = input()
                           if line == "EOF": break
                           lines.append(line)
                       new_value = "\n".join(lines) if lines else "" # Empty string if no input
                 elif field == "tags" and kind == "note":
                       print(f"Current Tags: {', '.join(current_value) if current_value else 'None'}")
                       new_value = input(f"Enter new Tags (comma-separated, leave blank to keep): ").strip()
                 else:
                       print(f"Current {field.replace('_',' ').capitalize()}: {current_value}")
                       new_value = input(f"Enter new {field.replace('_',' ').capitalize()} (leave blank to keep): ").strip()

                 if new_value: # Only add to update dict if user provided input
                      if field == "tags" and kind == "note":
                           updated_data_fields[field] = [tag.strip() for tag in new_value.split(',') if tag.strip()]
                      else:
                           updated_data_fields[field] = new_value

             if not updated_data_fields:
                 print(colored("No changes entered.", "yellow"))
                 return

             # Confirm changes before applying
             print("\nChanges to be applied:")
             for field, value in updated_data_fields.items():
                  print(f"  {field}: {value[:50] + '...' if len(value)>50 else value}") # Truncate long values
             if confirm_action("Proceed with these modifications? (Y/N): "):
                  self.modify_entry(entry_num_to_modify, updated_data_fields)
             else:
                  print(colored("Modification cancelled.", "yellow"))


        def handle_delete_entry_cli(self) -> None:
             """Handles the CLI interaction for deleting an entry."""
             print(colored("\n--- Delete Entry ---", "yellow"))
             all_entries = self.list_all_entries()
             if not all_entries:
                  print(colored("No entries found locally to delete.", "yellow"))
                  return

             print("Available Entries:")
             for entry in sorted(all_entries, key=lambda x: x.get("entry_num", -1)):
                 num = entry.get("entry_num", "N/A")
                 kind = entry.get("kind", "Unknown")
                 title = entry.get("data", {}).get("title", "No Title")
                 print(f"  {Style.BRIGHT}{num}{Style.RESET_ALL}. {title} ({kind})")

             while True:
                 try:
                     choice_str = input("Enter entry number to DELETE: ").strip()
                     entry_num_to_delete = int(choice_str)
                     # Verify entry exists before confirming
                     existing_entry = next((e for e in all_entries if e.get("entry_num") == entry_num_to_delete), None)
                     if existing_entry:
                          title_to_delete = existing_entry.get("data", {}).get("title", "No Title")
                          break
                     else:
                         print(colored("Invalid entry number.", "red"))
                 except ValueError:
                     print(colored("Invalid input. Please enter a number.", "red"))
                 except KeyboardInterrupt:
                      print(colored("\nCancelled.", "yellow"))
                      return

             if confirm_action(colored(f"Are you SURE you want to delete entry {entry_num_to_delete} ('{title_to_delete}')?\nThis is IRREVERSIBLE locally and will post a deletion marker to Nostr. (Y/N): ", "red", attrs=["bold"])):
                  self.delete_entry(entry_num_to_delete)
             else:
                  print(colored("Deletion cancelled.", "yellow"))


        def handle_backup_entry_cli(self) -> None:
             """Handles CLI for backing up a specific entry."""
             print(colored("\n--- Backup Entry ---", "yellow"))
             all_entries = self.list_all_entries()
             if not all_entries:
                  print(colored("No entries found locally to back up.", "yellow"))
                  return

             print("Available Entries:")
             for entry in sorted(all_entries, key=lambda x: x.get("entry_num", -1)):
                 num = entry.get("entry_num", "N/A")
                 kind = entry.get("kind", "Unknown")
                 title = entry.get("data", {}).get("title", "No Title")
                 print(f"  {Style.BRIGHT}{num}{Style.RESET_ALL}. {title} ({kind})")

             while True:
                 try:
                     choice_str = input("Enter entry number to backup: ").strip()
                     entry_num_to_backup = int(choice_str)
                     if any(e.get("entry_num") == entry_num_to_backup for e in all_entries):
                          self.backup_manager.create_backup_for_entry(entry_num_to_backup)
                          break
                     else:
                          print(colored("Invalid entry number.", "red"))
                 except ValueError:
                      print(colored("Invalid input. Please enter a number.", "red"))
                 except KeyboardInterrupt:
                      print(colored("\nCancelled.", "yellow"))
                      break

        def handle_restore_entry_cli(self) -> None:
             """Handles CLI for restoring an entry from backup."""
             print(colored("\n--- Restore Entry from Backup ---", "yellow"))
             all_entries = self.list_all_entries()
             if not all_entries:
                 print(colored("No entries exist. Cannot restore.", "yellow")) # Or maybe allow restoring to create? For now, require existing entry number.
                 # If allowing restore-to-create, need to list all backups first.
                 return

             print("Select entry number to restore:")
             for entry in sorted(all_entries, key=lambda x: x.get("entry_num", -1)):
                 num = entry.get("entry_num", "N/A")
                 kind = entry.get("kind", "Unknown")
                 title = entry.get("data", {}).get("title", "No Title")
                 print(f"  {Style.BRIGHT}{num}{Style.RESET_ALL}. {title} ({kind})")

             entry_num_to_restore = None
             while entry_num_to_restore is None:
                 try:
                     choice_str = input("Enter entry number: ").strip()
                     num = int(choice_str)
                     if any(e.get("entry_num") == num for e in all_entries):
                          entry_num_to_restore = num
                     else:
                          print(colored("Invalid entry number.", "red"))
                 except ValueError:
                      print(colored("Invalid input. Please enter a number.", "red"))
                 except KeyboardInterrupt:
                      print(colored("\nCancelled.", "yellow"))
                      return

             # List backups for the selected entry
             backups = self.backup_manager.list_backups_for_entry(entry_num_to_restore)
             if not backups:
                 print(colored(f"No backups found for entry {entry_num_to_restore}.", "yellow"))
                 return

             print(colored(f"\nAvailable Backups for Entry {entry_num_to_restore}:", "cyan"))
             for i, backup_path in enumerate(backups):
                  try:
                      creation_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(backup_path.stat().st_mtime))
                      print(colored(f"  {i+1}. {backup_path.name} ({creation_time})", "cyan"))
                  except Exception:
                       print(colored(f"  {i+1}. {backup_path.name} (Error reading time)", "red"))

             while True:
                 try:
                     choice_str = input("Select backup number to restore: ").strip()
                     choice = int(choice_str) - 1
                     if 0 <= choice < len(backups):
                         selected_backup_path = backups[choice]
                         if confirm_action(f"Restore entry {entry_num_to_restore} from {selected_backup_path.name}? This will overwrite the current entry. (Y/N): "):
                              self.backup_manager.restore_entry_from_backup(entry_num_to_restore, selected_backup_path.name)
                              # Ask user if they want to post the restored version to Nostr?
                              if confirm_action("Do you want to post this restored version to Nostr (overwriting any newer version there)? (Y/N):"):
                                  restored_entry = self.entry_manager.load_entry(entry_num_to_restore)
                                  if restored_entry:
                                       kind_details = get_kind_details(restored_entry.get("kind"))
                                       if kind_details:
                                           entry_json = json.dumps(restored_entry).encode('utf-8')
                                           encrypted_entry_data = self.encryption_manager.encrypt_data(entry_json)
                                           identifier = f"{kind_details['identifier_tag']}{entry_num_to_restore}"
                                           nostr_kind_int = kind_details['nostr_kind']
                                           self.nostr_client.publish_entry(
                                                encrypted_entry_data=encrypted_entry_data,
                                                nostr_kind=nostr_kind_int,
                                                d_tag=identifier
                                           )
                                           print(colored("Restored entry posted to Nostr.", "green"))
                                       else: print(colored("Could not post to Nostr: Unknown kind.", "red"))
                                  else: print(colored("Could not post to Nostr: Failed to reload restored entry.", "red"))
                         else:
                              print(colored("Restore cancelled.", "yellow"))
                         break # Exit loop
                     else:
                         print(colored("Invalid selection.", "red"))
                 except ValueError:
                     print(colored("Invalid input. Please enter a number.", "red"))
                 except KeyboardInterrupt:
                     print(colored("\nCancelled.", "yellow"))
                     break # Exit loop

        def handle_verify_checksum(self) -> None:
             """Verifies main script checksum."""
             # This remains unchanged as it checks the script file itself
             try:
                 # Assuming __main__.__file__ gives the path to main.py when run
                 script_path = os.path.abspath(sys.modules['__main__'].__file__)
                 current_checksum = calculate_script_checksum(script_path)
                 if verify_script_checksum(current_checksum, str(SCRIPT_CHECKSUM_FILE)): # Convert Path to str
                     print(colored("Script checksum verification passed.", 'green'))
                     logging.info("Script checksum verification passed.")
                 else:
                     print(colored("Checksum verification failed. The main script may have been modified.", 'red'))
                     logging.error("Script checksum verification failed.")
             except Exception as e:
                 logging.error(f"Error during script checksum verification: {e}", exc_info=True)
                 print(colored(f"Error: Failed to verify script checksum: {e}", 'red'))

        def handle_backup_reveal_parent_seed(self) -> None:
            """Handles backup/reveal of the parent seed (remains largely unchanged)."""
            if not self.parent_seed or not self.fingerprint_dir or not self.encryption_manager:
                 print(colored("Error: Profile not fully loaded.", "red"))
                 return
            try:
                print(colored("\n=== Backup/Reveal Parent Seed ===", 'yellow'))
                print(colored("Warning: Revealing your parent seed is a highly sensitive operation.", 'red'))
                print(colored("Ensure you're in a secure, private environment.", 'red'))

                password = prompt_existing_password("Enter your master password to continue: ")
                if not self.verify_password(password):
                    print(colored("Incorrect password. Operation aborted.", 'red'))
                    return

                if not confirm_action("Are you absolutely SURE you want to reveal your parent seed? (Y/N): "):
                    print(colored("Operation cancelled by user.", 'yellow'))
                    return

                print(colored("\n=== Your 12-Word BIP-39 Parent Seed ===", 'green', attrs=['bold']))
                print(colored(self.parent_seed, 'yellow'))
                print(colored("\nWRITE THIS DOWN if you haven't. Store it securely offline.", 'red'))

                if confirm_action("Do you want to save this seed to a separate encrypted backup file? (Y/N): "):
                    default_name = f"seedpass_seed_{self.current_fingerprint}_backup.enc"
                    filename = input(f"Enter filename (default: {default_name}): ").strip() or default_name
                    # Basic filename validation (avoids path traversal)
                    if '/' in filename or '\\' in filename or '..' in filename:
                         print(colored("Invalid filename.", "red"))
                         return
                    backup_path = self.fingerprint_dir / filename

                    # Use encrypt_and_save_file which handles locking etc.
                    self.encryption_manager.encrypt_and_save_file(self.parent_seed.encode('utf-8'), backup_path.relative_to(self.fingerprint_dir))
                    print(colored(f"Encrypted seed backup saved to '{backup_path}'. Keep this file safe!", 'green'))

            except Exception as e:
                logger.error(f"Error during parent seed backup/reveal: {e}", exc_info=True)
                print(colored(f"Error: Failed during seed backup/reveal: {e}", 'red'))

        # --- Fingerprint Management Handlers (No change needed here) ---
        def handle_switch_fingerprint(self) -> bool:
             """Handles switching active profile."""
             print(colored("\n--- Switch SeedPass Profile ---", "yellow"))
             # Get current selection before listing
             current_fp = self.current_fingerprint
             fingerprints = self.fingerprint_manager.list_fingerprints()

             if not fingerprints or len(fingerprints) <= 1:
                  print(colored("No other profiles available to switch to.", "yellow"))
                  return False

             print("Available Profiles:")
             available_to_switch = []
             display_idx = 1
             for fp in fingerprints:
                  if fp != current_fp:
                       print(colored(f"{display_idx}. {fp}", 'cyan'))
                       available_to_switch.append(fp)
                       display_idx += 1
                  else:
                       print(colored(f"   {fp} (Current)", "grey"))


             if not available_to_switch:
                   print(colored("No other profiles available to switch to.", "yellow"))
                   return False

             while True:
                 choice_str = input("Select profile number to switch to (or 'c' to cancel): ").strip().lower()
                 if choice_str == 'c':
                     print(colored("Switch cancelled.", "yellow"))
                     return False
                 if not choice_str.isdigit():
                     print(colored("Invalid input.", "red"))
                     continue

                 choice = int(choice_str)
                 if 1 <= choice <= len(available_to_switch):
                     selected_fingerprint = available_to_switch[choice - 1]
                     # select_fingerprint handles password prompt and manager re-init
                     return self.select_fingerprint(selected_fingerprint)
                 else:
                     print(colored("Invalid selection.", 'red'))


        # Other fingerprint handlers (add_new_fingerprint_cli, remove_fingerprint_cli, list_fingerprints_cli)
        # would call the underlying FingerprintManager methods, similar to the existing structure in main.py,
        # but should be methods within PasswordManager for better encapsulation.

        def handle_add_new_fingerprint_cli(self):
             return self.add_new_fingerprint() # Calls the internal method

        def handle_remove_fingerprint_cli(self):
             print(colored("\n--- Remove SeedPass Profile ---", "yellow", attrs=['bold']))
             print(colored("WARNING: This will delete the profile's fingerprint, encrypted seed,", attrs=['bold']), colored("all associated entries, and backups locally.", "red", attrs=['bold']))
             print(colored("This action is IRREVERSIBLE.", "red", attrs=['bold']))

             fingerprints = self.fingerprint_manager.list_fingerprints()
             if not fingerprints:
                  print(colored("No profiles available to remove.", 'yellow'))
                  return

             print("Available Profiles:")
             current_fp = self.current_fingerprint
             removable_fps = []
             display_idx = 1
             for fp in fingerprints:
                 is_current = "(Current)" if fp == current_fp else ""
                 print(colored(f"{display_idx}. {fp} {is_current}", 'cyan' if fp != current_fp else 'grey'))
                 removable_fps.append(fp)
                 display_idx += 1

             while True:
                 choice_str = input("Enter profile number to remove (or 'c' to cancel): ").strip().lower()
                 if choice_str == 'c':
                     print(colored("Removal cancelled.", "yellow"))
                     return
                 if not choice_str.isdigit():
                     print(colored("Invalid input.", "red"))
                     continue

                 choice = int(choice_str)
                 if 1 <= choice <= len(removable_fps):
                     selected_fingerprint = removable_fps[choice - 1]
                     if selected_fingerprint == self.current_fingerprint:
                          print(colored("Cannot remove the currently active profile. Switch profiles first.", "red"))
                          return

                     if confirm_action(colored(f"REALLY remove profile '{selected_fingerprint}' and all its data? (Y/N): ", "red")):
                          if self.fingerprint_manager.remove_fingerprint(selected_fingerprint):
                              print(colored(f"Profile {selected_fingerprint} removed successfully.", 'green'))
                          else:
                              print(colored("Failed to remove profile.", 'red'))
                     else:
                          print(colored("Removal cancelled.", 'yellow'))
                     return # Exit after attempt or cancel
                 else:
                     print(colored("Invalid selection.", 'red'))

        def handle_list_fingerprints_cli(self):
             print(colored("\n--- SeedPass Profiles (Fingerprints) ---", "yellow"))
             fingerprints = self.fingerprint_manager.list_fingerprints()
             if not fingerprints:
                  print(colored("No profiles configured.", 'yellow'))
                  return
             current_fp = self.current_fingerprint
             for fp in fingerprints:
                  is_current = colored("(Current)", "green") if fp == current_fp else ""
                  print(colored(f"- {fp} {is_current}", 'cyan'))

        # --- Old/Removed Methods ---
        # Remove handle_generate_password, handle_retrieve_password, handle_modify_entry (old index versions)
        # Remove get_encrypted_data, decrypt_and_save_index_from_nostr (old index versions)
        # Remove backup_database, restore_database (old index versions)
    ```

**Phase 4: Refactor `NostrClient`**

*   **`nostr/client.py` (Refactored):**
    ```python
    # nostr/client.py

    import os
    import sys
    import logging
    import traceback
    import json
    import time
    import base64
    import hashlib
    import asyncio
    import concurrent.futures
    from typing import List, Optional, Callable, Dict, Any
    from pathlib import Path

    from monstr.client.client import ClientPool, Client
    from monstr.encrypt import Keys # Keep Keys
    # Remove NIP4Encrypt unless needed for direct DMs (not needed for current backup plan)
    # from monstr.encrypt import NIP4Encrypt
    from monstr.event.event import Event
    from monstr.event.event_handlers import StoreEventHandler # Useful for collecting events
    from monstr.util import util_funcs # For relay set conversion

    import threading
    import uuid
    import fcntl

    # Import necessary components from SeedPass structure
    from password_manager.encryption import EncryptionManager # Used in init
    from .key_manager import KeyManager
    # EventHandler is now different - handles processing entries
    # from .event_handler import EventHandler # Remove old event handler import
    from constants import APP_DIR # Keep if needed, but paths managed by PasswordManager now
    from utils.file_lock import lock_file # Keep if needed

    logger = logging.getLogger(__name__)

    # Set the logging level specific to this module if desired
    # logger.setLevel(logging.DEBUG) # Example: More verbose Nostr logs

    DEFAULT_RELAYS = [
        "wss://relay.snort.social",
        "wss://nostr.oxtr.dev",
        "wss://relay.primal.net",
        "wss://relay.damus.io",
        "wss://nostr.wine"
    ]

    # Define the Nostr Kind for SeedPass entries
    SEEDPASS_NOSTR_KIND = 31111 # Replaceable event kind for entries

    class NostrClient:
        """
        Handles interactions with the Nostr network for SeedPass entries.
        Uses replaceable events (Kind 31111) with 'd' tags for synchronization.
        """

        def __init__(self, encryption_manager: EncryptionManager, fingerprint: str, relays: Optional[List[str]] = None):
            """
            Initializes the NostrClient.

            :param encryption_manager: Instance for decrypting the parent seed.
            :param fingerprint: The active fingerprint for deriving Nostr keys.
            :param relays: Optional list of relay URLs.
            """
            self.encryption_manager = encryption_manager
            self.fingerprint = fingerprint
            # Derive keys *immediately* upon init
            try:
                self.key_manager = KeyManager(
                    self.encryption_manager.decrypt_parent_seed(), # Decrypt seed here
                    self.fingerprint
                )
            except Exception as key_err:
                 logger.critical(f"Failed to derive Nostr keys for fingerprint {fingerprint}: {key_err}", exc_info=True)
                 print(colored(f"Error: Could not initialize Nostr identity for profile {fingerprint}.", "red"))
                 raise RuntimeError("Nostr key generation failed") from key_err

            # Use default or provided relays
            self.relays = relays if relays else DEFAULT_RELAYS
            # Convert relay list to set for ClientPool if needed by monstr version
            relay_set = util_funcs.str_filter_to_set(self.relays)
            if not relay_set:
                logger.warning("No valid relays configured for NostrClient.")
                relay_set = {"wss://relay.damus.io"} # Fallback? Or raise error?

            self.client_pool = ClientPool(list(relay_set)) # ClientPool might expect list
            self.subscriptions: Dict[str, Any] = {} # Track subscriptions

            # For async operations from sync methods
            self.loop = asyncio.new_event_loop()
            self.loop_thread = threading.Thread(target=self._run_event_loop, daemon=True)
            self.loop_thread.start()

            # Wait for initial connection
            self.wait_for_connection()
            logger.info(f"NostrClient initialized for fingerprint {fingerprint} (PubKey: {self.key_manager.get_public_key_hex()[:10]}...).")

            # Shutdown flag
            self.is_shutting_down = False


        def _run_event_loop(self):
            """Runs the asyncio event loop in a separate thread."""
            asyncio.set_event_loop(self.loop)
            try:
                self.loop.run_forever()
            finally:
                # Clean up loop resources before thread exits
                tasks = asyncio.all_tasks(loop=self.loop)
                for task in tasks:
                    task.cancel()
                # Run loop briefly to allow tasks to finish cancelling
                self.loop.run_until_complete(asyncio.sleep(0.1))
                self.loop.close()
                logger.info("NostrClient event loop closed.")


        def wait_for_connection(self, timeout=10):
            """Waits for the client pool to connect to at least one relay."""
            start_time = time.time()
            while not self.client_pool.connected:
                if time.time() - start_time > timeout:
                    logger.warning(f"NostrClient connection timeout after {timeout}s.")
                    print(colored("Warning: Could not connect to Nostr relays within timeout.", "yellow"))
                    # Decide if this is fatal or not. Maybe allow offline operation?
                    # For now, let it proceed but log warning.
                    break
                time.sleep(0.2)
            if self.client_pool.connected:
                 logger.debug("NostrClient connected to relays.")

        async def publish_entry_async(self, encrypted_entry_data: bytes, nostr_kind: int, d_tag: str, is_deletion: bool = False):
             """
             Asynchronously publishes an entry as a replaceable event.

             :param encrypted_entry_data: The fully encrypted entry JSON as bytes.
             :param nostr_kind: The Nostr event kind (e.g., 31111).
             :param d_tag: The unique identifier for the 'd' tag (e.g., "seedpass_gp_123").
             :param is_deletion: If True, content might be empty/special marker (though we encrypt empty dict currently).
             """
             try:
                 content_b64 = base64.b64encode(encrypted_entry_data).decode('utf-8')

                 # Create replaceable event
                 event = Event(
                     kind=nostr_kind,
                     content=content_b64,
                     pub_key=self.key_manager.get_public_key_hex(),
                     tags=[
                         ["d", d_tag],
                         ["t", "seedpass"] # General tag for SeedPass entries
                         # Add ["k", str(nostr_kind)] ? Maybe redundant.
                     ]
                 )
                 # created_at will be set automatically by monstr on sign if not present
                 event.sign(self.key_manager.get_private_key_hex())

                 logger.debug(f"Prepared Nostr Event (Kind: {nostr_kind}, d: {d_tag}, ID: {event.id})")
                 # Publish using the client pool
                 self.client_pool.publish(event)
                 logger.info(f"Published entry {'(Deletion Marker)' if is_deletion else ''} to Nostr (Kind: {nostr_kind}, d: {d_tag}, EventID: {event.id})")

             except Exception as e:
                  logger.error(f"Failed to publish Nostr event (Kind: {nostr_kind}, d: {d_tag}): {e}", exc_info=True)
                  # Should this raise or just log? Logging for now.
                  print(colored(f"Error: Failed to post entry update to Nostr: {e}", "red"))

        def publish_entry(self, encrypted_entry_data: bytes, nostr_kind: int, d_tag: str, is_deletion: bool = False):
             """Synchronous wrapper to publish an entry."""
             if not self.loop.is_running():
                  logger.error("Cannot publish entry: Event loop is not running.")
                  return
             future = asyncio.run_coroutine_threadsafe(
                 self.publish_entry_async(encrypted_entry_data, nostr_kind, d_tag, is_deletion),
                 self.loop
             )
             try:
                  future.result(timeout=10) # Wait for publish to be sent
             except concurrent.futures.TimeoutError:
                  logger.warning(f"Timeout waiting for Nostr publish confirmation (Kind: {nostr_kind}, d: {d_tag}). Event might still be sent.")
                  print(colored("Warning: Timeout posting to Nostr. Update might be delayed.", "yellow"))
             except Exception as e:
                  logger.error(f"Error submitting publish task to event loop: {e}", exc_info=True)

        async def fetch_all_entries_async(self, since: Optional[int] = None, limit: int = 500) -> Optional[List[Event]]:
            """
            Asynchronously fetches all SeedPass entries (Kind 31111) from Nostr.

            :param since: Optional Unix timestamp to fetch events newer than this.
            :param limit: Max number of events per relay query (relays might override).
            :return: A list of Event objects, or None if a critical error occurs.
            """
            if not self.client_pool.connected:
                 logger.warning("Cannot fetch entries: Nostr client not connected.")
                 # Return empty list instead of None to indicate no *new* entries found due to connection issue
                 return []

            results = []
            err_flag = asyncio.Event() # To signal errors from handler

            # Using StoreEventHandler to collect events
            store = StoreEventHandler()

            def on_error_handler(the_client: Client, sub_id: str, data: Any):
                 logger.error(f"Error received on subscription {sub_id} from {the_client.url}: {data}")
                 err_flag.set() # Signal that an error occurred

            # Filter for the specific replaceable kind authored by the user
            filters = [{
                "authors": [self.key_manager.get_public_key_hex()],
                "kinds": [SEEDPASS_NOSTR_KIND],
                "#t": ["seedpass"], # Filter by general tag
                "limit": limit
            }]
            if since is not None and isinstance(since, int) and since >= 0:
                 filters[0]["since"] = since # Add time filter if provided

            sub_id = None
            try:
                 sub_id = f"seedpass_fetch_{uuid.uuid4()}"
                 logger.debug(f"Subscribing to fetch entries with filter: {filters}, sub_id: {sub_id}")

                 # Subscribe using the store handler and error handler
                 self.client_pool.subscribe(
                     handlers=[store, on_error_handler], # Pass list of handlers
                     filters=filters,
                     sub_id=sub_id,
                     eose_func=lambda client, sub_id, events: logger.debug(f"Received EOSE for {sub_id} from {client.url}")
                 )
                 self.subscriptions[sub_id] = filters # Store subscription info

                 # Wait for EOSE from relays or a timeout/error
                 # Timeout needs to be long enough for relays to respond
                 fetch_timeout = 15.0
                 try:
                      await asyncio.wait_for(
                           self.client_pool.eose_matching(sub_id=sub_id), # Wait for EOSE events
                           timeout=fetch_timeout
                      )
                      logger.info(f"Received EOSE from relays for fetch subscription {sub_id}.")
                 except asyncio.TimeoutError:
                      logger.warning(f"Timeout waiting for EOSE on fetch subscription {sub_id} after {fetch_timeout}s.")
                      # Continue with whatever events were received

                 # Check if any error occurred during subscription
                 if err_flag.is_set():
                      logger.error(f"Error occurred during Nostr fetch subscription {sub_id}.")
                      # Depending on severity, maybe return None or partial results?
                      # For now, return None to indicate failure.
                      return None

                 # Unsubscribe after fetching
                 self.client_pool.unsubscribe(sub_id)
                 if sub_id in self.subscriptions: del self.subscriptions[sub_id]
                 logger.debug(f"Unsubscribed from fetch subscription {sub_id}.")

                 # Get collected events from the store
                 # Need to filter results by sub_id if store is reused, or use a fresh store each time.
                 # Assuming store collects globally, filter results by pubkey/kind again for safety.
                 # Actually, StoreEventHandler stores by event ID. Need a way to get all events received for the sub.
                 # Let's refine this - maybe collect in a simple list within this function?

                 # --- Alternative Collection ---
                 collected_events = []
                 eose_received = asyncio.Event()

                 def event_collector(the_client: Client, r_sub_id: str, evt: Event):
                      if r_sub_id == sub_id:
                           # Basic validation
                           if evt.pub_key == self.key_manager.get_public_key_hex() and evt.kind == SEEDPASS_NOSTR_KIND:
                                collected_events.append(evt)
                           else:
                                logger.warning(f"Received unexpected event during fetch: {evt.id} from {the_client.url}")

                 def eose_marker(the_client: Client, r_sub_id: str, evts: List):
                      if r_sub_id == sub_id:
                           logger.debug(f"Received EOSE for {sub_id} from {the_client.url}")
                           # We need to know when *enough* relays have sent EOSE.
                           # This simple approach just sets a flag. `client_pool.eose_matching` is better.
                           # For simplicity here, let's just use a timeout after subscribing.

                 # --- Revert to simpler timeout-based fetch ---
                 # This is less reliable than waiting for EOSE but simpler to implement without deeper monstr changes.
                 collected_events_dict: Dict[str, Event] = {} # Use dict to store latest per d_tag

                 def event_collector_simple(the_client: Client, r_sub_id: str, evt: Event):
                     if r_sub_id == sub_id:
                         if evt.pub_key == self.key_manager.get_public_key_hex() and evt.kind == SEEDPASS_NOSTR_KIND:
                             d_tag_val = evt.get_tags("d")
                             if d_tag_val: # Ensure 'd' tag exists
                                 d_tag = d_tag_val[0] # Get first 'd' tag
                                 # Store only the latest event for each 'd' tag
                                 if d_tag not in collected_events_dict or evt.created_at > collected_events_dict[d_tag].created_at:
                                      collected_events_dict[d_tag] = evt
                         else:
                              logger.warning(f"Received unexpected event during fetch: {evt.id} from {the_client.url}")


                 sub_id = f"seedpass_fetch_{uuid.uuid4()}"
                 self.client_pool.subscribe(
                     handlers=event_collector_simple,
                     filters=filters,
                     sub_id=sub_id
                 )
                 self.subscriptions[sub_id] = filters
                 logger.debug(f"Subscribed to fetch entries with filter: {filters}, sub_id: {sub_id}")

                 # Wait for a fixed time to allow events to arrive
                 await asyncio.sleep(5.0) # Adjust this wait time as needed

                 self.client_pool.unsubscribe(sub_id)
                 if sub_id in self.subscriptions: del self.subscriptions[sub_id]
                 logger.debug(f"Unsubscribed from fetch subscription {sub_id}. Collected {len(collected_events_dict)} unique entries.")

                 return list(collected_events_dict.values()) # Return the latest event for each d_tag

            except Exception as e:
                 logger.error(f"Failed during Nostr fetch: {e}", exc_info=True)
                 # Clean up subscription if needed
                 if sub_id and sub_id in self.subscriptions:
                     try:
                         self.client_pool.unsubscribe(sub_id)
                         del self.subscriptions[sub_id]
                     except Exception as unsub_err:
                         logger.error(f"Error unsubscribing during fetch error handling: {unsub_err}")
                 return None # Indicate failure

        def fetch_all_entries_sync(self, since: Optional[int] = None, limit: int = 500) -> Optional[List[Event]]:
            """Synchronous wrapper to fetch all entries."""
            if not self.loop.is_running():
                 logger.error("Cannot fetch entries: Event loop is not running.")
                 return None
            future = asyncio.run_coroutine_threadsafe(
                self.fetch_all_entries_async(since=since, limit=limit),
                self.loop
            )
            try:
                 return future.result(timeout=20) # Longer timeout for fetching
            except concurrent.futures.TimeoutError:
                 logger.error("Timeout occurred while fetching entries from Nostr.")
                 print(colored("Error: Timeout occurred while fetching entries from Nostr.", "red"))
                 return None
            except Exception as e:
                 logger.error(f"Error submitting fetch task to event loop: {e}", exc_info=True)
                 return None

        def close_client_pool(self):
            """Gracefully shuts down the Nostr client pool and event loop."""
            if self.is_shutting_down:
                logger.debug("Shutdown already in progress.")
                return
            self.is_shutting_down = True
            logger.info("Initiating NostrClient shutdown...")

            # Schedule the async close in the running loop
            if self.loop.is_running():
                future = asyncio.run_coroutine_threadsafe(self._close_pool_async(), self.loop)
                try:
                    future.result(timeout=10) # Wait for async close to finish
                except (concurrent.futures.TimeoutError, Exception) as e:
                    logger.warning(f"Error or timeout during async pool close: {e}. Proceeding with loop stop.")

                # Stop the loop from the thread that owns it
                if self.loop.is_running():
                     self.loop.call_soon_threadsafe(self.loop.stop)
            else:
                 logger.warning("NostrClient event loop was not running during shutdown.")

            # Wait for the thread to finish
            if self.loop_thread.is_alive():
                 self.loop_thread.join(timeout=5)
                 if self.loop_thread.is_alive():
                      logger.warning("NostrClient event loop thread did not exit cleanly.")

            logger.info("NostrClient shutdown complete.")
            self.is_shutting_down = False


        async def _close_pool_async(self):
             """Async part of the shutdown sequence."""
             try:
                 logger.debug("Closing Nostr subscriptions...")
                 sub_ids = list(self.subscriptions.keys())
                 for sub_id in sub_ids:
                     try:
                         self.client_pool.unsubscribe(sub_id)
                         if sub_id in self.subscriptions: del self.subscriptions[sub_id]
                         logger.debug(f"Unsubscribed from {sub_id}")
                     except Exception as e:
                         logger.warning(f"Error unsubscribing from {sub_id}: {e}")

                 logger.debug("Closing Nostr client connections...")
                 # Use await self.client_pool.disconnect() if available and preferred by monstr version
                 # Otherwise, manually close underlying clients if accessible
                 if hasattr(self.client_pool, '_clients'): # Accessing protected member, check monstr docs
                     tasks = [self._safe_close_connection(c) for c in self.client_pool._clients.values()]
                     await asyncio.gather(*tasks, return_exceptions=True)
                 elif hasattr(self.client_pool, 'clients'): # Public attribute?
                      tasks = [self._safe_close_connection(c) for c in self.client_pool.clients]
                      await asyncio.gather(*tasks, return_exceptions=True)
                 else:
                      logger.warning("Cannot access client pool clients for explicit closure.")

                 logger.debug("Async pool closure steps finished.")

             except Exception as e:
                 logger.error(f"Error during async Nostr pool closure: {e}", exc_info=True)


        async def _safe_close_connection(self, client: Client):
             """Safely attempts to close a single client connection."""
             # Older monstr versions might not have close_connection or disconnect
             close_method = getattr(client, 'disconnect', getattr(client, 'close_connection', None))
             if close_method and asyncio.iscoroutinefunction(close_method):
                 try:
                     await asyncio.wait_for(close_method(), timeout=3)
                     logger.debug(f"Closed connection to {client.url}")
                 except asyncio.TimeoutError:
                      logger.warning(f"Timeout closing connection to {client.url}")
                 except Exception as e:
                      logger.warning(f"Error closing connection to {client.url}: {e}")
             elif close_method: # Non-async close? Less likely for websockets.
                 try:
                     close_method()
                     logger.debug(f"Closed connection to {client.url} (sync)")
                 except Exception as e:
                      logger.warning(f"Error closing connection to {client.url} (sync): {e}")
             else:
                  logger.warning(f"No suitable close method found for client connected to {client.url}")


        # --- Remove Old Methods ---
        # remove publish_event, subscribe, retrieve_json_from_nostr_async, retrieve_json_from_nostr
        # remove do_post_async, subscribe_feed_async, publish_and_subscribe_async, publish_and_subscribe
        # remove decrypt_and_save_index_from_nostr, save_json_data, update_checksum, decrypt_data_from_file
        # remove publish_json_to_nostr, retrieve_json_from_nostr_sync, decrypt_and_save_index_from_nostr_public

    ```

**Phase 5: Refactor `EventHandler`**

*   **`nostr/event_handler.py` (Simplified/Removed):**
    The event handling logic is now tightly coupled with synchronization in `PasswordManager`. A separate `EventHandler` class primarily for logging received events (as it was before) might still be useful for debugging, but it won't be directly involved in processing SeedPass entries anymore. The `event_collector_simple` function inside `NostrClient.fetch_all_entries_async` now handles the basic reception. The actual processing happens in `PasswordManager.synchronize_with_nostr`.
    **Decision:** We can remove the old `EventHandler` class or keep it purely for debug logging if needed, but it's not essential for the new flow. Let's comment it out for now.

    ```python
    # nostr/event_handler.py

    # import time
    # import logging
    # import traceback
    # from monstr.event.event import Event

    # logger = logging.getLogger(__name__)

    # class EventHandler:
    #     """
    #     Handles incoming Nostr events (Primarily for Debug Logging now).
    #     Actual entry processing is done within PasswordManager.synchronize_with_nostr.
    #     """
    #     def __init__(self):
    #         pass # No password manager reference needed now

    #     def handle_new_event(self, the_client, sub_id, evt: Event):
    #         """Processes incoming events by logging their details."""
    #         # This might be attached to a general subscription for debugging
    #         try:
    #             created_at_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(evt.created_at))
    #             logger.debug(
    #                 f"[Debug Event Handler] Received Event:"
    #                 f" SubID: {sub_id}"
    #                 f" | Relay: {the_client.url}"
    #                 f" | Kind: {evt.kind}"
    #                 f" | ID: {evt.id}"
    #                 f" | Created: {created_at_str}"
    #                 f" | Content Preview: {evt.content[:50]}..."
    #             )
    #         except Exception as e:
    #             logger.error(f"Error in debug event handler: {e}", exc_info=True)
    ```

**Phase 6: Refactor `main.py`**

*   **`main.py` (Major Changes to Menu and Handlers):**
    ```python
    # main.py
    import os
    import sys
    import logging
    import signal
    from colorama import init as colorama_init, Style
    from termcolor import colored
    import traceback

    # Import PasswordManager - NostrClient is now initialized within it
    from password_manager.manager import PasswordManager
    # from nostr.client import NostrClient # No longer needed here

    colorama_init(autoreset=True) # Autoreset colors

    # --- Logging Configuration (Keep as is) ---
    def configure_logging():
        # ... (keep existing logging setup) ...
        pass # Keep existing code

    # --- Confirmation Helper (Keep as is) ---
    def confirm_action(prompt: str) -> bool:
        # ... (keep existing confirmation logic) ...
        pass # Keep existing code

    # --- New CLI Interaction Logic ---

    def display_main_menu(password_manager: PasswordManager):
        """Displays the main interactive menu."""
        print(colored("\n--- SeedPass Main Menu ---", "blue", attrs=["bold"]))
        print(f"Active Profile: {colored(password_manager.current_fingerprint, 'green')}\n")

        menu_options = {
            "1": ("Add New Entry", password_manager.handle_add_entry_cli),
            "2": ("List / Retrieve Entries", password_manager.handle_retrieve_entry_cli),
            "3": ("Modify Entry", password_manager.handle_modify_entry_cli),
            "4": ("Delete Entry", password_manager.handle_delete_entry_cli),
            "5": ("Synchronize with Nostr", password_manager.synchronize_with_nostr), # Changed
            "6": ("Display Nostr Public Key (npub)", handle_display_npub), # Needs adapting
            "7": ("Manage Backups", handle_backup_menu), # New Sub-menu
            "8": ("Manage Profiles (Seeds)", handle_profile_menu), # New Sub-menu
            "9": ("Verify Script Checksum", password_manager.handle_verify_checksum),
            "10": ("Exit", None) # Handled in loop
        }

        for key, (text, _) in menu_options.items():
             print(f"  {Style.BRIGHT}{key}{Style.RESET_ALL}. {text}")

        return menu_options


    def handle_display_npub(password_manager: PasswordManager):
        """Displays the Nostr public key (npub)."""
        # Assumes nostr_client and key_manager are initialized
        if password_manager.nostr_client and password_manager.nostr_client.key_manager:
            try:
                npub = password_manager.nostr_client.key_manager.get_npub()
                print(colored(f"\nYour Nostr Public Key (npub) for profile '{password_manager.current_fingerprint}':", 'cyan'))
                print(colored(npub, 'yellow'))
                print(colored("Share this key for others to send you encrypted messages (if supported).", 'cyan'))
            except Exception as e:
                logger.error(f"Failed to get npub: {e}", exc_info=True)
                print(colored(f"Error displaying npub: {e}", "red"))
        else:
            print(colored("Nostr client not initialized for this profile.", "red"))


    def handle_backup_menu(password_manager: PasswordManager):
         """Handles the backup management sub-menu."""
         if not password_manager.backup_manager:
             print(colored("Backup manager not initialized.", "red"))
             return

         backup_menu_options = {
             "1": ("Backup Specific Entry", password_manager.handle_backup_entry_cli),
             "2": ("Restore Specific Entry", password_manager.handle_restore_entry_cli),
             "3": ("List Backups for Entry", lambda: password_manager.backup_manager.display_backups(
                 entry_num=int(input("Enter entry number to list backups for: ")) # Add error handling
             )),
             "4": ("List All Backups", lambda: password_manager.backup_manager.display_backups()),
             "5": ("Return to Main Menu", None)
         }

         while True:
             print(colored("\n--- Backup Management ---", "blue"))
             for key, (text, _) in backup_menu_options.items():
                 print(f"  {key}. {text}")

             choice = input("Enter your choice: ").strip()
             if choice == '5': break # Return to main menu
             selected_option = backup_menu_options.get(choice)

             if selected_option and selected_option[1]:
                 try:
                     selected_option[1]() # Call the handler function
                 except ValueError:
                      print(colored("Invalid numeric input.", "red"))
                 except Exception as e:
                      logger.error(f"Error in backup menu option {choice}: {e}", exc_info=True)
                      print(colored(f"An error occurred: {e}", "red"))
             elif selected_option: # Option exists but no function (like return)
                  pass
             else:
                 print(colored("Invalid choice.", "red"))


    def handle_profile_menu(password_manager: PasswordManager):
         """Handles the profile (fingerprint) management sub-menu."""
         if not password_manager.fingerprint_manager:
              print(colored("Profile manager not initialized.", "red"))
              return

         profile_menu_options = {
             "1": ("Switch Active Profile", password_manager.handle_switch_fingerprint), # Assumes this returns bool
             "2": ("Add New Profile", password_manager.handle_add_new_fingerprint_cli),
             "3": ("Remove Profile", password_manager.handle_remove_fingerprint_cli),
             "4": ("List All Profiles", password_manager.handle_list_fingerprints_cli),
             "5": ("Backup/Reveal Current Profile Seed", password_manager.handle_backup_reveal_parent_seed), # Moved here
             "6": ("Return to Main Menu", None)
         }

         while True:
             print(colored("\n--- Profile Management ---", "blue"))
             for key, (text, _) in profile_menu_options.items():
                 print(f"  {key}. {text}")

             choice = input("Enter your choice: ").strip()
             if choice == '6': break # Return to main menu
             selected_option = profile_menu_options.get(choice)

             if selected_option and selected_option[1]:
                 try:
                     result = selected_option[1]() # Call the handler function
                     # Handle specific results if needed (e.g., switch profile might fail)
                     if selected_option[0] == "Switch Active Profile" and result:
                          print(colored("Profile switched successfully. Returning to main menu.", "green"))
                          break # Exit sub-menu after successful switch
                 except Exception as e:
                      logger.error(f"Error in profile menu option {choice}: {e}", exc_info=True)
                      print(colored(f"An error occurred: {e}", "red"))
             elif selected_option:
                  pass
             else:
                 print(colored("Invalid choice.", "red"))


    # --- Main Execution Logic ---

    if __name__ == '__main__':
        configure_logging()
        logger = logging.getLogger(__name__)
        logger.info("--- Starting SeedPass ---")

        password_manager: Optional[PasswordManager] = None # Define before try block

        try:
            # Initialization is now more complex, handled inside PasswordManager __init__
            password_manager = PasswordManager()
            logger.info("PasswordManager initialization complete.")

        except SystemExit:
             logger.warning("SystemExit during initialization.")
             # Don't print error message again if sys.exit was called intentionally
             sys.exit(1) # Ensure exit code reflects failure
        except Exception as e:
            # Catch any other unexpected init errors
            logger.critical(f"Unhandled exception during PasswordManager initialization: {e}", exc_info=True)
            print(colored(f"FATAL ERROR during startup: {e}. Check logs.", "red", attrs=["bold"]))
            # Ensure cleanup if partially initialized? Difficult here.
            if password_manager and password_manager.nostr_client:
                password_manager.nostr_client.close_client_pool()
            sys.exit(1)


        # Register signal handlers for graceful shutdown
        def signal_handler(sig, frame):
            print(colored("\nReceived shutdown signal. Exiting gracefully...", 'yellow'))
            logging.info(f"Received shutdown signal: {sig}. Initiating graceful shutdown.")
            if password_manager and password_manager.nostr_client:
                try:
                    password_manager.nostr_client.close_client_pool()
                    logging.info("NostrClient closed successfully.")
                except Exception as e:
                    logging.error(f"Error closing NostrClient during shutdown: {e}", exc_info=True)
                    print(colored(f"Error during Nostr shutdown: {e}", 'red'))
            logging.info("--- SeedPass Shutting Down ---")
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)   # Handle Ctrl+C
        signal.signal(signal.SIGTERM, signal_handler)  # Handle termination signals


        # --- Main Application Loop ---
        try:
            while True:
                menu = display_main_menu(password_manager)
                choice = input(colored('Enter your choice: ', "magenta")).strip()

                if choice == '10': # Exit option
                    break # Exit loop

                # Execute chosen action
                selected_option = menu.get(choice)
                if selected_option and selected_option[1]:
                    try:
                        # Call the appropriate handler function (now mostly methods of PasswordManager)
                        # Pass password_manager instance only if the handler is a standalone function (like handle_display_npub)
                        if selected_option[0] == "Display Nostr Public Key (npub)":
                             handle_display_npub(password_manager)
                        elif selected_option[0] == "Manage Backups":
                             handle_backup_menu(password_manager)
                        elif selected_option[0] == "Manage Profiles (Seeds)":
                             handle_profile_menu(password_manager)
                        else:
                             selected_option[1]() # Call method on password_manager instance
                    except Exception as menu_err:
                        logger.error(f"Error during menu action '{selected_option[0]}': {menu_err}", exc_info=True)
                        print(colored(f"An error occurred: {menu_err}", "red"))
                elif selected_option: # Option exists but no function (should not happen with this menu structure)
                     pass
                else:
                    print(colored("Invalid choice. Please select a valid option.", 'red'))

        except KeyboardInterrupt:
            logger.info("Program terminated by user (Ctrl+C in main loop).")
            print(colored("\nExiting...", 'yellow'))
            # Signal handler should have been called, but call cleanup just in case
            if password_manager and password_manager.nostr_client:
                 password_manager.nostr_client.close_client_pool()
            sys.exit(0)
        except Exception as main_loop_err:
             logger.critical(f"An unexpected error occurred in the main loop: {main_loop_err}", exc_info=True)
             print(colored(f"FATAL ERROR: An unexpected error occurred: {main_loop_err}", 'red', attrs=["bold"]))
             # Attempt cleanup
             if password_manager and password_manager.nostr_client:
                  password_manager.nostr_client.close_client_pool()
             sys.exit(1)
        finally:
            # Ensure cleanup runs on normal exit too
            logger.info("Exiting main loop.")
            if password_manager and password_manager.nostr_client:
                password_manager.nostr_client.close_client_pool()
            logging.info("--- SeedPass Finished ---")
            print(colored("Exiting SeedPass.", 'green'))
            sys.exit(0)

    ```

**Phase 7: Remove Obsolete Files**

*   Delete `nostr/encryption_manager.py`.

**Summary of Key Changes:**

1.  **`kinds.py`:** Central definition for entry types.
2.  **`handlers/`:** Specific logic for processing each `kind`.
3.  **`state_manager.py`:** Tracks last generated password index and sync time.
4.  **`EntryManager`:** Now manages individual entry *files* (saving, loading, deleting, checksumming data *within* the entry). No longer holds the index logic.
5.  **`BackupManager`:** Adapted to back up/restore individual entry files.
6.  **`PasswordManager`:** Orchestrates the new flow. Contains methods for `add_entry`, `modify_entry`, `delete_entry`, `synchronize_with_nostr`, `process_entry`, data migration, and CLI handlers. Reads/writes state via `StateManager`.
7.  **`NostrClient`:** Publishes/fetches individual replaceable events (Kind 31111 suggested) using `d` tags. Fetching retrieves latest versions. Uses `StoreEventHandler` (or similar) for collecting results. `publish_json_to_nostr` and `retrieve_json_from_nostr_sync` removed/replaced.
8.  **`main.py`:** Updated menu structure, calling new `PasswordManager` methods and sub-menu handlers.

**Next Steps:**

1.  **Review Thoroughly:** Carefully compare the refactored code against the original and the plan.
2.  **Implement Tests:** Write unit tests for `StateManager`, new `EntryManager` methods, `kinds.py` helpers, and the handlers. Write integration tests for the `add -> sync -> retrieve` flow.
3.  **Refine `NostrClient` Fetching:** The `fetch_all_entries_async` implementation using a simple timeout is basic. Improving it to reliably use EOSE detection across multiple relays (`client_pool.eose_matching`) would be more robust.
4.  **Error Handling:** Add more specific error handling, especially around file I/O, network issues, and migration edge cases.
5.  **User Experience:** Test the CLI flow extensively. Ensure prompts are clear and error messages are helpful. Consider how users will select entries for modification/deletion (the current implementation lists all and asks for a number). Search functionality might be needed later.