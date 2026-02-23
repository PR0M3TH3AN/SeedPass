from __future__ import annotations

import logging
from typing import Optional, TYPE_CHECKING

from termcolor import colored

import seedpass.core.manager as manager_module

from utils.password_prompt import prompt_existing_password

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .manager import PasswordManager
    from nostr.client import NostrClient


class ProfileService:
    """Profile-related operations for :class:`PasswordManager`."""

    def __init__(self, manager: PasswordManager) -> None:
        self.manager = manager

    def handle_switch_fingerprint(self, *, password: Optional[str] = None) -> bool:
        """Handle switching to a different seed profile."""
        pm = self.manager
        try:
            print(colored("\nAvailable Seed Profiles:", "cyan"))
            fingerprints = pm.fingerprint_manager.list_fingerprints()
            for idx, fp in enumerate(fingerprints, start=1):
                display = (
                    pm.fingerprint_manager.display_name(fp)
                    if hasattr(pm.fingerprint_manager, "display_name")
                    else fp
                )
                print(colored(f"{idx}. {display}", "cyan"))

            choice = input("Select a seed profile by number to switch: ").strip()
            if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
                print(colored("Invalid selection. Returning to main menu.", "red"))
                return False

            selected_fingerprint = fingerprints[int(choice) - 1]
            pm.fingerprint_manager.current_fingerprint = selected_fingerprint
            pm.current_fingerprint = selected_fingerprint
            if not getattr(pm, "manifest_id", None):
                pm.manifest_id = None

            pm.fingerprint_dir = pm.fingerprint_manager.get_current_fingerprint_dir()
            if not pm.fingerprint_dir:
                print(
                    colored(
                        f"Error: Seed profile directory for {selected_fingerprint} not found.",
                        "red",
                    )
                )
                return False

            if password is None:
                password = prompt_existing_password(
                    "Enter the master password for the selected seed profile: "
                )

            if not pm.setup_encryption_manager(
                pm.fingerprint_dir, password, exit_on_fail=False
            ):
                return False

            pm.initialize_bip85()
            pm.initialize_managers()
            pm.start_background_sync()
            print(colored(f"Switched to seed profile {selected_fingerprint}.", "green"))

            try:
                pm.nostr_client = manager_module.NostrClient(
                    encryption_manager=pm.encryption_manager,
                    fingerprint=pm.current_fingerprint,
                    config_manager=getattr(pm, "config_manager", None),
                    parent_seed=getattr(pm, "parent_seed", None),
                    key_index=pm.KEY_INDEX,
                    account_index=pm.nostr_account_idx,
                )
                if getattr(pm, "manifest_id", None) and hasattr(
                    pm.nostr_client, "_state_lock"
                ):
                    from nostr.backup_models import Manifest

                    with pm.nostr_client._state_lock:
                        pm.nostr_client.current_manifest_id = pm.manifest_id
                        pm.nostr_client.current_manifest = Manifest(
                            ver=1,
                            algo="gzip",
                            chunks=[],
                            delta_since=pm.delta_since or None,
                        )
                logging.info(
                    f"NostrClient re-initialized with seed profile {pm.current_fingerprint}."
                )
            except Exception as e:
                logging.error(f"Failed to re-initialize NostrClient: {e}")
                print(
                    colored(f"Error: Failed to re-initialize NostrClient: {e}", "red")
                )
                return False

            return True
        except Exception as e:  # pragma: no cover - defensive
            logging.error(f"Error during seed profile switching: {e}", exc_info=True)
            print(colored(f"Error: Failed to switch seed profiles: {e}", "red"))
            return False
