from __future__ import annotations

import logging
import sys
import time
from typing import TYPE_CHECKING

from termcolor import colored

from seedpass.core.entry_types import EntryType
from seedpass.core.totp import TotpManager
from utils.color_scheme import color_text

if TYPE_CHECKING:
    from seedpass.core.manager import PasswordManager

logger = logging.getLogger(__name__)


class DisplayService:
    """Service for displaying sensitive entry information."""

    def __init__(self, manager: PasswordManager) -> None:
        self.manager = manager

    @staticmethod
    def _manager_module():
        # Route interactive helpers through seedpass.core.manager so tests
        # can monkeypatch one module surface consistently.
        from seedpass.core import manager as manager_module

        return manager_module

    def _confirm_action(self, prompt_message: str) -> bool:
        return self._manager_module().confirm_action(prompt_message)

    def _copy_to_clipboard(self, value: str) -> bool:
        return self._manager_module().copy_to_clipboard(
            value, self.manager.clipboard_clear_delay
        )

    def _timed_input(self, prompt: str, timeout: float) -> str:
        return self._manager_module().timed_input(prompt, timeout)

    def display_sensitive_entry_info(self, entry: dict, index: int) -> None:
        """Display information for a sensitive entry.

        Parameters
        ----------
        entry: dict
            Entry data retrieved from the vault.
        index: int
            Index of the entry being displayed.
        """
        # Access private attribute directly as we are moving logic from manager
        self.manager._suppress_entry_actions_menu = False

        entry_type = self.manager._entry_type_str(entry)

        if entry_type == EntryType.TOTP.value:
            self._display_totp(entry, index)
        elif entry_type == EntryType.SSH.value:
            self._display_ssh(entry, index)
        elif entry_type == EntryType.SEED.value:
            self._display_seed(entry, index)
        elif entry_type == EntryType.PGP.value:
            self._display_pgp(entry, index)
        elif entry_type == EntryType.NOSTR.value:
            self._display_nostr(entry, index)
        elif entry_type == EntryType.KEY_VALUE.value:
            self._display_key_value(entry, index)
        elif entry_type == EntryType.DOCUMENT.value:
            self._display_document(entry, index)
        elif entry_type == EntryType.MANAGED_ACCOUNT.value:
            self._display_managed_account(entry, index)
        else:
            self._display_password(entry, index)

    def _display_totp(self, entry: dict, index: int) -> None:
        label = entry.get("label", "")
        period = int(entry.get("period", 30))
        notes = entry.get("notes", "")
        print(colored(f"Retrieving 2FA code for '{label}'.", "cyan"))
        print(colored("Press Enter to return to the menu.", "cyan"))
        try:
            key = self.manager.KEY_TOTP_DET or getattr(
                self.manager, "parent_seed", None
            )
            secret = self.manager.entry_manager.get_totp_secret(index, key)
            while True:
                code = TotpManager.current_code_from_secret(secret)
                if self.manager.secret_mode_enabled:
                    if self._copy_to_clipboard(code):
                        print(
                            colored(
                                f"[+] 2FA code for '{label}' copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                                "green",
                            )
                        )
                else:
                    print(colored("\n[+] Retrieved 2FA Code:\n", "green"))
                    print(colored(f"Label: {label}", "cyan"))
                    imported = "secret" in entry
                    category = "imported" if imported else "deterministic"
                    print(color_text(f"Code: {code}", category))
                if notes:
                    print(colored(f"Notes: {notes}", "cyan"))
                tags = entry.get("tags", [])
                if tags:
                    print(colored(f"Tags: {', '.join(tags)}", "cyan"))
                remaining = self.manager.entry_manager.get_totp_time_remaining(index)
                exit_loop = False
                while remaining > 0:
                    filled = int(20 * (period - remaining) / period)
                    bar = "[" + "#" * filled + "-" * (20 - filled) + "]"
                    sys.stdout.write(f"\r{bar} {remaining:2d}s")
                    sys.stdout.flush()
                    try:
                        user_input = self._timed_input("", 1)
                        if (
                            user_input.strip() == ""
                            or user_input.strip().lower() == "b"
                        ):
                            exit_loop = True
                            break
                    except TimeoutError:
                        pass
                    except KeyboardInterrupt:
                        exit_loop = True
                        print()
                        break
                    remaining -= 1
                sys.stdout.write("\n")
                sys.stdout.flush()
                if exit_loop:
                    break
        except Exception as e:
            logger.error(f"Error generating TOTP code: {e}", exc_info=True)
            print(colored(f"Error: Failed to generate TOTP code: {e}", "red"))

    def _display_ssh(self, entry: dict, index: int) -> None:
        notes = entry.get("notes", "")
        label = entry.get("label", "")
        if not self._confirm_action(
            "WARNING: Displaying SSH keys reveals sensitive information. Continue? (Y/N): "
        ):
            self.manager.notify("SSH key display cancelled.", level="WARNING")
            return
        try:
            priv_pem, pub_pem = self.manager.entry_manager.get_ssh_key_pair(
                index, self.manager.parent_seed
            )
            print(colored("\n[+] Retrieved SSH Key Pair:\n", "green"))
            if label:
                print(colored(f"Label: {label}", "cyan"))
            if notes:
                print(colored(f"Notes: {notes}", "cyan"))
            tags = entry.get("tags", [])
            if tags:
                print(colored(f"Tags: {', '.join(tags)}", "cyan"))
            print(colored("Public Key:", "cyan"))
            print(color_text(pub_pem, "default"))
            if self.manager.secret_mode_enabled:
                if self._copy_to_clipboard(priv_pem):
                    print(
                        colored(
                            f"[+] SSH private key copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                            "green",
                        )
                    )
            else:
                print(colored("Private Key:", "cyan"))
                print(color_text(priv_pem, "deterministic"))
        except Exception as e:
            logger.error(f"Error deriving SSH key pair: {e}", exc_info=True)
            print(colored(f"Error: Failed to derive SSH keys: {e}", "red"))

    def _display_seed(self, entry: dict, index: int) -> None:
        notes = entry.get("notes", "")
        label = entry.get("label", "")
        if not self._confirm_action(
            "WARNING: Displaying the seed phrase reveals sensitive information. Continue? (Y/N): "
        ):
            self.manager.notify("Seed phrase display cancelled.", level="WARNING")
            return
        try:
            phrase = self.manager.entry_manager.get_seed_phrase(
                index, self.manager.parent_seed
            )
            print(colored("\n[+] Retrieved Seed Phrase:\n", "green"))
            print(colored(f"Index: {index}", "cyan"))
            if label:
                print(colored(f"Label: {label}", "cyan"))
            if notes:
                print(colored(f"Notes: {notes}", "cyan"))
            tags = entry.get("tags", [])
            if tags:
                print(colored(f"Tags: {', '.join(tags)}", "cyan"))
            if self.manager.secret_mode_enabled:
                if self._copy_to_clipboard(phrase):
                    print(
                        colored(
                            f"[+] Seed phrase copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                            "green",
                        )
                    )
            else:
                print(color_text(phrase, "deterministic"))
            if self._confirm_action("Show derived entropy as hex? (Y/N): "):
                from local_bip85.bip85 import BIP85
                from bip_utils import Bip39SeedGenerator

                words = int(entry.get("word_count", entry.get("words", 24)))
                entropy_bytes = {12: 16, 18: 24, 24: 32}.get(words, 32)
                seed_bytes = Bip39SeedGenerator(self.manager.parent_seed).Generate()
                bip85 = BIP85(seed_bytes)
                entropy = bip85.derive_entropy(
                    index=int(entry.get("index", index)),
                    entropy_bytes=entropy_bytes,
                    app_no=39,
                    word_count=words,
                )
                print(color_text(f"Entropy: {entropy.hex()}", "deterministic"))
        except Exception as e:
            logger.error(f"Error deriving seed phrase: {e}", exc_info=True)
            print(colored(f"Error: Failed to derive seed phrase: {e}", "red"))

    def _display_pgp(self, entry: dict, index: int) -> None:
        notes = entry.get("notes", "")
        label = entry.get("user_id", "")
        if not self._confirm_action(
            "WARNING: Displaying the PGP key reveals sensitive information. Continue? (Y/N): "
        ):
            self.manager.notify("PGP key display cancelled.", level="WARNING")
            return
        try:
            priv_key, fingerprint = self.manager.entry_manager.get_pgp_key(
                index, self.manager.parent_seed
            )
            print(colored("\n[+] Retrieved PGP Key:\n", "green"))
            if label:
                print(colored(f"User ID: {label}", "cyan"))
            if notes:
                print(colored(f"Notes: {notes}", "cyan"))
            tags = entry.get("tags", [])
            if tags:
                print(colored(f"Tags: {', '.join(tags)}", "cyan"))
            print(colored(f"Fingerprint: {fingerprint}", "cyan"))
            if self.manager.secret_mode_enabled:
                if self._copy_to_clipboard(priv_key):
                    print(
                        colored(
                            f"[+] PGP key copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                            "green",
                        )
                    )
            else:
                print(color_text(priv_key, "deterministic"))
        except Exception as e:
            logger.error(f"Error deriving PGP key: {e}", exc_info=True)
            print(colored(f"Error: Failed to derive PGP key: {e}", "red"))

    def _display_nostr(self, entry: dict, index: int) -> None:
        label = entry.get("label", "")
        notes = entry.get("notes", "")
        try:
            npub, nsec = self.manager.entry_manager.get_nostr_key_pair(
                index, self.manager.parent_seed
            )
            print(colored("\n[+] Retrieved Nostr Keys:\n", "green"))
            print(colored(f"Label: {label}", "cyan"))
            print(colored(f"npub: {npub}", "cyan"))
            if self.manager.secret_mode_enabled:
                if self._copy_to_clipboard(nsec):
                    print(
                        colored(
                            f"[+] nsec copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                            "green",
                        )
                    )
            else:
                print(color_text(f"nsec: {nsec}", "deterministic"))
            if notes:
                print(colored(f"Notes: {notes}", "cyan"))
            tags = entry.get("tags", [])
            if tags:
                print(colored(f"Tags: {', '.join(tags)}", "cyan"))
        except Exception as e:
            logger.error(f"Error deriving Nostr keys: {e}", exc_info=True)
            print(colored(f"Error: Failed to derive Nostr keys: {e}", "red"))

    def _display_key_value(self, entry: dict, index: int) -> None:
        label = entry.get("label", "")
        value = entry.get("value", "")
        notes = entry.get("notes", "")
        archived = entry.get("archived", False)
        print(colored(f"Retrieving value for key '{label}'.", "cyan"))
        if notes:
            print(colored(f"Notes: {notes}", "cyan"))
        tags = entry.get("tags", [])
        if tags:
            print(colored(f"Tags: {', '.join(tags)}", "cyan"))
        print(
            colored(f"Archived Status: {'Archived' if archived else 'Active'}", "cyan")
        )
        if self.manager.secret_mode_enabled:
            if self._copy_to_clipboard(value):
                print(
                    colored(
                        f"[+] Value copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                        "green",
                    )
                )
        else:
            print(color_text(f"Value: {value}", "deterministic"))

        custom_fields = entry.get("custom_fields", [])
        if custom_fields:
            print(colored("Additional Fields:", "cyan"))
            hidden_fields = []
            for field in custom_fields:
                f_label = field.get("label", "")
                f_value = field.get("value", "")
                if field.get("is_hidden"):
                    hidden_fields.append((f_label, f_value))
                    print(colored(f"  {f_label}: [hidden]", "cyan"))
                else:
                    print(colored(f"  {f_label}: {f_value}", "cyan"))
            if hidden_fields:
                show = input("Reveal hidden fields? (y/N): ").strip().lower()
                if show == "y":
                    for f_label, f_value in hidden_fields:
                        if self.manager.secret_mode_enabled:
                            if self._copy_to_clipboard(f_value):
                                print(
                                    colored(
                                        f"[+] {f_label} copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                                        "green",
                                    )
                                )
                        else:
                            print(colored(f"  {f_label}: {f_value}", "cyan"))

    def _display_managed_account(self, entry: dict, index: int) -> None:
        label = entry.get("label", "")
        notes = entry.get("notes", "")
        archived = entry.get("archived", False)
        fingerprint = entry.get("fingerprint", "")
        print(colored(f"Managed account '{label}'.", "cyan"))
        if notes:
            print(colored(f"Notes: {notes}", "cyan"))
        if fingerprint:
            print(colored(f"Fingerprint: {fingerprint}", "cyan"))
        tags = entry.get("tags", [])
        if tags:
            print(colored(f"Tags: {', '.join(tags)}", "cyan"))
        print(
            colored(f"Archived Status: {'Archived' if archived else 'Active'}", "cyan")
        )
        action = (
            input(
                "Enter 'r' to reveal seed, 'l' to load account, or press Enter to go back: "
            )
            .strip()
            .lower()
        )
        if action == "r":
            seed = self.manager.entry_manager.get_managed_account_seed(
                index, self.manager.parent_seed
            )
            if self.manager.secret_mode_enabled:
                if self._copy_to_clipboard(seed):
                    print(
                        colored(
                            f"[+] Seed phrase copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                            "green",
                        )
                    )
            else:
                print(color_text(seed, "deterministic"))
            return
        if action == "l":
            self.manager._suppress_entry_actions_menu = True
            self.manager.load_managed_account(index)
            return

    def _display_document(self, entry: dict, _index: int) -> None:
        label = entry.get("label", "")
        file_type = entry.get("file_type", "txt")
        notes = entry.get("notes", "")
        content = str(entry.get("content", ""))
        archived = entry.get("archived", False)
        print(colored(f"Document '{label}' ({file_type})", "cyan"))
        if notes:
            print(colored(f"Notes: {notes}", "cyan"))
        tags = entry.get("tags", [])
        if tags:
            print(colored(f"Tags: {', '.join(tags)}", "cyan"))
        print(
            colored(f"Archived Status: {'Archived' if archived else 'Active'}", "cyan")
        )
        print(color_text("\n--- BEGIN DOCUMENT ---", "index"))
        print(color_text(content, "index"))
        print(color_text("--- END DOCUMENT ---\n", "index"))
        custom_fields = entry.get("custom_fields", [])
        if custom_fields:
            print(colored("Additional Fields:", "cyan"))
            hidden_fields = []
            for field in custom_fields:
                f_label = field.get("label", "")
                f_value = field.get("value", "")
                if field.get("is_hidden"):
                    hidden_fields.append((f_label, f_value))
                    print(colored(f"  {f_label}: [hidden]", "cyan"))
                else:
                    print(colored(f"  {f_label}: {f_value}", "cyan"))
            if hidden_fields:
                show = input("Reveal hidden fields? (y/N): ").strip().lower()
                if show == "y":
                    for f_label, f_value in hidden_fields:
                        if self.manager.secret_mode_enabled:
                            if self._copy_to_clipboard(f_value):
                                print(
                                    colored(
                                        f"[+] {f_label} copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                                        "green",
                                    )
                                )
                        else:
                            print(colored(f"  {f_label}: {f_value}", "cyan"))

    def _display_password(self, entry: dict, index: int) -> None:
        website_name = entry.get("label", entry.get("website"))
        length = entry.get("length")
        username = entry.get("username")
        url = entry.get("url")
        blacklisted = entry.get("archived", entry.get("blacklisted"))
        notes = entry.get("notes", "")

        print(
            colored(
                f"Retrieving password for '{website_name}' with length {length}.",
                "cyan",
            )
        )
        if username:
            print(colored(f"Username: {username}", "cyan"))
        if url:
            print(colored(f"URL: {url}", "cyan"))
        if blacklisted:
            self.manager.notify(
                "Warning: This password is archived and should not be used.",
                level="WARNING",
            )

        password = self.manager._generate_password_for_entry(entry, index, length)

        if password:
            if self.manager.secret_mode_enabled:
                if self._copy_to_clipboard(password):
                    print(
                        colored(
                            f"[+] Password for '{website_name}' copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                            "green",
                        )
                    )
            else:
                print(
                    colored(
                        f"\n[+] Retrieved Password for {website_name}:\n",
                        "green",
                    )
                )
                print(color_text(f"Password: {password}", "deterministic"))
                print(colored(f"Associated Username: {username or 'N/A'}", "cyan"))
                print(colored(f"Associated URL: {url or 'N/A'}", "cyan"))
                print(
                    colored(
                        f"Archived Status: {'Archived' if blacklisted else 'Active'}",
                        "cyan",
                    )
                )
                if notes:
                    print(colored(f"Notes: {notes}", "cyan"))
                tags = entry.get("tags", [])
                if tags:
                    print(colored(f"Tags: {', '.join(tags)}", "cyan"))
                custom_fields = entry.get("custom_fields", [])
                if custom_fields:
                    print(colored("Additional Fields:", "cyan"))
                    hidden_fields = []
                    for field in custom_fields:
                        label = field.get("label", "")
                        value = field.get("value", "")
                        if field.get("is_hidden"):
                            hidden_fields.append((label, value))
                            print(colored(f"  {label}: [hidden]", "cyan"))
                        else:
                            print(colored(f"  {label}: {value}", "cyan"))
                    if hidden_fields:
                        show = input("Reveal hidden fields? (y/N): ").strip().lower()
                        if show == "y":
                            for label, value in hidden_fields:
                                if self.manager.secret_mode_enabled:
                                    if self._copy_to_clipboard(value):
                                        print(
                                            colored(
                                                f"[+] {label} copied to clipboard. Will clear in {self.manager.clipboard_clear_delay} seconds.",
                                                "green",
                                            )
                                        )
                                else:
                                    print(colored(f"  {label}: {value}", "cyan"))
        else:
            print(colored("Error: Failed to retrieve the password.", "red"))
