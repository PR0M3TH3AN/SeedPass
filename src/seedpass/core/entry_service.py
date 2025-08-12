from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from termcolor import colored

from constants import (
    DEFAULT_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
)
import seedpass.core.manager as manager_module
from utils.terminal_utils import clear_header_with_notification, pause

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .manager import PasswordManager


class EntryService:
    """Entry management operations for :class:`PasswordManager`."""

    def __init__(self, manager: PasswordManager) -> None:
        self.manager = manager

    def handle_add_password(self) -> None:
        pm = self.manager
        try:
            fp, parent_fp, child_fp = pm.header_fingerprint_args
            clear_header_with_notification(
                pm,
                fp,
                "Main Menu > Add Entry > Password",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )

            def prompt_length() -> int | None:
                length_input = input(
                    f"Enter desired password length (default {DEFAULT_PASSWORD_LENGTH}): "
                ).strip()
                length = DEFAULT_PASSWORD_LENGTH
                if length_input:
                    if not length_input.isdigit():
                        print(
                            colored("Error: Password length must be a number.", "red")
                        )
                        return None
                    length = int(length_input)
                    if not (MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH):
                        print(
                            colored(
                                f"Error: Password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}.",
                                "red",
                            )
                        )
                        return None
                return length

            def finalize_entry(index: int, label: str, length: int) -> None:
                pm.is_dirty = True
                pm.last_update = time.time()

                entry = pm.entry_manager.retrieve_entry(index)
                password = pm._generate_password_for_entry(entry, index, length)

                print(
                    colored(
                        f"\n[+] Password generated and indexed with ID {index}.\n",
                        "green",
                    )
                )
                if pm.secret_mode_enabled:
                    if manager_module.copy_to_clipboard(
                        password, pm.clipboard_clear_delay
                    ):
                        print(
                            colored(
                                f"[+] Password copied to clipboard. Will clear in {pm.clipboard_clear_delay} seconds.",
                                "green",
                            )
                        )
                else:
                    print(colored(f"Password for {label}: {password}\n", "yellow"))

                try:
                    pm.start_background_vault_sync()
                    logging.info(
                        "Encrypted index posted to Nostr after entry addition."
                    )
                except Exception as nostr_error:  # pragma: no cover - best effort
                    logging.error(
                        f"Failed to post updated index to Nostr: {nostr_error}",
                        exc_info=True,
                    )
                pause()

            mode = input("Choose mode: [Q]uick or [A]dvanced? ").strip().lower()

            website_name = input("Enter the label or website name: ").strip()
            if not website_name:
                print(colored("Error: Label cannot be empty.", "red"))
                return

            username = input("Enter the username (optional): ").strip()
            url = input("Enter the URL (optional): ").strip()

            if mode.startswith("q"):
                length = prompt_length()
                if length is None:
                    return
                include_special_input = (
                    input("Include special characters? (Y/n): ").strip().lower()
                )
                include_special_chars: bool | None = None
                if include_special_input:
                    include_special_chars = include_special_input != "n"

                index = pm.entry_manager.add_entry(
                    website_name,
                    length,
                    username,
                    url,
                    include_special_chars=include_special_chars,
                )

                finalize_entry(index, website_name, length)
                return

            notes = input("Enter notes (optional): ").strip()
            tags_input = input("Enter tags (comma-separated, optional): ").strip()
            tags = (
                [t.strip() for t in tags_input.split(",") if t.strip()]
                if tags_input
                else []
            )

            custom_fields: list[dict[str, object]] = []
            while True:
                add_field = input("Add custom field? (y/N): ").strip().lower()
                if add_field != "y":
                    break
                label = input("  Field label: ").strip()
                value = input("  Field value: ").strip()
                hidden = input("  Hidden field? (y/N): ").strip().lower() == "y"
                custom_fields.append(
                    {"label": label, "value": value, "is_hidden": hidden}
                )

            length = prompt_length()
            if length is None:
                return

            include_special_input = (
                input("Include special characters? (Y/n): ").strip().lower()
            )
            include_special_chars: bool | None = None
            if include_special_input:
                include_special_chars = include_special_input != "n"

            allowed_special_chars = input(
                "Allowed special characters (leave blank for default): "
            ).strip()
            if not allowed_special_chars:
                allowed_special_chars = None

            special_mode = input("Special character mode (safe/leave blank): ").strip()
            if not special_mode:
                special_mode = None

            exclude_ambiguous_input = (
                input("Exclude ambiguous characters? (y/N): ").strip().lower()
            )
            exclude_ambiguous: bool | None = None
            if exclude_ambiguous_input:
                exclude_ambiguous = exclude_ambiguous_input == "y"

            min_uppercase_input = input(
                "Minimum uppercase letters (blank for default): "
            ).strip()
            if min_uppercase_input and not min_uppercase_input.isdigit():
                print(colored("Error: Minimum uppercase must be a number.", "red"))
                return
            min_uppercase = int(min_uppercase_input) if min_uppercase_input else None

            min_lowercase_input = input(
                "Minimum lowercase letters (blank for default): "
            ).strip()
            if min_lowercase_input and not min_lowercase_input.isdigit():
                print(colored("Error: Minimum lowercase must be a number.", "red"))
                return
            min_lowercase = int(min_lowercase_input) if min_lowercase_input else None

            min_digits_input = input("Minimum digits (blank for default): ").strip()
            if min_digits_input and not min_digits_input.isdigit():
                print(colored("Error: Minimum digits must be a number.", "red"))
                return
            min_digits = int(min_digits_input) if min_digits_input else None

            min_special_input = input(
                "Minimum special characters (blank for default): "
            ).strip()
            if min_special_input and not min_special_input.isdigit():
                print(colored("Error: Minimum special must be a number.", "red"))
                return
            min_special = int(min_special_input) if min_special_input else None

            index = pm.entry_manager.add_entry(
                website_name,
                length,
                username,
                url,
                archived=False,
                notes=notes,
                custom_fields=custom_fields,
                tags=tags,
                include_special_chars=include_special_chars,
                allowed_special_chars=allowed_special_chars,
                special_mode=special_mode,
                exclude_ambiguous=exclude_ambiguous,
                min_uppercase=min_uppercase,
                min_lowercase=min_lowercase,
                min_digits=min_digits,
                min_special=min_special,
            )

            finalize_entry(index, website_name, length)

        except Exception as e:  # pragma: no cover - defensive
            logging.error(f"Error during password generation: {e}", exc_info=True)
            print(colored(f"Error: Failed to generate password: {e}", "red"))
            pause()
