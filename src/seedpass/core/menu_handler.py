from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

from termcolor import colored

from .entry_types import EntryType, ALL_ENTRY_TYPES
import seedpass.core.manager as manager_module
from utils.color_scheme import color_text
from utils.terminal_utils import clear_header_with_notification
from utils.logging_utils import pause_logging_for_ui

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .manager import PasswordManager


class MenuHandler:
    """Handle interactive menu operations for :class:`PasswordManager`."""

    def __init__(self, manager: PasswordManager) -> None:
        self.manager = manager

    @pause_logging_for_ui
    def handle_list_entries(self) -> None:
        """List entries and optionally show details."""
        pm = self.manager
        try:
            while True:
                fp, parent_fp, child_fp = pm.header_fingerprint_args
                clear_header_with_notification(
                    pm,
                    fp,
                    "Main Menu > List Entries",
                    parent_fingerprint=parent_fp,
                    child_fingerprint=child_fp,
                )
                print(color_text("\nList Entries:", "menu"))
                print(color_text("1. All", "menu"))
                option_map: dict[str, str] = {}
                for i, etype in enumerate(ALL_ENTRY_TYPES, start=2):
                    label = etype.replace("_", " ").title()
                    print(color_text(f"{i}. {label}", "menu"))
                    option_map[str(i)] = etype
                choice = input("Select entry type or press Enter to go back: ").strip()
                if choice == "1":
                    filter_kinds = None
                elif choice in option_map:
                    filter_kinds = [option_map[choice]]
                elif not choice:
                    return
                else:
                    print(colored("Invalid choice.", "red"))
                    continue

                while True:
                    summaries = pm.entry_manager.get_entry_summaries(
                        filter_kinds, include_archived=False
                    )
                    if not summaries:
                        break
                    fp, parent_fp, child_fp = pm.header_fingerprint_args
                    clear_header_with_notification(
                        pm,
                        fp,
                        "Main Menu > List Entries",
                        parent_fingerprint=parent_fp,
                        child_fingerprint=child_fp,
                    )
                    print(colored("\n[+] Entries:\n", "green"))
                    for idx, etype, label in summaries:
                        if filter_kinds is None:
                            display_type = etype.capitalize()
                            print(colored(f"{idx}. {display_type} - {label}", "cyan"))
                        else:
                            print(colored(f"{idx}. {label}", "cyan"))
                    idx_input = input(
                        "Enter index to view details or press Enter to go back: "
                    ).strip()
                    if not idx_input:
                        break
                    if not idx_input.isdigit():
                        print(colored("Invalid index.", "red"))
                        continue
                    pm.show_entry_details_by_index(int(idx_input))
        except Exception as e:  # pragma: no cover - defensive
            logging.error(f"Failed to list entries: {e}", exc_info=True)
            print(colored(f"Error: Failed to list entries: {e}", "red"))

    @pause_logging_for_ui
    def handle_display_totp_codes(self) -> None:
        """Display all stored TOTP codes with a countdown progress bar."""
        pm = self.manager
        try:
            fp, parent_fp, child_fp = pm.header_fingerprint_args
            clear_header_with_notification(
                pm,
                fp,
                "Main Menu > 2FA Codes",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            data = pm.entry_manager.vault.load_index()
            entries = data.get("entries", {})
            totp_list: list[tuple[str, int, int, bool]] = []
            for idx_str, entry in entries.items():
                if pm._entry_type_str(entry) == EntryType.TOTP.value and not entry.get(
                    "archived", entry.get("blacklisted", False)
                ):
                    label = entry.get("label", "")
                    period = int(entry.get("period", 30))
                    imported = "secret" in entry
                    totp_list.append((label, int(idx_str), period, imported))

            if not totp_list:
                pm.notify("No 2FA entries found.", level="WARNING")
                return

            totp_list.sort(key=lambda t: t[0].lower())
            print(colored("Press Enter to return to the menu.", "cyan"))

            from .totp import TotpManager

            secrets_cache: dict[int, str] = {}
            key = getattr(pm, "KEY_TOTP_DET", None) or getattr(pm, "parent_seed", None)
            for _, idx, _, _ in totp_list:
                try:
                    secrets_cache[idx] = pm.entry_manager.get_totp_secret(idx, key)
                except Exception as e:
                    logging.error(f"Failed to retrieve TOTP secret for index {idx}: {e}")

            while True:
                fp, parent_fp, child_fp = pm.header_fingerprint_args
                clear_header_with_notification(
                    pm,
                    fp,
                    "Main Menu > 2FA Codes",
                    parent_fingerprint=parent_fp,
                    child_fingerprint=child_fp,
                )
                print(colored("Press Enter to return to the menu.", "cyan"))
                generated = [t for t in totp_list if not t[3]]
                imported_list = [t for t in totp_list if t[3]]
                if generated:
                    print(colored("\nGenerated 2FA Codes:", "green"))
                    for label, idx, period, _ in generated:
                        if idx in secrets_cache:
                            code = TotpManager.current_code_from_secret(
                                secrets_cache[idx]
                            )
                        else:
                            code = "ERROR"
                        remaining = pm.entry_manager.get_totp_time_remaining(idx)
                        filled = int(20 * (period - remaining) / period)
                        bar = "[" + "#" * filled + "-" * (20 - filled) + "]"
                        if pm.secret_mode_enabled:
                            if manager_module.copy_to_clipboard(
                                code, pm.clipboard_clear_delay
                            ):
                                print(
                                    f"[{idx}] {label}: [HIDDEN] {bar} {remaining:2d}s - copied to clipboard"
                                )
                        else:
                            print(
                                f"[{idx}] {label}: {color_text(code, 'deterministic')} {bar} {remaining:2d}s"
                            )
                if imported_list:
                    print(colored("\nImported 2FA Codes:", "green"))
                    for label, idx, period, _ in imported_list:
                        if idx in secrets_cache:
                            code = TotpManager.current_code_from_secret(
                                secrets_cache[idx]
                            )
                        else:
                            code = "ERROR"
                        remaining = pm.entry_manager.get_totp_time_remaining(idx)
                        filled = int(20 * (period - remaining) / period)
                        bar = "[" + "#" * filled + "-" * (20 - filled) + "]"
                        if pm.secret_mode_enabled:
                            if manager_module.copy_to_clipboard(
                                code, pm.clipboard_clear_delay
                            ):
                                print(
                                    f"[{idx}] {label}: [HIDDEN] {bar} {remaining:2d}s - copied to clipboard"
                                )
                        else:
                            print(
                                f"[{idx}] {label}: {color_text(code, 'imported')} {bar} {remaining:2d}s"
                            )
                sys.stdout.flush()
                try:
                    user_input = manager_module.timed_input("", 1)
                    if user_input.strip() == "" or user_input.strip().lower() == "b":
                        break
                except TimeoutError:
                    pass
                except KeyboardInterrupt:
                    print()
                    break
        except Exception as e:  # pragma: no cover - defensive
            logging.error(f"Error displaying TOTP codes: {e}", exc_info=True)
            print(colored(f"Error: Failed to display TOTP codes: {e}", "red"))
