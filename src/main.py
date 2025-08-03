# main.py
from pathlib import Path
import sys

# Add bundled vendor directory to sys.path so bundled dependencies can be imported
vendor_dir = Path(__file__).parent / "vendor"
if vendor_dir.exists():
    sys.path.insert(0, str(vendor_dir))

import os
import logging
import signal
import time
import argparse
import asyncio
import gzip
import tomli
from colorama import init as colorama_init
from termcolor import colored
from utils.color_scheme import color_text
import traceback

from seedpass.core.manager import PasswordManager
from nostr.client import NostrClient
from seedpass.core.entry_types import EntryType
from constants import INACTIVITY_TIMEOUT, initialize_app
from utils.password_prompt import PasswordPromptError
from utils import (
    timed_input,
    copy_to_clipboard,
    clear_screen,
    pause,
    clear_header_with_notification,
)
from utils.atomic_write import atomic_write
import queue
from local_bip85.bip85 import Bip85Error


colorama_init()


def load_global_config() -> dict:
    """Load configuration from ~/.seedpass/config.toml if present."""
    config_path = Path.home() / ".seedpass" / "config.toml"
    if not config_path.exists():
        return {}
    try:
        with open(config_path, "rb") as f:
            return tomli.load(f)
    except Exception as exc:
        logging.warning(f"Failed to read {config_path}: {exc}")
        return {}


def configure_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Keep this as DEBUG to capture all logs

    # Remove all handlers associated with the root logger object
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Ensure the 'logs' directory exists
    log_directory = Path("logs")
    if not log_directory.exists():
        log_directory.mkdir(parents=True, exist_ok=True)

    # Create handlers
    c_handler = logging.StreamHandler(sys.stdout)
    f_handler = logging.FileHandler(log_directory / "main.log")

    # Set levels: only errors and critical messages will be shown in the console
    c_handler.setLevel(logging.ERROR)
    f_handler.setLevel(logging.DEBUG)

    # Create formatters and add them to handlers
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]"
    )
    c_handler.setFormatter(formatter)
    f_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

    # Set logging level for third-party libraries to WARNING to suppress their debug logs
    logging.getLogger("monstr").setLevel(logging.WARNING)
    logging.getLogger("nostr").setLevel(logging.WARNING)


def confirm_action(prompt: str) -> bool:
    """
    Prompts the user for confirmation.

    :param prompt: The confirmation message to display.
    :return: True if user confirms, False otherwise.
    """
    while True:
        choice = input(colored(prompt, "yellow")).strip().lower()
        if choice in ["y", "yes"]:
            return True
        elif choice in ["n", "no"]:
            return False
        else:
            print(colored("Please enter 'Y' or 'N'.", "red"))


def drain_notifications(pm: PasswordManager) -> str | None:
    """Return the next queued notification message if available."""
    queue_obj = getattr(pm, "notifications", None)
    if queue_obj is None:
        return None
    try:
        note = queue_obj.get_nowait()
    except queue.Empty:
        return None
    category = getattr(note, "level", "info").lower()
    if category not in ("info", "warning", "error"):
        category = "info"
    return color_text(getattr(note, "message", ""), category)


def get_notification_text(pm: PasswordManager) -> str:
    """Return the current notification from ``pm`` as a colored string."""
    note = None
    if hasattr(pm, "get_current_notification"):
        try:
            note = pm.get_current_notification()
        except Exception:
            note = None
    if not note:
        return ""
    category = getattr(note, "level", "info").lower()
    if category not in ("info", "warning", "error"):
        category = "info"
    return color_text(getattr(note, "message", ""), category)


def handle_switch_fingerprint(password_manager: PasswordManager):
    """
    Handles switching the active fingerprint.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        fingerprints = password_manager.fingerprint_manager.list_fingerprints()
        if not fingerprints:
            print(
                colored(
                    "No seed profiles available to switch. Please add a new seed profile first.",
                    "yellow",
                )
            )
            return

        print(colored("Available Seed Profiles:", "cyan"))
        for idx, fp in enumerate(fingerprints, start=1):
            label = password_manager.fingerprint_manager.display_name(fp)
            print(colored(f"{idx}. {label}", "cyan"))

        choice = input("Select a seed profile by number to switch: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
            print(colored("Invalid selection.", "red"))
            return

        selected_fingerprint = fingerprints[int(choice) - 1]
        if password_manager.select_fingerprint(selected_fingerprint):
            print(colored(f"Switched to seed profile {selected_fingerprint}.", "green"))
        else:
            print(colored("Failed to switch seed profile.", "red"))
    except Exception as e:
        logging.error(f"Error during fingerprint switch: {e}", exc_info=True)
        print(colored(f"Error: Failed to switch seed profile: {e}", "red"))


def handle_add_new_fingerprint(password_manager: PasswordManager):
    """
    Handles adding a new seed profile.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        password_manager.add_new_fingerprint()
    except Exception as e:
        logging.error(f"Error adding new seed profile: {e}", exc_info=True)
        print(colored(f"Error: Failed to add new seed profile: {e}", "red"))


def handle_remove_fingerprint(password_manager: PasswordManager):
    """
    Handles removing an existing seed profile.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        fingerprints = password_manager.fingerprint_manager.list_fingerprints()
        if not fingerprints:
            print(colored("No seed profiles available to remove.", "yellow"))
            return

        print(colored("Available Seed Profiles:", "cyan"))
        for idx, fp in enumerate(fingerprints, start=1):
            label = password_manager.fingerprint_manager.display_name(fp)
            print(colored(f"{idx}. {label}", "cyan"))

        choice = input("Select a seed profile by number to remove: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
            print(colored("Invalid selection.", "red"))
            return

        selected_fingerprint = fingerprints[int(choice) - 1]
        confirm = confirm_action(
            f"Are you sure you want to remove seed profile {selected_fingerprint}? This will delete all associated data. (Y/N): "
        )
        if confirm:
            if password_manager.fingerprint_manager.remove_fingerprint(
                selected_fingerprint
            ):
                print(
                    colored(
                        f"Seed profile {selected_fingerprint} removed successfully.",
                        "green",
                    )
                )
            else:
                print(colored("Failed to remove seed profile.", "red"))
        else:
            print(colored("Seed profile removal cancelled.", "yellow"))
    except Exception as e:
        logging.error(f"Error removing seed profile: {e}", exc_info=True)
        print(colored(f"Error: Failed to remove seed profile: {e}", "red"))


def handle_list_fingerprints(password_manager: PasswordManager):
    """
    Handles listing all available seed profiles.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        fingerprints = password_manager.fingerprint_manager.list_fingerprints()
        if not fingerprints:
            print(colored("No seed profiles available.", "yellow"))
            return

        print(colored("Available Seed Profiles:", "cyan"))
        for fp in fingerprints:
            label = password_manager.fingerprint_manager.display_name(fp)
            print(colored(f"- {label}", "cyan"))
        pause()
    except Exception as e:
        logging.error(f"Error listing seed profiles: {e}", exc_info=True)
        print(colored(f"Error: Failed to list seed profiles: {e}", "red"))


def handle_display_npub(password_manager: PasswordManager):
    """
    Handles displaying the Nostr public key (npub) to the user.
    """
    try:
        npub = password_manager.nostr_client.key_manager.get_npub()
        if npub:
            print(colored(f"\nYour Nostr Public Key (npub):\n{npub}\n", "cyan"))
            logging.info("Displayed npub to the user.")
        else:
            print(colored("Nostr public key not available.", "red"))
            logging.error("Nostr public key not available.")
        pause()
    except Exception as e:
        logging.error(f"Failed to display npub: {e}", exc_info=True)
        print(colored(f"Error: Failed to display npub: {e}", "red"))


def _display_live_stats(
    password_manager: PasswordManager, interval: float = 1.0
) -> None:
    """Continuously refresh stats until the user presses Enter.

    Each refresh also triggers a background sync so the latest stats are
    displayed if newer data exists on Nostr.
    """

    stats_mgr = getattr(password_manager, "stats_manager", None)
    display_fn = getattr(password_manager, "display_stats", None)
    sync_fn = getattr(password_manager, "start_background_sync", None)
    if not callable(display_fn):
        return

    if callable(sync_fn):
        try:
            sync_fn()
        except Exception as exc:  # pragma: no cover - sync best effort
            logging.debug("Background sync failed during stats display: %s", exc)

    if not sys.stdin or not sys.stdin.isatty():
        clear_screen()
        display_fn()
        note = get_notification_text(password_manager)
        if note:
            print(note)
        print(colored("Press Enter to continue.", "cyan"))
        pause()
        if stats_mgr is not None:
            stats_mgr.reset()
        return

    while True:
        if callable(sync_fn):
            try:
                sync_fn()
            except Exception:  # pragma: no cover - sync best effort
                logging.debug("Background sync failed during stats display")
        clear_screen()
        display_fn()
        note = get_notification_text(password_manager)
        if note:
            print(note)
        print(colored("Press Enter to continue.", "cyan"))
        sys.stdout.flush()
        try:
            user_input = timed_input("", interval)
            if user_input.strip() == "" or user_input.strip().lower() == "b":
                break
        except TimeoutError:
            pass
        except KeyboardInterrupt:
            print()
            break
    if stats_mgr is not None:
        stats_mgr.reset()


def handle_display_stats(password_manager: PasswordManager) -> None:
    """Print seed profile statistics with live updates."""
    try:
        _display_live_stats(password_manager)
    except Exception as e:  # pragma: no cover - display best effort
        logging.error(f"Failed to display stats: {e}", exc_info=True)
        print(colored(f"Error: Failed to display stats: {e}", "red"))


def print_matches(
    password_manager: PasswordManager,
    matches: list[tuple[int, str, str | None, str | None, bool, EntryType]],
) -> None:
    """Print a list of search matches."""
    print(colored("\n[+] Matches:\n", "green"))
    for entry in matches:
        idx, website, username, url, blacklisted, etype = entry
        data = password_manager.entry_manager.retrieve_entry(idx)
        print(color_text(f"Index: {idx}", "index"))
        if etype == EntryType.TOTP:
            label = data.get("label", website) if data else website
            deriv = data.get("index", idx) if data else idx
            print(color_text(f"  Label: {label}", "index"))
            print(color_text(f"  Derivation Index: {deriv}", "index"))
        elif etype == EntryType.SEED:
            print(color_text("  Type: Seed Phrase", "index"))
        elif etype == EntryType.SSH:
            print(color_text("  Type: SSH Key", "index"))
        elif etype == EntryType.PGP:
            print(color_text("  Type: PGP Key", "index"))
        elif etype == EntryType.NOSTR:
            print(color_text("  Type: Nostr Key", "index"))
        elif etype == EntryType.KEY_VALUE:
            print(color_text("  Type: Key/Value", "index"))
        else:
            if website:
                print(color_text(f"  Label: {website}", "index"))
            if username:
                print(color_text(f"  Username: {username}", "index"))
            if url:
                print(color_text(f"  URL: {url}", "index"))
            print(color_text(f"  Archived: {'Yes' if blacklisted else 'No'}", "index"))
        print("-" * 40)


def handle_post_to_nostr(
    password_manager: PasswordManager, alt_summary: str | None = None
):
    """
    Handles the action of posting the encrypted password index to Nostr.
    """
    try:
        result = password_manager.sync_vault(alt_summary=alt_summary)
        if result:
            print(colored("\N{WHITE HEAVY CHECK MARK} Sync complete.", "green"))
            print("Event IDs:")
            print(f"  manifest: {result['manifest_id']}")
            for cid in result["chunk_ids"]:
                print(f"  chunk: {cid}")
            for did in result["delta_ids"]:
                print(f"  delta: {did}")
            logging.info("Encrypted index posted to Nostr successfully.")
        else:
            print(colored("\N{CROSS MARK} Sync failed…", "red"))
            logging.error("Failed to post encrypted index to Nostr.")
    except Exception as e:
        logging.error(f"Failed to post to Nostr: {e}", exc_info=True)
        print(colored(f"Error: Failed to post to Nostr: {e}", "red"))
    finally:
        pause()


def handle_retrieve_from_nostr(password_manager: PasswordManager):
    """
    Handles the action of retrieving the encrypted password index from Nostr.
    """
    try:
        password_manager.nostr_client.fingerprint = password_manager.current_fingerprint
        result = asyncio.run(password_manager.nostr_client.fetch_latest_snapshot())
        if result:
            manifest, chunks = result
            encrypted = gzip.decompress(b"".join(chunks))
            if manifest.delta_since:
                version = int(manifest.delta_since)
                deltas = asyncio.run(
                    password_manager.nostr_client.fetch_deltas_since(version)
                )
                if deltas:
                    encrypted = deltas[-1]
            password_manager.encryption_manager.decrypt_and_save_index_from_nostr(
                encrypted
            )
            print(colored("Encrypted index retrieved and saved successfully.", "green"))
            logging.info("Encrypted index retrieved and saved successfully from Nostr.")
        else:
            msg = (
                f"No Nostr events found for fingerprint"
                f" {password_manager.current_fingerprint}."
            )
            print(colored(msg, "red"))
            logging.error(msg)
    except Exception as e:
        logging.error(f"Failed to retrieve from Nostr: {e}", exc_info=True)
        print(colored(f"Error: Failed to retrieve from Nostr: {e}", "red"))
    finally:
        pause()


def handle_view_relays(cfg_mgr: "ConfigManager") -> None:
    """Display the currently configured Nostr relays."""
    try:
        cfg = cfg_mgr.load_config(require_pin=False)
        relays = cfg.get("relays", [])
        if not relays:
            print(colored("No relays configured.", "yellow"))
            return
        print(colored("\nCurrent Relays:", "cyan"))
        for idx, relay in enumerate(relays, start=1):
            print(colored(f"{idx}. {relay}", "cyan"))
        pause()
    except Exception as e:
        logging.error(f"Error displaying relays: {e}")
        print(colored(f"Error: {e}", "red"))


def _safe_close_client_pool(pm: PasswordManager) -> None:
    """Close the Nostr client pool if the client exists."""
    client = getattr(pm, "nostr_client", None)
    if client is None:
        return
    try:
        client.close_client_pool()
    except Exception as exc:
        logging.error(f"Error during NostrClient shutdown: {exc}")


def _reload_relays(password_manager: PasswordManager, relays: list) -> None:
    """Reload NostrClient with the updated relay list."""
    try:
        _safe_close_client_pool(password_manager)
    except Exception as exc:
        logging.warning(f"Failed to close client pool: {exc}")
    try:
        password_manager.nostr_client.relays = relays
        password_manager.nostr_client.initialize_client_pool()
    except Exception as exc:
        logging.error(f"Failed to reinitialize NostrClient: {exc}")


def handle_add_relay(password_manager: PasswordManager) -> None:
    """Prompt for a relay URL and add it to the config."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    url = input("Enter relay URL to add: ").strip()
    if not url:
        print(colored("No URL entered.", "yellow"))
        return
    try:
        cfg = cfg_mgr.load_config(require_pin=False)
        relays = cfg.get("relays", [])
        if url in relays:
            print(colored("Relay already present.", "yellow"))
            return
        relays.append(url)
        cfg_mgr.set_relays(relays)
        _reload_relays(password_manager, relays)
        print(colored("Relay added.", "green"))
        try:
            handle_post_to_nostr(password_manager)
        except Exception as backup_error:
            logging.error(f"Failed to backup index to Nostr: {backup_error}")
    except Exception as e:
        logging.error(f"Error adding relay: {e}")
        print(colored(f"Error: {e}", "red"))
    finally:
        pause()


def handle_remove_relay(password_manager: PasswordManager) -> None:
    """Remove a relay from the config by its index."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        cfg = cfg_mgr.load_config(require_pin=False)
        relays = cfg.get("relays", [])
        if not relays:
            print(colored("No relays configured.", "yellow"))
            return
        for idx, relay in enumerate(relays, start=1):
            print(colored(f"{idx}. {relay}", "cyan"))
        choice = input("Select relay number to remove: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(relays)):
            print(colored("Invalid selection.", "red"))
            return
        if len(relays) == 1:
            print(
                colored(
                    "At least one relay must be configured. Add another before removing this one.",
                    "red",
                )
            )
            return
        relays.pop(int(choice) - 1)
        cfg_mgr.set_relays(relays)
        _reload_relays(password_manager, relays)
        print(colored("Relay removed.", "green"))
    except Exception as e:
        logging.error(f"Error removing relay: {e}")
        print(colored(f"Error: {e}", "red"))
    finally:
        pause()


def handle_reset_relays(password_manager: PasswordManager) -> None:
    """Reset relay list to defaults."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    from nostr.client import DEFAULT_RELAYS

    try:
        cfg_mgr.set_relays(list(DEFAULT_RELAYS))
        _reload_relays(password_manager, list(DEFAULT_RELAYS))
        print(colored("Relays reset to defaults.", "green"))
    except Exception as e:
        logging.error(f"Error resetting relays: {e}")
        print(colored(f"Error: {e}", "red"))
    finally:
        pause()


def handle_set_inactivity_timeout(password_manager: PasswordManager) -> None:
    """Change the inactivity timeout for the current seed profile."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        current = cfg_mgr.get_inactivity_timeout() / 60
        print(colored(f"Current timeout: {current:.1f} minutes", "cyan"))
    except Exception as e:
        logging.error(f"Error loading timeout: {e}")
        print(colored(f"Error: {e}", "red"))
        return
    value = input("Enter new timeout in minutes: ").strip()
    if not value:
        print(colored("No timeout entered.", "yellow"))
        return
    try:
        minutes = float(value)
        if minutes <= 0:
            print(colored("Timeout must be positive.", "red"))
            return
    except ValueError:
        print(colored("Invalid number.", "red"))
        return
    try:
        cfg_mgr.set_inactivity_timeout(minutes * 60)
        password_manager.inactivity_timeout = minutes * 60
        print(colored("Inactivity timeout updated.", "green"))
    except Exception as e:
        logging.error(f"Error saving timeout: {e}")
        print(colored(f"Error: {e}", "red"))


def handle_set_kdf_iterations(password_manager: PasswordManager) -> None:
    """Change the PBKDF2 iteration count."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        current = cfg_mgr.get_kdf_iterations()
        print(colored(f"Current iterations: {current}", "cyan"))
    except Exception as e:
        logging.error(f"Error loading iterations: {e}")
        print(colored(f"Error: {e}", "red"))
        return
    value = input("Enter new iteration count: ").strip()
    if not value:
        print(colored("No iteration count entered.", "yellow"))
        return
    try:
        iterations = int(value)
        if iterations <= 0:
            print(colored("Iterations must be positive.", "red"))
            return
    except ValueError:
        print(colored("Invalid number.", "red"))
        return
    try:
        cfg_mgr.set_kdf_iterations(iterations)
        print(colored("KDF iteration count updated.", "green"))
    except Exception as e:
        logging.error(f"Error saving iterations: {e}")
        print(colored(f"Error: {e}", "red"))


def handle_set_additional_backup_location(pm: PasswordManager) -> None:
    """Configure an optional second backup directory."""
    cfg_mgr = pm.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        current = cfg_mgr.get_additional_backup_path()
        if current:
            print(colored(f"Current path: {current}", "cyan"))
        else:
            print(colored("No additional backup location configured.", "cyan"))
    except Exception as e:
        logging.error(f"Error loading backup path: {e}")
        print(colored(f"Error: {e}", "red"))
        return

    value = input(
        "Enter directory for extra backups (leave blank to disable): "
    ).strip()
    if not value:
        try:
            cfg_mgr.set_additional_backup_path(None)
            print(colored("Additional backup location disabled.", "green"))
        except Exception as e:
            logging.error(f"Error clearing path: {e}")
            print(colored(f"Error: {e}", "red"))
        return

    try:
        path = Path(value).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        test_file = path / ".seedpass_write_test"
        atomic_write(test_file, lambda f: f.write("test"))
        test_file.unlink()
    except Exception as e:
        print(colored(f"Path not writable: {e}", "red"))
        return

    try:
        cfg_mgr.set_additional_backup_path(str(path))
        print(colored(f"Additional backups will be copied to {path}", "green"))
        if pm.backup_manager is not None:
            pm.backup_manager.create_backup()
    except Exception as e:
        logging.error(f"Error saving backup path: {e}")
        print(colored(f"Error: {e}", "red"))


def handle_set_profile_name(pm: PasswordManager) -> None:
    """Set or clear the custom name for the current seed profile."""
    fp = getattr(pm.fingerprint_manager, "current_fingerprint", None)
    if not fp:
        print(colored("No seed profile selected.", "red"))
        return
    current = pm.fingerprint_manager.get_name(fp)
    if current:
        print(colored(f"Current name: {current}", "cyan"))
    else:
        print(colored("No custom name set.", "cyan"))
    value = input("Enter new name (leave blank to remove): ").strip()
    if pm.fingerprint_manager.set_name(fp, value or None):
        if value:
            print(colored("Name updated.", "green"))
        else:
            print(colored("Name removed.", "green"))


def handle_toggle_secret_mode(pm: PasswordManager) -> None:
    """Toggle secret mode and adjust clipboard delay."""
    cfg = pm.config_manager
    if cfg is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        enabled = cfg.get_secret_mode_enabled()
        delay = cfg.get_clipboard_clear_delay()
    except Exception as exc:
        logging.error(f"Error loading secret mode settings: {exc}")
        print(colored(f"Error loading settings: {exc}", "red"))
        return
    print(colored(f"Secret mode is currently {'ON' if enabled else 'OFF'}", "cyan"))
    value = input("Enable secret mode? (y/n, blank to keep): ").strip().lower()
    if value in ("y", "yes"):
        enabled = True
    elif value in ("n", "no"):
        enabled = False
    dur = input(f"Clipboard clear delay in seconds [{delay}]: ").strip()
    if dur:
        try:
            delay = int(dur)
            if delay <= 0:
                print(colored("Delay must be positive.", "red"))
                return
        except ValueError:
            print(colored("Invalid number.", "red"))
            return
    try:
        cfg.set_secret_mode_enabled(enabled)
        cfg.set_clipboard_clear_delay(delay)
        pm.secret_mode_enabled = enabled
        pm.clipboard_clear_delay = delay
        status = "enabled" if enabled else "disabled"
        print(colored(f"Secret mode {status}.", "green"))
    except Exception as exc:
        logging.error(f"Error saving secret mode: {exc}")
        print(colored(f"Error: {exc}", "red"))


def handle_toggle_quick_unlock(pm: PasswordManager) -> None:
    """Enable or disable Quick Unlock."""
    cfg = pm.config_manager
    if cfg is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        enabled = cfg.get_quick_unlock()
    except Exception as exc:
        logging.error(f"Error loading quick unlock setting: {exc}")
        print(colored(f"Error loading settings: {exc}", "red"))
        return
    print(colored(f"Quick Unlock is currently {'ON' if enabled else 'OFF'}", "cyan"))
    choice = input("Enable Quick Unlock? (y/n, blank to keep): ").strip().lower()
    if choice in ("y", "yes"):
        enabled = True
    elif choice in ("n", "no"):
        enabled = False
    try:
        cfg.set_quick_unlock(enabled)
        status = "enabled" if enabled else "disabled"
        print(colored(f"Quick Unlock {status}.", "green"))
    except Exception as exc:
        logging.error(f"Error saving quick unlock: {exc}")
        print(colored(f"Error: {exc}", "red"))


def handle_toggle_offline_mode(pm: PasswordManager) -> None:
    """Enable or disable offline mode."""
    cfg = pm.config_manager
    if cfg is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        enabled = cfg.get_offline_mode()
    except Exception as exc:
        logging.error(f"Error loading offline mode setting: {exc}")
        print(colored(f"Error loading settings: {exc}", "red"))
        return
    print(colored(f"Offline mode is currently {'ON' if enabled else 'OFF'}", "cyan"))
    choice = input("Enable offline mode? (y/n, blank to keep): ").strip().lower()
    if choice in ("y", "yes"):
        enabled = True
    elif choice in ("n", "no"):
        enabled = False
    try:
        cfg.set_offline_mode(enabled)
        pm.offline_mode = enabled
        status = "enabled" if enabled else "disabled"
        print(colored(f"Offline mode {status}.", "green"))
    except Exception as exc:
        logging.error(f"Error saving offline mode: {exc}")
        print(colored(f"Error: {exc}", "red"))


def handle_profiles_menu(password_manager: PasswordManager) -> None:
    """Submenu for managing seed profiles."""
    while True:
        fp, parent_fp, child_fp = getattr(
            password_manager,
            "header_fingerprint_args",
            (getattr(password_manager, "current_fingerprint", None), None, None),
        )
        clear_header_with_notification(
            fp,
            "Main Menu > Settings > Profiles",
            parent_fingerprint=parent_fp,
            child_fingerprint=child_fp,
        )
        print(color_text("\nProfiles:", "menu"))
        print(color_text("1. Switch Seed Profile", "menu"))
        print(color_text("2. Add a New Seed Profile", "menu"))
        print(color_text("3. Remove an Existing Seed Profile", "menu"))
        print(color_text("4. List All Seed Profiles", "menu"))
        print(color_text("5. Set Seed Profile Name", "menu"))
        choice = input("Select an option or press Enter to go back: ").strip()
        password_manager.update_activity()
        if choice == "1":
            if not password_manager.handle_switch_fingerprint():
                print(colored("Failed to switch seed profile.", "red"))
        elif choice == "2":
            handle_add_new_fingerprint(password_manager)
        elif choice == "3":
            handle_remove_fingerprint(password_manager)
        elif choice == "4":
            handle_list_fingerprints(password_manager)
        elif choice == "5":
            handle_set_profile_name(password_manager)
        elif not choice:
            break
        else:
            print(colored("Invalid choice.", "red"))


def handle_nostr_menu(password_manager: PasswordManager) -> None:
    """Submenu for Nostr-related actions and relay configuration."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        cfg_mgr.load_config()
    except Exception as e:
        print(colored(f"Error loading settings: {e}", "red"))
        return

    while True:
        fp, parent_fp, child_fp = getattr(
            password_manager,
            "header_fingerprint_args",
            (getattr(password_manager, "current_fingerprint", None), None, None),
        )
        clear_header_with_notification(
            fp,
            "Main Menu > Settings > Nostr",
            parent_fingerprint=parent_fp,
            child_fingerprint=child_fp,
        )
        print(color_text("\nNostr Settings:", "menu"))
        print(color_text("1. Backup to Nostr", "menu"))
        print(color_text("2. Restore from Nostr", "menu"))
        print(color_text("3. View current relays", "menu"))
        print(color_text("4. Add a relay URL", "menu"))
        print(color_text("5. Remove a relay by number", "menu"))
        print(color_text("6. Reset to default relays", "menu"))
        print(color_text("7. Display Nostr Public Key", "menu"))
        choice = input("Select an option or press Enter to go back: ").strip()
        password_manager.update_activity()
        if choice == "1":
            handle_post_to_nostr(password_manager)
        elif choice == "2":
            handle_retrieve_from_nostr(password_manager)
        elif choice == "3":
            handle_view_relays(cfg_mgr)
        elif choice == "4":
            handle_add_relay(password_manager)
        elif choice == "5":
            handle_remove_relay(password_manager)
        elif choice == "6":
            handle_reset_relays(password_manager)
        elif choice == "7":
            handle_display_npub(password_manager)
        elif not choice:
            break
        else:
            print(colored("Invalid choice.", "red"))


def handle_settings(password_manager: PasswordManager) -> None:
    """Interactive settings menu with submenus for profiles and Nostr."""
    while True:
        fp, parent_fp, child_fp = getattr(
            password_manager,
            "header_fingerprint_args",
            (getattr(password_manager, "current_fingerprint", None), None, None),
        )
        clear_header_with_notification(
            fp,
            "Main Menu > Settings",
            parent_fingerprint=parent_fp,
            child_fingerprint=child_fp,
        )
        print(color_text("\nSettings:", "menu"))
        print(color_text("1. Profiles", "menu"))
        print(color_text("2. Nostr", "menu"))
        print(color_text("3. Change password", "menu"))
        print(color_text("4. Verify Script Checksum", "menu"))
        print(color_text("5. Generate Script Checksum", "menu"))
        print(color_text("6. Backup Parent Seed", "menu"))
        print(color_text("7. Export database", "menu"))
        print(color_text("8. Import database", "menu"))
        print(color_text("9. Export 2FA codes", "menu"))
        print(color_text("10. Set additional backup location", "menu"))
        print(color_text("11. Set KDF iterations", "menu"))
        print(color_text("12. Set inactivity timeout", "menu"))
        print(color_text("13. Lock Vault", "menu"))
        print(color_text("14. Stats", "menu"))
        print(color_text("15. Toggle Secret Mode", "menu"))
        print(color_text("16. Toggle Offline Mode", "menu"))
        print(color_text("17. Toggle Quick Unlock", "menu"))
        choice = input("Select an option or press Enter to go back: ").strip()
        if choice == "1":
            handle_profiles_menu(password_manager)
        elif choice == "2":
            handle_nostr_menu(password_manager)
        elif choice == "3":
            password_manager.change_password()
            pause()
        elif choice == "4":
            password_manager.handle_verify_checksum()
            pause()
        elif choice == "5":
            password_manager.handle_update_script_checksum()
            pause()
        elif choice == "6":
            password_manager.handle_backup_reveal_parent_seed()
            pause()
        elif choice == "7":
            password_manager.handle_export_database()
            pause()
        elif choice == "8":
            path = input("Enter path to backup file: ").strip()
            if path:
                password_manager.handle_import_database(Path(path))
            pause()
        elif choice == "9":
            password_manager.handle_export_totp_codes()
            pause()
        elif choice == "10":
            handle_set_additional_backup_location(password_manager)
            pause()
        elif choice == "11":
            handle_set_kdf_iterations(password_manager)
            pause()
        elif choice == "12":
            handle_set_inactivity_timeout(password_manager)
            pause()
        elif choice == "13":
            password_manager.lock_vault()
            print(colored("Vault locked. Please re-enter your password.", "yellow"))
            password_manager.unlock_vault()
            password_manager.start_background_sync()
            getattr(password_manager, "start_background_relay_check", lambda: None)()
            pause()
        elif choice == "14":
            handle_display_stats(password_manager)
        elif choice == "15":
            handle_toggle_secret_mode(password_manager)
            pause()
        elif choice == "16":
            handle_toggle_offline_mode(password_manager)
            pause()
        elif choice == "17":
            handle_toggle_quick_unlock(password_manager)
            pause()
        elif not choice:
            break
        else:
            print(colored("Invalid choice.", "red"))


def display_menu(
    password_manager: PasswordManager,
    sync_interval: float = 60.0,
    inactivity_timeout: float = INACTIVITY_TIMEOUT,
):
    """
    Displays the interactive menu and handles user input to perform various actions.
    """
    menu = """
    Select an option:
    1. Add Entry
    2. Retrieve Entry
    3. Search Entries
    4. List Entries
    5. Modify an Existing Entry
    6. 2FA Codes
    7. Settings
    8. List Archived
    """
    password_manager.start_background_sync()
    getattr(password_manager, "start_background_relay_check", lambda: None)()
    _display_live_stats(password_manager)
    while True:
        fp, parent_fp, child_fp = getattr(
            password_manager,
            "header_fingerprint_args",
            (getattr(password_manager, "current_fingerprint", None), None, None),
        )
        clear_header_with_notification(
            password_manager,
            fp,
            "Main Menu",
            parent_fingerprint=parent_fp,
            child_fingerprint=child_fp,
        )
        if time.time() - password_manager.last_activity > inactivity_timeout:
            print(colored("Session timed out. Vault locked.", "yellow"))
            password_manager.lock_vault()
            password_manager.unlock_vault()
            password_manager.start_background_sync()
            getattr(password_manager, "start_background_relay_check", lambda: None)()
            continue
        # Periodically push updates to Nostr
        if (
            password_manager.is_dirty
            and time.time() - password_manager.last_update >= sync_interval
        ):
            handle_post_to_nostr(password_manager)
            password_manager.is_dirty = False

        # Flush logging handlers
        for handler in logging.getLogger().handlers:
            handler.flush()
        print(color_text(menu, "menu"))
        try:
            choice = timed_input(
                "Enter your choice (1-8) or press Enter to exit: ",
                inactivity_timeout,
            ).strip()
        except TimeoutError:
            print(colored("Session timed out. Vault locked.", "yellow"))
            password_manager.lock_vault()
            password_manager.unlock_vault()
            password_manager.start_background_sync()
            getattr(password_manager, "start_background_relay_check", lambda: None)()
            continue
        password_manager.update_activity()
        if not choice:
            if getattr(password_manager, "profile_stack", []):
                password_manager.exit_managed_account()
                continue
            logging.info("Exiting the program.")
            print(colored("Exiting the program.", "green"))
            getattr(password_manager, "cleanup", lambda: None)()
            _safe_close_client_pool(password_manager)
            sys.exit(0)
        if choice == "1":
            while True:
                fp, parent_fp, child_fp = getattr(
                    password_manager,
                    "header_fingerprint_args",
                    (
                        getattr(password_manager, "current_fingerprint", None),
                        None,
                        None,
                    ),
                )
                clear_header_with_notification(
                    fp,
                    "Main Menu > Add Entry",
                    parent_fingerprint=parent_fp,
                    child_fingerprint=child_fp,
                )
                print(color_text("\nAdd Entry:", "menu"))
                print(color_text("1. Password", "menu"))
                print(color_text("2. 2FA (TOTP)", "menu"))
                print(color_text("3. SSH Key", "menu"))
                print(color_text("4. Seed Phrase", "menu"))
                print(color_text("5. Nostr Key Pair", "menu"))
                print(color_text("6. PGP Key", "menu"))
                print(color_text("7. Key/Value", "menu"))
                print(color_text("8. Managed Account", "menu"))
                sub_choice = input(
                    "Select entry type or press Enter to go back: "
                ).strip()
                password_manager.update_activity()
                if sub_choice == "1":
                    password_manager.handle_add_password()
                    break
                elif sub_choice == "2":
                    password_manager.handle_add_totp()
                    break
                elif sub_choice == "3":
                    password_manager.handle_add_ssh_key()
                    break
                elif sub_choice == "4":
                    password_manager.handle_add_seed()
                    break
                elif sub_choice == "5":
                    password_manager.handle_add_nostr_key()
                    break
                elif sub_choice == "6":
                    password_manager.handle_add_pgp()
                    break
                elif sub_choice == "7":
                    password_manager.handle_add_key_value()
                    break
                elif sub_choice == "8":
                    password_manager.handle_add_managed_account()
                    break
                elif not sub_choice:
                    break
                else:
                    print(colored("Invalid choice.", "red"))
        elif choice == "2":
            password_manager.update_activity()
            password_manager.handle_retrieve_entry()
            fp, parent_fp, child_fp = getattr(
                password_manager,
                "header_fingerprint_args",
                (getattr(password_manager, "current_fingerprint", None), None, None),
            )
            clear_header_with_notification(
                fp,
                "Main Menu",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
        elif choice == "3":
            password_manager.update_activity()
            password_manager.handle_search_entries()
        elif choice == "4":
            password_manager.update_activity()
            password_manager.handle_list_entries()
        elif choice == "5":
            password_manager.update_activity()
            password_manager.handle_modify_entry()
        elif choice == "6":
            password_manager.update_activity()
            password_manager.handle_display_totp_codes()
        elif choice == "7":
            password_manager.update_activity()
            handle_settings(password_manager)
        elif choice == "8":
            password_manager.update_activity()
            password_manager.handle_view_archived_entries()
        else:
            print(colored("Invalid choice. Please select a valid option.", "red"))


def main(argv: list[str] | None = None, *, fingerprint: str | None = None) -> int:
    """Entry point for the SeedPass CLI.

    Parameters
    ----------
    argv:
        Command line arguments.
    fingerprint:
        Optional seed profile fingerprint to select automatically.
    """
    configure_logging()
    initialize_app()
    logger = logging.getLogger(__name__)
    logger.info("Starting SeedPass Password Manager")

    load_global_config()
    parser = argparse.ArgumentParser()
    parser.add_argument("--fingerprint")
    sub = parser.add_subparsers(dest="command")

    exp = sub.add_parser("export")
    exp.add_argument("--file")

    imp = sub.add_parser("import")
    imp.add_argument("--file")

    search_p = sub.add_parser("search")
    search_p.add_argument("query")

    get_p = sub.add_parser("get")
    get_p.add_argument("query")

    totp_p = sub.add_parser("totp")
    totp_p.add_argument("query")

    args = parser.parse_args(argv)

    try:
        password_manager = PasswordManager(fingerprint=args.fingerprint or fingerprint)
        logger.info("PasswordManager initialized successfully.")
    except (PasswordPromptError, Bip85Error) as e:
        logger.error(f"Failed to initialize PasswordManager: {e}", exc_info=True)
        print(colored(f"Error: Failed to initialize PasswordManager: {e}", "red"))
        return 1
    except Exception as e:
        logger.error(f"Failed to initialize PasswordManager: {e}", exc_info=True)
        print(colored(f"Error: Failed to initialize PasswordManager: {e}", "red"))
        return 1

    if args.command == "export":
        password_manager.handle_export_database(Path(args.file))
        return 0
    if args.command == "import":
        password_manager.handle_import_database(Path(args.file))
        return 0
    if args.command == "search":
        matches = password_manager.entry_manager.search_entries(args.query)
        if matches:
            print_matches(password_manager, matches)
        else:
            print(colored("No matching entries found.", "yellow"))
        return 0
    if args.command == "get":
        matches = password_manager.entry_manager.search_entries(args.query)
        if len(matches) != 1:
            if not matches:
                print(colored("No matching entries found.", "yellow"))
            else:
                print_matches(password_manager, matches)
            return 1
        idx = matches[0][0]
        entry = password_manager.entry_manager.retrieve_entry(idx)
        if entry.get("type", EntryType.PASSWORD.value) != EntryType.PASSWORD.value:
            print(colored("Entry is not a password entry.", "red"))
            return 1
        length = int(entry.get("length", 0))
        pw = password_manager.password_generator.generate_password(length, idx)
        print(pw)
        return 0
    if args.command == "totp":
        matches = password_manager.entry_manager.search_entries(args.query)
        if len(matches) != 1:
            if not matches:
                print(colored("No matching entries found.", "yellow"))
            else:
                print_matches(password_manager, matches)
            return 1
        idx = matches[0][0]
        entry = password_manager.entry_manager.retrieve_entry(idx)
        if entry.get("type") != EntryType.TOTP.value:
            print(colored("Entry is not a TOTP entry.", "red"))
            return 1
        code = password_manager.entry_manager.get_totp_code(
            idx, password_manager.parent_seed
        )
        print(code)
        if copy_to_clipboard(code, password_manager.clipboard_clear_delay):
            print(colored("Code copied to clipboard", "green"))
        return 0

    def signal_handler(sig, _frame):
        print(colored("\nReceived shutdown signal. Exiting gracefully...", "yellow"))
        logging.info(f"Received shutdown signal: {sig}. Initiating graceful shutdown.")
        try:
            getattr(password_manager, "cleanup", lambda: None)()
            _safe_close_client_pool(password_manager)
            logging.info("NostrClient closed successfully.")
        except Exception as exc:
            logging.error(f"Error during shutdown: {exc}")
            print(colored(f"Error during shutdown: {exc}", "red"))
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        display_menu(
            password_manager, inactivity_timeout=password_manager.inactivity_timeout
        )
    except KeyboardInterrupt:
        logger.info("Program terminated by user via KeyboardInterrupt.")
        print(colored("\nProgram terminated by user.", "yellow"))
        try:
            getattr(password_manager, "cleanup", lambda: None)()
            _safe_close_client_pool(password_manager)
            logging.info("NostrClient closed successfully.")
        except Exception as exc:
            logging.error(f"Error during shutdown: {exc}")
            print(colored(f"Error during shutdown: {exc}", "red"))
        return 0
    except (PasswordPromptError, Bip85Error) as e:
        logger.error(f"A user-related error occurred: {e}", exc_info=True)
        print(colored(f"Error: {e}", "red"))
        try:
            getattr(password_manager, "cleanup", lambda: None)()
            _safe_close_client_pool(password_manager)
            logging.info("NostrClient closed successfully.")
        except Exception as exc:
            logging.error(f"Error during shutdown: {exc}")
            print(colored(f"Error during shutdown: {exc}", "red"))
        return 1
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        print(colored(f"Error: An unexpected error occurred: {e}", "red"))
        try:
            getattr(password_manager, "cleanup", lambda: None)()
            _safe_close_client_pool(password_manager)
            logging.info("NostrClient closed successfully.")
        except Exception as exc:
            logging.error(f"Error during shutdown: {exc}")
            print(colored(f"Error during shutdown: {exc}", "red"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
