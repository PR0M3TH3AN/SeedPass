"""Utility functions for terminal output."""

import logging
import sys
import queue

from termcolor import colored

from utils.color_scheme import color_text


def format_profile(fingerprint: str | None, pm=None) -> str | None:
    """Return display string for a fingerprint with optional custom name."""
    if not fingerprint:
        return None
    if pm and getattr(pm, "fingerprint_manager", None):
        try:
            name = pm.fingerprint_manager.get_name(fingerprint)
            if name:
                return f"{name} ({fingerprint})"
        except Exception as exc:  # pragma: no cover - unexpected errors
            logging.error(
                "Error retrieving name for fingerprint %s: %s", fingerprint, exc
            )
            raise
    return fingerprint


def clear_screen() -> None:
    """Clear the terminal screen using an ANSI escape code."""
    print("\033c", end="")


def clear_and_print_fingerprint(
    fingerprint: str | None = None,
    breadcrumb: str | None = None,
    parent_fingerprint: str | None = None,
    child_fingerprint: str | None = None,
    pm=None,
) -> None:
    """Clear the screen and optionally display the current fingerprint and path."""
    clear_screen()
    header_fp = None
    if parent_fingerprint and child_fingerprint:
        header_fp = f"{format_profile(parent_fingerprint, pm)} > Managed Account > {format_profile(child_fingerprint, pm)}"
    elif fingerprint:
        header_fp = format_profile(fingerprint, pm)
    elif parent_fingerprint or child_fingerprint:
        header_fp = format_profile(parent_fingerprint or child_fingerprint, pm)
    if header_fp:
        header = f"Seed Profile: {header_fp}"
        if breadcrumb:
            header += f" > {breadcrumb}"
        print(colored(header, "green"))


def clear_and_print_profile_chain(
    fingerprints: list[str] | None, breadcrumb: str | None = None, pm=None
) -> None:
    """Clear the screen and display a chain of fingerprints."""
    clear_screen()
    if not fingerprints:
        return
    chain = format_profile(fingerprints[0], pm)
    for fp in fingerprints[1:]:
        chain += f" > Managed Account > {format_profile(fp, pm)}"
    header = f"Seed Profile: {chain}"
    if breadcrumb:
        header += f" > {breadcrumb}"
    print(colored(header, "green"))


def clear_header_with_notification(
    pm,
    fingerprint: str | None = None,
    breadcrumb: str | None = None,
    parent_fingerprint: str | None = None,
    child_fingerprint: str | None = None,
) -> None:
    """Clear the screen, print the header, then show the current notification."""

    clear_screen()
    header_fp = None
    if parent_fingerprint and child_fingerprint:
        header_fp = f"{format_profile(parent_fingerprint, pm)} > Managed Account > {format_profile(child_fingerprint, pm)}"
    elif fingerprint:
        header_fp = format_profile(fingerprint, pm)
    elif parent_fingerprint or child_fingerprint:
        header_fp = format_profile(parent_fingerprint or child_fingerprint, pm)
    if header_fp:
        header = f"Seed Profile: {header_fp}"
        if breadcrumb:
            header += f" > {breadcrumb}"
        print(colored(header, "green"))

    note = None
    if hasattr(pm, "get_current_notification"):
        try:
            note = pm.get_current_notification()
        except (queue.Empty, AttributeError):
            note = None
        except Exception as exc:  # pragma: no cover - unexpected errors
            logging.error("Error getting current notification: %s", exc)
            raise

    line = ""
    if note:
        category = getattr(note, "level", "info").lower()
        if category not in ("info", "warning", "error"):
            category = "info"
        line = color_text(getattr(note, "message", ""), category)

    print(line)


def pause(message: str = "Press Enter to continue...") -> None:
    """Wait for the user to press Enter before proceeding."""
    if not sys.stdin or not sys.stdin.isatty():
        return
    try:
        input(message)
    except EOFError:
        pass
