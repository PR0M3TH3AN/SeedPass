"""Utility functions for terminal output."""

import sys


from termcolor import colored


def clear_screen() -> None:
    """Clear the terminal screen using an ANSI escape code."""
    print("\033c", end="")


def clear_and_print_fingerprint(
    fingerprint: str | None, breadcrumb: str | None = None
) -> None:
    """Clear the screen and optionally display the current fingerprint and path."""
    clear_screen()
    if fingerprint:
        header = f"Seed Profile: {fingerprint}"
        if breadcrumb:
            header += f" > {breadcrumb}"
        print(colored(header, "green"))


def clear_and_print_profile_chain(
    fingerprints: list[str] | None, breadcrumb: str | None = None
) -> None:
    """Clear the screen and display a chain of fingerprints."""
    clear_screen()
    if not fingerprints:
        return
    chain = fingerprints[0]
    for fp in fingerprints[1:]:
        chain += f" > Managed Account > {fp}"
    header = f"Seed Profile: {chain}"
    if breadcrumb:
        header += f" > {breadcrumb}"
    print(colored(header, "green"))


def pause(message: str = "Press Enter to continue...") -> None:
    """Wait for the user to press Enter before proceeding."""
    if not sys.stdin or not sys.stdin.isatty():
        return
    try:
        input(message)
    except EOFError:
        pass
