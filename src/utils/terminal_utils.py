"""Utility functions for terminal output."""

import sys


from termcolor import colored


def clear_screen() -> None:
    """Clear the terminal screen using an ANSI escape code."""
    print("\033c", end="")


def clear_and_print_fingerprint(fingerprint: str | None) -> None:
    """Clear the screen and optionally display the current fingerprint."""
    clear_screen()
    if fingerprint:
        print(colored(f"Seed Profile: {fingerprint}", "green"))


def pause(message: str = "Press Enter to continue...") -> None:
    """Wait for the user to press Enter before proceeding."""
    if not sys.stdin or not sys.stdin.isatty():
        return
    try:
        input(message)
    except EOFError:
        pass
