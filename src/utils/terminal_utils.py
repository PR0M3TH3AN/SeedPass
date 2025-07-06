"""Utility functions for terminal output."""

import sys


def clear_screen() -> None:
    """Clear the terminal screen using an ANSI escape code."""
    print("\033c", end="")


def pause(message: str = "Press Enter to continue...") -> None:
    """Wait for the user to press Enter before proceeding."""
    if not sys.stdin or not sys.stdin.isatty():
        return
    try:
        input(message)
    except EOFError:
        pass
