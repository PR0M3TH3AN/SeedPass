"""Utility functions for SeedPass CLI color scheme."""

from termcolor import colored


# ANSI escape for 256-color orange (color code 208)
_ORANGE = "\033[38;5;208m"
_RESET = "\033[0m"


def _apply_orange(text: str) -> str:
    """Return text wrapped in ANSI codes for orange."""
    return f"{_ORANGE}{text}{_RESET}"


# Mapping of semantic color categories to actual colors
_COLOR_MAP = {
    "deterministic": "red",
    "imported": "orange",
    "index": "yellow",
    "menu": "cyan",
    "stats": "green",
    "info": "cyan",
    "warning": "yellow",
    "error": "red",
    "default": "white",
}


def color_text(text: str, category: str = "default") -> str:
    """Colorize ``text`` according to the given category."""
    color = _COLOR_MAP.get(category, "white")
    if color == "orange":
        return _apply_orange(text)
    return colored(text, color)
