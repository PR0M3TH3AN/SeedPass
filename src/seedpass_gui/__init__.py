"""Graphical user interface for SeedPass."""

from .app import SeedPassApp, build


def main() -> None:
    """Launch the GUI application."""
    build().main_loop()


__all__ = ["SeedPassApp", "main"]
