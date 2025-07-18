"""Graphical user interface for SeedPass."""

from .app import SeedPassApp


def main() -> None:
    """Launch the GUI application."""
    SeedPassApp().main_loop()


__all__ = ["SeedPassApp", "main"]
