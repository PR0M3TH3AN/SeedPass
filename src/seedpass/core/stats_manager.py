"""Manage display of stats screens."""

from __future__ import annotations


class StatsManager:
    """Track whether stats have been displayed."""

    def __init__(self) -> None:
        self._displayed = False

    def display_stats_once(self, manager) -> None:
        """Display stats using ``manager`` once per reset."""
        if not self._displayed:
            manager.display_stats()
            self._displayed = True

    def reset(self) -> None:
        """Reset the displayed flag."""
        self._displayed = False
