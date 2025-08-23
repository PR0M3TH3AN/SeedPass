import logging

_console_paused = False


class ConsolePauseFilter(logging.Filter):
    """Filter that blocks records when console logging is paused."""

    def filter(
        self, record: logging.LogRecord
    ) -> bool:  # pragma: no cover - small utility
        return not _console_paused


def pause_console_logging() -> None:
    """Temporarily pause logging to console handlers."""
    global _console_paused
    _console_paused = True


def resume_console_logging() -> None:
    """Resume logging to console handlers."""
    global _console_paused
    _console_paused = False
