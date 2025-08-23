import logging
from pathlib import Path
from contextlib import contextmanager
from functools import wraps

_console_paused = False


class ConsolePauseFilter(logging.Filter):
    """Filter that blocks records when console logging is paused."""

    def filter(
        self, record: logging.LogRecord
    ) -> bool:  # pragma: no cover - small utility
        return not _console_paused


class ChecksumWarningFilter(logging.Filter):
    """Filter allowing only checksum warnings and errors to surface."""

    def filter(
        self, record: logging.LogRecord
    ) -> bool:  # pragma: no cover - simple filter
        if record.levelno >= logging.ERROR:
            return True
        return (
            record.levelno == logging.WARNING
            and Path(record.pathname).name == "checksum.py"
        )


def pause_console_logging() -> None:
    """Temporarily pause logging to console handlers."""
    global _console_paused
    _console_paused = True


def resume_console_logging() -> None:
    """Resume logging to console handlers."""
    global _console_paused
    _console_paused = False


@contextmanager
def console_logging_paused() -> None:
    """Context manager to pause console logging within a block."""
    pause_console_logging()
    try:
        yield
    finally:
        resume_console_logging()


def pause_logging_for_ui(func):
    """Decorator to pause console logging while ``func`` executes."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        with console_logging_paused():
            return func(*args, **kwargs)

    return wrapper
