import logging
from contextlib import contextmanager
from functools import wraps

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
