# nostr/__init__.py

"""Nostr package exposing :class:`NostrClient` lazily."""

from importlib import import_module
import logging

logger = logging.getLogger(__name__)

__all__ = ["NostrClient"]


def __getattr__(name: str):
    if name == "NostrClient":
        return import_module(".client", __name__).NostrClient
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
