# nostr/__init__.py

"""Nostr package exposing :class:`NostrClient` lazily."""

from importlib import import_module
import logging

from .backup_models import (
    KIND_MANIFEST,
    KIND_SNAPSHOT_CHUNK,
    KIND_DELTA,
    Manifest,
    ChunkMeta,
)

logger = logging.getLogger(__name__)

__all__ = [
    "NostrClient",
    "KIND_MANIFEST",
    "KIND_SNAPSHOT_CHUNK",
    "KIND_DELTA",
    "Manifest",
    "ChunkMeta",
    "prepare_snapshot",
]


def __getattr__(name: str):
    if name == "NostrClient":
        return import_module(".client", __name__).NostrClient
    if name == "prepare_snapshot":
        return import_module(".client", __name__).prepare_snapshot
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
