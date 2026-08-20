from dataclasses import dataclass
from typing import Any, List, Optional

# Event kind constants used for SeedPass backups
KIND_MANIFEST = 30070
KIND_SNAPSHOT_CHUNK = 30071
KIND_DELTA = 30072


@dataclass
class ChunkMeta:
    """Metadata for an individual snapshot chunk."""

    id: str
    size: int
    hash: str
    event_id: Optional[str] = None


@dataclass
class Manifest:
    """Structure of the backup manifest JSON."""

    ver: int
    algo: str
    chunks: List[ChunkMeta]
    delta_since: Optional[int] = None
    nonce: Optional[str] = None
    index0: Optional[dict[str, Any]] = None
    #: Publication time in milliseconds, inside the signed manifest.
    #:
    #: Nostr's ``created_at`` has whole-second resolution, so two snapshots
    #: published in the same second tie, and whatever breaks that tie decides
    #: which vault a restore returns. Ordering by an arbitrary tie-break --
    #: or, as this implementation used to, by whichever event the relay
    #: happened to serve first -- silently restores a stale vault, losing
    #: every entry created between the two syncs.
    #:
    #: ``None`` on manifests written before this field existed; those are
    #: ordered by ``created_at`` alone (see ``manifest_order_ms``).
    published_ms: Optional[int] = None


def manifest_order_ms(manifest: "Manifest", created_at: int) -> int:
    """Total ordering key for manifests, newest-largest.

    ``published_ms`` when the publisher recorded it, otherwise the start of
    the ``created_at`` second. That fallback makes a new-format manifest win
    a tie against an old-format one published in the same second. Ordering
    the unknown one last instead would let a pre-upgrade snapshot outrank
    every post-upgrade one for that second, which is the failure this exists
    to prevent.

    Must stay byte-for-byte equivalent to the TypeScript ``manifestOrderMs``
    (js/packages/core/src/sync/snapshot.ts) or the two implementations will
    disagree about which snapshot is latest.
    """
    ms = getattr(manifest, "published_ms", None)
    return int(ms) if ms is not None else int(created_at) * 1000
