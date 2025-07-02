from dataclasses import dataclass
from typing import List, Optional

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


@dataclass
class Manifest:
    """Structure of the backup manifest JSON."""

    ver: int
    algo: str
    chunks: List[ChunkMeta]
    delta_since: Optional[str] = None
