"""Detect entries that share a BIP-85 derivation coordinate.

Three entry kinds derive from the same BIP-85 application, app 32, at the
entry's derivation index::

    ssh@N       -> 32 bytes of m/83696968'/32'/N'
    pgp@N       -> 32 bytes of m/83696968'/32'/N'   (the SAME 32 bytes)
    password@N  -> 64 bytes of m/83696968'/32'/N', then PBKDF2

So an SSH entry and a PGP entry at the same index are byte-for-byte the same
Ed25519 private key, and a password entry at that index takes the SSH/PGP
private key as the first half of its own input entropy. The password itself
stays safe -- 256 unknown bits remain and PBKDF2 is one-way -- but this is not
key separation, and SSH keys are exactly the sort of secret that gets exported
to a server or uploaded to a forge.

Neither implementation can *create* this state: a derivation index is the
entry's vault id, ids are unique, and the persisted watermark stops them being
reused after deletion. It arrives as data -- an imported backup, a vault
written by another tool, or a sync merge -- and both implementations will then
faithfully derive identical keys from it.

Fixing the derivation itself means domain-separating the three uses behind a
version, so existing entries keep deriving as they do; that is a protocol
change for both implementations and is tracked in TODO.md. Until then, the
defensible thing is to notice and say so, rather than hand over two
"different" keys that are the same key.

Must stay behaviourally identical to the TypeScript
``findDerivationCollisions``
(js/packages/core/src/vault/derivationCollisions.ts).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Entry kinds that derive from BIP-85 app 32 at their derivation index.
APP32_KINDS = ("ssh", "pgp", "password")

SEVERITY_IDENTICAL = "identical-key"
SEVERITY_PREFIX = "entropy-prefix"


@dataclass
class CollidingEntry:
    id: str
    kind: str
    label: str


@dataclass
class DerivationCollision:
    """Two or more entries deriving from one BIP-85 app-32 index."""

    index: int
    entries: List[CollidingEntry] = field(default_factory=list)
    severity: str = SEVERITY_PREFIX
    message: str = ""


def _derivation_index(entry_id: str, entry: Dict[str, Any]) -> Optional[int]:
    """The BIP-85 index this entry derives from, or ``None``.

    The entry's own ``index`` when it carries one, otherwise its vault id --
    which is what both implementations pass to BIP-85 for password entries.
    """
    explicit = entry.get("index")
    if isinstance(explicit, bool):
        # bool is an int subclass in Python; a boolean index is malformed data,
        # not index 0/1.
        return None
    if isinstance(explicit, int) and explicit >= 0:
        return explicit
    try:
        value = int(entry_id)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def find_derivation_collisions(index: Dict[str, Any]) -> List[DerivationCollision]:
    """Entries sharing an app-32 derivation index, worst first.

    Archived entries are included: archiving hides an entry from listings, it
    does not change what its index derives, and the key may already be in use
    somewhere.
    """
    entries = index.get("entries") or {}
    if not isinstance(entries, dict):
        return []

    by_index: Dict[int, List[CollidingEntry]] = {}
    for entry_id, raw in entries.items():
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind") or raw.get("type") or "")
        if kind not in APP32_KINDS:
            continue
        derivation_index = _derivation_index(str(entry_id), raw)
        if derivation_index is None:
            continue
        by_index.setdefault(derivation_index, []).append(
            CollidingEntry(
                id=str(entry_id), kind=kind, label=str(raw.get("label") or "")
            )
        )

    collisions: List[DerivationCollision] = []
    for derivation_index, bucket in by_index.items():
        if len(bucket) < 2:
            continue
        kinds = {e.kind for e in bucket}
        # Two entries of the SAME kind at one index are the same secret by
        # definition and are not a key-separation failure -- that is a
        # duplicate, which the id rules already prevent. Only a cross-kind
        # clash matters; reporting duplicates would train users to ignore this.
        if len(kinds) < 2:
            continue

        ordered = sorted(bucket, key=lambda e: e.id)
        identical = "ssh" in kinds and "pgp" in kinds
        labels = " and ".join(f"{e.kind} '{e.label}' (#{e.id})" for e in ordered)
        if identical:
            message = (
                f"{labels} derive the SAME private key (BIP-85 app 32, index "
                f"{derivation_index}). They are one key with two labels, not "
                f"two keys."
            )
        else:
            message = (
                f"{labels} share BIP-85 app-32 index {derivation_index}: the "
                f"key material of one is the entropy prefix of the other."
            )

        collisions.append(
            DerivationCollision(
                index=derivation_index,
                entries=ordered,
                severity=SEVERITY_IDENTICAL if identical else SEVERITY_PREFIX,
                message=message,
            )
        )

    # Identical keys first, then by index, so a caller showing only the first
    # line shows the worst case.
    collisions.sort(key=lambda c: (c.severity != SEVERITY_IDENTICAL, c.index))
    return collisions
