"""Manifest ordering: the newest snapshot wins, and the relay does not choose.

Restoring the wrong manifest is not a cosmetic ordering bug -- the manifest
that wins the comparison IS the vault the user gets back. Two failures fed
into each other here:

1. ``_fetch_manifest_with_keys`` asked the relay for ``limit(1)`` and used
   whatever came back, which handed the relay the choice of which snapshot to
   restore.
2. ``created_at`` is whole seconds, so two snapshots published in the same
   second tie on time regardless. The TypeScript port broke that tie by event
   id -- stable, but arbitrary with respect to time, so it returned the older
   vault roughly half the time.

``published_ms`` lives inside the signed manifest: finer-grained than
``created_at`` and not something a relay can steer. These tests pin the
ordering in Python; the equivalent TypeScript tests live in
js/packages/core/test/relay.test.ts, and the two must agree or the
implementations will disagree about which snapshot is latest.
"""

import json

import nostr.client  # noqa: F401  (resolves the package's circular import)
from nostr.backup_models import Manifest, manifest_order_ms
from nostr.snapshot import _sort_manifest_events_newest_first

SAME_SECOND = 1700001234


class FakeEvent:
    """Enough of the SDK event surface for the ordering code."""

    def __init__(self, event_id: str, created_at: int, published_ms: int | None):
        self._id = event_id
        self._created_at = created_at
        body = {
            "ver": 1,
            "algo": "gzip",
            "chunks": [],
            "delta_since": None,
            "nonce": None,
            "index0": None,
        }
        if published_ms is not None:
            body["published_ms"] = published_ms
        self._content = json.dumps(body)

    def content(self) -> str:
        return self._content

    @property
    def id(self) -> str:
        return self._id

    @property
    def created_at(self) -> int:
        return self._created_at


def test_order_key_prefers_published_ms():
    with_ms = Manifest(ver=1, algo="gzip", chunks=[], published_ms=SAME_SECOND * 1000 + 900)
    assert manifest_order_ms(with_ms, SAME_SECOND) == SAME_SECOND * 1000 + 900


def test_order_key_falls_back_to_the_created_at_second():
    # A manifest written before published_ms existed sorts at the start of its
    # second, so a new-format manifest from the same second outranks it.
    legacy = Manifest(ver=1, algo="gzip", chunks=[])
    assert manifest_order_ms(legacy, SAME_SECOND) == SAME_SECOND * 1000


def test_newer_same_second_snapshot_wins_despite_a_smaller_event_id():
    # The exact shape of the bug: ordering by event id, the older snapshot
    # wins whenever its id happens to sort higher.
    older = FakeEvent("ffff", SAME_SECOND, SAME_SECOND * 1000 + 100)
    newer = FakeEvent("0000", SAME_SECOND, SAME_SECOND * 1000 + 900)

    ordered = _sort_manifest_events_newest_first([older, newer])
    assert [e.id for e in ordered] == ["0000", "ffff"]

    # Order of arrival must not matter either -- that is the relay's choice.
    ordered_reversed = _sort_manifest_events_newest_first([newer, older])
    assert [e.id for e in ordered_reversed] == ["0000", "ffff"]


def test_a_legacy_manifest_does_not_outrank_a_newer_one():
    legacy = FakeEvent("aaaa", SAME_SECOND - 60, None)
    current = FakeEvent("bbbb", SAME_SECOND, SAME_SECOND * 1000 + 5)
    ordered = _sort_manifest_events_newest_first([legacy, current])
    assert ordered[0].id == "bbbb"


def test_event_id_still_breaks_an_exact_millisecond_tie():
    # Deterministic and relay-independent: the id is a hash of the event's own
    # contents, so no party chooses the winner.
    a = FakeEvent("1111", SAME_SECOND, SAME_SECOND * 1000 + 500)
    b = FakeEvent("2222", SAME_SECOND, SAME_SECOND * 1000 + 500)
    assert [e.id for e in _sort_manifest_events_newest_first([a, b])] == ["2222", "1111"]
    assert [e.id for e in _sort_manifest_events_newest_first([b, a])] == ["2222", "1111"]


def test_an_unparseable_manifest_orders_by_created_at_without_raising():
    class Broken(FakeEvent):
        def content(self) -> str:
            return "{not json"

    broken = Broken("cccc", SAME_SECOND - 120, None)
    good = FakeEvent("dddd", SAME_SECOND, SAME_SECOND * 1000)
    ordered = _sort_manifest_events_newest_first([broken, good])
    # It is rejected later, during parsing; ordering must not blow up first.
    assert ordered[0].id == "dddd"
