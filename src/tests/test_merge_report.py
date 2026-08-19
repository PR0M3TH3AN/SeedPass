"""What a merge resolves silently.

The merge is a deterministic CRDT and its outcome is frozen for parity with
the TypeScript implementation -- both must reach the same vault from the same
inputs, so the resolution rules are not up for negotiation. What was missing
is that the user is never told a resolution happened: an entry created on one
device is simply absent afterwards, with no error and nothing in the summary.

The load-bearing test here is the last one: passing a report must not change
the merged result. If observing could alter the outcome, it would be a parity
divergence rather than an observation.

Mirrors js/packages/core/test/mergeReport.test.ts.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from seedpass.core.sync_conflict import (  # noqa: E402
    TOMBSTONE_RETENTION_CAP,
    MergeReport,
    merge_index_payloads,
)


def entry(kind: str, label: str, ts: int, **extra):
    base = {
        "kind": kind,
        "type": kind,
        "label": label,
        "notes": "",
        "tags": [],
        "archived": False,
        "modified_ts": ts,
    }
    base.update(extra)
    return base


def index(entries, **extra):
    payload = {"schema_version": 4, "entries": entries}
    payload.update(extra)
    return payload


def test_same_id_conflict_names_kept_and_discarded():
    # The realistic case: two devices offline, both allocate id 5.
    local = index({"5": entry("password", "bank.example", 1700000100, length=16)})
    remote = index({"5": entry("ssh", "deploy-key", 1700000200, index=5)})

    report = MergeReport()
    merged = merge_index_payloads(local, remote, source_tag="t", report=report)

    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert conflict.id == "5"
    assert conflict.different_kind is True
    # Describe the actual outcome rather than assuming which side wins.
    survivor = merged["entries"]["5"]["label"]
    assert conflict.kept["label"] == survivor
    assert conflict.discarded["label"] != survivor
    assert sorted([conflict.kept["label"], conflict.discarded["label"]]) == [
        "bank.example",
        "deploy-key",
    ]


def test_a_conflict_is_reported_whichever_side_wins():
    # A report that only fired when the incoming side won would miss half of
    # all real losses.
    older = index({"5": entry("password", "bank.example", 1700000100, length=16)})
    newer = index({"5": entry("ssh", "deploy-key", 1700000200, index=5)})

    forward = MergeReport()
    merge_index_payloads(older, newer, source_tag="t", report=forward)
    backward = MergeReport()
    merge_index_payloads(newer, older, source_tag="t", report=backward)

    assert len(forward.conflicts) == 1
    assert len(backward.conflicts) == 1


def test_an_ordinary_edit_is_not_reported():
    # The overwhelmingly common case. Reporting it would bury the case that
    # matters in noise and train the user to ignore the warning.
    local = index({"5": entry("password", "bank.example", 1700000100, length=16)})
    remote = index({"5": entry("password", "bank.example", 1700000200, length=24)})
    report = MergeReport()
    merge_index_payloads(local, remote, source_tag="t", report=report)
    assert report.conflicts == []


def test_same_kind_different_label_is_reported():
    local = index({"5": entry("password", "bank.example", 1700000100, length=16)})
    remote = index({"5": entry("password", "forum.example", 1700000200, length=16)})
    report = MergeReport()
    merge_index_payloads(local, remote, source_tag="t", report=report)
    assert len(report.conflicts) == 1
    assert report.conflicts[0].different_kind is False


def test_no_overlap_reports_nothing():
    local = index({"1": entry("password", "a", 1700000100, length=16)})
    remote = index({"2": entry("password", "b", 1700000200, length=16)})
    report = MergeReport()
    merged = merge_index_payloads(local, remote, source_tag="t", report=report)
    assert report.conflicts == []
    assert sorted(merged["entries"].keys()) == ["1", "2"]


def test_tombstone_eviction_is_counted():
    # Past the cap the oldest deletions are dropped, and merging a stale
    # replica then resurrects those entries.
    overflow = 5
    tombstones = {
        str(i): {
            "deleted_ts": 1700000000 + i,
            "entry_hash": "",
            "event_hash": "",
            "source": "t",
        }
        for i in range(TOMBSTONE_RETENTION_CAP + overflow)
    }
    local = index({}, _sync_meta={"tombstones": tombstones})
    report = MergeReport()
    merge_index_payloads(local, index({}), source_tag="t", report=report)
    assert report.tombstones_evicted == overflow


def test_no_eviction_below_the_cap():
    local = index(
        {},
        _sync_meta={
            "tombstones": {
                "1": {
                    "deleted_ts": 1700000000,
                    "entry_hash": "",
                    "event_hash": "",
                    "source": "t",
                }
            }
        },
    )
    report = MergeReport()
    merge_index_payloads(local, index({}), source_tag="t", report=report)
    assert report.tombstones_evicted == 0


def test_observing_the_merge_does_not_change_it():
    """The parity guarantee.

    The merged vault must not depend on whether anyone was watching --
    otherwise the two implementations could reach different vaults from the
    same inputs, which is the one thing the deterministic merge exists to
    prevent.
    """
    local = index(
        {
            "1": entry("password", "kept", 1700000100, length=16),
            "5": entry("password", "loser", 1700000100, length=16),
        },
        _sync_meta={
            "next_index": 6,
            "tombstones": {
                "9": {
                    "deleted_ts": 1700000050,
                    "entry_hash": "",
                    "event_hash": "",
                    "source": "t",
                }
            },
        },
    )
    remote = index(
        {
            "5": entry("ssh", "winner", 1700000200, index=5),
            "7": entry("totp", "extra", 1700000300, index=7, period=30, digits=6),
        },
        _sync_meta={"next_index": 8, "tombstones": {}},
    )

    with_report = merge_index_payloads(
        local, remote, source_tag="t", report=MergeReport()
    )
    without_report = merge_index_payloads(local, remote, source_tag="t")
    assert json.dumps(with_report, sort_keys=True) == json.dumps(
        without_report, sort_keys=True
    )


def test_merging_does_not_mutate_the_caller_s_payloads():
    """The merge reads its inputs; it does not edit them.

    ``dict(current)`` shares the nested ``entries`` dict with the caller, so
    the merge used to write its result straight into the argument: after
    merging, the caller's "current" payload had already become the merged one.
    Anything comparing before-and-after, or merging the same payload twice,
    silently saw the wrong input -- which is exactly how
    ``test_a_conflict_is_reported_whichever_side_wins`` first failed.
    """
    local = index({"5": entry("password", "bank.example", 1700000100, length=16)})
    remote = index({"5": entry("ssh", "deploy-key", 1700000200, index=5)})
    local_before = json.dumps(local, sort_keys=True)
    remote_before = json.dumps(remote, sort_keys=True)

    merge_index_payloads(local, remote, source_tag="t")

    assert json.dumps(local, sort_keys=True) == local_before
    assert json.dumps(remote, sort_keys=True) == remote_before
