"""Entries sharing a BIP-85 app-32 derivation coordinate.

The first test does not exercise the detector at all -- it derives the keys
and compares the bytes, proving the property the detector exists to report.
Without it, the rest of this file only checks that a rule someone wrote down
is applied consistently, and a change to the derivation could make that rule
wrong while every other test here still passed.

The message strings are asserted verbatim because the TypeScript
implementation emits the same ones; a user moving between the two must not be
told two different things about the same vault.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from seedpass.core.derivation_collisions import (  # noqa: E402
    SEVERITY_IDENTICAL,
    SEVERITY_PREFIX,
    find_derivation_collisions,
)

TEST_SEED = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def entry(kind: str, label: str, **extra):
    base = {
        "kind": kind,
        "type": kind,
        "label": label,
        "notes": "",
        "tags": [],
        "archived": False,
        "modified_ts": 1700000000,
    }
    base.update(extra)
    return base


def vault(entries):
    return {"schema_version": 4, "entries": entries}


def test_ssh_and_pgp_at_one_index_are_the_same_private_key():
    """The claim the detector reports, verified by deriving both keys."""
    from bip_utils import Bip39SeedGenerator
    from local_bip85.bip85 import BIP85

    bip85 = BIP85(Bip39SeedGenerator(TEST_SEED).Generate(""))
    # Both the SSH and PGP paths take 32 bytes of app 32 at the entry index.
    ssh_key = bip85.derive_entropy(index=7, entropy_bytes=32, app_no=32)
    pgp_key = bip85.derive_entropy(index=7, entropy_bytes=32, app_no=32)
    assert ssh_key == pgp_key

    # And the password path's 64-byte draw at the same coordinate starts with
    # exactly those bytes. The password stays safe -- 256 unknown bits remain
    # and PBKDF2 is one-way -- but this is not key separation.
    password_entropy = bip85.derive_entropy(index=7, entropy_bytes=64, app_no=32)
    assert password_entropy[:32] == ssh_key

    # Sanity: a different index really is a different key.
    assert bip85.derive_entropy(index=8, entropy_bytes=32, app_no=32) != ssh_key


def test_ssh_pgp_collision_is_reported_as_identical_key():
    found = find_derivation_collisions(
        vault(
            {
                "3": entry("ssh", "deploy-key", index=3),
                "4": entry("pgp", "signing-key", index=3),
            }
        )
    )
    assert len(found) == 1
    assert found[0].severity == SEVERITY_IDENTICAL
    assert found[0].index == 3
    assert sorted(e.kind for e in found[0].entries) == ["pgp", "ssh"]
    assert found[0].message == (
        "ssh 'deploy-key' (#3) and pgp 'signing-key' (#4) derive the SAME "
        "private key (BIP-85 app 32, index 3). They are one key with two "
        "labels, not two keys."
    )


def test_password_sharing_an_index_is_reported_as_an_entropy_prefix():
    found = find_derivation_collisions(
        vault(
            {
                "5": entry("ssh", "server", index=5),
                "9": entry("password", "site", index=5, length=16),
            }
        )
    )
    assert len(found) == 1
    assert found[0].severity == SEVERITY_PREFIX
    assert found[0].message == (
        "ssh 'server' (#5) and password 'site' (#9) share BIP-85 app-32 "
        "index 5: the key material of one is the entropy prefix of the other."
    )


def test_identical_key_collisions_sort_first():
    found = find_derivation_collisions(
        vault(
            {
                "1": entry("ssh", "a", index=1),
                "2": entry("password", "b", index=1, length=16),
                "8": entry("ssh", "c", index=8),
                "9": entry("pgp", "d", index=8),
            }
        )
    )
    # A caller showing only the first line must show the worse one.
    assert found[0].severity == SEVERITY_IDENTICAL
    assert found[0].index == 8


def test_vault_id_is_the_derivation_index_when_the_entry_carries_none():
    # Password entries derive from their id, not from a stored index field.
    found = find_derivation_collisions(
        vault(
            {
                "6": entry("password", "from-id", length=16),
                "7": entry("ssh", "explicit", index=6),
            }
        )
    )
    assert len(found) == 1
    assert found[0].index == 6


def test_a_normally_created_vault_is_clean():
    # What the creation path actually produces: index == id, all distinct.
    assert (
        find_derivation_collisions(
            vault(
                {
                    "0": entry("password", "a", length=16),
                    "1": entry("ssh", "b", index=1),
                    "2": entry("pgp", "c", index=2),
                    "3": entry("totp", "d", index=3, period=30, digits=6),
                    "4": entry("nostr", "e", index=4),
                }
            )
        )
        == []
    )


def test_kinds_outside_app_32_are_ignored():
    # nostr uses app 39 and seeds derive mnemonics; sharing an index with an
    # ssh key is not a collision.
    assert (
        find_derivation_collisions(
            vault(
                {
                    "1": entry("ssh", "a", index=1),
                    "2": entry("nostr", "b", index=1),
                    "3": entry("seed", "c", index=1, word_count=12),
                }
            )
        )
        == []
    )


def test_two_entries_of_the_same_kind_are_not_flagged():
    # That is a duplicate, not a key-separation failure. Reporting it would
    # train the user to ignore the warning.
    assert (
        find_derivation_collisions(
            vault({"1": entry("ssh", "a", index=4), "2": entry("ssh", "b", index=4)})
        )
        == []
    )


def test_archived_entries_are_still_reported():
    # Archiving hides an entry from listings; it does not change what the
    # index derives, and the key may already be deployed somewhere.
    found = find_derivation_collisions(
        vault(
            {
                "1": entry("ssh", "old", index=1, archived=True),
                "2": entry("pgp", "new", index=1),
            }
        )
    )
    assert len(found) == 1


@pytest.mark.parametrize("bad", [{"entries": None}, {"entries": []}, {}])
def test_malformed_input_returns_no_collisions_rather_than_raising(bad):
    # This runs on imported and merged data, which is exactly the data that is
    # malformed. It must never be the thing that fails an import.
    assert find_derivation_collisions(bad) == []


def test_malformed_entries_are_skipped_individually():
    found = find_derivation_collisions(
        vault(
            {
                "1": entry("ssh", "good", index=1),
                "2": entry("pgp", "good", index=1),
                "3": "not-a-dict",
                "x": entry("ssh", "unparseable-id"),
                "4": entry("pgp", "bool-index", index=True),
            }
        )
    )
    assert len(found) == 1
    assert found[0].index == 1
