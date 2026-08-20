"""Entropy and RNG integrity — the compatibility contract for derived secrets.

Covers audit item M4 from ``docs/entropy_audit_2026-07-31.md``.

Two distinct jobs live here:

1. **Frozen v1 password vectors.** SeedPass never stores a password. Every entry
   is re-derived on demand from ``(seed, index, length, policy)``, and entry
   records carry no algorithm version. Any change to ``generate_password``
   therefore changes every existing password in every vault, unrecoverably.
   These vectors are what live vaults re-derive today.

   **A failure here is never "update the expected value".** It means the change
   being attempted is vault-breaking. Either revert it, or land it behind a new
   ``gen_version`` while leaving v1 byte-identical -- see M1/M2/M3 in the audit.

   Regenerate these ONLY when introducing a new generation version, and then
   only by appending a new ``V2_VECTORS`` table; the v1 table below is immutable.

2. **Fail-closed RNG behaviour.** Nothing else in the suite asserts what happens
   when secure randomness is unavailable. A deterministic stream passes every
   self-consistency test we have -- that is precisely how a predictable RNG
   survives a health check that only asks "does the output look random?".
"""

import base64
import collections
import os
import string
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from bip_utils import Bip39SeedGenerator

from local_bip85.bip85 import BIP85
from seedpass.core.encryption import EncryptionManager
from seedpass.core.password_generation import (
    CURRENT_PASSWORD_GEN_VERSION,
    PasswordGenerator,
    PasswordPolicy,
)

pytestmark = pytest.mark.determinism


# BIP-39 canonical all-"abandon" test vector. Public, never used for real funds.
TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


class _SeedDeriver:
    """Mirrors EncryptionManager.derive_seed_from_mnemonic without a vault."""

    def derive_seed_from_mnemonic(self, mnemonic, passphrase=""):
        return Bip39SeedGenerator(mnemonic).Generate(passphrase)


POLICIES = {
    "default": PasswordPolicy(),
    "exclude_ambiguous": PasswordPolicy(exclude_ambiguous=True),
    "safe_special": PasswordPolicy(special_mode="safe"),
    "no_special": PasswordPolicy(include_special_chars=False),
    "custom_special": PasswordPolicy(allowed_special_chars="!@#"),
    "high_minima": PasswordPolicy(
        min_uppercase=5, min_lowercase=5, min_digits=5, min_special=5
    ),
}

# (policy_name, length, index, expected_password)
#
# Lengths 8 and 128 are MIN/MAX_PASSWORD_LENGTH; 16 is the default. 33, 40, 64
# and 128 all cross the 32-byte DeterministicStream wrap boundary, so they pin
# the behaviour audit item M3 proposes to change.
V1_VECTORS = [
    ("default", 8, 0, "d]C}13hI"),
    ("default", 16, 0, "Cq5kO%t>0O3$0r$Q"),
    ("default", 16, 1, '221x&^bX1qB"GDm~'),
    ("default", 16, 7, "E1v%%o&3/npC0LO5"),
    ("default", 16, 4095, "e[5D^q62SEmJ2l%>"),
    ("default", 20, 3, "92mT1~D3<NgQf9<>#Wxd"),
    ("default", 32, 2, "y9A2=&CKK@[Wgg>902Aqu)4JuG9>c'j2"),
    ("default", 33, 2, "0g&L4aAj\\;g2o62:V4,r9k%XV]Jz-DZq5"),
    (
        "default",
        64,
        5,
        "SbtiQwfLDa6t[911Rq1]9G1?7M54(?2_M8h=o,(e]V@17Vz)FI@C1n_v-VaMcA5$",
    ),
    (
        "default",
        128,
        11,
        "%3OBz\\zbo?=ads|8y`LrG^FdWE572Cfb:TB939%'0HUn340pB&\\?7M?EN5O1*P.5"
        "GBE7.=h4<Ft-UoDs3Xm&/8r0Ag^}Jr[3[f306oZ^$*e-44y3w6`ovDut:T3p01WY",
    ),
    ("exclude_ambiguous", 16, 0, "2t5V(h$6}yCtU2X>"),
    ("exclude_ambiguous", 40, 2, 'wue$:"}JY2.9AQx\\RKn2:62,k9Z8<67j3fPYXzv@'),
    ("safe_special", 16, 0, "Cq5kO_t-0O3-0r?Q"),
    ("safe_special", 40, 2, "na_4qOEbr-s1L2nZ7$*6Gj4A@+DQ5f@49X+V0?y#"),
    ("no_special", 16, 0, "03RrqOTi4NC1hT0r"),
    ("no_special", 40, 2, "6gGz4Aru62y4is90OzDq4QX57XZqgGVLjV25g9hY"),
    ("custom_special", 16, 0, "3q1O#z@4@rCrH0T#"),
    ("high_minima", 24, 0, "Cc+r=_R3hrI01i0q#C(O*T01"),
]


def _generator(policy: PasswordPolicy) -> PasswordGenerator:
    seed = Bip39SeedGenerator(TEST_MNEMONIC).Generate()
    return PasswordGenerator(_SeedDeriver(), TEST_MNEMONIC, BIP85(seed), policy=policy)


# --------------------------------------------------------------------------
# 1. Frozen v1 derivation
# --------------------------------------------------------------------------


@pytest.mark.parametrize("policy_name,length,index,expected", V1_VECTORS)
def test_v1_password_vectors_are_frozen(policy_name, length, index, expected):
    """Live vaults re-derive these exact strings. Do not update on failure.

    See this module's docstring before changing anything here.
    """
    pg = _generator(POLICIES[policy_name])
    assert pg.generate_password(length=length, index=index) == expected, (
        f"v1 derivation changed for policy={policy_name} length={length} "
        f"index={index}. This breaks every existing vault entry. Revert the "
        f"change, or land it behind a new gen_version leaving v1 untouched."
    )


def test_v1_vectors_cover_the_stream_wrap_boundary():
    """Guards the guard: M3's fix must be caught by the table above.

    DeterministicStream wraps a 32-byte key. If every vector were <= 32
    characters, changing the wrap behaviour would leave this file green while
    silently altering longer passwords.
    """
    assert any(length > 32 for _, length, _, _ in V1_VECTORS)


def test_v1_vectors_cover_every_policy():
    assert {name for name, _, _, _ in V1_VECTORS} == set(POLICIES)


def test_derivation_is_stable_across_generator_instances():
    """A fresh generator over the same seed must reproduce the same password."""
    first = _generator(POLICIES["default"]).generate_password(length=24, index=9)
    second = _generator(POLICIES["default"]).generate_password(length=24, index=9)
    assert first == second


# --------------------------------------------------------------------------
# 2. Fail-closed RNG behaviour
# --------------------------------------------------------------------------


def test_seed_generation_aborts_when_urandom_fails(monkeypatch):
    """No secure entropy must mean no seed -- never a substituted value."""
    from seedpass.core import manager as manager_module

    def _explode(_n):
        raise OSError("entropy pool unavailable")

    monkeypatch.setattr(manager_module.os, "urandom", _explode)

    with pytest.raises(Exception) as excinfo:
        manager_module.PasswordManager.generate_bip85_seed(object())

    # The failure must propagate. A returned mnemonic here would mean the
    # generator fell back to something -- the exact COLDCARD defect class.
    assert "entropy pool unavailable" in str(excinfo.value) or isinstance(
        excinfo.value.__cause__, OSError
    )


def test_seed_generation_aborts_on_short_read(monkeypatch):
    """A partial entropy read must not be silently accepted as a full seed."""
    from seedpass.core import manager as manager_module

    monkeypatch.setattr(manager_module.os, "urandom", lambda n: b"\x2b" * 4)

    with pytest.raises(Exception):
        manager_module.PasswordManager.generate_bip85_seed(object())


def test_entropy_draw_sits_outside_the_try_block(monkeypatch):
    """L3: no except clause may stand between os.urandom and the caller.

    The generator's exception handling wraps BIP-85 failures in SeedPassError,
    which is fine -- but an entropy failure must never be reachable by any
    handler that could substitute a value. Keeping the draw outside the try is
    the structural version of that guarantee, stronger than narrowing which
    exception types get caught.
    """
    from seedpass.core import manager as manager_module

    sentinel = OSError("entropy pool unavailable")

    def _explode(_n):
        raise sentinel

    monkeypatch.setattr(manager_module.os, "urandom", _explode)

    with pytest.raises(OSError) as excinfo:
        manager_module.PasswordManager.generate_bip85_seed(object())

    # Propagates as itself, not repackaged -- proof nothing caught it.
    assert excinfo.value is sentinel


@pytest.mark.parametrize("words_num,expected", [(12, 12), (24, 24)])
def test_master_seed_word_count_is_selectable(words_num, expected):
    """L2: the master seed can now be 256-bit, not only 128-bit."""
    from seedpass.core.manager import PasswordManager

    mnemonic = PasswordManager.generate_bip85_seed(object(), words_num=words_num)
    assert len(mnemonic.split()) == expected


def test_master_seed_default_is_unchanged():
    """Existing profiles are 12-word; the default must not move under them."""
    from seedpass.core.manager import PasswordManager

    assert len(PasswordManager.generate_bip85_seed(object()).split()) == 12


def test_unsupported_word_count_is_rejected():
    from seedpass.core.errors import SeedPassError
    from seedpass.core.manager import PasswordManager

    for bad in (0, 11, 18, 25, -12):
        with pytest.raises(SeedPassError, match="Seed word count"):
            PasswordManager.generate_bip85_seed(object(), words_num=bad)


def test_all_zero_entropy_is_not_currently_detected(monkeypatch):
    """Recorded gap, not an endorsement.

    If os.urandom returned all zeros, SeedPass would mint a valid-looking
    mnemonic from it. There is no health check on the entropy source. This test
    pins the CURRENT behaviour so that adding such a check is a deliberate,
    visible change rather than an accident -- and so the gap cannot be forgotten.

    Tracked as part of M4 in docs/entropy_audit_2026-07-31.md. Realistically low
    risk: on Linux os.urandom is getrandom(2), which does not return zeros post
    boot. The threat this guards is a future code change, not a kernel failure.
    """
    from seedpass.core import manager as manager_module

    monkeypatch.setattr(manager_module.os, "urandom", lambda n: b"\x00" * n)

    mnemonic = manager_module.PasswordManager.generate_bip85_seed(object())
    assert len(mnemonic.split()) == 12  # currently accepted; see docstring


# --------------------------------------------------------------------------
# 3. Version 2 properties (audit items M1, M2, M3)
# --------------------------------------------------------------------------


def _v2(length, index, policy=None):
    return _generator(policy or POLICIES["default"]).generate_password(
        length=length, index=index, gen_version=CURRENT_PASSWORD_GEN_VERSION
    )


def _classes(pw):
    return (
        sum(c in string.ascii_uppercase for c in pw),
        sum(c in string.ascii_lowercase for c in pw),
        sum(c in string.digits for c in pw),
        sum(not c.isalnum() for c in pw),
    )


def test_v2_does_not_pin_the_class_composition():
    """The core of M1: v1 produced exactly one composition, always.

    v1 forced length/4 of each class into every password, making any SeedPass
    password identifiable from its composition alone. v2 must vary.
    """
    pg = _generator(POLICIES["default"])
    v1 = {
        _classes(pg.generate_password(length=16, index=i, gen_version=1))
        for i in range(120)
    }
    v2 = {
        _classes(
            pg.generate_password(
                length=16, index=i, gen_version=CURRENT_PASSWORD_GEN_VERSION
            )
        )
        for i in range(120)
    }
    assert len(v1) == 1, "v1 is expected to be degenerate; that is the finding"
    assert len(v2) > 20, f"v2 composition still too rigid: {len(v2)} distinct"


def test_v2_still_satisfies_the_policy_minima():
    for length in (8, 16, 33, 64):
        for index in range(25):
            upper, lower, digits, special = _classes(_v2(length, index))
            assert upper >= 2 and lower >= 2 and digits >= 2 and special >= 2


def test_v2_respects_non_default_policies():
    for name in ("exclude_ambiguous", "safe_special", "no_special", "custom_special"):
        policy = POLICIES[name]
        for index in range(10):
            pw = _v2(24, index, policy)
            assert len(pw) == 24
            if name == "no_special":
                assert all(c.isalnum() for c in pw)
            if name == "custom_special":
                assert all(c.isalnum() or c in "!@#" for c in pw)
            if name == "exclude_ambiguous":
                assert not any(c in "O0Il1" for c in pw)


def test_v2_rejects_a_policy_that_cannot_fit():
    """sum(minima) > length is impossible; say so instead of silently failing."""
    policy = PasswordPolicy(
        min_uppercase=5, min_lowercase=5, min_digits=5, min_special=5
    )
    with pytest.raises(ValueError, match="requires at least"):
        _v2(8, 0, policy)


def test_v2_has_no_modulo_bias():
    """M2: chi-square over the 94-char alphabet. df=93, p<0.001 crit ~147."""
    pws = [_v2(64, i) for i in range(180)]
    counts = collections.Counter(c for pw in pws for c in pw)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    n = sum(counts.values())
    expected = n / len(alphabet)
    chi2 = sum((counts.get(ch, 0) - expected) ** 2 / expected for ch in alphabet)
    assert chi2 < 147, f"character distribution looks biased (chi2={chi2:.1f})"


def test_v2_stream_does_not_repeat_at_the_32_byte_boundary():
    """M3: v1 cycled a 32-byte key, so position i and i+32 shared a source byte."""
    pws = [_v2(128, i) for i in range(80)]
    matches = sum(1 for pw in pws for i in range(len(pw) - 32) if pw[i] == pw[i + 32])
    total = sum(len(pw) - 32 for pw in pws)
    rate = matches / total
    chance = 1 / 94
    # Generous band: this catches a repeating pad (which would spike the rate),
    # not small sampling noise.
    assert rate < chance * 2.5, f"lag-32 repeat rate {rate:.5f} vs chance {chance:.5f}"


def test_v2_is_deterministic_across_instances():
    assert _v2(24, 9) == _v2(24, 9)


def test_v2_differs_from_v1():
    pg = _generator(POLICIES["default"])
    assert pg.generate_password(length=24, index=9, gen_version=1) != _v2(24, 9)


def test_unknown_generation_version_is_rejected():
    """Never guess which algorithm produced a password."""
    pg = _generator(POLICIES["default"])
    for bad in (0, 3, 99):
        with pytest.raises(ValueError, match="Unknown password generation version"):
            pg.generate_password(length=16, index=0, gen_version=bad)


def test_default_gen_version_is_legacy():
    """Any caller that does not opt in must keep deriving v1."""
    pg = _generator(POLICIES["default"])
    assert pg.generate_password(length=16, index=0) == pg.generate_password(
        length=16, index=0, gen_version=1
    )


def test_new_entries_are_stamped_with_the_current_version():
    from seedpass.core.password_generation import CURRENT_PASSWORD_GEN_VERSION as cur

    assert cur == 2


# --------------------------------------------------------------------------
# 4. Entry -> version plumbing (the part that protects existing vaults)
# --------------------------------------------------------------------------


def _manager_with(pg):
    from seedpass.core.manager import PasswordManager

    pm = PasswordManager.__new__(PasswordManager)
    pm.password_generator = pg
    return pm


def test_entry_without_gen_version_still_derives_v1():
    """The single most important behaviour: existing vaults must not change.

    Entries written before versioning carry no field. They must keep deriving
    through v1 forever.
    """
    from seedpass.core.manager import PasswordManager

    pg = _generator(POLICIES["default"])
    pm = _manager_with(pg)
    got = PasswordManager._generate_password_for_entry(pm, {"length": 16}, 3)
    assert got == pg.generate_password(16, 3, gen_version=1)


def test_entry_with_gen_version_2_derives_v2():
    from seedpass.core.manager import PasswordManager

    pg = _generator(POLICIES["default"])
    pm = _manager_with(pg)
    entry = {"length": 16, "gen_version": CURRENT_PASSWORD_GEN_VERSION}
    got = PasswordManager._generate_password_for_entry(pm, entry, 3)
    assert got == pg.generate_password(16, 3, gen_version=CURRENT_PASSWORD_GEN_VERSION)
    assert got != pg.generate_password(16, 3, gen_version=1)


def test_policy_override_still_applies_on_a_versioned_entry():
    from seedpass.core.manager import PasswordManager

    pg = _generator(POLICIES["default"])
    pm = _manager_with(pg)
    entry = {
        "length": 16,
        "gen_version": CURRENT_PASSWORD_GEN_VERSION,
        "policy": {"include_special_chars": False},
    }
    got = PasswordManager._generate_password_for_entry(pm, entry, 3)
    assert got.isalnum()
    assert pg.policy == PasswordPolicy(), "base policy must be restored"


def test_unreadable_entry_gen_version_fails_loudly():
    """Never guess which algorithm produced an entry's password."""
    from seedpass.core.manager import PasswordManager

    pm = _manager_with(_generator(POLICIES["default"]))
    with pytest.raises(ValueError, match="unreadable gen_version"):
        PasswordManager._generate_password_for_entry(
            pm, {"length": 16, "gen_version": "??"}, 3
        )


def test_encryption_nonce_is_fresh_per_call(tmp_path):
    """AES-GCM nonce reuse under one key is catastrophic, not gradual."""
    key = base64.urlsafe_b64encode(os.urandom(32))
    em = EncryptionManager(key, tmp_path)

    payloads = [em.encrypt_data(b"identical plaintext") for _ in range(64)]
    nonces = {blob[3:15] for blob in payloads}  # b"V3|" + 12-byte nonce

    assert len(nonces) == 64, "AES-GCM nonce repeated across encrypt_data calls"
    assert len({bytes(b) for b in payloads}) == 64
    assert all(blob.startswith(b"V3|") for blob in payloads)
    assert em.decrypt_data(payloads[0]) == b"identical plaintext"


def test_totp_secret_is_fresh_per_call():
    from seedpass.core.totp import random_totp_secret

    secrets_seen = {random_totp_secret() for _ in range(64)}
    assert len(secrets_seen) == 64
