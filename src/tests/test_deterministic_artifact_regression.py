import hashlib
from dataclasses import dataclass

import pytest
from bip_utils import Bip39SeedGenerator
from local_bip85.bip85 import BIP85
from nostr.coincurve_keys import Keys

from seedpass.core.password_generation import (
    PasswordPolicy,
    PasswordGenerator,
    derive_pgp_key,
    derive_seed_phrase,
    derive_ssh_key_pair,
)
from seedpass.core.totp import TotpManager

TEST_SEED = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon about"
)

pytestmark = pytest.mark.determinism


@dataclass(frozen=True)
class DeterministicVector:
    index: int
    password: str
    ssh_priv_sha256: str
    ssh_pub_sha256: str
    seed24: str
    totp_secret: str
    totp_code_at_1700000000: str
    npub: str
    nsec: str


VECTORS = (
    DeterministicVector(
        index=0,
        password="Ti+q<_O4dcO07h1r#Q(C]R10",
        ssh_priv_sha256="f30df9cf394783bd2c8f33cacf147344032d04ab60184abc1b09286b845461c0",
        ssh_pub_sha256="8e8e0b8d2662c6bf47e2a03fc0d6c191744aa343df14b7d506c566d14347547c",
        seed24=(
            "stick exact spice sock filter ginger museum horse kit multiply "
            "manual wear grief demand derive alert quiz fault december lava "
            "picture immune decade jaguar"
        ),
        totp_secret="DRUATVCMCPFH4EEQXM5FEJZMU3BUTQ47",
        totp_code_at_1700000000="919492",
        npub="npub1xw0hg33pyty45095rg27pqhde0pl6guu2rremsszedtm254hrqlqnh0zc3",
        nsec="nsec18ggmuuvurkq6p2mrp25mhlzzt3trenmw8tpnth3fmt69mrq06grs3duayu",
    ),
    DeterministicVector(
        index=1,
        password='B1O"C2D813Gm:]b"gm7>q/xX',
        ssh_priv_sha256="0410faeb273218505f4c9cfd23acf59a54d03fade4162bf8db01425c71d2a620",
        ssh_pub_sha256="f4db960980a446333b6af8fe25a196e4c5e808d5c163484e67fb55a7d6665a07",
        seed24=(
            "trade clock mom turtle clutch love surge truth bus reward hover "
            "truck palm paddle fossil near group cactus alley gas borrow "
            "amateur learn leisure"
        ),
        totp_secret="CLQCBCRIBIBSJUBKQVSLUUQIFZBNDHOG",
        totp_code_at_1700000000="125654",
        npub="npub176503mwgzhknlyd02kyz2qxc2umpzj9em0pceqvmpk658vdxgjfsf8zh8y",
        nsec="nsec1gg9jjq7q64uwzz9g3dl6pn0f7n9csrzrk6hthamzchat5ahs4u2qhhtper",
    ),
    DeterministicVector(
        index=352,
        password="$oEEz0$606DE2g9o(%$wH;Uu",
        ssh_priv_sha256="076b0eece3b5cb0ff3dec8c654fd5e47a53493597403a2211aa3b077b2c097aa",
        ssh_pub_sha256="271a2934cf3739356fb86ce916f1b0463dff917fb97d2fadc8ef712be24db0ac",
        seed24=(
            "scrub please antenna tower shoulder oven public cinnamon catch "
            "wrong excuse afford infant open fetch diet badge detail private "
            "produce nuclear issue bottom pyramid"
        ),
        totp_secret="W7JJRQUQ7XSAJ4GCRKABXMN5GNWIF4S5",
        totp_code_at_1700000000="716409",
        npub="npub1hyz0p8386nq9u57rxwtxpqnc4p3ma32lqt8ecmws8q8yfjndkszspgeusn",
        nsec="nsec12stv7u29f26ltzety2czeg38fgydsyc23hcfakcawgd8wccrs7zqat7a9v",
    ),
    DeterministicVector(
        index=1024,
        password="hO59JB_em--Do1)H1y90$n[O",
        ssh_priv_sha256="553ff8f9849e7601b01b1f60f20edb9a6f196be46ef12dc55211ea104464d142",
        ssh_pub_sha256="0262cb6a35b98a55976b31e98d4e6e2f1b75558d488f00f24f2c86019fe133f2",
        seed24=(
            "dove empty shadow speak outside cram account venture please aware "
            "short slim neglect endless say cluster garbage lemon betray "
            "arrive rookie display purpose soda"
        ),
        totp_secret="J67YM5ZPJV464YI7NQEAEJYVOP65DSRO",
        totp_code_at_1700000000="642229",
        npub="npub1l9hfe5f5akx8fa7tzyqa0a6z3fgven558cd8382nep346hmqnwysalt4qx",
        nsec="nsec1pja266pu7umwtg9lzuz02etxjzgx7v8nf3r2247el6g0rv75pyrqjznlqu",
    ),
)


class _MnemonicSeedEncoder:
    """Minimal shim to satisfy PasswordGenerator dependency contract."""

    @staticmethod
    def derive_seed_from_mnemonic(mnemonic: str) -> bytes:
        return Bip39SeedGenerator(mnemonic).Generate()


def _build_password_generator(
    seed_phrase: str, policy: PasswordPolicy | None = None
) -> PasswordGenerator:
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    bip85 = BIP85(seed_bytes)
    return PasswordGenerator(_MnemonicSeedEncoder(), seed_phrase, bip85, policy=policy)


def test_deterministic_vectors_index_352_regression():
    """Lock deterministic outputs so derivation drift fails CI immediately."""
    seed_bytes = Bip39SeedGenerator(TEST_SEED).Generate()
    bip85 = BIP85(seed_bytes)
    generator = _build_password_generator(TEST_SEED)

    for vector in VECTORS:
        password = generator.generate_password(length=24, index=vector.index)
        ssh_priv, ssh_pub = derive_ssh_key_pair(TEST_SEED, vector.index)
        seed24 = derive_seed_phrase(bip85, vector.index, 24)
        totp_secret = TotpManager.derive_secret(TEST_SEED, vector.index)
        totp_code = TotpManager.current_code(
            TEST_SEED, vector.index, timestamp=1700000000
        )

        entropy = bip85.derive_entropy(index=vector.index, entropy_bytes=32)
        nostr_keys = Keys(priv_k=entropy.hex())
        npub = Keys.hex_to_bech32(nostr_keys.public_key_hex(), "npub")
        nsec = Keys.hex_to_bech32(nostr_keys.private_key_hex(), "nsec")

        assert password == vector.password
        assert seed24 == vector.seed24
        assert totp_secret == vector.totp_secret
        assert totp_code == vector.totp_code_at_1700000000
        assert npub == vector.npub
        assert nsec == vector.nsec
        assert (
            hashlib.sha256(ssh_priv.encode("utf-8")).hexdigest()
            == vector.ssh_priv_sha256
        )
        assert (
            hashlib.sha256(ssh_pub.encode("utf-8")).hexdigest() == vector.ssh_pub_sha256
        )

    pgp_key, pgp_pub, pgp_fp = derive_pgp_key(
        bip85, 352, "ed25519", "SeedPass Regression"
    )
    assert pgp_fp == "46A5AEB6797495ABCDC91E5687DC058A9B6AF8FA"
    assert (
        hashlib.sha256(pgp_key.encode("utf-8")).hexdigest()
        == "8e5e8128422901a7c3b1655f416ede4c1570470bef7e0f90c33adf743b7191ae"
    )

    # Pin deterministic RSA behavior at one known vector too.
    rsa_key, rsa_pub, rsa_fp = derive_pgp_key(bip85, 352, "rsa", "SeedPass Regression")
    assert rsa_fp == "A04FE91ED24354AC13E25C43677FE463B8C74495"
    assert (
        hashlib.sha256(rsa_key.encode("utf-8")).hexdigest()
        == "2953b095a9214f29cde0846d5828ff6ea1fa3f431f3116a29bc94b812f1d2d05"
    )


def test_repeatability_for_same_seed_and_index():
    """Same seed/index must always produce identical artifacts within a run."""
    generator = _build_password_generator(TEST_SEED)

    for vector in VECTORS:
        pw_1 = generator.generate_password(length=24, index=vector.index)
        pw_2 = generator.generate_password(length=24, index=vector.index)
        assert pw_1 == pw_2

        ssh_priv_1, ssh_pub_1 = derive_ssh_key_pair(TEST_SEED, vector.index)
        ssh_priv_2, ssh_pub_2 = derive_ssh_key_pair(TEST_SEED, vector.index)
        assert ssh_priv_1 == ssh_priv_2
        assert ssh_pub_1 == ssh_pub_2

        totp_secret_1 = TotpManager.derive_secret(TEST_SEED, vector.index)
        totp_secret_2 = TotpManager.derive_secret(TEST_SEED, vector.index)
        assert totp_secret_1 == totp_secret_2


@pytest.mark.parametrize(
    "index,expected_sha256",
    [
        (0, "4e4df93e6a35f03eb5108f7bfca41f4469a13c287876cfb1b0c6c4fa48d4026f"),
        (1, "c28902c1ba33cacab86d2fdc4524cee594809277337f9e77a4124e6946c3ae80"),
        (352, "85ff7ed5b2be3277f822fb0c141b35ba8636badbd9adec089531172d689fa815"),
        (
            1024,
            "834a72f2fbea70964239bbc085c6ba4262032b961542333e2eef5ccdc05214b4",
        ),
    ],
)
def test_password_entropy_stream_hash_regression(index: int, expected_sha256: str):
    """Pin entropy stream outputs for known indexes to catch derivation drift."""
    generator = _build_password_generator(TEST_SEED)
    stream = generator._derive_password_entropy(index=index)
    assert hashlib.sha256(stream).hexdigest() == expected_sha256


@pytest.mark.parametrize(
    "policy,index,length,expected_password",
    [
        (
            PasswordPolicy(),
            352,
            24,
            "$oEEz0$606DE2g9o(%$wH;Uu",
        ),
        (
            PasswordPolicy(special_mode="safe"),
            352,
            24,
            "o66U^o!g%D0w!6E2E=ZH6uw!",
        ),
        (
            PasswordPolicy(include_special_chars=False, min_special=0),
            352,
            24,
            "0E6jwUo92EZ96GDoeuoHiU56",
        ),
        (
            PasswordPolicy(exclude_ambiguous=True),
            17,
            20,
            "59ik9Z3k=UJW_%)tZm_6",
        ),
        (
            PasswordPolicy(
                allowed_special_chars="@#",
                min_uppercase=2,
                min_lowercase=2,
                min_digits=2,
                min_special=2,
            ),
            99,
            22,
            "x@N#M82#Jwf#7b8u99NM5@",
        ),
    ],
    ids=[
        "default",
        "safe_special_mode",
        "no_special_characters",
        "exclude_ambiguous",
        "restricted_special_charset",
    ],
)
def test_password_policy_vector_regression(
    policy: PasswordPolicy,
    index: int,
    length: int,
    expected_password: str,
):
    """Lock policy-specific password outputs to prevent accidental behavior changes."""
    generator = _build_password_generator(TEST_SEED, policy=policy)
    password = generator.generate_password(length=length, index=index)
    assert password == expected_password
