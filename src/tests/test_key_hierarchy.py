import base64
from bip_utils import Bip39SeedGenerator
from utils.key_hierarchy import kd
from utils.key_derivation import derive_index_key


def test_kd_distinct_infos():
    root = b"root" * 8
    k1 = kd(root, b"info1")
    k2 = kd(root, b"info2")
    assert k1 != k2


def test_derive_index_key_matches_hierarchy():
    seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed_bytes = Bip39SeedGenerator(seed).Generate()
    master = kd(seed_bytes, b"seedpass:v1:master")
    expected = base64.urlsafe_b64encode(kd(master, b"seedpass:v1:storage"))
    assert derive_index_key(seed) == expected
