from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.determinism

TEST_SEED = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon about"
)


def _run_derivation_subprocess(index: int) -> dict[str, str]:
    repo_root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    pythonpath = env.get("PYTHONPATH", "")
    src_path = str(repo_root / "src")
    env["PYTHONPATH"] = f"{src_path}:{pythonpath}" if pythonpath else src_path

    code = f"""
import hashlib
import json
from bip_utils import Bip39SeedGenerator
from local_bip85.bip85 import BIP85
from nostr.coincurve_keys import Keys
from seedpass.core.password_generation import PasswordGenerator, derive_seed_phrase, derive_ssh_key_pair
from seedpass.core.totp import TotpManager

seed = "{TEST_SEED}"
index = {index}

class _MnemonicSeedEncoder:
    @staticmethod
    def derive_seed_from_mnemonic(mnemonic: str) -> bytes:
        return Bip39SeedGenerator(mnemonic).Generate()

seed_bytes = Bip39SeedGenerator(seed).Generate()
bip85 = BIP85(seed_bytes)
pg = PasswordGenerator(_MnemonicSeedEncoder(), seed, bip85)
pw = pg.generate_password(length=24, index=index)
ssh_priv, ssh_pub = derive_ssh_key_pair(seed, index)
seed24 = derive_seed_phrase(bip85, index, 24)
totp_secret = TotpManager.derive_secret(seed, index)
totp_code = TotpManager.current_code(seed, index, timestamp=1700000000)
entropy = bip85.derive_entropy(index=index, entropy_bytes=32)
nostr_keys = Keys(priv_k=entropy.hex())
npub = Keys.hex_to_bech32(nostr_keys.public_key_hex(), "npub")
nsec = Keys.hex_to_bech32(nostr_keys.private_key_hex(), "nsec")

print(json.dumps({{
    "password": pw,
    "ssh_priv_sha256": hashlib.sha256(ssh_priv.encode("utf-8")).hexdigest(),
    "ssh_pub_sha256": hashlib.sha256(ssh_pub.encode("utf-8")).hexdigest(),
    "seed24": seed24,
    "totp_secret": totp_secret,
    "totp_code_at_1700000000": totp_code,
    "npub": npub,
    "nsec": nsec,
}}, sort_keys=True))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
        env=env,
        check=True,
    )
    return json.loads(result.stdout.strip())


@pytest.mark.parametrize("index", [0, 352, 1024])
def test_artifacts_are_identical_across_processes(index: int):
    first = _run_derivation_subprocess(index)
    second = _run_derivation_subprocess(index)
    assert first == second
