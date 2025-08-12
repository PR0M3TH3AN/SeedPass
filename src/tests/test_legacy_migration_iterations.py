import base64
import json
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

import pytest

import seedpass.core.encryption as enc_module
import seedpass.core.vault as vault_module
from helpers import TEST_PASSWORD
from seedpass.core.encryption import (
    EncryptionManager,
    _derive_legacy_key_from_password,
)
from seedpass.core.config_manager import ConfigManager
from seedpass.core.vault import Vault
from seedpass.core.migrations import LATEST_VERSION


def _setup_legacy_file(tmp_path: Path, iterations: int) -> None:
    legacy_key = _derive_legacy_key_from_password(TEST_PASSWORD, iterations=iterations)
    mgr = EncryptionManager(legacy_key, tmp_path)
    data = {"schema_version": LATEST_VERSION, "entries": {"0": {"kind": "test"}}}
    json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
    legacy_encrypted = mgr.fernet.encrypt(json_bytes)
    (tmp_path / "seedpass_entries_db.json.enc").write_bytes(legacy_encrypted)


@pytest.mark.parametrize("iterations", [50_000, 100_000])
def test_migrate_iterations(tmp_path, monkeypatch, iterations):
    _setup_legacy_file(tmp_path, iterations)

    new_key = base64.urlsafe_b64encode(b"B" * 32)
    mgr = EncryptionManager(new_key, tmp_path)
    vault = Vault(mgr, tmp_path)

    prompts: list[int] = []

    def fake_prompt(_msg: str) -> str:
        prompts.append(1)
        return TEST_PASSWORD

    monkeypatch.setattr(enc_module, "prompt_existing_password", fake_prompt)
    monkeypatch.setattr(vault_module, "prompt_existing_password", fake_prompt)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "2")

    calls: list[int] = []
    orig_derive = enc_module._derive_legacy_key_from_password

    def tracking_derive(password: str, iterations: int = 100_000) -> bytes:
        calls.append(iterations)
        return orig_derive(password, iterations=iterations)

    monkeypatch.setattr(enc_module, "_derive_legacy_key_from_password", tracking_derive)

    vault.load_index()
    # Loading again should not prompt for password or attempt legacy counts
    vault.load_index()

    assert prompts == [1]
    expected = [50_000] if iterations == 50_000 else [50_000, 100_000]
    assert calls == expected

    cfg = ConfigManager(vault, tmp_path)
    assert cfg.get_kdf_iterations() == iterations

    content = (tmp_path / "seedpass_entries_db.json.enc").read_bytes()
    assert content.startswith(b"V2:")
