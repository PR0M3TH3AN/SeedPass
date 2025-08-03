import json
import base64
import hashlib
import unicodedata
import logging
from cryptography.fernet import Fernet

from helpers import create_vault, TEST_PASSWORD
import seedpass.core.encryption as enc_module


def test_legacy_password_only_fallback(monkeypatch, tmp_path, caplog):
    calls: list[int] = []

    def _fast_legacy_key(password: str, iterations: int = 100_000) -> bytes:
        calls.append(iterations)
        normalized = unicodedata.normalize("NFKD", password).strip().encode("utf-8")
        key = hashlib.pbkdf2_hmac("sha256", normalized, b"", 1, dklen=32)
        return base64.urlsafe_b64encode(key)

    # Speed up legacy key derivation
    monkeypatch.setattr(
        enc_module, "_derive_legacy_key_from_password", _fast_legacy_key
    )
    monkeypatch.setattr(
        enc_module, "prompt_existing_password", lambda *_a, **_k: TEST_PASSWORD
    )
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "2")

    vault, enc_mgr = create_vault(tmp_path)
    data = {"schema_version": 4, "entries": {}}
    legacy_key = _fast_legacy_key(TEST_PASSWORD, iterations=50_000)
    encrypted = Fernet(legacy_key).encrypt(json.dumps(data).encode())

    caplog.set_level(logging.WARNING)
    assert enc_mgr.decrypt_and_save_index_from_nostr(encrypted)
    assert vault.load_index() == data
    assert any("legacy password-only" in rec.message for rec in caplog.records)
    assert calls == [50_000, 50_000]
