import base64
import hashlib
import unicodedata

from helpers import TEST_PASSWORD
import seedpass.core.encryption as enc_module
from seedpass.core.encryption import EncryptionManager
from utils.key_derivation import derive_key_from_password


def test_decrypt_data_password_fallback(tmp_path, monkeypatch):
    calls: list[int] = []

    def _fast_legacy_key(password: str, iterations: int = 100_000) -> bytes:
        calls.append(iterations)
        normalized = unicodedata.normalize("NFKD", password).strip().encode("utf-8")
        key = hashlib.pbkdf2_hmac("sha256", normalized, b"", 1, dklen=32)
        return base64.urlsafe_b64encode(key)

    monkeypatch.setattr(
        enc_module, "_derive_legacy_key_from_password", _fast_legacy_key
    )
    monkeypatch.setattr(
        enc_module, "prompt_existing_password", lambda *_a, **_k: TEST_PASSWORD
    )

    legacy_key = _fast_legacy_key(TEST_PASSWORD, iterations=50_000)
    legacy_mgr = EncryptionManager(legacy_key, tmp_path)
    payload = legacy_mgr.encrypt_data(b"secret")

    new_key = derive_key_from_password(TEST_PASSWORD, "fp")
    new_mgr = EncryptionManager(new_key, tmp_path)

    assert new_mgr.decrypt_data(payload) == b"secret"
    assert calls == [50_000, 50_000]
