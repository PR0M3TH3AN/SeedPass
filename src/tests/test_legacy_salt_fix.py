import base64
import json
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from helpers import TEST_PASSWORD
from seedpass.core.encryption import (
    EncryptionManager,
    _derive_legacy_key_from_password,
)
from seedpass.core.migrations import LATEST_VERSION


def test_decrypt_legacy_with_new_salt(tmp_path):
    # Setup: Create a legacy file encrypted with a non-empty salt
    fingerprint = "test-fingerprint"
    fingerprint_dir = tmp_path / fingerprint
    fingerprint_dir.mkdir()

    salt = fingerprint.encode()
    iterations = 50_000
    legacy_key = _derive_legacy_key_from_password(
        TEST_PASSWORD, iterations=iterations, salt=salt
    )

    mgr = EncryptionManager(legacy_key, fingerprint_dir)
    data = {"schema_version": LATEST_VERSION, "entries": {"0": {"kind": "test"}}}
    json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
    legacy_encrypted = mgr.fernet.encrypt(json_bytes)

    # Target file
    target_file = fingerprint_dir / "seedpass_entries_db.json.enc"
    target_file.write_bytes(legacy_encrypted)

    # Act: Use EncryptionManager to decrypt it via decrypt_legacy
    dummy_key = base64.urlsafe_b64encode(b"A" * 32)
    test_mgr = EncryptionManager(dummy_key, fingerprint_dir)

    decrypted = test_mgr.decrypt_legacy(legacy_encrypted, TEST_PASSWORD)

    # Assert
    assert json.loads(decrypted) == data


def test_decrypt_legacy_with_empty_salt_fallback(tmp_path):
    # Setup: Create a legacy file encrypted with an empty salt (old behavior)
    fingerprint = "test-fingerprint-legacy"
    fingerprint_dir = tmp_path / fingerprint
    fingerprint_dir.mkdir()

    salt = b""
    iterations = 50_000
    legacy_key = _derive_legacy_key_from_password(
        TEST_PASSWORD, iterations=iterations, salt=salt
    )

    mgr = EncryptionManager(legacy_key, fingerprint_dir)
    data = {"schema_version": LATEST_VERSION, "entries": {"0": {"kind": "legacy-test"}}}
    json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
    legacy_encrypted = mgr.fernet.encrypt(json_bytes)

    # Target file
    target_file = fingerprint_dir / "seedpass_entries_db.json.enc"
    target_file.write_bytes(legacy_encrypted)

    # Act: Use EncryptionManager to decrypt it via decrypt_legacy
    dummy_key = base64.urlsafe_b64encode(b"A" * 32)
    test_mgr = EncryptionManager(dummy_key, fingerprint_dir)

    decrypted = test_mgr.decrypt_legacy(legacy_encrypted, TEST_PASSWORD)

    # Assert
    assert json.loads(decrypted) == data
