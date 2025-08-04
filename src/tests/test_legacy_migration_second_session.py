import json
import hashlib
from pathlib import Path
from types import SimpleNamespace

from cryptography.fernet import Fernet

from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from seedpass.core.manager import PasswordManager, EncryptionMode
from seedpass.core.vault import Vault
from seedpass.core.encryption import EncryptionManager
from utils.key_derivation import derive_index_key
from utils.fingerprint import generate_fingerprint


def test_legacy_migration_second_session(monkeypatch, tmp_path: Path) -> None:
    fingerprint = generate_fingerprint(TEST_SEED)
    fp_dir = tmp_path / fingerprint
    fp_dir.mkdir()
    vault, _ = create_vault(fp_dir, TEST_SEED, TEST_PASSWORD)

    key = derive_index_key(TEST_SEED)
    data = {"schema_version": 4, "entries": {}}
    enc = Fernet(key).encrypt(json.dumps(data).encode())
    legacy_file = fp_dir / "seedpass_passwords_db.json.enc"
    legacy_file.write_bytes(enc)
    (fp_dir / "seedpass_passwords_db_checksum.txt").write_text(
        hashlib.sha256(enc).hexdigest()
    )

    monkeypatch.setattr(
        "seedpass.core.encryption.prompt_existing_password", lambda *_: TEST_PASSWORD
    )
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "y")
    vault.load_index()
    new_file = fp_dir / "seedpass_entries_db.json.enc"
    assert new_file.read_bytes().startswith(b"V2:")

    new_enc_mgr = EncryptionManager(key, fp_dir)
    new_vault = Vault(new_enc_mgr, fp_dir)
    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = new_enc_mgr
    pm.vault = new_vault
    pm.parent_seed = TEST_SEED
    pm.fingerprint_dir = fp_dir
    pm.current_fingerprint = fp_dir.name
    pm.bip85 = SimpleNamespace()
    monkeypatch.setattr(
        "seedpass.core.manager.NostrClient", lambda *a, **k: SimpleNamespace()
    )

    def fail_prompt(*_a, **_k):  # pragma: no cover - ensures no prompts occur
        raise AssertionError("Prompt should not be called")

    monkeypatch.setattr("builtins.input", fail_prompt)
    monkeypatch.setattr(
        "seedpass.core.encryption.prompt_existing_password", fail_prompt
    )

    pm.initialize_managers()
    assert new_file.read_bytes().startswith(b"V2:")
