import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager


def test_json_save_and_load_round_trip():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        manager = EncryptionManager(key, Path(tmpdir))

        data = {"hello": "world", "nums": [1, 2, 3]}
        manager.save_json_data(data)
        loaded = manager.load_json_data()
        assert loaded == data

        file_path = Path(tmpdir) / "seedpass_entries_db.json.enc"
        raw = file_path.read_bytes()
        assert raw != json.dumps(data, indent=4).encode("utf-8")


def test_encrypt_and_decrypt_file_binary_round_trip():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        manager = EncryptionManager(key, Path(tmpdir))

        payload = b"binary secret"
        rel = Path("payload.bin.enc")
        manager.encrypt_and_save_file(payload, rel)
        decrypted = manager.decrypt_file(rel)
        assert decrypted == payload

        file_path = Path(tmpdir) / rel
        raw = file_path.read_bytes()
        assert raw != payload
