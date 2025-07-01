import re
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from utils.checksum import verify_and_update_checksum


def test_encryption_checksum_workflow():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        key = Fernet.generate_key()
        manager = EncryptionManager(key, tmp_path)

        data = {"value": 1}
        manager.save_json_data(data)
        manager.update_checksum()

        enc_file = tmp_path / "seedpass_passwords_db.json.enc"
        chk_file = tmp_path / "seedpass_passwords_db.json_checksum.txt"

        checksum = chk_file.read_text().strip()
        assert re.fullmatch(r"[0-9a-f]{64}", checksum)

        manager.save_json_data({"value": 2})
        assert not verify_and_update_checksum(str(enc_file), str(chk_file))

        manager.update_checksum()
        assert verify_and_update_checksum(str(enc_file), str(chk_file))
