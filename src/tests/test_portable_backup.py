import json
import base64
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

import seedpass.core.encryption as enc_module
from seedpass.core.encryption import EncryptionManager
from seedpass.core.vault import Vault
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.errors import ProfileMismatchError
from seedpass.core.portable_backup import export_backup, import_backup
from seedpass.core.portable_backup import PortableMode
from utils.key_derivation import derive_index_key, derive_key_from_password
from utils.fingerprint import generate_fingerprint

SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PASSWORD = "passw0rd"


def setup_vault(tmp: Path):
    fp = generate_fingerprint(SEED)
    seed_key = derive_key_from_password(PASSWORD, fp)
    seed_mgr = EncryptionManager(seed_key, tmp)
    seed_mgr.encrypt_parent_seed(SEED)

    index_key = derive_index_key(SEED)
    enc_mgr = EncryptionManager(index_key, tmp)
    vault = Vault(enc_mgr, tmp)
    cfg = ConfigManager(vault, tmp)
    backup = BackupManager(tmp, cfg)
    return vault, backup, cfg


def test_round_trip(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
        data = {"pw": 1}
        vault.save_index(data)

        path = export_backup(vault, backup, parent_seed=SEED)
        assert path.exists()
        wrapper = json.loads(path.read_text())
        assert wrapper.get("cipher") == "aes-gcm"

        vault.save_index({"pw": 0})
        import_backup(vault, backup, path, parent_seed=SEED)
        assert vault.load_index()["pw"] == data["pw"]


def test_round_trip_unencrypted(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
        data = {"pw": 1}
        vault.save_index(data)

        path = export_backup(vault, backup, parent_seed=SEED, encrypt=False)
        wrapper = json.loads(path.read_text())
        assert wrapper["encryption_mode"] == PortableMode.NONE.value

        vault.save_index({"pw": 0})
        import_backup(vault, backup, path, parent_seed=SEED)
        assert vault.load_index()["pw"] == data["pw"]


from cryptography.fernet import InvalidToken


@pytest.mark.skipif(sys.platform.startswith("win"), reason="flaky on Windows")
def test_corruption_detection(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
        vault.save_index({"a": 1})

        path = export_backup(vault, backup, parent_seed=SEED)

        content = json.loads(path.read_text())
        payload = base64.b64decode(content["payload"])
        payload = b"x" + payload[1:]
        content["payload"] = base64.b64encode(payload).decode()
        path.write_text(json.dumps(content))

        def _fast_legacy_key(password: str, iterations: int = 100_000) -> bytes:
            return base64.urlsafe_b64encode(b"0" * 32)

        monkeypatch.setattr(
            enc_module, "_derive_legacy_key_from_password", _fast_legacy_key
        )
        monkeypatch.setattr(
            enc_module, "prompt_existing_password", lambda *_a, **_k: PASSWORD
        )

        with pytest.raises(InvalidToken):
            import_backup(vault, backup, path, parent_seed=SEED)


def test_import_over_existing(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
        vault.save_index({"v": 1})

        path = export_backup(vault, backup, parent_seed=SEED)

        vault.save_index({"v": 2})
        import_backup(vault, backup, path, parent_seed=SEED)
        loaded = vault.load_index()
        assert loaded["v"] == 1


def test_checksum_mismatch_detection(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
        vault.save_index({"a": 1})

        path = export_backup(vault, backup, parent_seed=SEED)

        wrapper = json.loads(path.read_text())
        payload = base64.b64decode(wrapper["payload"])
        key = derive_index_key(SEED)
        enc_mgr = EncryptionManager(key, tmp)
        data = json.loads(enc_mgr.decrypt_data(payload).decode())
        data["a"] = 2
        mod_canon = json.dumps(data, sort_keys=True, separators=(",", ":"))
        new_payload = enc_mgr.encrypt_data(mod_canon.encode())
        wrapper["payload"] = base64.b64encode(new_payload).decode()
        path.write_text(json.dumps(wrapper))

        with pytest.raises(ValueError):
            import_backup(vault, backup, path, parent_seed=SEED)


def test_export_import_seed_encrypted_with_different_key(monkeypatch):
    """Ensure backup round trip works when seed is encrypted with another key."""
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
        vault.save_index({"v": 123})

        path = export_backup(vault, backup, parent_seed=SEED)
        vault.save_index({"v": 0})
        import_backup(vault, backup, path, parent_seed=SEED)
        assert vault.load_index()["v"] == 123


def test_export_creates_additional_backup_and_import(monkeypatch):
    with TemporaryDirectory() as td, TemporaryDirectory() as extra:
        tmp = Path(td)

        fp = generate_fingerprint(SEED)
        seed_key = derive_key_from_password(PASSWORD, fp)
        seed_mgr = EncryptionManager(seed_key, tmp)
        seed_mgr.encrypt_parent_seed(SEED)

        index_key = derive_index_key(SEED)
        enc_mgr = EncryptionManager(index_key, tmp)
        vault = Vault(enc_mgr, tmp)
        cfg = ConfigManager(vault, tmp)
        cfg.set_additional_backup_path(extra)
        backup = BackupManager(tmp, cfg)

        vault.save_index({"v": 1})

        monkeypatch.setattr(time, "time", lambda: 4444)
        path = export_backup(vault, backup, parent_seed=SEED)

        extra_file = Path(extra) / f"{tmp.name}_{path.name}"
        assert extra_file.exists()

        vault.save_index({"v": 0})
        import_backup(vault, backup, extra_file, parent_seed=SEED)
        assert vault.load_index()["v"] == 1


def test_plaintext_backup_from_another_profile_is_refused():
    """A plaintext backup has no cryptographic binding to the seed it came from.

    The wrong profile can read it perfectly well, and every derived entry is
    then re-derived from the TARGET seed -- so the user gets a vault full of
    entries whose secrets differ from the ones the backup was taken to
    preserve, with nothing erroring along the way. That silence is what makes
    refusing worthwhile.
    """
    with TemporaryDirectory() as td_a, TemporaryDirectory() as td_b:
        tmp_a, tmp_b = Path(td_a), Path(td_b)
        vault_a, backup_a, _ = setup_vault(tmp_a)
        vault_a.save_index({"pw": 1})
        path = export_backup(vault_a, backup_a, parent_seed=SEED, encrypt=False)

        # A second profile whose directory name is a different fingerprint.
        vault_b, backup_b, _ = setup_vault(tmp_b)
        vault_b.save_index({"pw": 0})

        wrapper = json.loads(path.read_text())
        foreign = tmp_b / "foreign-backup.json"
        wrapper["fingerprint"] = "0123456789ABCDEF"
        foreign.write_text(json.dumps(wrapper))

        with pytest.raises(ProfileMismatchError) as excinfo:
            import_backup(vault_b, backup_b, foreign, parent_seed=SEED)
        assert "belongs to profile 0123456789ABCDEF" in str(excinfo.value)
        # Nothing was written.
        assert vault_b.load_index()["pw"] == 0

        # Still possible on purpose: the point is that it cannot happen by
        # accident, not that it is forbidden.
        import_backup(
            vault_b,
            backup_b,
            foreign,
            parent_seed=SEED,
            allow_fingerprint_mismatch=True,
        )
        assert vault_b.load_index()["pw"] == 1


def test_a_matching_fingerprint_imports_without_the_override():
    """The production shape: a profile directory named for its fingerprint."""
    with TemporaryDirectory() as td:
        # Named the way real profiles are, so the check actually engages
        # rather than being skipped for want of a well-formed fingerprint.
        tmp = Path(td) / generate_fingerprint(SEED)
        tmp.mkdir()
        vault, backup, _ = setup_vault(tmp)
        vault.save_index({"pw": 1})
        path = export_backup(vault, backup, parent_seed=SEED, encrypt=False)
        assert json.loads(path.read_text())["fingerprint"] == generate_fingerprint(SEED)
        vault.save_index({"pw": 0})
        import_backup(vault, backup, path, parent_seed=SEED)
        assert vault.load_index()["pw"] == 1


def test_the_same_seed_restores_into_a_differently_named_profile():
    """Restoring your own vault into a fresh profile must not be refused.

    The check asks "was this backup made from my seed?", not "does the
    directory have the same name?" -- so a legitimate recovery into a newly
    created profile directory goes through.
    """
    with TemporaryDirectory() as td_a, TemporaryDirectory() as td_b:
        src_dir = Path(td_a) / generate_fingerprint(SEED)
        src_dir.mkdir()
        vault_a, backup_a, _ = setup_vault(src_dir)
        vault_a.save_index({"pw": 1})
        path = export_backup(vault_a, backup_a, parent_seed=SEED, encrypt=False)

        dest_dir = Path(td_b) / "freshly-named-profile"
        dest_dir.mkdir()
        vault_b, backup_b, _ = setup_vault(dest_dir)
        vault_b.save_index({"pw": 0})

        import_backup(vault_b, backup_b, path, parent_seed=SEED)
        assert vault_b.load_index()["pw"] == 1


def test_a_backup_whose_fingerprint_is_not_a_fingerprint_is_not_refused():
    """No evidence about the source seed means no grounds to refuse.

    Refusing here would block restores without making anyone safer.
    """
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
        vault.save_index({"pw": 1})
        path = export_backup(vault, backup, parent_seed=SEED, encrypt=False)
        wrapper = json.loads(path.read_text())
        wrapper["fingerprint"] = "some-old-label"
        path.write_text(json.dumps(wrapper))

        vault.save_index({"pw": 0})
        import_backup(vault, backup, path, parent_seed=SEED)
        assert vault.load_index()["pw"] == 1


def test_import_warns_about_colliding_derivation_indices(capsys):
    """Imported data is one of the two ways an app-32 collision arrives."""
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault, backup, _ = setup_vault(tmp)
        vault.save_index(
            {
                "schema_version": 4,
                "entries": {
                    "3": {"kind": "ssh", "type": "ssh", "label": "deploy", "index": 3},
                    "4": {"kind": "pgp", "type": "pgp", "label": "sign", "index": 3},
                },
            }
        )
        path = export_backup(vault, backup, parent_seed=SEED, encrypt=False)
        capsys.readouterr()

        import_backup(vault, backup, path, parent_seed=SEED)
        out = capsys.readouterr().out
        assert "SAME private key" in out
