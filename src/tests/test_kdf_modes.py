import bcrypt
import hashlib
import base64
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import pytest

from utils.key_derivation import (
    derive_key_from_password,
    derive_key_from_password_argon2,
    derive_index_key,
    KdfConfig,
)
from seedpass.core.encryption import EncryptionManager
from seedpass.core.vault import Vault
from seedpass.core.config_manager import ConfigManager
from seedpass.core.manager import PasswordManager, EncryptionMode
from seedpass.core.errors import DecryptionError
from seedpass.core.encryption import LegacyFormatRequiresMigrationError

TEST_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
TEST_PASSWORD = "pw"


def _setup_profile(tmp: Path, mode: str):
    argon_kwargs = dict(time_cost=1, memory_cost=8, parallelism=1)
    fp = tmp.name
    if mode == "argon2":
        cfg = KdfConfig(
            params=argon_kwargs,
            salt_b64=base64.b64encode(
                hashlib.sha256(fp.encode()).digest()[:16]
            ).decode(),
        )
        seed_key = derive_key_from_password_argon2(TEST_PASSWORD, cfg)
        EncryptionManager(seed_key, tmp).encrypt_parent_seed(TEST_SEED, kdf=cfg)
    else:
        seed_key = derive_key_from_password(TEST_PASSWORD, fp, iterations=1)
        cfg = KdfConfig(
            name="pbkdf2",
            params={"iterations": 1},
            salt_b64=base64.b64encode(
                hashlib.sha256(fp.encode()).digest()[:16]
            ).decode(),
        )
        EncryptionManager(seed_key, tmp).encrypt_parent_seed(TEST_SEED, kdf=cfg)

    index_key = derive_index_key(TEST_SEED)
    enc_mgr = EncryptionManager(index_key, tmp)
    vault = Vault(enc_mgr, tmp)
    cfg_mgr = ConfigManager(vault, tmp)
    cfg = cfg_mgr.load_config(require_pin=False)
    cfg["password_hash"] = bcrypt.hashpw(
        TEST_PASSWORD.encode(), bcrypt.gensalt()
    ).decode()
    cfg["kdf_mode"] = mode
    cfg["kdf_iterations"] = 1
    cfg_mgr.save_config(cfg)
    return cfg_mgr


def _make_pm(tmp: Path, cfg: ConfigManager):
    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.config_manager = cfg
    pm.fingerprint_dir = tmp
    pm.current_fingerprint = tmp.name
    pm.verify_password = lambda pw: True
    return pm


def test_setup_encryption_manager_kdf_modes(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        argon_kwargs = dict(time_cost=1, memory_cost=8, parallelism=1)
        for mode in ("pbkdf2", "argon2"):
            path = tmp / mode
            path.mkdir()
            cfg = _setup_profile(path, mode)
            pm = _make_pm(path, cfg)
            monkeypatch.setattr(
                "seedpass.core.manager.prompt_existing_password",
                lambda *_: TEST_PASSWORD,
            )
            if mode == "argon2":
                monkeypatch.setattr(
                    "seedpass.core.manager.KdfConfig",
                    lambda salt_b64, **_: KdfConfig(
                        params=argon_kwargs, salt_b64=salt_b64
                    ),
                )
            monkeypatch.setattr(PasswordManager, "initialize_bip85", lambda self: None)
            monkeypatch.setattr(
                PasswordManager, "initialize_managers", lambda self: None
            )
            assert pm.setup_encryption_manager(path, exit_on_fail=False)
            assert pm.parent_seed == TEST_SEED


def test_kdf_param_round_trip(tmp_path):
    cfg = KdfConfig(
        params={"time_cost": 3, "memory_cost": 32, "parallelism": 1},
        salt_b64=base64.b64encode(b"static-salt-1234").decode(),
    )
    key = derive_key_from_password_argon2(TEST_PASSWORD, cfg)
    mgr = EncryptionManager(key, tmp_path)
    mgr.encrypt_parent_seed(TEST_SEED, kdf=cfg)
    stored = mgr.get_file_kdf(Path("parent_seed.enc"))
    assert stored.params == cfg.params


def test_vault_kdf_migration(tmp_path):
    index_key = derive_index_key(TEST_SEED)
    mgr = EncryptionManager(index_key, tmp_path)
    vault = Vault(mgr, tmp_path)
    old_kdf = KdfConfig(name="hkdf", version=0, params={}, salt_b64="")
    mgr.save_json_data({"entries": {}}, vault.index_file, kdf=old_kdf)
    vault.load_index()
    new_kdf = mgr.get_file_kdf(vault.index_file)
    assert new_kdf.version == KdfConfig().version


def test_derive_seed_key_argon2_uses_configured_time_cost(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.config_manager = SimpleNamespace(
        get_kdf_mode=lambda: "argon2",
        get_argon2_time_cost=lambda: 5,
        get_kdf_iterations=lambda: 50_000,
    )

    captured = {}

    def fake_argon2(password, cfg):
        captured["password"] = password
        captured["cfg"] = cfg
        return b"derived-argon2-key"

    monkeypatch.setattr(
        "seedpass.core.manager.derive_key_from_password_argon2", fake_argon2
    )
    key = pm._derive_seed_key("pw", "fingerprint123")

    assert key == b"derived-argon2-key"
    assert captured["password"] == "pw"
    assert captured["cfg"].params["time_cost"] == 5
    assert captured["cfg"].params["memory_cost"] == 64 * 1024
    assert captured["cfg"].params["parallelism"] == 8
    expected_salt = hashlib.sha256("fingerprint123".encode()).digest()[:16]
    assert base64.b64decode(captured["cfg"].salt_b64) == expected_salt


def test_derive_seed_key_pbkdf2_respects_iteration_override(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.config_manager = SimpleNamespace(
        get_kdf_mode=lambda: "pbkdf2",
        get_argon2_time_cost=lambda: 2,
        get_kdf_iterations=lambda: 777,
    )

    captured = {}

    def fake_pbkdf2(password, fingerprint, iterations):
        captured["password"] = password
        captured["fingerprint"] = fingerprint
        captured["iterations"] = iterations
        return b"derived-pbkdf2-key"

    monkeypatch.setattr("seedpass.core.manager.derive_key_from_password", fake_pbkdf2)
    key = pm._derive_seed_key("pw", "fp", iterations=123)

    assert key == b"derived-pbkdf2-key"
    assert captured == {"password": "pw", "fingerprint": "fp", "iterations": 123}


def test_derive_seed_key_pbkdf2_enforces_policy_floor(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.config_manager = SimpleNamespace(
        get_kdf_mode=lambda: "pbkdf2",
        get_argon2_time_cost=lambda: 2,
        get_kdf_iterations=lambda: 1,
    )

    captured = {}

    def fake_pbkdf2(password, fingerprint, iterations):
        captured["password"] = password
        captured["fingerprint"] = fingerprint
        captured["iterations"] = iterations
        return b"derived-pbkdf2-key"

    monkeypatch.setattr("seedpass.core.manager.derive_key_from_password", fake_pbkdf2)
    key = pm._derive_seed_key("pw", "fp")

    assert key == b"derived-pbkdf2-key"
    assert captured["iterations"] == ConfigManager.DEFAULT_PBKDF2_ITERATIONS


def test_tampered_kdf_wrapper_payload_is_rejected(tmp_path):
    fp = "profile123"
    cfg = KdfConfig(
        name="pbkdf2",
        params={"iterations": 123_456},
        salt_b64=base64.b64encode(hashlib.sha256(fp.encode()).digest()[:16]).decode(),
    )
    key = derive_key_from_password(TEST_PASSWORD, fp, iterations=123_456)
    mgr = EncryptionManager(key, tmp_path)
    mgr.encrypt_parent_seed(TEST_SEED, kdf=cfg)

    seed_file = tmp_path / "parent_seed.enc"
    wrapper = json.loads(seed_file.read_text())
    wrapper["ct"] = "!!!not-valid-base64!!!"
    seed_file.write_text(json.dumps(wrapper))

    wrong_mgr = EncryptionManager(key, tmp_path)
    with pytest.raises((DecryptionError, LegacyFormatRequiresMigrationError)):
        wrong_mgr.decrypt_parent_seed()


def test_setup_encryption_manager_rejects_wrong_argon2_params(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        fp = tmp.name
        cfg = KdfConfig(
            params={
                "time_cost": 1,
                "memory_cost": 64 * 1024,
                "parallelism": 8,
            },
            salt_b64=base64.b64encode(
                hashlib.sha256(fp.encode()).digest()[:16]
            ).decode(),
        )
        seed_key = derive_key_from_password_argon2(TEST_PASSWORD, cfg)
        EncryptionManager(seed_key, tmp).encrypt_parent_seed(TEST_SEED, kdf=cfg)

        index_key = derive_index_key(TEST_SEED)
        enc_mgr = EncryptionManager(index_key, tmp)
        vault = Vault(enc_mgr, tmp)
        cfg_mgr = ConfigManager(vault, tmp)
        profile_cfg = cfg_mgr.load_config(require_pin=False)
        profile_cfg["password_hash"] = bcrypt.hashpw(
            TEST_PASSWORD.encode(), bcrypt.gensalt()
        ).decode()
        profile_cfg["kdf_mode"] = "argon2"
        profile_cfg["argon2_time_cost"] = 2
        cfg_mgr.save_config(profile_cfg)

        pm = _make_pm(tmp, cfg_mgr)
        monkeypatch.setattr(
            "seedpass.core.manager.prompt_existing_password",
            lambda *_: TEST_PASSWORD,
        )
        monkeypatch.setattr(PasswordManager, "initialize_bip85", lambda self: None)
        monkeypatch.setattr(PasswordManager, "initialize_managers", lambda self: None)

        assert not pm.setup_encryption_manager(tmp, exit_on_fail=False)
