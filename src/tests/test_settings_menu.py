import sys
import importlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main
from nostr.client import DEFAULT_RELAYS
from password_manager.encryption import EncryptionManager
from password_manager.config_manager import ConfigManager
from password_manager.vault import Vault
from utils.fingerprint_manager import FingerprintManager


def setup_pm(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    import constants

    importlib.reload(constants)
    importlib.reload(main)

    fp_dir = constants.APP_DIR / "fp"
    fp_dir.mkdir(parents=True)
    enc_mgr = EncryptionManager(Fernet.generate_key(), fp_dir)
    vault = Vault(enc_mgr, fp_dir)
    cfg_mgr = ConfigManager(vault, fp_dir)
    fp_mgr = FingerprintManager(constants.APP_DIR)

    nostr_stub = SimpleNamespace(
        relays=list(DEFAULT_RELAYS),
        close_client_pool=lambda: None,
        initialize_client_pool=lambda: None,
        publish_json_to_nostr=lambda data: None,
        key_manager=SimpleNamespace(get_npub=lambda: "npub"),
    )

    pm = SimpleNamespace(
        config_manager=cfg_mgr,
        fingerprint_manager=fp_mgr,
        nostr_client=nostr_stub,
    )
    return pm, cfg_mgr, fp_mgr


def test_relay_and_profile_actions(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm, cfg_mgr, fp_mgr = setup_pm(tmp_path, monkeypatch)

        # Add two fingerprints for listing
        fp1 = fp_mgr.add_fingerprint(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        fp2 = fp_mgr.add_fingerprint(
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        )

        # Add a relay
        with patch("builtins.input", return_value="wss://new"), patch(
            "main.handle_post_to_nostr"
        ), patch("main._reload_relays"):
            main.handle_add_relay(pm)
        cfg = cfg_mgr.load_config(require_pin=False)
        assert "wss://new" in cfg["relays"]

        # Remove the relay
        idx = cfg["relays"].index("wss://new") + 1
        with patch("builtins.input", return_value=str(idx)), patch(
            "main._reload_relays"
        ):
            main.handle_remove_relay(pm)
        cfg = cfg_mgr.load_config(require_pin=False)
        assert "wss://new" not in cfg["relays"]

        # Reset to defaults
        with patch("main._reload_relays"):
            main.handle_reset_relays(pm)
        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["relays"] == list(DEFAULT_RELAYS)

        # List profiles
        main.handle_list_fingerprints(pm)
        out = capsys.readouterr().out
        assert fp1 in out
        assert fp2 in out
