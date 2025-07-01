import sys
from pathlib import Path
import argparse
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main
from utils.key_derivation import EncryptionMode
from password_manager.manager import PasswordManager


def _get_mode(monkeypatch, args=None, cfg=None):
    if args is None:
        args = []
    if cfg is None:
        cfg = {}
    monkeypatch.setattr(main, "load_global_config", lambda: cfg)
    monkeypatch.setattr(sys, "argv", ["prog"] + args)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--encryption-mode",
        choices=[m.value for m in EncryptionMode],
        help="Select encryption mode",
    )
    parsed = parser.parse_args()
    mode_value = cfg.get("encryption_mode", EncryptionMode.SEED_ONLY.value)
    if parsed.encryption_mode:
        mode_value = parsed.encryption_mode
    return EncryptionMode(mode_value)


def test_default_mode_is_seed_only(monkeypatch):
    mode = _get_mode(monkeypatch)
    assert mode is EncryptionMode.SEED_ONLY


def test_cli_flag_overrides_config(monkeypatch):
    cfg = {"encryption_mode": EncryptionMode.PW_ONLY.value}
    mode = _get_mode(monkeypatch, ["--encryption-mode", "seed+pw"], cfg)
    assert mode is EncryptionMode.SEED_PLUS_PW


def test_pw_only_emits_warning(monkeypatch, capsys):
    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.fingerprint_manager = object()
    pm.setup_existing_seed = lambda: None
    pm.generate_new_seed = lambda: None
    inputs = iter(["3", "1"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
    pm.handle_new_seed_setup()
    out = capsys.readouterr().out
    assert "Password-only encryption is less secure" in out
    assert pm.encryption_mode is EncryptionMode.PW_ONLY
