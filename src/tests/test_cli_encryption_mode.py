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
