"""Tests for load_global_config failure scenarios."""

import logging
from pathlib import Path

import pytest

from main import load_global_config


def test_load_global_config_invalid_toml(monkeypatch, tmp_path, caplog):
    """Invalid TOML should log a warning and return an empty dict."""
    config_dir = tmp_path / ".seedpass"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    config_file.write_text("invalid = [")

    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    with caplog.at_level(logging.WARNING):
        result = load_global_config()

    assert result == {}
    assert "Failed to read" in caplog.text
