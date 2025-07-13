import pytest
from types import SimpleNamespace
from typer.testing import CliRunner

from seedpass.cli import app
from seedpass import cli

runner = CliRunner()


@pytest.mark.parametrize(
    "key,value,method,expected",
    [
        ("secret_mode_enabled", "true", "set_secret_mode_enabled", True),
        ("clipboard_clear_delay", "10", "set_clipboard_clear_delay", 10),
        ("additional_backup_path", "", "set_additional_backup_path", None),
        ("backup_interval", "5", "set_backup_interval", 5.0),
        ("kdf_iterations", "123", "set_kdf_iterations", 123),
        (
            "relays",
            "wss://a.com, wss://b.com",
            "set_relays",
            ["wss://a.com", "wss://b.com"],
        ),
    ],
)
def test_config_set_variants(monkeypatch, key, value, method, expected):
    called = {}

    def func(val, **kwargs):
        called["val"] = val
        called.update(kwargs)

    pm = SimpleNamespace(
        config_manager=SimpleNamespace(**{method: func}),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)

    result = runner.invoke(app, ["config", "set", key, value])

    assert result.exit_code == 0
    assert "Updated" in result.stdout
    assert called.get("val") == expected
    if key == "relays":
        assert called.get("require_pin") is False
