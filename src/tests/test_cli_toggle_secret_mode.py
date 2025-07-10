import types
from types import SimpleNamespace
from typer.testing import CliRunner

from seedpass.cli import app
from seedpass import cli

runner = CliRunner()


def _make_pm(called, enabled=False, delay=45):
    cfg = SimpleNamespace(
        get_secret_mode_enabled=lambda: enabled,
        get_clipboard_clear_delay=lambda: delay,
        set_secret_mode_enabled=lambda v: called.setdefault("enabled", v),
        set_clipboard_clear_delay=lambda v: called.setdefault("delay", v),
    )
    pm = SimpleNamespace(
        config_manager=cfg,
        secret_mode_enabled=enabled,
        clipboard_clear_delay=delay,
        select_fingerprint=lambda fp: None,
    )
    return pm


def test_toggle_secret_mode_updates(monkeypatch):
    called = {}
    pm = _make_pm(called)
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["config", "toggle-secret-mode"], input="y\n10\n")
    assert result.exit_code == 0
    assert called == {"enabled": True, "delay": 10}
    assert "Secret mode enabled." in result.stdout


def test_toggle_secret_mode_keep(monkeypatch):
    called = {}
    pm = _make_pm(called, enabled=True, delay=30)
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["config", "toggle-secret-mode"], input="\n\n")
    assert result.exit_code == 0
    assert called == {"enabled": True, "delay": 30}
    assert "Secret mode enabled." in result.stdout
