from types import SimpleNamespace
from typer.testing import CliRunner

from seedpass.cli import app
from seedpass.cli import common as cli_common

runner = CliRunner()


def _make_pm(called, enabled=True):
    cfg = SimpleNamespace(
        get_offline_mode=lambda: enabled,
        set_offline_mode=lambda v: called.setdefault("enabled", v),
    )
    pm = SimpleNamespace(
        config_manager=cfg,
        offline_mode=enabled,
        select_fingerprint=lambda fp: None,
    )
    return pm


def test_toggle_offline_updates(monkeypatch):
    called = {}
    pm = _make_pm(called)
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["config", "toggle-offline"], input="n\n")
    assert result.exit_code == 0
    assert called == {"enabled": False}
    assert "Offline mode disabled." in result.stdout


def test_toggle_offline_keep(monkeypatch):
    called = {}
    pm = _make_pm(called, enabled=True)
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["config", "toggle-offline"], input="\n")
    assert result.exit_code == 0
    assert called == {"enabled": True}
    assert "Offline mode enabled." in result.stdout
