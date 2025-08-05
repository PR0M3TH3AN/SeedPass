import json
from types import SimpleNamespace
from typer.testing import CliRunner

from seedpass.cli import app
from seedpass.cli import common as cli_common

runner = CliRunner()


def test_vault_stats_command(monkeypatch):
    stats = {
        "total_entries": 2,
        "entries": {"password": 1, "totp": 1},
    }
    pm = SimpleNamespace(
        get_profile_stats=lambda: stats, select_fingerprint=lambda fp: None
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["vault", "stats"])
    assert result.exit_code == 0
    out = result.stdout
    # Output should be pretty JSON with the expected values
    data = json.loads(out)
    assert data == stats
