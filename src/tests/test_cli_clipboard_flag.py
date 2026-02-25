from typer.testing import CliRunner

from seedpass.cli import app, entry as cli_entry
from seedpass.core.entry_types import EntryType
from utils.clipboard import ClipboardUnavailableError

runner = CliRunner()


def _stub_service(ctx, raise_error=True):
    class Service:
        def search_entries(self, query, kinds=None):
            return [(1, "label", None, None, False, EntryType.PASSWORD)]

        def retrieve_entry(self, idx):
            return {"type": EntryType.PASSWORD.value, "length": 12}

        def generate_password(self, length, index):
            if raise_error and not ctx.obj.get("no_clipboard"):
                raise ClipboardUnavailableError("missing")
            return "pwd"

    return Service()


def test_entry_get_handles_missing_clipboard(monkeypatch):
    monkeypatch.setattr(
        cli_entry, "_get_entry_service", lambda ctx: _stub_service(ctx, True)
    )
    result = runner.invoke(app, ["entry", "get", "label"], catch_exceptions=False)
    assert result.exit_code == 1
    assert "no-clipboard" in result.stderr.lower()


def test_entry_get_no_clipboard_flag(monkeypatch):
    monkeypatch.setattr(
        cli_entry, "_get_entry_service", lambda ctx: _stub_service(ctx, True)
    )
    result = runner.invoke(
        app, ["--no-clipboard", "entry", "get", "label"], catch_exceptions=False
    )
    assert result.exit_code == 0
    assert "pwd" in result.stdout
