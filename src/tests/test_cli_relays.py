from types import SimpleNamespace
from typer.testing import CliRunner

from seedpass.cli import app
from seedpass.cli import common as cli_common


class DummyService:
    def __init__(self, relays):
        self.relays = relays

    def get_pubkey(self):
        return "npub"

    def list_relays(self):
        return self.relays

    def add_relay(self, url):
        if url in self.relays:
            raise ValueError("exists")
        self.relays.append(url)

    def remove_relay(self, idx):
        if not 1 <= idx <= len(self.relays):
            raise ValueError("bad")
        if len(self.relays) == 1:
            raise ValueError("min")
        self.relays.pop(idx - 1)


runner = CliRunner()


def test_cli_relay_crud(monkeypatch):
    relays = ["wss://a"]

    def pm_factory(*a, **k):
        return SimpleNamespace()

    monkeypatch.setattr(cli_common, "PasswordManager", pm_factory)
    monkeypatch.setattr(cli_common, "NostrService", lambda pm: DummyService(relays))

    result = runner.invoke(app, ["nostr", "list-relays"])
    assert "1: wss://a" in result.stdout

    result = runner.invoke(app, ["nostr", "add-relay", "wss://b"])
    assert result.exit_code == 0
    assert "Added" in result.stdout
    assert relays == ["wss://a", "wss://b"]

    result = runner.invoke(app, ["nostr", "remove-relay", "1"])
    assert result.exit_code == 0
    assert relays == ["wss://b"]
