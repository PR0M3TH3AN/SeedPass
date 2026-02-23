import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.append(str(Path(__file__).resolve().parents[1]))


class FakePasswordGenerator:
    def generate_password(self, length: int, index: int) -> str:  # noqa: D401
        return "pw"


def test_edit_tags_from_retrieve(monkeypatch, password_manager):
    pm = password_manager
    pm.password_generator = FakePasswordGenerator()
    pm.nostr_client = SimpleNamespace()

    index = pm.entry_manager.add_entry("example.com", 8, tags=["old"])

    inputs = iter([str(index), "t", "newtag", ""])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))

    pm.handle_retrieve_entry()

    entry = pm.entry_manager.retrieve_entry(index)
    assert entry.get("tags", []) == ["newtag"]
