import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.append(str(Path(__file__).resolve().parents[1]))


def test_retrieve_entry_shows_custom_fields(monkeypatch, capsys, password_manager):
    pm = password_manager
    pm.password_generator = SimpleNamespace(generate_password=lambda l, i: "pw")
    pm.nostr_client = SimpleNamespace()

    pm.entry_manager.add_entry(
        "example",
        8,
        custom_fields=[
            {"label": "visible", "value": "shown", "is_hidden": False},
            {"label": "token", "value": "secret", "is_hidden": True},
        ],
    )

    inputs = iter(["0", "y", "", ""])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))

    pm.handle_retrieve_entry()
    out = capsys.readouterr().out
    assert "Additional Fields:" in out
    assert "visible: shown" in out
    assert "token" in out
    assert "secret" in out
