import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main
from password_manager.entry_types import EntryType


def make_pm(search_results, entry=None, totp_code="123456"):
    entry_mgr = SimpleNamespace(
        search_entries=lambda q: search_results,
        retrieve_entry=lambda idx: entry,
        get_totp_code=lambda idx, seed: totp_code,
    )
    pg = SimpleNamespace(generate_password=lambda l, i: "pw")
    pm = SimpleNamespace(
        entry_manager=entry_mgr,
        password_generator=pg,
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
        parent_seed="seed",
        inactivity_timeout=1,
        clipboard_clear_delay=45,
    )
    return pm


def test_search_command(monkeypatch, capsys):
    pm = make_pm([(0, "Example", "user", "", False)])
    monkeypatch.setattr(main, "PasswordManager", lambda: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)
    rc = main.main(["search", "ex"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Example" in out


def test_get_command(monkeypatch, capsys):
    entry = {"type": EntryType.PASSWORD.value, "length": 8}
    pm = make_pm([(0, "Example", "user", "", False)], entry=entry)
    monkeypatch.setattr(main, "PasswordManager", lambda: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)
    rc = main.main(["get", "ex"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pw" in out


def test_totp_command(monkeypatch, capsys):
    entry = {"type": EntryType.TOTP.value, "period": 30, "index": 0}
    pm = make_pm([(0, "Example", None, None, False)], entry=entry)
    called = {}
    monkeypatch.setattr(main, "PasswordManager", lambda: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)
    monkeypatch.setattr(
        main, "copy_to_clipboard", lambda v, d: called.setdefault("val", v)
    )
    rc = main.main(["totp", "ex"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "123456" in out
    assert "copied to clipboard" in out.lower()
    assert called.get("val") == "123456"


def test_search_command_no_results(monkeypatch, capsys):
    pm = make_pm([])
    monkeypatch.setattr(main, "PasswordManager", lambda: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)
    rc = main.main(["search", "none"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "No matching entries found" in out


def test_get_command_multiple_matches(monkeypatch, capsys):
    matches = [(0, "Example", "user", "", False), (1, "Ex2", "bob", "", False)]
    pm = make_pm(matches)
    monkeypatch.setattr(main, "PasswordManager", lambda: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)
    rc = main.main(["get", "ex"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "Matches" in out


def test_get_command_wrong_type(monkeypatch, capsys):
    entry = {"type": EntryType.TOTP.value}
    pm = make_pm([(0, "Example", "user", "", False)], entry=entry)
    monkeypatch.setattr(main, "PasswordManager", lambda: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)
    rc = main.main(["get", "ex"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "Entry is not a password entry" in out


def test_totp_command_multiple_matches(monkeypatch, capsys):
    matches = [(0, "GH", None, None, False), (1, "Git", None, None, False)]
    pm = make_pm(matches)
    monkeypatch.setattr(main, "PasswordManager", lambda: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)
    rc = main.main(["totp", "g"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "Matches" in out


def test_totp_command_wrong_type(monkeypatch, capsys):
    entry = {"type": EntryType.PASSWORD.value, "length": 8}
    pm = make_pm([(0, "Example", "user", "", False)], entry=entry)
    monkeypatch.setattr(main, "PasswordManager", lambda: pm)
    monkeypatch.setattr(main, "configure_logging", lambda: None)
    monkeypatch.setattr(main, "initialize_app", lambda: None)
    monkeypatch.setattr(main.signal, "signal", lambda *a, **k: None)
    rc = main.main(["totp", "ex"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "Entry is not a TOTP entry" in out
