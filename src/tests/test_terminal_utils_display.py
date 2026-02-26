import queue
from types import SimpleNamespace

from utils import terminal_utils


class _NamedFingerprintManager:
    def get_name(self, fingerprint):
        return {"parent": "Parent Name", "child": "Child Name"}.get(fingerprint)


def test_format_profile_returns_custom_name():
    pm = SimpleNamespace(fingerprint_manager=_NamedFingerprintManager())
    assert terminal_utils.format_profile("parent", pm) == "Parent Name (parent)"


def test_format_profile_returns_raw_when_name_missing():
    pm = SimpleNamespace(fingerprint_manager=_NamedFingerprintManager())
    assert terminal_utils.format_profile("unknown", pm) == "unknown"


def test_clear_and_print_fingerprint_parent_child_breadcrumb(monkeypatch, capsys):
    pm = SimpleNamespace(fingerprint_manager=_NamedFingerprintManager())
    monkeypatch.setattr(terminal_utils, "clear_screen", lambda: None)
    monkeypatch.setattr(terminal_utils, "colored", lambda text, _color: text)

    terminal_utils.clear_and_print_fingerprint(
        parent_fingerprint="parent",
        child_fingerprint="child",
        breadcrumb="Settings",
        pm=pm,
    )

    out = capsys.readouterr().out
    assert (
        "Seed Profile: Parent Name (parent) > Managed Account > Child Name (child)"
        in out
    )
    assert "> Settings" in out


def test_clear_and_print_profile_chain_with_breadcrumb(monkeypatch, capsys):
    pm = SimpleNamespace(fingerprint_manager=_NamedFingerprintManager())
    monkeypatch.setattr(terminal_utils, "clear_screen", lambda: None)
    monkeypatch.setattr(terminal_utils, "colored", lambda text, _color: text)

    terminal_utils.clear_and_print_profile_chain(
        ["parent", "child"], breadcrumb="Retrieve Entry", pm=pm
    )

    out = capsys.readouterr().out
    assert (
        "Seed Profile: Parent Name (parent) > Managed Account > Child Name (child)"
        in out
    )
    assert "> Retrieve Entry" in out


def test_clear_header_with_notification_invalid_level_falls_back_to_info(
    monkeypatch, capsys
):
    pm = SimpleNamespace(
        fingerprint_manager=_NamedFingerprintManager(),
        get_current_notification=lambda: SimpleNamespace(
            level="DEBUG", message="sync complete"
        ),
    )
    monkeypatch.setattr(terminal_utils, "clear_screen", lambda: None)
    monkeypatch.setattr(terminal_utils, "colored", lambda text, _color: text)
    monkeypatch.setattr(
        terminal_utils,
        "color_text",
        lambda message, category: f"[{category}] {message}",
    )

    terminal_utils.clear_header_with_notification(pm, fingerprint="parent")

    out = capsys.readouterr().out
    assert "Seed Profile: Parent Name (parent)" in out
    assert "[info] sync complete" in out


def test_clear_header_with_notification_handles_queue_empty(monkeypatch, capsys):
    pm = SimpleNamespace(
        fingerprint_manager=_NamedFingerprintManager(),
        get_current_notification=lambda: (_ for _ in ()).throw(queue.Empty()),
    )
    monkeypatch.setattr(terminal_utils, "clear_screen", lambda: None)
    monkeypatch.setattr(terminal_utils, "colored", lambda text, _color: text)

    terminal_utils.clear_header_with_notification(pm, fingerprint="parent")

    out = capsys.readouterr().out
    assert "Seed Profile: Parent Name (parent)" in out


def test_pause_returns_early_when_not_tty(monkeypatch):
    monkeypatch.setattr(
        terminal_utils.sys,
        "stdin",
        SimpleNamespace(isatty=lambda: False),
    )
    called = {"input": False}
    monkeypatch.setattr(
        "builtins.input",
        lambda _msg: called.__setitem__("input", True),
    )

    terminal_utils.pause("ignored")
    assert called["input"] is False


def test_pause_swallows_eoferror(monkeypatch):
    monkeypatch.setattr(
        terminal_utils.sys,
        "stdin",
        SimpleNamespace(isatty=lambda: True),
    )
    monkeypatch.setattr(
        "builtins.input",
        lambda _msg: (_ for _ in ()).throw(EOFError()),
    )
    terminal_utils.pause("Press Enter")
