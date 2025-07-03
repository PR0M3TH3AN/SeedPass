import logging

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from nostr import event_handler


class SimpleEvent:
    def __init__(self, id: str, created_at: int, content: str) -> None:
        self.id = id
        self.created_at = created_at
        self.content = content


def test_handle_new_event_logs(caplog):
    handler = event_handler.EventHandler()
    evt = SimpleEvent("1", 0, "hello")

    caplog.set_level(logging.INFO, logger=event_handler.logger.name)
    handler.handle_new_event(evt)

    assert (
        "[New Event] ID: 1 | Created At: 1970-01-01 00:00:00 | Content: hello"
        in caplog.text
    )


def test_handle_new_event_error(monkeypatch, caplog):
    handler = event_handler.EventHandler()
    evt = SimpleEvent("2", 0, "boom")

    def raise_info(*args, **kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr(event_handler.logger, "info", raise_info)
    caplog.set_level(logging.ERROR, logger=event_handler.logger.name)

    handler.handle_new_event(evt)

    assert "Error handling new event: fail" in caplog.text
