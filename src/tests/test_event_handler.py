import logging
import time

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from nostr import event_handler
from nostr_sdk import EventBuilder, Keys


def test_handle_new_event_logs(caplog):
    handler = event_handler.EventHandler()
    keys = Keys.generate()
    evt = EventBuilder.text_note("hello").sign_with_keys(keys)

    caplog.set_level(logging.INFO, logger=event_handler.logger.name)
    handler.handle_new_event(evt)

    event_id = evt.id().to_hex()
    created_at = evt.created_at().as_secs()
    created_at_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(created_at))

    assert (
        f"[New Event] ID: {event_id} | Created At: {created_at_str} | Content: hello"
        in caplog.text
    )


def test_handle_new_event_error(monkeypatch, caplog):
    handler = event_handler.EventHandler()
    keys = Keys.generate()
    evt = EventBuilder.text_note("boom").sign_with_keys(keys)

    def raise_info(*args, **kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr(event_handler.logger, "info", raise_info)
    caplog.set_level(logging.ERROR, logger=event_handler.logger.name)

    handler.handle_new_event(evt)

    assert "Error handling new event: fail" in caplog.text
