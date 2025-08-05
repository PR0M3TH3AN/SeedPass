import logging
from types import SimpleNamespace

from seedpass import api


def test_reload_relays_logs_errors(caplog):
    def close():
        raise RuntimeError("close fail")

    def init():
        raise OSError("init fail")

    pm = SimpleNamespace(
        nostr_client=SimpleNamespace(
            close_client_pool=close,
            initialize_client_pool=init,
            relays=[],
        )
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pm=pm)))

    with caplog.at_level(logging.WARNING):
        api._reload_relays(request, ["ws://relay"])

    assert "Failed to close NostrClient pool" in caplog.text
    assert "close fail" in caplog.text
    assert "Failed to initialize NostrClient with relays" in caplog.text
    assert "init fail" in caplog.text
