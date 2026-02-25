import sys
from pathlib import Path

from helpers import TEST_SEED

sys.path.append(str(Path(__file__).resolve().parents[1]))

import pytest


@pytest.mark.parametrize(
    "adder,needs_confirm",
    [
        (lambda mgr: mgr.add_seed("seed", TEST_SEED), True),
        (lambda mgr: mgr.add_pgp_key("pgp", TEST_SEED, user_id="test"), True),
        (lambda mgr: mgr.add_ssh_key("ssh", TEST_SEED), True),
        (lambda mgr: mgr.add_nostr_key("nostr", TEST_SEED), False),
    ],
)
def test_pause_before_entry_actions(
    monkeypatch, adder, needs_confirm, password_manager
):
    pm = password_manager

    index = adder(pm.entry_manager)

    pause_calls = []
    monkeypatch.setattr(
        "seedpass.core.manager.pause", lambda *a, **k: pause_calls.append(True)
    )
    monkeypatch.setattr(pm, "_entry_actions_menu", lambda *a, **k: None)
    monkeypatch.setattr("builtins.input", lambda *a, **k: str(index))
    if needs_confirm:
        monkeypatch.setattr(
            "seedpass.core.manager.confirm_action", lambda *a, **k: True
        )

    pm.handle_retrieve_entry()
    assert len(pause_calls) == 1
