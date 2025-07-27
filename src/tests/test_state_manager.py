from tempfile import TemporaryDirectory
from pathlib import Path

from seedpass.core.state_manager import StateManager
from nostr.client import DEFAULT_RELAYS


def test_state_manager_round_trip():
    with TemporaryDirectory() as tmpdir:
        sm = StateManager(Path(tmpdir))
        state = sm.state
        assert state["relays"] == list(DEFAULT_RELAYS)
        assert state["last_bip85_idx"] == 0
        assert state["last_sync_ts"] == 0
        assert state["manifest_id"] is None
        assert state["delta_since"] == 0

        sm.add_relay("wss://example.com")
        sm.update_state(
            last_bip85_idx=5,
            last_sync_ts=123,
            manifest_id="mid",
            delta_since=111,
        )

        sm2 = StateManager(Path(tmpdir))
        state2 = sm2.state
        assert "wss://example.com" in state2["relays"]
        assert state2["last_bip85_idx"] == 5
        assert state2["last_sync_ts"] == 123
        assert state2["manifest_id"] == "mid"
        assert state2["delta_since"] == 111

        sm2.remove_relay(1)  # remove first default relay
        assert len(sm2.list_relays()) == len(DEFAULT_RELAYS)
