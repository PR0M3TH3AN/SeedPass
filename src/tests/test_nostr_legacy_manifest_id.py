import asyncio

from helpers import TEST_SEED, dummy_nostr_client
from nostr.backup_models import KIND_MANIFEST
from nostr.client import MANIFEST_ID_PREFIX, NostrClient


def test_fetch_latest_snapshot_legacy_identifier(dummy_nostr_client, monkeypatch):
    client, relay = dummy_nostr_client
    data = b"legacy"
    asyncio.run(client.publish_snapshot(data))
    relay.manifests[-1].tags = [MANIFEST_ID_PREFIX.rstrip("-")]
    relay.filters.clear()

    orig_fetch = relay.fetch_events

    async def fetch_events(self, f, timeout):
        identifier = f.ids[0] if getattr(f, "ids", None) else None
        kind = getattr(f, "kind_val", None)
        if kind == KIND_MANIFEST:
            events = [m for m in self.manifests if identifier in m.tags]
            self.filters.append(f)

            class Res:
                def __init__(self, evs):
                    self._evs = evs

                def to_vec(self):
                    return self._evs

            return Res(events)
        return await orig_fetch(f, timeout)

    monkeypatch.setattr(
        relay, "fetch_events", fetch_events.__get__(relay, relay.__class__)
    )

    enc_mgr = client.encryption_manager
    monkeypatch.setattr(
        enc_mgr, "decrypt_parent_seed", lambda: TEST_SEED, raising=False
    )
    monkeypatch.setattr("nostr.client.KeyManager", type(client.key_manager))
    client2 = NostrClient(enc_mgr, "fp")
    relay.filters.clear()
    result = asyncio.run(client2.fetch_latest_snapshot())
    assert result is not None
    ids = [f.ids[0] for f in relay.filters]
    assert ids[0] == f"{MANIFEST_ID_PREFIX}fp"
    assert MANIFEST_ID_PREFIX.rstrip("-") in ids
