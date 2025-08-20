import asyncio

from helpers import dummy_nostr_client


def test_published_events_no_fingerprint(dummy_nostr_client):
    client, relay = dummy_nostr_client
    asyncio.run(client.publish_snapshot(b"secret"))
    fingerprint = "fp"
    events = list(relay.manifests) + list(relay.chunks.values())
    seen = set()
    for ev in events:
        if id(ev) in seen:
            continue
        seen.add(id(ev))
        assert fingerprint not in ev.id
        for tag in getattr(ev, "tags", []):
            assert fingerprint not in tag
