import sys
import time
import json
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.vault import Vault
from password_manager.encryption import EncryptionManager
from utils.key_derivation import (
    derive_index_key,
    derive_key_from_password,
)

TEST_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
TEST_PASSWORD = "pw"


def create_vault(
    dir_path: Path,
    seed: str = TEST_SEED,
    password: str = TEST_PASSWORD,
) -> tuple[Vault, EncryptionManager]:
    """Create a Vault initialized for tests."""
    seed_key = derive_key_from_password(password)
    seed_mgr = EncryptionManager(seed_key, dir_path)
    seed_mgr.encrypt_parent_seed(seed)

    index_key = derive_index_key(seed)
    enc_mgr = EncryptionManager(index_key, dir_path)
    vault = Vault(enc_mgr, dir_path)
    return vault, enc_mgr


import uuid
import asyncio
import pytest

from nostr.backup_models import (
    KIND_MANIFEST,
    KIND_SNAPSHOT_CHUNK,
    KIND_DELTA,
)


class DummyEvent:
    def __init__(self, kind: int, content: str, tags=None, event_id: str | None = None):
        self.kind = kind
        self._content = content
        self.tags = tags or []
        self.id = event_id or f"evt-{uuid.uuid4().hex}"

    def content(self):
        return self._content


class DummyUnsignedEvent:
    def __init__(self, kind: int, content: str, tags: list[str]):
        self.kind = kind
        self.content = content
        self.tags = tags

    def sign_with_keys(self, _keys):
        return DummyEvent(self.kind, self.content, self.tags)


class DummyBuilder:
    def __init__(self, kind=None, content=""):
        if hasattr(kind, "as_u16"):
            self.kind = kind.as_u16()
        elif hasattr(kind, "value"):
            self.kind = kind.value
        else:
            self.kind = int(kind)
        self.content = content
        self._tags: list[str] = []

    def tags(self, tags):
        # store raw tag values
        self._tags.extend(tags)
        return self

    def build(self, _pk):
        return DummyUnsignedEvent(self.kind, self.content, self._tags)


class DummyTag:
    @staticmethod
    def identifier(value):
        return value

    @staticmethod
    def event(value):
        return value

    @staticmethod
    def alt(value):
        return value

    @staticmethod
    def expiration(value):
        return value


class DummyFilter:
    def __init__(self):
        self.kind_val: int | None = None
        self.ids: list[str] = []
        self.limit_val: int | None = None
        self.since_val: int | None = None

    def author(self, _pk):
        return self

    def kind(self, kind):
        if hasattr(kind, "as_u16"):
            self.kind_val = kind.as_u16()
        elif hasattr(kind, "value"):
            self.kind_val = kind.value
        else:
            self.kind_val = int(kind)
        return self

    def identifier(self, ident: str):
        self.ids.append(ident)
        return self

    def limit(self, val: int):
        self.limit_val = val
        return self

    def since(self, ts):
        self.since_val = getattr(ts, "secs", ts)
        return self


class DummyTimestamp:
    def __init__(self, secs: int):
        self.secs = secs

    @staticmethod
    def from_secs(secs: int) -> "DummyTimestamp":
        return DummyTimestamp(secs)


class DummyEventId:
    def __init__(self, val: str):
        self.val = val

    def to_hex(self) -> str:
        return self.val

    @staticmethod
    def parse(val: str) -> str:
        return val


class DummySendResult:
    def __init__(self, event_id: str):
        self.id = DummyEventId(event_id)


class DummyRelayClient:
    def __init__(self):
        self.counter = 0
        self.manifests: list[DummyEvent] = []
        self.chunks: dict[str, DummyEvent] = {}
        self.deltas: list[DummyEvent] = []

    async def add_relays(self, _relays):
        pass

    async def add_relay(self, _relay):
        pass

    async def connect(self):
        pass

    async def disconnect(self):
        pass

    async def send_event(self, event):
        self.counter += 1
        eid = str(self.counter)
        if isinstance(event, DummyEvent):
            event.id = eid
        if event.kind == KIND_MANIFEST:
            try:
                data = json.loads(event.content())
                event.delta_since = data.get("delta_since")
            except Exception:
                event.delta_since = None
            self.manifests.append(event)
        elif event.kind == KIND_SNAPSHOT_CHUNK:
            ident = event.tags[0] if event.tags else str(self.counter)
            self.chunks[ident] = event
        elif event.kind == KIND_DELTA:
            if not hasattr(event, "created_at"):
                event.created_at = int(time.time())
            self.deltas.append(event)
        return DummySendResult(eid)

    async def fetch_events(self, f, _timeout):
        kind = getattr(f, "kind_val", None)
        limit = getattr(f, "limit_val", None)
        identifier = f.ids[0] if getattr(f, "ids", None) else None
        since = getattr(f, "since_val", None)
        events: list[DummyEvent] = []
        if kind == KIND_MANIFEST:
            events = list(reversed(self.manifests))
        elif kind == KIND_SNAPSHOT_CHUNK and identifier is not None:
            if identifier in self.chunks:
                events = [self.chunks[identifier]]
        elif kind == KIND_DELTA:
            events = [d for d in self.deltas if since is None or int(d.id) > since]
        if limit is not None:
            events = events[:limit]

        class Result:
            def __init__(self, evs):
                self._evs = evs

            def to_vec(self):
                return self._evs

        return Result(events)


@pytest.fixture
def dummy_nostr_client(tmp_path, monkeypatch):
    """Return a NostrClient wired to a DummyRelayClient."""
    from cryptography.fernet import Fernet
    from nostr.client import NostrClient

    relay = DummyRelayClient()
    monkeypatch.setattr("nostr.client.Client", lambda signer: relay)
    monkeypatch.setattr("nostr.client.EventBuilder", DummyBuilder)
    monkeypatch.setattr("nostr.client.Filter", DummyFilter)
    monkeypatch.setattr("nostr.client.Tag", DummyTag)
    monkeypatch.setattr("nostr.client.Timestamp", DummyTimestamp)
    monkeypatch.setattr("nostr.client.EventId", DummyEventId)
    from nostr.backup_models import KIND_DELTA as KD

    monkeypatch.setattr("nostr.client.KIND_DELTA", KD, raising=False)
    monkeypatch.setattr(NostrClient, "initialize_client_pool", lambda self: None)

    enc_mgr = EncryptionManager(Fernet.generate_key(), tmp_path)

    class DummyKeys:
        def private_key_hex(self):
            return "1" * 64

        def public_key_hex(self):
            return "2" * 64

    class DummyKeyManager:
        def __init__(self, *a, **k):
            self.keys = DummyKeys()

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("nostr.client.KeyManager", DummyKeyManager)
        mp.setattr(enc_mgr, "decrypt_parent_seed", lambda: TEST_SEED)
        client = NostrClient(enc_mgr, "fp")
    return client, relay
