import importlib.util
import logging
import sys
from pathlib import Path

import pytest
from types import SimpleNamespace
from httpx import ASGITransport, AsyncClient
import bcrypt

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass import api
from seedpass.core.entry_types import EntryType
from helpers import (
    create_vault,
    TEST_PASSWORD,
    TEST_SEED,
    DummyBuilder,
    DummyFilter,
    DummyTag,
    DummyTimestamp,
    DummyEventId,
    DummyRelayClient,
)
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.manager import EncryptionMode, PasswordManager
from seedpass.core.encryption import EncryptionManager as EncMgr


@pytest.fixture(
    params=["asyncio"] + (["trio"] if importlib.util.find_spec("trio") else [])
)
def anyio_backend(request):
    return request.param


@pytest.fixture(autouse=True)
def mute_logging():
    logging.getLogger().setLevel(logging.WARNING)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--stress",
        action="store_true",
        default=False,
        help="run stress tests",
    )
    parser.addoption(
        "--desktop",
        action="store_true",
        default=False,
        help="run desktop-only tests",
    )
    parser.addoption(
        "--max-entries",
        type=int,
        default=None,
        help="maximum entries for nostr index size test",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "stress: long running stress tests")
    config.addinivalue_line("markers", "desktop: desktop only tests")


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--stress"):
        return

    skip_stress = pytest.mark.skip(reason="need --stress option to run")
    for item in items:
        if "stress" in item.keywords:
            item.add_marker(skip_stress)

    if not config.getoption("--desktop"):
        skip_desktop = pytest.mark.skip(reason="need --desktop option to run")
        for item in items:
            if "desktop" in item.keywords:
                item.add_marker(skip_desktop)


@pytest.fixture
def vault(tmp_path):
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    return vault


@pytest.fixture
def password_manager(vault, tmp_path):
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    entry_mgr = EntryManager(vault, backup_mgr)

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = vault.encryption_manager
    pm.vault = vault
    pm.entry_manager = entry_mgr
    pm.backup_manager = backup_mgr
    pm.parent_seed = TEST_SEED
    pm.nostr_client = None
    pm.fingerprint_dir = tmp_path
    pm.is_dirty = False
    pm.secret_mode_enabled = False
    return pm


@pytest.fixture
async def client(monkeypatch):
    dummy = SimpleNamespace(
        entry_manager=SimpleNamespace(
            search_entries=lambda q: [
                (1, "Site", "user", "url", False, EntryType.PASSWORD)
            ],
            retrieve_entry=lambda i: {"label": "Site"},
            add_entry=lambda *a, **k: 1,
            modify_entry=lambda *a, **k: None,
            archive_entry=lambda i: None,
            restore_entry=lambda i: None,
        ),
        config_manager=SimpleNamespace(
            load_config=lambda require_pin=False: {"k": "v"},
            set_pin=lambda v: None,
            set_password_hash=lambda v: None,
            set_relays=lambda v, require_pin=False: None,
            set_inactivity_timeout=lambda v: None,
            set_additional_backup_path=lambda v: None,
            set_secret_mode_enabled=lambda v: None,
            set_clipboard_clear_delay=lambda v: None,
            set_quick_unlock=lambda v: None,
        ),
        fingerprint_manager=SimpleNamespace(list_fingerprints=lambda: ["fp"]),
        nostr_client=SimpleNamespace(
            key_manager=SimpleNamespace(get_npub=lambda: "np")
        ),
        verify_password=lambda pw: True,
    )
    monkeypatch.setattr(api, "PasswordManager", lambda: dummy)
    monkeypatch.setenv("SEEDPASS_CORS_ORIGINS", "http://example.com")
    token = api.start_server()
    transport = ASGITransport(app=api.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac, token


@pytest.fixture
def make_dummy_nostr_client(monkeypatch):
    """Factory to return a NostrClient wired to a DummyRelayClient."""
    from cryptography.fernet import Fernet
    from nostr.client import NostrClient

    def _make(base_path):
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

        enc_mgr = EncMgr(Fernet.generate_key(), base_path)

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

    return _make


@pytest.fixture
def dummy_nostr_client(make_dummy_nostr_client, tmp_path):
    return make_dummy_nostr_client(tmp_path)
