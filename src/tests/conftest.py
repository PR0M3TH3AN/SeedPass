import importlib.util
import logging
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from helpers import create_vault, TEST_PASSWORD, TEST_SEED
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.manager import EncryptionMode, PasswordManager


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
