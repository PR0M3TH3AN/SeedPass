from pathlib import Path
from types import SimpleNamespace

from seedpass.core.api import VaultService
from helpers import create_vault, TEST_SEED, TEST_PASSWORD


def test_profile_export_import_round_trip(tmp_path):
    dir1 = tmp_path / "a"
    vault1, _ = create_vault(dir1, TEST_SEED, TEST_PASSWORD)
    data = {
        "schema_version": 4,
        "entries": {"0": {"label": "example", "type": "password"}},
    }
    vault1.save_index(data)
    pm1 = SimpleNamespace(vault=vault1, sync_vault=lambda: None)
    service1 = VaultService(pm1)
    blob = service1.export_profile()

    dir2 = tmp_path / "b"
    vault2, _ = create_vault(dir2, TEST_SEED, TEST_PASSWORD)
    vault2.save_index({"schema_version": 4, "entries": {}})
    called = {}

    def sync():
        called["synced"] = True

    pm2 = SimpleNamespace(vault=vault2, sync_vault=sync)
    service2 = VaultService(pm2)
    service2.import_profile(blob)

    assert called.get("synced") is True
    assert vault2.load_index() == data
