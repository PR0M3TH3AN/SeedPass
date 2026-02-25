import importlib
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import asyncio
import gzip


def load_script():
    script_path = (
        Path(__file__).resolve().parents[2] / "scripts" / "generate_test_profile.py"
    )
    spec = importlib.util.spec_from_file_location("generate_test_profile", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_generate_test_profile_sync(monkeypatch, dummy_nostr_client):
    client, _relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        constants = importlib.import_module("constants")
        importlib.reload(constants)
        gtp = load_script()

        monkeypatch.setattr(gtp, "NostrClient", lambda *a, **k: client)

        seed, entry_mgr, dir_path, fingerprint, cfg_mgr = gtp.initialize_profile("test")
        gtp.populate(entry_mgr, seed, 5)

        encrypted = entry_mgr.vault.get_encrypted_index()
        nc = gtp.NostrClient(
            entry_mgr.vault.encryption_manager,
            fingerprint,
            parent_seed=seed,
            config_manager=cfg_mgr,
        )
        asyncio.run(nc.publish_snapshot(encrypted))

        from nostr.client import NostrClient as RealClient

        class DummyKeys:
            def private_key_hex(self):
                return "1" * 64

            def public_key_hex(self):
                return "2" * 64

        class DummyKeyManager:
            def __init__(self, *a, **k):
                self.keys = DummyKeys()

        monkeypatch.setattr("nostr.client.KeyManager", DummyKeyManager)
        client2 = RealClient(
            entry_mgr.vault.encryption_manager,
            fingerprint,
            parent_seed=seed,
            config_manager=cfg_mgr,
        )
        result = asyncio.run(client2.fetch_latest_snapshot())

        assert result is not None
        _manifest, chunks = result
        assert _manifest.delta_since is None
        retrieved = gzip.decompress(b"".join(chunks))
        assert retrieved == encrypted
