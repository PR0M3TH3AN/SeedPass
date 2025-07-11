import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager


def setup_entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_search_by_website():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        idx0 = entry_mgr.add_entry("Example.com", 12, "alice")
        entry_mgr.add_entry("Other.com", 8, "bob")

        result = entry_mgr.search_entries("example")
        assert result == [(idx0, "Example.com", "alice", "", False)]


def test_search_by_username():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        entry_mgr.add_entry("Example.com", 12, "alice")
        idx1 = entry_mgr.add_entry("Test.com", 8, "Bob")

        result = entry_mgr.search_entries("bob")
        assert result == [(idx1, "Test.com", "Bob", "", False)]


def test_search_by_url():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        idx = entry_mgr.add_entry("Example", 12, url="https://ex.com/login")
        entry_mgr.add_entry("Other", 8)

        result = entry_mgr.search_entries("login")
        assert result == [(idx, "Example", "", "https://ex.com/login", False)]


def test_search_by_notes_and_totp():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        idx_pw = entry_mgr.add_entry("Site", 8, notes="secret note")
        entry_mgr.add_totp("GH", TEST_SEED)
        idx_totp = entry_mgr.search_entries("GH")[0][0]
        entry_mgr.modify_entry(idx_totp, notes="otp note")

        res_notes = entry_mgr.search_entries("secret")
        assert res_notes == [(idx_pw, "Site", "", "", False)]

        res_totp = entry_mgr.search_entries("otp")
        assert res_totp == [(idx_totp, "GH", None, None, False)]


def test_search_by_custom_field():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        custom = [
            {"label": "api", "value": "secret123", "is_hidden": True},
            {"label": "note", "value": "visible", "is_hidden": False},
        ]
        idx = entry_mgr.add_entry("Example", 8, custom_fields=custom)

        result = entry_mgr.search_entries("secret123")
        assert result == [(idx, "Example", "", "", False)]


def test_search_key_value_value():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        idx = entry_mgr.add_key_value("API", "token123")

        result = entry_mgr.search_entries("token123")
        assert result == [(idx, "API", None, None, False)]


def test_search_no_results():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        entry_mgr.add_entry("Example.com", 12, "alice")
        result = entry_mgr.search_entries("missing")
        assert result == []


def test_search_by_tag_password():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        idx = entry_mgr.add_entry("TaggedSite", 8, tags=["work"])

        result = entry_mgr.search_entries("work")
        assert result == [(idx, "TaggedSite", "", "", False)]


def test_search_by_tag_totp():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        entry_mgr.add_totp("OTPAccount", TEST_SEED, tags=["mfa"])
        idx = entry_mgr.search_entries("OTPAccount")[0][0]

        result = entry_mgr.search_entries("mfa")
        assert result == [(idx, "OTPAccount", None, None, False)]
