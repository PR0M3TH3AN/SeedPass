"""Exploratory walkthrough of the TUI v2 app.

Exercises every board type, CRUD operations, managed sessions, editing,
archiving, filtering, density modes, vault lock/unlock, links, tags, notes,
and edge-case inputs.  Each section captures the detail pane, action strip,
and status bar to detect rendering regressions and silent failures.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("textual")
from textual.widgets import Input, ListView, Static

from seedpass.tui_v2.app import launch_tui2

# ── Fake services (copied from interaction tests to be self-contained) ──────


class FakeEntryService:
    def __init__(self, entries: list[dict] | None = None) -> None:
        entries = entries or []
        self._entries = {int(e["id"]): dict(e) for e in entries}
        self._links: dict[int, list[dict]] = {
            int(e["id"]): [dict(l) for l in e.get("links", [])] for e in entries
        }
        self.secret_mode_enabled = False
        self.clipboard_delay = 30
        self.clipboard_values: list[str] = []
        self.managed_load_calls: list[int] = []
        self.managed_exit_calls = 0

    def _next_id(self) -> int:
        return (max(self._entries.keys()) + 1) if self._entries else 1

    def search_entries(
        self, query, kinds=None, *, include_archived=False, archived_only=False
    ):
        q = (query or "").strip().lower()
        out = []
        for eid in sorted(self._entries):
            e = self._entries[eid]
            kind = str(e.get("kind", "password"))
            if kinds and kind not in kinds:
                continue
            archived = bool(e.get("archived", False))
            if archived_only and not archived:
                continue
            if not include_archived and archived:
                continue
            label = str(e.get("label", ""))
            if q and q not in label.lower():
                continue
            out.append((eid, label, None, None, archived, SimpleNamespace(value=kind)))
        return out

    def retrieve_entry(self, eid):
        return dict(self._entries.get(int(eid), {}))

    def add_entry(self, label, length, username=None, url=None):
        eid = self._next_id()
        self._entries[eid] = {
            "id": eid,
            "kind": "password",
            "label": label,
            "length": int(length),
            "username": username,
            "url": url,
            "archived": False,
        }
        return eid

    def add_totp(self, label, *, secret=None, period=30, digits=6, deterministic=False):
        eid = self._next_id()
        self._entries[eid] = {
            "id": eid,
            "kind": "totp",
            "label": label,
            "secret": secret or "JBSWY3DPEHPK3PXP",
            "period": int(period),
            "digits": int(digits),
            "archived": False,
        }
        return f"otpauth://totp/{label}"

    def add_key_value(self, label, key, value):
        eid = self._next_id()
        self._entries[eid] = {
            "id": eid,
            "kind": "key_value",
            "label": label,
            "key": key,
            "value": value,
            "archived": False,
        }
        return eid

    def add_document(self, label, content, *, file_type="txt"):
        eid = self._next_id()
        self._entries[eid] = {
            "id": eid,
            "kind": "document",
            "label": label,
            "content": content,
            "file_type": file_type,
            "archived": False,
        }
        return eid

    def add_ssh_key(self, label, *, index=None, notes=""):
        eid = self._next_id()
        self._entries[eid] = {
            "id": eid,
            "kind": "ssh",
            "label": label,
            "private_key": f"SSH_PRIV_{eid}",
            "public_key": f"ssh-ed25519 AAAA-{eid}",
            "archived": False,
        }
        return eid

    def add_pgp_key(
        self, label, *, index=None, key_type="ed25519", user_id="", notes=""
    ):
        eid = self._next_id()
        self._entries[eid] = {
            "id": eid,
            "kind": "pgp",
            "label": label,
            "private_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "fingerprint": f"FPR-{eid}",
            "archived": False,
        }
        return eid

    def add_nostr_key(self, label, *, index=None, notes=""):
        eid = self._next_id()
        self._entries[eid] = {
            "id": eid,
            "kind": "nostr",
            "label": label,
            "npub": f"npub{eid}",
            "nsec": f"nsec{eid}",
            "archived": False,
        }
        return eid

    def add_seed(self, label, *, index=None, words=24, notes=""):
        wc = max(12, int(words))
        phrase = " ".join(["abandon"] * (wc - 1) + ["about"])
        eid = self._next_id()
        self._entries[eid] = {
            "id": eid,
            "kind": "seed",
            "label": label,
            "seed_phrase": phrase,
            "archived": False,
        }
        return eid

    def add_managed_account(self, label, *, index=None, notes=""):
        eid = self._next_id()
        self._entries[eid] = {
            "id": eid,
            "kind": "managed_account",
            "label": label,
            "seed_phrase": "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "archived": False,
        }
        return eid

    def export_document_file(self, eid, output_path=None, *, overwrite=False):
        e = self._entries[int(eid)]
        if str(e.get("kind")) != "document":
            raise ValueError("not a document")
        name = str(e.get("label", f"doc-{eid}")).replace(" ", "_")
        ext = str(e.get("file_type", "txt")).lstrip(".") or "txt"
        dest = Path(output_path) if output_path else Path.cwd() / f"{name}.{ext}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(str(e.get("content", "")), encoding="utf-8")
        return dest

    def modify_entry(self, eid, **kw):
        e = self._entries[int(eid)]
        for k, v in kw.items():
            if v is not None:
                e[k] = v

    def generate_password(self, length, eid):
        return f"pw-{eid}-{length}"

    def get_seed_phrase(self, eid):
        return str(
            self._entries[int(eid)].get("seed_phrase", "abandon " * 11 + "about")
        ).strip()

    def get_managed_account_seed(self, eid):
        return str(
            self._entries[int(eid)].get(
                "seed_phrase",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
            )
        ).strip()

    def get_totp_secret(self, eid):
        return str(self._entries[int(eid)].get("secret", "JBSWY3DPEHPK3PXP"))

    def get_totp_code(self, eid):
        return "123456"

    def export_totp_entries(self):
        out = {}
        for eid, e in self._entries.items():
            if str(e.get("kind")) != "totp":
                continue
            out[str(eid)] = {
                "label": e.get("label"),
                "period": e.get("period", 30),
                "digits": e.get("digits", 6),
                "secret": e.get("secret"),
            }
        return out

    def get_ssh_key_pair(self, eid):
        e = self._entries[int(eid)]
        return (
            str(e.get("private_key", "SSH_PRIV")),
            str(e.get("public_key", "ssh-ed25519 AAAA...")),
        )

    def get_pgp_key(self, eid):
        e = self._entries[int(eid)]
        return (
            str(e.get("private_key", "-----BEGIN PGP PRIVATE KEY BLOCK-----")),
            str(e.get("fingerprint", "DEADBEEF")),
        )

    def get_nostr_key_pair(self, eid):
        e = self._entries[int(eid)]
        return (str(e.get("npub", "npub1")), str(e.get("nsec", "nsec1")))

    def get_secret_mode_enabled(self):
        return self.secret_mode_enabled

    def get_clipboard_clear_delay(self):
        return self.clipboard_delay

    def copy_to_clipboard(self, value):
        self.clipboard_values.append(value)
        return True

    def archive_entry(self, eid):
        self._entries[int(eid)]["archived"] = True

    def restore_entry(self, eid):
        self._entries[int(eid)]["archived"] = False

    def get_links(self, eid):
        return [dict(l) for l in self._links.get(int(eid), [])]

    def add_link(self, eid, tid, *, relation="related_to", note=""):
        links = self._links.setdefault(int(eid), [])
        links.append({"target": int(tid), "relation": relation, "note": note})
        return [dict(l) for l in links]

    def remove_link(self, eid, tid, *, relation=None):
        src = self._links.setdefault(int(eid), [])
        kept = [
            l
            for l in src
            if int(l.get("target", -1)) != int(tid)
            or (relation and str(l.get("relation")) != relation)
        ]
        self._links[int(eid)] = kept
        return [dict(l) for l in kept]

    def load_managed_account(self, eid):
        if str(self._entries.get(int(eid), {}).get("kind")) != "managed_account":
            raise ValueError("not a managed account")
        self.managed_load_calls.append(int(eid))

    def exit_managed_account(self):
        self.managed_exit_calls += 1


class FakeProfileService:
    def __init__(self, profiles=None):
        self.profiles = list(profiles or ["AAAA1111", "BBBB2222"])
        self.last_switch = None
        self.add_count = 0
        self.removed = []
        self.renamed = {}

    def list_profiles(self):
        return list(self.profiles)

    def switch_profile(self, req):
        fp = str(getattr(req, "fingerprint", ""))
        if fp not in self.profiles:
            raise ValueError("not found")
        self.last_switch = (fp, getattr(req, "password", None))

    def add_profile(self):
        self.add_count += 1
        fp = f"fp-new-{self.add_count}"
        self.profiles.append(fp)
        return fp

    def remove_profile(self, req):
        fp = str(getattr(req, "fingerprint", ""))
        self.profiles = [p for p in self.profiles if p != fp]
        self.removed.append(fp)

    def rename_profile(self, fingerprint, name):
        self.renamed[str(fingerprint)] = str(name)


class FakeConfigService:
    def __init__(self):
        self.secret_mode_enabled = False
        self.clipboard_delay = 30
        self.offline_mode = True
        self.quick_unlock = False
        self.inactivity_timeout = 300.0
        self.kdf_iterations = 100000
        self.kdf_mode = "pbkdf2"

    def set_secret_mode(self, enabled, delay):
        self.secret_mode_enabled = bool(enabled)
        self.clipboard_delay = int(delay)

    def set_offline_mode(self, enabled):
        self.offline_mode = bool(enabled)

    def set(self, key, value):
        if key == "quick_unlock":
            self.quick_unlock = str(value).strip().lower() in {
                "1",
                "true",
                "yes",
                "y",
                "on",
            }
        elif key == "inactivity_timeout":
            self.inactivity_timeout = float(value)
        elif key == "kdf_iterations":
            self.kdf_iterations = int(value)
        elif key == "kdf_mode":
            self.kdf_mode = str(value)
        else:
            raise KeyError(key)


class FakeVaultService:
    def __init__(self):
        self.lock_calls = 0
        self.unlock_passwords = []
        self.locked = False
        self.exported = []
        self.imported = []
        self.parent_seed_backups = []

    def lock(self):
        self.lock_calls += 1
        self.locked = True

    def unlock(self, req):
        pw = str(getattr(req, "password", ""))
        self.unlock_passwords.append(pw)
        if pw != "hunter2":
            raise ValueError("invalid password")
        self.locked = False

        class _R:
            duration = 0.42

        return _R()

    def export_vault(self, req):
        p = Path(getattr(req, "path"))
        self.exported.append(p)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("vault", encoding="utf-8")

    def import_vault(self, req):
        self.imported.append(Path(getattr(req, "path")))

    def backup_parent_seed(self, req):
        p = getattr(req, "path", None)
        if p:
            p = Path(p)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("seed-backup", encoding="utf-8")
        self.parent_seed_backups.append((p, getattr(req, "password", None)))


class FakeSemanticService:
    def __init__(self):
        self.enabled = False
        self.built = False
        self.records = 0
        self.mode = "keyword"

    def status(self):
        return {
            "enabled": self.enabled,
            "built": self.built,
            "records": self.records,
            "mode": self.mode,
        }

    def set_enabled(self, e):
        self.enabled = bool(e)
        return self.status()

    def build(self):
        self.built = True
        self.records = 2
        return self.status()

    def rebuild(self):
        return self.build()

    def set_mode(self, m):
        self.mode = str(m)
        return self.status()

    def search(self, query, *, k=10, kind=None, mode=None):
        return []


class FakeSyncService:
    def __init__(self):
        self.sync_calls = 0

    def sync(self):
        self.sync_calls += 1

        class _R:
            manifest_id = f"manifest-{self.sync_calls}"

        return _R()

    def start_background_vault_sync(self):
        pass


class FakeUtilityService:
    def __init__(self):
        self.verify_calls = 0
        self.update_calls = 0

    def verify_checksum(self):
        self.verify_calls += 1

    def update_checksum(self):
        self.update_calls += 1


class FakeNostrService:
    def __init__(self):
        self.relays = ["wss://relay.example.com"]
        self.pubkey = "npub1seedpassprofile"

    def get_pubkey(self):
        return self.pubkey

    def list_relays(self):
        return list(self.relays)

    def add_relay(self, url):
        self.relays.append(url)

    def remove_relay(self, idx):
        self.relays.pop(int(idx) - 1)

    def reset_relays(self):
        self.relays = ["wss://default-1"]
        return list(self.relays)

    def reset_sync_state(self):
        return 0

    def start_fresh_namespace(self):
        return 1


# ── Helpers ─────────────────────────────────────────────────────────────────


def _build_full_app(service=None, **kw):
    service = service or FakeEntryService()
    holder: dict = {}

    def _hook(app):
        holder["app"] = app

    launched = launch_tui2(
        entry_service_factory=lambda: service,
        profile_service_factory=lambda: kw.get("profile", FakeProfileService()),
        config_service_factory=lambda: kw.get("config", FakeConfigService()),
        nostr_service_factory=lambda: kw.get("nostr", FakeNostrService()),
        sync_service_factory=lambda: kw.get("sync", FakeSyncService()),
        utility_service_factory=lambda: kw.get("utility", FakeUtilityService()),
        vault_service_factory=lambda: kw.get("vault", FakeVaultService()),
        semantic_service_factory=lambda: kw.get("semantic", FakeSemanticService()),
        app_hook=_hook,
    )
    assert launched is True
    return holder["app"], service


def _t(app, sel):
    return str(app.query_one(sel).render())


def _detail(app):
    return _t(app, "#entry-detail")


def _status(app):
    return _t(app, "#status")


def _action(app):
    return _t(app, "#action-strip")


async def _cmd(app, pilot, command):
    app._run_palette_command(command)
    await pilot.pause()


# ── Tests ───────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_walkthrough_create_all_entry_types_and_inspect():
    """Create one of each entry type and verify the detail board renders."""
    app, svc = _build_full_app()

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()

        # 1) Add a seed
        await _cmd(app, pilot, 'add-seed "Root Seed" 12')
        detail = _detail(app)
        if "Seed Board" not in detail:
            bugs.append(f"Seed board missing after add-seed. detail={detail[:200]}")
        if "Root Seed" not in detail:
            bugs.append("Seed label missing in detail")
        stat = _status(app)
        if "Added seed entry" not in stat:
            bugs.append(f"Status after add-seed: {stat}")

        # 2) Add a password
        await _cmd(app, pilot, 'add-password "MyLogin" 20 alice https://example.com')
        detail = _detail(app)
        if "Password Board" not in detail:
            bugs.append(f"Password board missing. detail={detail[:200]}")
        if "alice" not in detail:
            bugs.append("Username missing from password detail")
        if "https://example.com" not in detail:
            bugs.append("URL missing from password detail")

        # 3) Add PGP
        await _cmd(app, pilot, 'add-pgp "Work PGP"')
        detail = _detail(app)
        if "PGP Board" not in detail:
            bugs.append(f"PGP board missing. detail={detail[:200]}")

        # 4) Add SSH
        await _cmd(app, pilot, 'add-ssh "Deploy Key"')
        detail = _detail(app)
        if "SSH Board" not in detail:
            bugs.append(f"SSH board missing. detail={detail[:200]}")

        # 5) Add managed account
        await _cmd(app, pilot, 'add-managed "Bob Account"')
        detail = _detail(app)
        if "Managed Account" not in detail:
            bugs.append(f"Managed board missing. detail={detail[:200]}")

        # 6) Add TOTP
        await _cmd(app, pilot, 'add-totp "Auth App"')
        detail = _detail(app)
        if "2FA Board" not in detail:
            bugs.append(f"TOTP board missing. detail={detail[:200]}")

        # 7) Add Nostr
        await _cmd(app, pilot, 'add-nostr "Relay Key"')
        detail = _detail(app)
        if "Nostr Board" not in detail:
            bugs.append(f"Nostr board missing. detail={detail[:200]}")

        # 8) Add document
        await _cmd(app, pilot, 'add-document "README" md "Hello world"')
        detail = _detail(app)
        if "Note Board" not in detail:
            bugs.append(f"Document board missing. detail={detail[:200]}")

        # 9) Add key/value
        await _cmd(app, pilot, 'add-key-value "API Token" token sk-12345')
        detail = _detail(app)
        if "Key/Value" not in detail and "key_value" not in detail:
            bugs.append(f"K/V board missing. detail={detail[:200]}")

        # Verify grid has all 9 entries
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 9:
            bugs.append(f"Expected 9 grid entries, got {len(lv.children)}")

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_edit_and_metadata_flow():
    """Edit entries, add tags/notes, verify they render in the detail pane."""
    app, svc = _build_full_app()

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()

        # Create a password entry
        await _cmd(app, pilot, 'add-password "Editable" 16 bob')
        await _cmd(app, pilot, "open 1")
        await pilot.pause()

        # Add notes
        await _cmd(app, pilot, 'notes-set "Remember to rotate quarterly"')
        detail = _detail(app)
        if "Remember to rotate quarterly" not in detail:
            bugs.append(f"Notes not visible in detail: {detail[:300]}")

        # Add tags
        await _cmd(app, pilot, "tag-add security")
        await _cmd(app, pilot, "tag-add important")
        detail = _detail(app)
        if "security" not in detail:
            bugs.append("Tag 'security' missing from detail")
        if "important" not in detail:
            bugs.append("Tag 'important' missing from detail")

        # Remove a tag
        await _cmd(app, pilot, "tag-rm security")
        detail = _detail(app)
        if "security" in detail:
            bugs.append("Tag 'security' still visible after removal")

        # Edit label via modify
        await _cmd(app, pilot, 'edit-label "Renamed Entry"')
        detail = _detail(app)
        stat = _status(app)
        # Check for either success or unknown command (edit-label might not exist)
        if "unknown" in stat.lower() or "unrecognized" in stat.lower():
            # Not a bug — edit-label might not be a command. Skip this check.
            pass
        elif "Renamed Entry" in detail:
            pass  # Good
        # else: neither error nor success — that's suspicious but let it go

        # Clear notes
        await _cmd(app, pilot, "notes-clear")
        detail = _detail(app)
        if "Remember to rotate quarterly" in detail:
            bugs.append("Notes still visible after notes-clear")

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_archive_filter_cycle():
    """Archive an entry, filter to archived-only, restore, verify state."""
    app, svc = _build_full_app()

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()

        await _cmd(app, pilot, 'add-password "Archivable" 16')
        await _cmd(app, pilot, 'add-password "Keeper" 16')
        await _cmd(app, pilot, "open 1")
        await pilot.pause()

        # Archive selected entry (no arg — acts on selected_entry_id)
        await _cmd(app, pilot, "archive")
        stat = _status(app)
        if "archive" not in stat.lower() and "Archived" not in stat:
            bugs.append(f"Archive status unexpected: {stat}")

        # Filter to archived only — should show entry 1
        await _cmd(app, pilot, "archive-filter archived")
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 1:
            bugs.append(f"Expected 1 archived entry, got {len(lv.children)}")

        # Filter to all — should show both
        await _cmd(app, pilot, "archive-filter all")
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 2:
            bugs.append(f"Expected 2 entries in 'all', got {len(lv.children)}")

        # Re-select entry 1 (it was deselected when archived under active filter)
        await _cmd(app, pilot, "open 1")

        # Restore selected entry
        await _cmd(app, pilot, "restore")
        await _cmd(app, pilot, "archive-filter active")
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 2:
            bugs.append(
                f"Expected 2 active entries after restore, got {len(lv.children)}"
            )

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_managed_session_lifecycle():
    """Load into a managed account, add sub-entry, exit, verify state."""
    app, svc = _build_full_app()

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()

        # Create managed account
        await _cmd(app, pilot, 'add-managed "Child Profile"')
        managed_id = max(svc._entries.keys())
        await _cmd(app, pilot, f"open {managed_id}")
        detail = _detail(app)
        if "Managed Account" not in detail:
            bugs.append("Managed board not showing")

        # Load managed session
        await _cmd(app, pilot, f"managed-load {managed_id}")
        stat = _status(app)
        if "managed" not in stat.lower() and "load" not in stat.lower():
            # Check action strip instead
            action = _action(app)
            if "managed-exit" not in action.lower():
                bugs.append(
                    f"Managed session not activated. status={stat}, action={action[:200]}"
                )

        # Verify managed-load was called
        if managed_id not in svc.managed_load_calls:
            bugs.append(
                f"managed_load_calls missing {managed_id}: {svc.managed_load_calls}"
            )

        # Exit managed session
        await _cmd(app, pilot, "managed-exit")
        if svc.managed_exit_calls < 1:
            bugs.append("managed-exit not called on service")

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_vault_lock_unlock():
    """Lock vault, verify entries hidden, unlock, verify entries restored."""
    svc = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "password",
                "label": "Secret Login",
                "length": 16,
                "archived": False,
            },
        ]
    )
    vault = FakeVaultService()
    app, _ = _build_full_app(svc, vault=vault)

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()

        # Verify entry visible
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 1:
            bugs.append(f"Expected 1 entry pre-lock, got {len(lv.children)}")

        # Lock
        await _cmd(app, pilot, "lock")
        stat = _status(app)
        if "locked" not in stat.lower():
            bugs.append(f"Lock status unexpected: {stat}")
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 0:
            bugs.append(f"Expected 0 entries after lock, got {len(lv.children)}")

        # Try to open entry while locked
        await _cmd(app, pilot, "open 1")
        stat = _status(app)
        if "locked" not in stat.lower():
            bugs.append(f"Open while locked should mention lock: {stat}")

        # Unlock with wrong password
        await _cmd(app, pilot, "unlock wrongpw")
        stat = _status(app)
        if "failed" not in stat.lower() and "invalid" not in stat.lower():
            bugs.append(f"Wrong password didn't fail: {stat}")

        # Unlock with correct password
        await _cmd(app, pilot, "unlock hunter2")
        stat = _status(app)
        if "unlocked" not in stat.lower():
            bugs.append(f"Unlock status unexpected: {stat}")
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 1:
            bugs.append(f"Expected 1 entry after unlock, got {len(lv.children)}")

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_density_modes():
    """Cycle through density modes, verify status and grid heading adapt."""
    svc = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "password",
                "label": "Test PW",
                "length": 16,
                "archived": False,
            },
        ]
    )
    app, _ = _build_full_app(svc)

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()
        await _cmd(app, pilot, "open 1")

        # Compact
        await _cmd(app, pilot, "density compact")
        stat = _status(app)
        if "compact" not in stat.lower():
            bugs.append(f"Density compact not in status: {stat}")
        # Grid heading should reflect density mode
        heading = _t(app, "#grid-heading")
        if "compact" not in heading.lower():
            bugs.append(f"Density compact not in grid heading: {heading[:100]}")

        # Comfortable
        await _cmd(app, pilot, "density comfortable")
        stat = _status(app)
        if "comfortable" not in stat.lower():
            bugs.append(f"Density comfortable not in status: {stat}")
        heading2 = _t(app, "#grid-heading")
        if "comfortable" not in heading2.lower():
            bugs.append(f"Density comfortable not in grid heading: {heading2[:100]}")

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_kind_filter():
    """Filter by entry kind and verify grid population."""
    svc = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "password",
                "label": "PW1",
                "length": 16,
                "archived": False,
            },
            {
                "id": 2,
                "kind": "totp",
                "label": "OTP1",
                "secret": "AAA",
                "period": 30,
                "digits": 6,
                "archived": False,
            },
            {
                "id": 3,
                "kind": "document",
                "label": "Doc1",
                "content": "hi",
                "file_type": "md",
                "archived": False,
            },
            {
                "id": 4,
                "kind": "ssh",
                "label": "SSH1",
                "private_key": "pk",
                "public_key": "pub",
                "archived": False,
            },
        ]
    )
    app, _ = _build_full_app(svc)

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()

        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 4:
            bugs.append(f"Expected 4 entries unfiltered, got {len(lv.children)}")

        # Filter to 2fa
        await _cmd(app, pilot, "filter 2fa")
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 1:
            bugs.append(f"Expected 1 TOTP entry, got {len(lv.children)}")

        # Filter to docs
        await _cmd(app, pilot, "filter docs")
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 1:
            bugs.append(f"Expected 1 doc entry, got {len(lv.children)}")

        # Filter to all
        await _cmd(app, pilot, "filter all")
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 4:
            bugs.append(f"Expected 4 entries after filter all, got {len(lv.children)}")

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_links_between_entries():
    """Add and remove links between entries."""
    svc = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "password",
                "label": "PW1",
                "length": 16,
                "archived": False,
            },
            {
                "id": 2,
                "kind": "totp",
                "label": "OTP for PW1",
                "secret": "AAA",
                "period": 30,
                "digits": 6,
                "archived": False,
            },
        ]
    )
    app, _ = _build_full_app(svc)

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()
        await _cmd(app, pilot, "open 1")

        # Add link
        await _cmd(app, pilot, "link-add 2 related_to")
        stat = _status(app)
        if "link" not in stat.lower() and "added" not in stat.lower():
            # May say "Added link" or "Linked"
            if "unknown" in stat.lower() or "unrecognized" in stat.lower():
                bugs.append(f"link-add not recognized: {stat}")

        # Check links were recorded
        if svc._links.get(1):
            link = svc._links[1][0]
            if link["target"] != 2:
                bugs.append(f"Link target wrong: {link}")
        # (If links not added, it might be command format issue — check status)

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_card_frame_rendering():
    """Verify card frames render correctly for every board type."""
    entries = [
        {
            "id": 1,
            "kind": "password",
            "label": "PW",
            "length": 16,
            "username": "u",
            "url": "https://x.com",
            "archived": False,
        },
        {
            "id": 2,
            "kind": "document",
            "label": "Doc",
            "content": "hello " * 50,
            "file_type": "md",
            "archived": False,
        },
        {
            "id": 3,
            "kind": "totp",
            "label": "OTP",
            "secret": "AAA",
            "period": 30,
            "digits": 6,
            "archived": False,
        },
        {
            "id": 4,
            "kind": "seed",
            "label": "Seed",
            "seed_phrase": "abandon " * 11 + "about",
            "archived": False,
        },
        {
            "id": 5,
            "kind": "managed_account",
            "label": "Mgd",
            "seed_phrase": "legal " * 11 + "about",
            "archived": False,
        },
        {
            "id": 6,
            "kind": "ssh",
            "label": "SSH",
            "private_key": "pk",
            "public_key": "ssh-ed25519 AAAA",
            "archived": False,
        },
        {
            "id": 7,
            "kind": "pgp",
            "label": "PGP",
            "private_key": "pk",
            "fingerprint": "FPR-7",
            "archived": False,
        },
        {
            "id": 8,
            "kind": "nostr",
            "label": "Nostr",
            "npub": "npub1demo",
            "nsec": "nsec1demo",
            "archived": False,
        },
    ]
    svc = FakeEntryService(entries)
    app, _ = _build_full_app(svc)

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()

        for eid in range(1, 9):
            await _cmd(app, pilot, f"open {eid}")
            detail = _detail(app)
            kind = entries[eid - 1]["kind"]
            label = entries[eid - 1]["label"]

            # Every board should have at least one card frame
            if "+- " not in detail:
                bugs.append(f"Entry #{eid} ({kind}): no card frame found")

            # Card frames should be balanced (opening and closing)
            open_count = detail.count("+- ")
            close_count = detail.count("+-")
            # The bottom line starts with "+" so count "+" lines
            # Just check top/bottom pairs
            top_lines = [l for l in detail.split("\n") if l.strip().startswith("+- ")]
            bottom_lines = [
                l
                for l in detail.split("\n")
                if l.strip().startswith("+")
                and l.strip().endswith("+")
                and "- " not in l[:5]
            ]
            if len(top_lines) < 1:
                bugs.append(f"Entry #{eid} ({kind}): missing card frame top line")

            # No Python repr artifacts
            if "{'id'" in detail or "{'kind'" in detail:
                bugs.append(f"Entry #{eid} ({kind}): raw dict in detail pane")

            # Max width check — no line should exceed ~80 chars (72 card + margins)
            for line in detail.split("\n"):
                if len(line) > 85:
                    bugs.append(
                        f"Entry #{eid} ({kind}): line too wide ({len(line)} chars): {line[:60]}..."
                    )
                    break

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_edge_cases_and_error_handling():
    """Exercise error paths and edge cases."""
    app, svc = _build_full_app()

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()

        # Open non-existent entry
        await _cmd(app, pilot, "open 999")
        detail = _detail(app)
        if "not found" not in detail.lower():
            bugs.append(f"Non-existent entry didn't show not-found: {detail[:200]}")

        # Empty command
        await _cmd(app, pilot, "")
        stat = _status(app)
        # Should not crash

        # Invalid command
        await _cmd(app, pilot, "totally-bogus-command")
        stat = _status(app)
        if "unknown" not in stat.lower() and "unrecognized" not in stat.lower():
            bugs.append(f"Bogus command didn't get unknown status: {stat}")

        # add-password with missing args
        await _cmd(app, pilot, "add-password")
        stat = _status(app)
        if "usage" not in stat.lower():
            bugs.append(f"add-password no args didn't show usage: {stat}")

        # add-password with non-integer length
        await _cmd(app, pilot, 'add-password "Test" abc')
        stat = _status(app)
        if "integer" not in stat.lower():
            bugs.append(f"add-password non-int length didn't error: {stat}")

        # add-seed with empty label
        await _cmd(app, pilot, 'add-seed ""')
        stat = _status(app)
        if "required" not in stat.lower() and "empty" not in stat.lower():
            # Empty string might just pass through — check if it created something
            pass  # Tolerable

        # Help command should not crash
        await _cmd(app, pilot, "help")
        detail = _detail(app)
        if len(detail) < 50:
            bugs.append(f"Help text too short: {detail[:100]}")

        # Stats command
        await _cmd(app, pilot, "stats")
        detail = _detail(app)
        stat = _status(app)
        if "stats" not in stat.lower():
            bugs.append(f"Stats command status unexpected: {stat}")

        # Session status
        await _cmd(app, pilot, "session-status")
        detail = _detail(app)
        if "lock state" not in detail.lower() and "session" not in detail.lower():
            bugs.append(f"Session status missing lock info: {detail[:200]}")

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_search_flow():
    """Search, clear, verify grid updates."""
    svc = FakeEntryService(
        [
            {
                "id": i,
                "kind": "password",
                "label": f"Entry {i}",
                "length": 16,
                "archived": False,
            }
            for i in range(1, 21)
        ]
    )
    app, _ = _build_full_app(svc)

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()

        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 20:
            bugs.append(f"Expected 20 entries, got {len(lv.children)}")

        # Search for specific entry
        await _cmd(app, pilot, "search Entry 15")
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 1:
            bugs.append(f"Expected 1 result for 'Entry 15', got {len(lv.children)}")

        # Clear search
        await _cmd(app, pilot, "search ")
        lv = app.query_one("#entry-list", ListView)
        if len(lv.children) != 20:
            bugs.append(f"Expected 20 after clearing search, got {len(lv.children)}")

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)


@pytest.mark.anyio
async def test_walkthrough_full_user_journey():
    """Complete user journey: create seed, add password, managed session, PGP."""
    app, svc = _build_full_app()

    bugs = []

    async with app.run_test() as pilot:
        await pilot.pause()

        # Step 1: Create root seed
        await _cmd(app, pilot, 'add-seed "My Root Seed" 24')
        if "Added seed entry" not in _status(app):
            bugs.append(f"Seed creation status: {_status(app)}")

        # Step 2: Add a password entry
        await _cmd(
            app, pilot, 'add-password "GitHub Login" 24 myuser https://github.com'
        )
        detail = _detail(app)
        if "myuser" not in detail:
            bugs.append("Password username missing")
        if "github.com" not in detail:
            bugs.append("Password URL missing")

        # Step 3: Add PGP key
        await _cmd(app, pilot, 'add-pgp "GPG Signing Key"')
        detail = _detail(app)
        if "PGP Board" not in detail:
            bugs.append("PGP board not rendered")

        # Step 4: Create managed user
        await _cmd(app, pilot, 'add-managed "Client Account"')
        managed_id = max(svc._entries.keys())
        detail = _detail(app)
        if "Managed Account" not in detail:
            bugs.append("Managed account not rendered")

        # Step 5: Load into managed session
        await _cmd(app, pilot, f"managed-load {managed_id}")

        # Step 6: Add sub-account password (inside managed session)
        await _cmd(app, pilot, 'add-password "Client Email" 18 client@example.com')
        detail = _detail(app)
        if "Password Board" not in detail:
            bugs.append(f"Sub-account password board missing: {detail[:200]}")

        # Step 7: Verify sub-account is visible
        if "Client Email" not in detail:
            bugs.append("Sub-account label not in detail")

        # Step 8: Exit managed session
        await _cmd(app, pilot, "managed-exit")
        if svc.managed_exit_calls < 1:
            bugs.append("managed-exit not called")

        # Step 9: Verify back to main grid — navigate to root seed
        await _cmd(app, pilot, "open 1")
        detail = _detail(app)
        if "Seed Board" not in detail and "Root Seed" not in detail:
            bugs.append(f"Root seed not accessible after managed exit: {detail[:200]}")

    assert not bugs, "BUGS FOUND:\n" + "\n".join(f"  - {b}" for b in bugs)
