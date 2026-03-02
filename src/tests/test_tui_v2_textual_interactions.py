from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("textual")
from textual.widgets import Input, ListView, Static

from seedpass.tui_v2.app import launch_tui2


class FakeEntryService:
    def __init__(self, entries: list[dict], *, fail_search_times: int = 0) -> None:
        self._entries = {int(entry["id"]): dict(entry) for entry in entries}
        self._links = {
            int(entry["id"]): [dict(link) for link in entry.get("links", [])]
            for entry in entries
        }
        self.fail_search_times = fail_search_times
        self.secret_mode_enabled = False
        self.clipboard_delay = 30
        self.clipboard_values: list[str] = []
        self.managed_load_calls: list[int] = []
        self.managed_exit_calls = 0

    def _next_id(self) -> int:
        return (max(self._entries.keys()) + 1) if self._entries else 1

    def search_entries(
        self,
        query: str,
        kinds: list[str] | None = None,
        *,
        include_archived: bool = False,
        archived_only: bool = False,
    ):
        if self.fail_search_times > 0:
            self.fail_search_times -= 1
            raise RuntimeError("temporary search failure")

        q = (query or "").strip().lower()
        out = []
        for entry_id in sorted(self._entries.keys()):
            entry = self._entries[entry_id]
            kind = str(entry.get("kind", "password"))
            if kinds and kind not in kinds:
                continue
            archived = bool(entry.get("archived", False))
            if archived_only and not archived:
                continue
            if not include_archived and archived:
                continue
            label = str(entry.get("label", ""))
            if q and q not in label.lower():
                continue
            out.append(
                (
                    entry_id,
                    label,
                    None,
                    None,
                    archived,
                    SimpleNamespace(value=kind),
                )
            )
        return out

    def retrieve_entry(self, entry_id: int):
        return dict(self._entries.get(int(entry_id), {}))

    def add_entry(
        self,
        label: str,
        length: int,
        username: str | None = None,
        url: str | None = None,
    ) -> int:
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "password",
            "label": label,
            "length": int(length),
            "username": username,
            "url": url,
            "archived": False,
        }
        return entry_id

    def add_totp(
        self,
        label: str,
        *,
        secret: str | None = None,
        period: int = 30,
        digits: int = 6,
        deterministic: bool = False,
    ) -> str:
        _ = deterministic
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "totp",
            "label": label,
            "secret": secret or "JBSWY3DPEHPK3PXP",
            "period": int(period),
            "digits": int(digits),
            "archived": False,
        }
        return f"otpauth://totp/{label}"

    def add_key_value(self, label: str, key: str, value: str) -> int:
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "key_value",
            "label": label,
            "key": key,
            "value": value,
            "archived": False,
        }
        return entry_id

    def add_document(self, label: str, content: str, *, file_type: str = "txt") -> int:
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "document",
            "label": label,
            "content": content,
            "file_type": file_type,
            "archived": False,
        }
        return entry_id

    def add_ssh_key(
        self, label: str, *, index: int | None = None, notes: str = ""
    ) -> int:
        _ = (index, notes)
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "ssh",
            "label": label,
            "private_key": f"SSH_PRIVATE_{entry_id}",
            "public_key": f"ssh-ed25519 AAAA-{entry_id}",
            "archived": False,
        }
        return entry_id

    def add_pgp_key(
        self,
        label: str,
        *,
        index: int | None = None,
        key_type: str = "ed25519",
        user_id: str = "",
        notes: str = "",
    ) -> int:
        _ = (index, key_type, user_id, notes)
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "pgp",
            "label": label,
            "private_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "fingerprint": f"FPR-{entry_id}",
            "archived": False,
        }
        return entry_id

    def add_nostr_key(
        self, label: str, *, index: int | None = None, notes: str = ""
    ) -> int:
        _ = (index, notes)
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "nostr",
            "label": label,
            "npub": f"npub{entry_id}",
            "nsec": f"nsec{entry_id}",
            "archived": False,
        }
        return entry_id

    def add_seed(
        self,
        label: str,
        *,
        index: int | None = None,
        words: int = 24,
        notes: str = "",
    ) -> int:
        _ = (index, notes)
        word_count = max(12, int(words))
        phrase = " ".join(["abandon"] * (word_count - 1) + ["about"])
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "seed",
            "label": label,
            "seed_phrase": phrase,
            "archived": False,
        }
        return entry_id

    def add_managed_account(
        self, label: str, *, index: int | None = None, notes: str = ""
    ) -> int:
        _ = (index, notes)
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "managed_account",
            "label": label,
            "seed_phrase": "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "archived": False,
        }
        return entry_id

    def export_document_file(
        self,
        entry_id: int,
        output_path: str | Path | None = None,
        *,
        overwrite: bool = False,
    ) -> Path:
        _ = overwrite
        entry = self._entries[int(entry_id)]
        kind = str(entry.get("kind", ""))
        if kind != "document":
            raise ValueError("Entry is not a document entry")
        name = str(entry.get("label", f"document-{entry_id}")).replace(" ", "_")
        ext = str(entry.get("file_type", "txt")).lstrip(".") or "txt"
        if output_path is None:
            dest = Path.cwd() / f"{name}.{ext}"
        else:
            raw = Path(output_path)
            if raw.suffix:
                dest = raw
            else:
                dest = raw / f"{name}.{ext}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(str(entry.get("content", "")), encoding="utf-8")
        return dest

    def modify_entry(self, entry_id: int, **kwargs) -> None:
        entry = self._entries[int(entry_id)]
        for key, value in kwargs.items():
            if value is None:
                continue
            entry[key] = value

    def generate_password(self, length: int, entry_id: int) -> str:
        return f"pw-{entry_id}-{length}"

    def get_seed_phrase(self, entry_id: int) -> str:
        entry = self._entries[int(entry_id)]
        return str(entry.get("seed_phrase", "abandon " * 11 + "about")).strip()

    def get_managed_account_seed(self, entry_id: int) -> str:
        entry = self._entries[int(entry_id)]
        return str(
            entry.get(
                "seed_phrase",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
            )
        ).strip()

    def get_totp_secret(self, entry_id: int) -> str:
        entry = self._entries[int(entry_id)]
        return str(entry.get("secret", "JBSWY3DPEHPK3PXP"))

    def get_totp_code(self, entry_id: int) -> str:
        _ = entry_id
        return "123456"

    def export_totp_entries(self) -> dict:
        payload: dict[str, dict[str, object]] = {}
        for entry_id, entry in self._entries.items():
            if str(entry.get("kind")) != "totp":
                continue
            payload[str(entry_id)] = {
                "label": str(entry.get("label", f"totp-{entry_id}")),
                "period": int(entry.get("period", 30)),
                "digits": int(entry.get("digits", 6)),
                "secret": str(entry.get("secret", "JBSWY3DPEHPK3PXP")),
            }
        return payload

    def get_ssh_key_pair(self, entry_id: int):
        entry = self._entries[int(entry_id)]
        return (
            str(entry.get("private_key", "SSH_PRIVATE")),
            str(entry.get("public_key", "ssh-ed25519 AAAA...")),
        )

    def get_pgp_key(self, entry_id: int):
        entry = self._entries[int(entry_id)]
        return (
            str(entry.get("private_key", "-----BEGIN PGP PRIVATE KEY BLOCK-----")),
            str(entry.get("fingerprint", "DEADBEEF")),
        )

    def get_nostr_key_pair(self, entry_id: int):
        entry = self._entries[int(entry_id)]
        return (
            str(entry.get("npub", "npub1example")),
            str(entry.get("nsec", "nsec1example")),
        )

    def get_secret_mode_enabled(self) -> bool:
        return self.secret_mode_enabled

    def get_clipboard_clear_delay(self) -> int:
        return self.clipboard_delay

    def copy_to_clipboard(self, value: str) -> bool:
        self.clipboard_values.append(value)
        return True

    def archive_entry(self, entry_id: int) -> None:
        self._entries[int(entry_id)]["archived"] = True

    def restore_entry(self, entry_id: int) -> None:
        self._entries[int(entry_id)]["archived"] = False

    def get_links(self, entry_id: int):
        return [dict(link) for link in self._links.get(int(entry_id), [])]

    def add_link(
        self,
        entry_id: int,
        target_id: int,
        *,
        relation: str = "related_to",
        note: str = "",
    ):
        links = self._links.setdefault(int(entry_id), [])
        links.append(
            {
                "target": int(target_id),
                "relation": relation,
                "note": note,
            }
        )
        return [dict(link) for link in links]

    def remove_link(
        self, entry_id: int, target_id: int, *, relation: str | None = None
    ):
        src = self._links.setdefault(int(entry_id), [])
        kept = []
        for link in src:
            if int(link.get("target", -1)) != int(target_id):
                kept.append(link)
                continue
            if relation is not None and str(link.get("relation")) != relation:
                kept.append(link)
        self._links[int(entry_id)] = kept
        return [dict(link) for link in kept]

    def load_managed_account(self, entry_id: int) -> None:
        entry = self._entries.get(int(entry_id), {})
        kind = str(entry.get("kind", ""))
        if kind != "managed_account":
            raise ValueError("Entry is not a managed account")
        self.managed_load_calls.append(int(entry_id))

    def exit_managed_account(self) -> None:
        self.managed_exit_calls += 1


class FakeProfileService:
    def __init__(self, profiles: list[str]) -> None:
        self.profiles = list(profiles)
        self.last_switch: tuple[str, str | None] | None = None
        self.add_count = 0
        self.removed: list[str] = []
        self.renamed: dict[str, str] = {}

    def list_profiles(self) -> list[str]:
        return list(self.profiles)

    def switch_profile(self, req) -> None:
        fp = str(getattr(req, "fingerprint", ""))
        pw = getattr(req, "password", None)
        if fp not in self.profiles:
            raise ValueError("profile not found")
        self.last_switch = (fp, pw)

    def add_profile(self) -> str:
        self.add_count += 1
        fp = f"fp-new-{self.add_count}"
        self.profiles.append(fp)
        return fp

    def remove_profile(self, req) -> None:
        fp = str(getattr(req, "fingerprint", ""))
        if fp not in self.profiles:
            raise ValueError("profile not found")
        self.profiles = [item for item in self.profiles if item != fp]
        self.removed.append(fp)

    def rename_profile(self, fingerprint: str, name: str | None) -> None:
        fp = str(fingerprint)
        if fp not in self.profiles:
            raise ValueError("profile not found")
        if not name:
            raise ValueError("name required")
        self.renamed[fp] = str(name)


class FakeConfigService:
    def __init__(self) -> None:
        self.secret_mode_enabled = False
        self.clipboard_delay = 30
        self.offline_mode = True
        self.quick_unlock = False
        self.inactivity_timeout = 300.0
        self.kdf_iterations = 100000
        self.kdf_mode = "pbkdf2"

    def set_secret_mode(self, enabled: bool, delay: int) -> None:
        self.secret_mode_enabled = bool(enabled)
        self.clipboard_delay = int(delay)

    def set_offline_mode(self, enabled: bool) -> None:
        self.offline_mode = bool(enabled)

    def set(self, key: str, value: str) -> None:
        if key == "quick_unlock":
            self.quick_unlock = value.strip().lower() in {
                "1",
                "true",
                "yes",
                "y",
                "on",
            }
            return
        if key == "inactivity_timeout":
            self.inactivity_timeout = float(value)
            return
        if key == "kdf_iterations":
            self.kdf_iterations = int(value)
            return
        if key == "kdf_mode":
            self.kdf_mode = str(value)
            return
        raise KeyError(key)


class FakeNostrService:
    def __init__(self, relays: list[str]) -> None:
        self.relays = list(relays)
        self.account_idx = 0
        self.pubkey = "npub1seedpassprofile"

    def get_pubkey(self) -> str:
        return str(self.pubkey)

    def list_relays(self) -> list[str]:
        return list(self.relays)

    def add_relay(self, url: str) -> None:
        if url in self.relays:
            return
        self.relays.append(url)

    def remove_relay(self, idx: int) -> None:
        if not 1 <= int(idx) <= len(self.relays):
            raise ValueError("invalid relay index")
        self.relays.pop(int(idx) - 1)

    def reset_relays(self) -> list[str]:
        self.relays = ["wss://default-1", "wss://default-2"]
        return list(self.relays)

    def reset_sync_state(self) -> int:
        return int(self.account_idx)

    def start_fresh_namespace(self) -> int:
        self.account_idx += 1
        return int(self.account_idx)


class FakeSyncResult:
    def __init__(self, manifest_id: str) -> None:
        self.manifest_id = manifest_id


class FakeSyncService:
    def __init__(self) -> None:
        self.sync_calls = 0
        self.bg_calls = 0

    def sync(self):
        self.sync_calls += 1
        return FakeSyncResult(f"manifest-{self.sync_calls}")

    def start_background_vault_sync(self) -> None:
        self.bg_calls += 1


class FakeUtilityService:
    def __init__(self) -> None:
        self.verify_calls = 0
        self.update_calls = 0

    def verify_checksum(self) -> None:
        self.verify_calls += 1

    def update_checksum(self) -> None:
        self.update_calls += 1


class FakeVaultService:
    def __init__(self) -> None:
        self.exported: list[Path] = []
        self.imported: list[Path] = []
        self.parent_seed_backups: list[tuple[Path | None, str | None]] = []
        self.lock_calls = 0
        self.unlock_passwords: list[str] = []
        self.locked = False

    def export_vault(self, req) -> None:
        path = Path(getattr(req, "path"))
        self.exported.append(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("vault-export", encoding="utf-8")

    def import_vault(self, req) -> None:
        path = Path(getattr(req, "path"))
        self.imported.append(path)

    def backup_parent_seed(self, req) -> None:
        path = getattr(req, "path", None)
        password = getattr(req, "password", None)
        if path is not None:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("seed-backup", encoding="utf-8")
        self.parent_seed_backups.append((path, password))

    def lock(self) -> None:
        self.lock_calls += 1
        self.locked = True

    def unlock(self, req):
        password = str(getattr(req, "password", ""))
        self.unlock_passwords.append(password)
        if password != "hunter2":
            raise ValueError("invalid password")
        self.locked = False

        class _Resp:
            duration = 0.42

        return _Resp()


class FakeSemanticService:
    def __init__(self) -> None:
        self.enabled = False
        self.built = False
        self.records = 0
        self.mode = "keyword"
        self.last_query: str | None = None

    def status(self):
        return {
            "enabled": bool(self.enabled),
            "built": bool(self.built),
            "records": int(self.records),
            "mode": str(self.mode),
        }

    def set_enabled(self, enabled: bool):
        self.enabled = bool(enabled)
        return self.status()

    def build(self):
        self.built = True
        self.records = 2
        return self.status()

    def rebuild(self):
        self.built = True
        self.records = 2
        return self.status()

    def set_mode(self, mode: str):
        self.mode = str(mode)
        return self.status()

    def search(
        self,
        query: str,
        *,
        k: int = 10,
        kind: str | None = None,
        mode: str | None = None,
    ):
        self.last_query = str(query)
        if mode:
            self.mode = str(mode)
        if not query.strip():
            return []
        return [
            {
                "entry_id": 1,
                "kind": kind or "document",
                "label": "Doc",
                "score": 0.7,
                "excerpt": f"query={query} k={k}",
            }
        ]


def _build_app(
    service: FakeEntryService,
    *,
    profile_service=None,
    config_service=None,
    nostr_service=None,
    sync_service=None,
    utility_service=None,
    vault_service=None,
    semantic_service=None,
):
    holder: dict[str, object] = {}

    def _hook(app):
        holder["app"] = app

    launched = launch_tui2(
        entry_service_factory=lambda: service,
        profile_service_factory=(
            (lambda: profile_service) if profile_service is not None else None
        ),
        config_service_factory=(
            (lambda: config_service) if config_service is not None else None
        ),
        nostr_service_factory=(
            (lambda: nostr_service) if nostr_service is not None else None
        ),
        sync_service_factory=(
            (lambda: sync_service) if sync_service is not None else None
        ),
        utility_service_factory=(
            (lambda: utility_service) if utility_service is not None else None
        ),
        vault_service_factory=(
            (lambda: vault_service) if vault_service is not None else None
        ),
        semantic_service_factory=(
            (lambda: semantic_service) if semantic_service is not None else None
        ),
        app_hook=_hook,
    )
    assert launched is True
    app = holder.get("app")
    assert app is not None
    return app


def _widget_text(app, selector: str) -> str:
    return str(app.query_one(selector).render())


def _status_text(app) -> str:
    return _widget_text(app, "#status")


def _filters_text(app) -> str:
    return _widget_text(app, "#filters")


async def _run_palette(app, pilot, command: str) -> None:
    app.action_open_palette()
    await pilot.pause()
    app._run_palette_command(command)
    app._set_palette_visible(False)
    await pilot.pause()


@pytest.mark.anyio
async def test_tui2_textual_pagination_and_search_flow() -> None:
    entries = [
        {"id": i, "kind": "document", "label": f"Entry {i}", "content": "x"}
        for i in range(1, 451)
    ]
    app = _build_app(FakeEntryService(entries))

    async with app.run_test() as pilot:
        await pilot.pause()
        list_view = app.query_one("#entry-list", ListView)
        assert len(list_view.children) == 200
        assert "Page: 1/3" in _filters_text(app)

        app.action_next_page()
        await pilot.pause()
        assert "Page: 2/3" in _filters_text(app)

        app.action_toggle_density()
        await pilot.pause()
        assert "Density: comfortable" in _status_text(app)
        assert "Density: comfortable" in _filters_text(app)

        app._run_palette_command("density compact")
        await pilot.pause()
        assert "Density set to compact" in _status_text(app)
        assert "Density: compact" in _filters_text(app)

        app.query_one("#search", Input).value = "Entry 44"
        app._load_entries(query="Entry 44", reset_page=True)
        await pilot.pause()
        assert len(list_view.children) == 11
        assert "Page: 1/1" in _filters_text(app)


@pytest.mark.anyio
async def test_tui2_textual_archive_scope_filters() -> None:
    service = FakeEntryService(
        [
            {"id": 1, "kind": "document", "label": "Active Doc", "content": "x"},
            {
                "id": 2,
                "kind": "document",
                "label": "Archived Doc",
                "content": "y",
                "archived": True,
            },
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        list_view = app.query_one("#entry-list", ListView)
        assert len(list_view.children) == 1
        assert "Archive: active" in _filters_text(app)

        app.action_cycle_archive_scope()
        await pilot.pause()
        assert len(list_view.children) == 2
        assert "Archive: all" in _filters_text(app)

        app.action_cycle_archive_scope()
        await pilot.pause()
        assert len(list_view.children) == 1
        assert "Archive: archived" in _filters_text(app)
        assert app._entry_ids_in_view == [2]

        await _run_palette(app, pilot, "archive-filter active")
        assert len(list_view.children) == 1
        assert "Archive: active" in _filters_text(app)


@pytest.mark.anyio
async def test_tui2_textual_document_edit_save_flow() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "document",
                "label": "Doc A",
                "content": "hello",
                "file_type": "txt",
                "tags": ["alpha"],
            }
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_edit_document()
        await pilot.pause()

        app.query_one("#doc-edit-label", Input).value = "Doc A Updated"
        app.query_one("#doc-edit-file-type", Input).value = "md"
        app.query_one("#doc-edit-tags", Input).value = "alpha, beta"
        if len(app.query("#doc-edit-content")) > 0:
            area = app.query_one("#doc-edit-content")
            if hasattr(area, "load_text"):
                area.load_text("new content")
            else:
                area.text = "new content"
        else:
            app.query_one("#doc-edit-content-single", Input).value = "new content"

        app.action_save_document()
        await pilot.pause()

        entry = service.retrieve_entry(1)
        assert entry["label"] == "Doc A Updated"
        assert entry["file_type"] == "md"
        assert entry["tags"] == ["alpha", "beta"]
        assert "Saved document 1" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_link_commands_and_neighbor_open() -> None:
    service = FakeEntryService(
        [
            {"id": 1, "kind": "document", "label": "Doc 1", "content": "a"},
            {"id": 2, "kind": "password", "label": "Login 2"},
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        await _run_palette(app, pilot, "link-add 2 references rel-note")
        links_text = _widget_text(app, "#link-detail")
        assert "references -> 2 (rel-note)" in links_text

        app.action_open_link_target()
        await pilot.pause()
        assert "Opened linked entry 2" in _status_text(app)

        await _run_palette(app, pilot, "link-rm 2 references")
        links_text = _widget_text(app, "#link-detail")
        assert "No graph links" in links_text


@pytest.mark.anyio
async def test_tui2_textual_palette_help_commands_reference() -> None:
    service = FakeEntryService([{"id": 1, "kind": "document", "label": "Doc 1"}])
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        await _run_palette(app, pilot, "help-commands")
        detail = _widget_text(app, "#entry-detail")
        assert "Palette Reference" in detail
        assert "archive-filter <active|all|archived>" in detail
        assert "npub" in detail
        assert "Displayed full palette command reference" in _status_text(app)

        await _run_palette(app, pilot, "help")
        assert "Palette Reference" in _widget_text(app, "#entry-detail")
        assert "Palette commands:" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_quickstart_and_stats_commands() -> None:
    service = FakeEntryService(
        [
            {"id": 1, "kind": "password", "label": "Login 1", "length": 16},
            {"id": 2, "kind": "document", "label": "Doc 2", "content": "x"},
            {"id": 3, "kind": "totp", "label": "Auth 3", "secret": "JBSWY3DPEHPK3PXP"},
            {"id": 4, "kind": "seed", "label": "Seed 4", "archived": True},
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        await _run_palette(app, pilot, "onboarding")
        detail = _widget_text(app, "#entry-detail")
        assert "Onboarding Quick Start" in detail
        assert "Step 1: Create your first entry" in detail
        assert "Displayed onboarding guide" in _status_text(app)

        await _run_palette(app, pilot, "quickstart")
        detail = _widget_text(app, "#entry-detail")
        assert "Onboarding Quick Start" in detail
        assert "add-password" in detail
        assert "Displayed quick start guide" in _status_text(app)

        await _run_palette(app, pilot, "stats")
        detail = _widget_text(app, "#entry-detail")
        assert "Vault Stats" in detail
        assert "Total entries: 4" in detail
        assert "Archived entries: 1" in detail
        assert "- password: 1" in detail
        assert "Displayed vault stats" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_empty_vault_shows_quickstart() -> None:
    app = _build_app(FakeEntryService([]))
    async with app.run_test() as pilot:
        await pilot.pause()
        detail = _widget_text(app, "#entry-detail")
        assert "Onboarding Quick Start" in detail
        assert "add-password" in detail
        assert "Vault is empty." in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_reveal_and_qr_flow() -> None:
    service = FakeEntryService(
        [
            {"id": 1, "kind": "password", "label": "Login 1", "length": 16},
            {
                "id": 2,
                "kind": "seed",
                "label": "Seed 2",
                "seed_phrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            },
            {
                "id": 3,
                "kind": "totp",
                "label": "TOTP 3",
                "secret": "JBSWY3DPEHPK3PXP",
                "period": 30,
                "digits": 6,
            },
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("open 1")
        app.action_reveal_selected()
        await pilot.pause()
        assert "Password : pw-1-16" in _widget_text(app, "#secret-detail")

        app._run_palette_command("open 2")
        app.action_show_qr()
        await pilot.pause()
        qr_text = _widget_text(app, "#secret-detail")
        assert "Seed #2 QR" in qr_text
        assert "Payload:" in qr_text

        app._run_palette_command("open 3")
        app._run_palette_command("reveal")
        await pilot.pause()
        assert "Secret : JBSWY3DPEHPK3PXP" in _widget_text(app, "#secret-detail")

        app._run_palette_command("qr")
        await pilot.pause()
        assert "TOTP #3 QR" in _widget_text(app, "#secret-detail")


@pytest.mark.anyio
async def test_tui2_textual_managed_account_keyboard_reveal_and_qr() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "managed_account",
                "label": "Acct 1",
                "seed_phrase": (
                    "legal winner thank year wave sausage worth useful "
                    "legal winner thank yellow"
                ),
            }
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        app._run_palette_command("open 1")
        await pilot.pause()
        app.query_one("#entry-list", ListView).focus()
        await pilot.pause()

        await pilot.press("v")
        await pilot.pause()
        assert "requires confirmation" in _status_text(app)
        assert "Run: reveal confirm" in _widget_text(app, "#secret-detail")

        await pilot.press("g")
        await pilot.pause()
        qr_text = _widget_text(app, "#secret-detail")
        assert "Managed Account Seed #1 QR" in qr_text
        assert "Payload:" in qr_text


@pytest.mark.anyio
async def test_tui2_textual_default_focus_keeps_sensitive_hotkeys_active() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "managed_account",
                "label": "Acct 1",
                "seed_phrase": (
                    "legal winner thank year wave sausage worth useful "
                    "legal winner thank yellow"
                ),
            }
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        assert getattr(app.focused, "id", None) == "entry-list"

        await pilot.press("v")
        await pilot.pause()
        assert "requires confirmation" in _status_text(app)
        assert "Run: reveal confirm" in _widget_text(app, "#secret-detail")

        await pilot.press("g")
        await pilot.pause()
        qr_text = _widget_text(app, "#secret-detail")
        assert "Managed Account Seed #1 QR" in qr_text
        assert "Payload:" in qr_text


@pytest.mark.anyio
async def test_tui2_textual_compact_layout_hides_link_panel_and_can_restore() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "document",
                "label": "Doc 1",
                "notes": "compact note",
                "tags": ["alpha", "beta"],
            }
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        link_detail = app.query_one("#link-detail", Static)
        assert link_detail.has_class("hidden")
        assert "Compact" in _widget_text(app, "#action-strip")
        detail = _widget_text(app, "#entry-detail")
        assert "Compact: Notes/Tags shown inline." in detail
        assert "Tags: alpha, beta" in detail
        assert "Notes: compact note" in detail

        app._update_responsive_layout(width=220)
        await pilot.pause()
        assert not link_detail.has_class("hidden")

        app._update_responsive_layout(width=120)
        await pilot.pause()
        assert link_detail.has_class("hidden")
        assert "Compact" in _widget_text(app, "#action-strip")


@pytest.mark.anyio
async def test_tui2_textual_viewport_balance_hides_activity_on_short_height() -> None:
    service = FakeEntryService([{"id": 1, "kind": "document", "label": "Doc 1"}])
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        activity = app.query_one("#activity", Static)
        assert activity.has_class("hidden")

        app._update_responsive_layout(width=120, height=28)
        await pilot.pause()
        assert activity.has_class("hidden")

        app._update_responsive_layout(width=170, height=46)
        await pilot.pause()
        assert not activity.has_class("hidden")


@pytest.mark.anyio
async def test_tui2_textual_ssh_pgp_nostr_boards_show_action_fidelity() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "ssh",
                "label": "SSH 1",
                "private_key": "SSH_PRIVATE_1",
                "public_key": "ssh-ed25519 AAAA-1",
            },
            {
                "id": 2,
                "kind": "pgp",
                "label": "PGP 2",
                "private_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                "fingerprint": "FPR-2",
            },
            {
                "id": 3,
                "kind": "nostr",
                "label": "Nostr 3",
                "npub": "npub1abc",
                "nsec": "nsec1abc",
            },
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("open 1")
        await pilot.pause()
        board = _widget_text(app, "#entry-detail")
        assert "SSH Board" in board
        assert "▣ Copy Public" in board
        assert "▣ Reveal Private" in board

        app._run_palette_command("open 2")
        await pilot.pause()
        board = _widget_text(app, "#entry-detail")
        assert "PGP Board" in board
        assert "Fingerprint: FPR-2" in board
        assert "▣ Export Private" in board

        app._run_palette_command("open 3")
        await pilot.pause()
        board = _widget_text(app, "#entry-detail")
        assert "Nostr Board" in board
        assert "▣ QR Public" in board
        assert "▣ QR Private" in board


@pytest.mark.anyio
async def test_tui2_textual_seed_and_managed_seed_boards_show_fidelity() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "seed",
                "label": "Seed 1",
                "seed_phrase": (
                    "abandon abandon abandon abandon abandon abandon "
                    "abandon abandon abandon abandon abandon about"
                ),
                "index": 1,
            },
            {
                "id": 2,
                "kind": "managed_account",
                "label": "Managed 2",
                "seed_phrase": (
                    "legal winner thank year wave sausage worth useful "
                    "legal winner thank yellow"
                ),
                "index": 2,
            },
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("open 1")
        await pilot.pause()
        board = _widget_text(app, "#entry-detail")
        assert "BIP-39 Seed Board" in board
        assert "Word Count: 12" in board
        assert "copy seed confirm" in board

        app._run_palette_command("open 2")
        await pilot.pause()
        board = _widget_text(app, "#entry-detail")
        assert "Managed Account Seed Board" in board
        assert "Word Count: 12" in board
        assert "export-field seed <path> confirm" in board


@pytest.mark.anyio
async def test_tui2_textual_note_and_totp_boards_include_common_metadata() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "document",
                "label": "Note 1",
                "content": "hello",
                "file_type": "md",
                "index": 1,
            },
            {
                "id": 2,
                "kind": "totp",
                "label": "Auth 2",
                "secret": "JBSWY3DPEHPK3PXP",
                "period": 30,
                "digits": 6,
                "index": 2,
            },
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("open 1")
        await pilot.pause()
        board = _widget_text(app, "#entry-detail")
        assert "Note Board" in board
        assert "Kind: document | Modified:" in board
        assert "Index Num*:" in board

        app._run_palette_command("open 2")
        await pilot.pause()
        board = _widget_text(app, "#entry-detail")
        assert "2FA Board" in board
        assert "Kind: totp | Modified:" in board
        assert "Index Num*:" in board


@pytest.mark.anyio
async def test_tui2_textual_filters_panel_tracks_selected_entry() -> None:
    service = FakeEntryService(
        [
            {"id": 1, "kind": "password", "label": "Login 1", "length": 16},
            {"id": 2, "kind": "managed_account", "label": "Acct 2", "index": 2},
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        filters_text = _widget_text(app, "#filters")
        assert "Selected: #1" in filters_text
        assert "Login 1" in filters_text

        app._run_palette_command("open 2")
        await pilot.pause()
        filters_text = _widget_text(app, "#filters")
        assert "Selected: #2" in filters_text
        assert "Acct 2" in filters_text


@pytest.mark.anyio
async def test_tui2_textual_sensitive_confirm_and_secret_mode_clipboard() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "ssh",
                "label": "SSH 1",
                "private_key": "SSH_PRIVATE_1",
                "public_key": "ssh-ed25519 AAAA-1",
            },
            {
                "id": 2,
                "kind": "nostr",
                "label": "Nostr 2",
                "npub": "npub1abc",
                "nsec": "nsec1abc",
            },
        ]
    )
    service.secret_mode_enabled = True
    service.clipboard_delay = 45
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("open 1")
        app._run_palette_command("reveal")
        await pilot.pause()
        assert "requires confirmation" in _status_text(app)

        app._run_palette_command("reveal confirm")
        await pilot.pause()
        assert "copied to clipboard" in _widget_text(app, "#secret-detail")
        assert service.clipboard_values[-1] == "SSH_PRIVATE_1"

        app._run_palette_command("open 2")
        app._run_palette_command("qr private")
        await pilot.pause()
        assert "requires confirmation" in _status_text(app)

        app._run_palette_command("qr private confirm")
        await pilot.pause()
        assert "Nostr #2 QR" in _widget_text(app, "#secret-detail")


@pytest.mark.anyio
async def test_tui2_textual_copy_command_for_core_and_advanced_fields(tmp_path) -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "password",
                "label": "Login 1",
                "length": 16,
                "username": "alice",
                "url": "https://example.com",
            },
            {
                "id": 2,
                "kind": "ssh",
                "label": "SSH 2",
                "private_key": "SSH_PRIVATE_2",
                "public_key": "ssh-ed25519 AAAA-2",
            },
            {
                "id": 3,
                "kind": "nostr",
                "label": "Nostr 3",
                "npub": "npub3",
                "nsec": "nsec3",
            },
            {
                "id": 4,
                "kind": "key_value",
                "label": "KV 4",
                "key": "TOKEN",
                "value": "abc123",
            },
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("open 1")
        app._run_palette_command("copy password")
        await pilot.pause()
        assert "copy password is sensitive" in _status_text(app)

        app._run_palette_command("copy password confirm")
        await pilot.pause()
        assert "Copied password to clipboard" in _status_text(app)
        assert service.clipboard_values[-1] == "pw-1-16"

        app._run_palette_command("copy username")
        await pilot.pause()
        assert "Copied username to clipboard" in _status_text(app)
        assert service.clipboard_values[-1] == "alice"

        app._run_palette_command("open 2")
        app._run_palette_command("copy private")
        await pilot.pause()
        assert "copy private_key is sensitive" in _status_text(app)
        app._run_palette_command("copy private confirm")
        await pilot.pause()
        assert "Copied private_key to clipboard" in _status_text(app)
        assert service.clipboard_values[-1] == "SSH_PRIVATE_2"

        app._run_palette_command("open 3")
        app._run_palette_command("copy npub")
        await pilot.pause()
        assert "Copied npub to clipboard" in _status_text(app)
        assert service.clipboard_values[-1] == "npub3"

        app._run_palette_command("copy nsec confirm")
        await pilot.pause()
        assert "Copied nsec to clipboard" in _status_text(app)
        assert service.clipboard_values[-1] == "nsec3"

        app._run_palette_command("open 4")
        app._run_palette_command("copy value confirm")
        await pilot.pause()
        assert "Copied value to clipboard" in _status_text(app)
        assert service.clipboard_values[-1] == "abc123"

        app._run_palette_command("export-field value value.txt confirm")
        await pilot.pause()
        assert "Exported value to" in _status_text(app)
        assert (Path.cwd() / "value.txt").exists()
        assert (Path.cwd() / "value.txt").read_text(encoding="utf-8") == "abc123"
        (Path.cwd() / "value.txt").unlink(missing_ok=True)

        out_file = tmp_path / "nostr.nsec"
        app._run_palette_command("open 3")
        app._run_palette_command(f"export-field nsec {out_file}")
        await pilot.pause()
        assert "export-field nsec is sensitive" in _status_text(app)

        app._run_palette_command(f"export-field nsec {out_file} confirm")
        await pilot.pause()
        assert "Exported nsec to" in _status_text(app)
        assert out_file.read_text(encoding="utf-8") == "nsec3"

        app._run_palette_command("open 4")
        app._run_palette_command("copy bogus")
        await pilot.pause()
        assert "copy field unsupported for key_value" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_retry_after_search_failure() -> None:
    service = FakeEntryService(
        [{"id": 1, "kind": "document", "label": "Doc 1", "content": "a"}],
        fail_search_times=1,
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        assert "Failed to load entries" in _status_text(app)

        app.action_retry_last_error()
        await pilot.pause()

        list_view = app.query_one("#entry-list", ListView)
        assert len(list_view.children) == 1
        assert "retry" not in _status_text(app).lower()


@pytest.mark.anyio
async def test_tui2_textual_palette_add_commands() -> None:
    service = FakeEntryService([{"id": 1, "kind": "document", "label": "Start"}])
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("add-password Login 20 alice https://example.com")
        await pilot.pause()
        assert "Added password entry #2" in _status_text(app)
        assert service.retrieve_entry(2)["kind"] == "password"

        app._run_palette_command("add-totp Auth 45 8 JBSWY3DPEHPK3PXP")
        await pilot.pause()
        assert "Added TOTP entry #3" in _status_text(app)
        assert service.retrieve_entry(3)["period"] == 45
        assert service.retrieve_entry(3)["digits"] == 8

        app._run_palette_command("add-key-value Env API_KEY abc123")
        await pilot.pause()
        assert "Added key/value entry #4" in _status_text(app)
        assert service.retrieve_entry(4)["value"] == "abc123"

        app._run_palette_command("add-document Notes md body")
        await pilot.pause()
        assert "Added document entry #5" in _status_text(app)
        assert service.retrieve_entry(5)["file_type"] == "md"

        app._run_palette_command("add-ssh HostKey 7")
        await pilot.pause()
        assert "Added SSH entry #6" in _status_text(app)
        assert service.retrieve_entry(6)["kind"] == "ssh"

        app._run_palette_command("add-pgp PgpKey 8 ed25519 user@example.com")
        await pilot.pause()
        assert "Added PGP entry #7" in _status_text(app)
        assert service.retrieve_entry(7)["kind"] == "pgp"

        app._run_palette_command("add-nostr NostrKey 9")
        await pilot.pause()
        assert "Added Nostr entry #8" in _status_text(app)
        assert service.retrieve_entry(8)["kind"] == "nostr"

        app._run_palette_command("add-seed TravelSeed 12 10")
        await pilot.pause()
        assert "Added seed entry #9" in _status_text(app)
        assert service.retrieve_entry(9)["kind"] == "seed"

        app._run_palette_command("add-managed-account Managed 11")
        await pilot.pause()
        assert "Added managed account entry #10" in _status_text(app)
        assert service.retrieve_entry(10)["kind"] == "managed_account"


@pytest.mark.anyio
async def test_tui2_textual_palette_add_commands_validation_errors() -> None:
    service = FakeEntryService([{"id": 1, "kind": "document", "label": "Start"}])
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("add-password Login not-a-number")
        await pilot.pause()
        assert "length must be an integer" in _status_text(app)

        app._run_palette_command("add-totp Auth bad 8")
        await pilot.pause()
        assert "period must be an integer" in _status_text(app)

        app._run_palette_command("add-key-value only-two-args key")
        await pilot.pause()
        assert "Usage: add-key-value <label> <key> <value>" in _status_text(app)

        app._run_palette_command("add-document too few")
        await pilot.pause()
        assert "Usage: add-document <label> <file_type> <content>" in _status_text(app)

        app._run_palette_command("add-ssh Host abc")
        await pilot.pause()
        assert "add-ssh index must be an integer" in _status_text(app)

        app._run_palette_command("add-pgp Pgp nope")
        await pilot.pause()
        assert "add-pgp index must be an integer" in _status_text(app)

        app._run_palette_command("add-nostr Nostr nope")
        await pilot.pause()
        assert "add-nostr index must be an integer" in _status_text(app)

        app._run_palette_command("add-seed Seed nope")
        await pilot.pause()
        assert "add-seed words must be an integer" in _status_text(app)

        app._run_palette_command("add-managed-account Managed nope")
        await pilot.pause()
        assert "add-managed-account index must be an integer" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_palette_notes_tags_fields_and_doc_export(
    tmp_path: Path,
) -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "document",
                "label": "Runbook",
                "content": "line-1\nline-2",
                "file_type": "md",
                "notes": "old",
                "tags": ["alpha"],
                "custom_fields": [
                    {"label": "token", "value": "abc", "is_hidden": False}
                ],
            },
            {"id": 2, "kind": "password", "label": "Login"},
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        app._run_palette_command("open 1")
        await pilot.pause()

        app._run_palette_command('notes-set "updated note"')
        await pilot.pause()
        assert service.retrieve_entry(1)["notes"] == "updated note"

        app._run_palette_command("tag-add beta")
        await pilot.pause()
        assert "beta" in service.retrieve_entry(1).get("tags", [])

        app._run_palette_command("tag-rm alpha")
        await pilot.pause()
        assert "alpha" not in service.retrieve_entry(1).get("tags", [])

        app._run_palette_command("tags-set gamma, delta")
        await pilot.pause()
        assert service.retrieve_entry(1).get("tags", []) == ["gamma", "delta"]

        app._run_palette_command("field-add api_key secret hidden")
        await pilot.pause()
        fields = service.retrieve_entry(1).get("custom_fields", [])
        assert any(
            f.get("label") == "api_key" and f.get("is_hidden") is True for f in fields
        )

        app._run_palette_command("field-rm api_key")
        await pilot.pause()
        fields = service.retrieve_entry(1).get("custom_fields", [])
        assert all(f.get("label") != "api_key" for f in fields)

        out_dir = tmp_path / "exports"
        app._run_palette_command(f"doc-export {out_dir}")
        await pilot.pause()
        exported = out_dir / "Runbook.md"
        assert exported.exists()
        assert exported.read_text(encoding="utf-8") == "line-1\nline-2"
        assert "Exported document to" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_palette_notes_tags_fields_and_doc_export_validation() -> (
    None
):
    service = FakeEntryService(
        [
            {"id": 1, "kind": "document", "label": "Doc", "content": "x"},
            {"id": 2, "kind": "password", "label": "Pw"},
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        app._run_palette_command("notes-set")
        await pilot.pause()
        assert "Usage: notes-set <text>" in _status_text(app)

        app._run_palette_command("notes-clear nope")
        await pilot.pause()
        assert "Usage: notes-clear" in _status_text(app)

        app._run_palette_command("tag-add")
        await pilot.pause()
        assert "Usage: tag-add <tag>" in _status_text(app)

        app._run_palette_command("tag-rm")
        await pilot.pause()
        assert "Usage: tag-rm <tag>" in _status_text(app)

        app._run_palette_command("tags-set")
        await pilot.pause()
        assert "Usage: tags-set <comma-separated tags>" in _status_text(app)

        app._run_palette_command("tags-clear nope")
        await pilot.pause()
        assert "Usage: tags-clear" in _status_text(app)

        app._run_palette_command("field-add one")
        await pilot.pause()
        assert "Usage: field-add <label> <value> (optional: hidden)" in _status_text(
            app
        )

        app._run_palette_command("field-rm")
        await pilot.pause()
        assert "Usage: field-rm <label>" in _status_text(app)

        app._run_palette_command("doc-export one two")
        await pilot.pause()
        assert "Usage: doc-export (optional: output_path)" in _status_text(app)

        app._run_palette_command("open 2")
        await pilot.pause()
        app._run_palette_command("doc-export")
        await pilot.pause()
        assert "doc-export requires selected document entry" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_palette_set_clear_field_non_document_kinds() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "password",
                "label": "Login",
                "username": "alice",
                "url": "https://old",
                "length": 16,
                "notes": "old",
            },
            {
                "id": 2,
                "kind": "totp",
                "label": "Auth",
                "period": 30,
                "digits": 6,
                "notes": "old",
            },
            {
                "id": 3,
                "kind": "key_value",
                "label": "Env",
                "key": "API_KEY",
                "value": "v1",
                "notes": "old",
            },
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("open 1")
        await pilot.pause()
        app._run_palette_command("set-field username bob")
        app._run_palette_command("set-field url https://new")
        app._run_palette_command("set-field length 24")
        await pilot.pause()
        pw = service.retrieve_entry(1)
        assert pw["username"] == "bob"
        assert pw["url"] == "https://new"
        assert pw["length"] == 24
        app._run_palette_command("clear-field username")
        await pilot.pause()
        assert service.retrieve_entry(1)["username"] == ""

        app._run_palette_command("open 2")
        await pilot.pause()
        app._run_palette_command("set-field period 45")
        app._run_palette_command("set-field digits 8")
        await pilot.pause()
        totp = service.retrieve_entry(2)
        assert totp["period"] == 45
        assert totp["digits"] == 8

        app._run_palette_command("open 3")
        await pilot.pause()
        app._run_palette_command("set-field key TOKEN")
        app._run_palette_command("set-field value v2")
        app._run_palette_command("clear-field value")
        await pilot.pause()
        kv = service.retrieve_entry(3)
        assert kv["key"] == "TOKEN"
        assert kv["value"] == ""


@pytest.mark.anyio
async def test_tui2_textual_palette_set_clear_field_validation() -> None:
    service = FakeEntryService(
        [
            {"id": 1, "kind": "password", "label": "Login", "length": 16},
            {"id": 2, "kind": "totp", "label": "Auth"},
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        app._run_palette_command("set-field")
        await pilot.pause()
        assert "Usage: set-field <name> <value>" in _status_text(app)

        app._run_palette_command("clear-field")
        await pilot.pause()
        assert "Usage: clear-field <name>" in _status_text(app)

        app._run_palette_command("open 1")
        await pilot.pause()
        app._run_palette_command("set-field length nope")
        await pilot.pause()
        assert "set-field length must be an integer" in _status_text(app)

        app._run_palette_command("set-field period 30")
        await pilot.pause()
        assert "not supported for kind 'password'" in _status_text(app)

        app._run_palette_command("clear-field period")
        await pilot.pause()
        assert "not supported for kind 'password'" in _status_text(app)

        app._run_palette_command("open 2")
        await pilot.pause()
        app._run_palette_command("set-field digits nope")
        await pilot.pause()
        assert "set-field digits must be an integer" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_2fa_board_view_timer_and_copy() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "totp",
                "label": "Det Auth",
                "period": 30,
                "digits": 6,
                "deterministic": True,
            },
            {
                "id": 2,
                "kind": "totp",
                "label": "Imported Auth",
                "period": 45,
                "digits": 6,
                "secret": "JBSWY3DPEHPK3PXP",
                "deterministic": False,
            },
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        app._time_now = lambda: 91
        app._run_palette_command("2fa-board")
        await pilot.pause()
        board_text = _widget_text(app, "#totp-board")
        assert "2FA Board" in board_text
        assert "Det Auth" in board_text
        assert "Imported Auth" in board_text
        assert "det=deterministic, imp=imported" in board_text
        assert "29" in board_text or "14" in board_text

        app._run_palette_command("2fa-copy 1")
        await pilot.pause()
        assert service.clipboard_values[-1] == "123456"
        assert "Copied TOTP code for entry 1" in _status_text(app)

        app._run_palette_command("2fa-copy-url 1")
        await pilot.pause()
        copied_uri = service.clipboard_values[-1]
        assert copied_uri.startswith("otpauth://totp/")
        assert "secret=" in copied_uri
        assert "Copied TOTP URL for entry 1" in _status_text(app)

        app._run_palette_command("2fa-refresh")
        await pilot.pause()
        assert "2FA board refreshed" in _status_text(app)

        app.action_toggle_totp_board()
        await pilot.pause()
        assert "2FA board closed" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_2fa_board_secret_mode_and_validation() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "totp",
                "label": "Auth",
                "period": 30,
                "digits": 6,
                "secret": "JBSWY3DPEHPK3PXP",
            }
        ]
    )
    service.secret_mode_enabled = True
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        app._time_now = lambda: 100
        app._run_palette_command("2fa-copy")
        await pilot.pause()
        assert "Usage: 2fa-copy <entry_id>" in _status_text(app)

        app._run_palette_command("2fa-copy nope")
        await pilot.pause()
        assert "2fa-copy entry_id must be an integer" in _status_text(app)

        app._run_palette_command("2fa-copy-url")
        await pilot.pause()
        assert "Usage: 2fa-copy-url <entry_id>" in _status_text(app)

        app._run_palette_command("2fa-copy-url nope")
        await pilot.pause()
        assert "2fa-copy-url entry_id must be an integer" in _status_text(app)

        app._run_palette_command("2fa-board")
        await pilot.pause()
        board_text = _widget_text(app, "#totp-board")
        assert "******" in board_text
        assert "123456" not in board_text
        assert "2fa-copy-url <entry_id>" in board_text

        app._run_palette_command("2fa-hide")
        await pilot.pause()
        assert "2FA board closed" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_profiles_and_settings_palette_commands() -> None:
    service = FakeEntryService([{"id": 1, "kind": "document", "label": "Doc"}])
    profiles = FakeProfileService(["fp-a", "fp-b"])
    config = FakeConfigService()
    nostr = FakeNostrService(["wss://r1", "wss://r2"])
    sync = FakeSyncService()
    utility = FakeUtilityService()
    vault = FakeVaultService()
    semantic = FakeSemanticService()
    app = _build_app(
        service,
        profile_service=profiles,
        config_service=config,
        nostr_service=nostr,
        sync_service=sync,
        utility_service=utility,
        vault_service=vault,
        semantic_service=semantic,
    )

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("profiles-list")
        await pilot.pause()
        assert "Profiles (2): fp-a, fp-b" in _status_text(app)

        app.action_focus_left()
        await pilot.pause()
        app.action_profile_tree_next()
        await pilot.pause()
        assert "Profile selection: fp-b" in _status_text(app)

        app.action_profile_tree_open()
        await pilot.pause()
        assert profiles.last_switch == ("fp-b", None)
        assert "Switched profile to fp-b" in _status_text(app)

        app._run_palette_command("profile-switch fp-b")
        await pilot.pause()
        assert profiles.last_switch == ("fp-b", None)
        assert "Switched profile to fp-b" in _status_text(app)

        app._run_palette_command("setting-secret on 42")
        await pilot.pause()
        assert config.secret_mode_enabled is True
        assert config.clipboard_delay == 42
        assert "Secret mode on (delay 42s)" in _status_text(app)

        app._run_palette_command("setting-offline off")
        await pilot.pause()
        assert config.offline_mode is False
        assert "Offline mode off" in _status_text(app)

        app._run_palette_command("setting-quick-unlock on")
        await pilot.pause()
        assert config.quick_unlock is True
        assert "Quick unlock on" in _status_text(app)

        app._run_palette_command("setting-timeout 600")
        await pilot.pause()
        assert config.inactivity_timeout == 600.0
        assert "Inactivity timeout set to 600.0s" in _status_text(app)

        app._run_palette_command("setting-kdf-iterations 200000")
        await pilot.pause()
        assert config.kdf_iterations == 200000
        assert "KDF iterations set to 200000" in _status_text(app)

        app._run_palette_command("setting-kdf-mode argon2")
        await pilot.pause()
        assert config.kdf_mode == "argon2"
        assert "KDF mode set to argon2" in _status_text(app)

        app._run_palette_command("semantic-status")
        await pilot.pause()
        assert "Displayed semantic index status" in _status_text(app)

        app._run_palette_command("semantic-enable")
        await pilot.pause()
        assert semantic.enabled is True
        assert "Semantic index enabled" in _status_text(app)

        app._run_palette_command("search-mode hybrid")
        await pilot.pause()
        assert semantic.mode == "hybrid"
        assert "Search mode set to hybrid" in _status_text(app)

        app._run_palette_command("semantic-build")
        await pilot.pause()
        assert semantic.built is True
        assert "Semantic index built" in _status_text(app)

        app._run_palette_command("semantic-search relay recovery")
        await pilot.pause()
        assert semantic.last_query == "relay recovery"
        assert "Semantic matches: 1 for 'relay recovery'" in _status_text(app)

        app._run_palette_command("semantic-rebuild")
        await pilot.pause()
        assert "Semantic index rebuilt" in _status_text(app)

        app._run_palette_command("semantic-disable")
        await pilot.pause()
        assert semantic.enabled is False
        assert "Semantic index disabled" in _status_text(app)

        app._run_palette_command("profile-add")
        await pilot.pause()
        assert "Created profile fp-new-1" in _status_text(app)

        app._run_palette_command("profile-remove fp-a")
        await pilot.pause()
        assert "Removed profile fp-a" in _status_text(app)
        assert "fp-a" not in profiles.profiles

        app._run_palette_command("profile-rename fp-b Team Profile")
        await pilot.pause()
        assert "Renamed profile fp-b to 'Team Profile'" in _status_text(app)
        assert profiles.renamed["fp-b"] == "Team Profile"

        app._run_palette_command("relay-list")
        await pilot.pause()
        assert "Relays (2): wss://r1, wss://r2" in _status_text(app)

        app._run_palette_command("npub")
        await pilot.pause()
        assert "Displayed active Nostr pubkey" in _status_text(app)
        assert "npub: npub1seedpassprofile" in _widget_text(app, "#secret-detail")

        app._run_palette_command("relay-add wss://r3")
        await pilot.pause()
        assert "Added relay wss://r3" in _status_text(app)
        assert "wss://r3" in nostr.relays

        app._run_palette_command("relay-rm 3")
        await pilot.pause()
        assert "Removed relay #3" in _status_text(app)

        app._run_palette_command("relay-reset")
        await pilot.pause()
        assert "Relays reset (2)" in _status_text(app)
        assert nostr.relays == ["wss://default-1", "wss://default-2"]

        app._run_palette_command("nostr-reset-sync-state")
        await pilot.pause()
        assert "Nostr sync state reset (account index 0)" in _status_text(app)

        app._run_palette_command("nostr-fresh-namespace")
        await pilot.pause()
        assert "Started fresh Nostr namespace at account index 1" in _status_text(app)
        assert nostr.account_idx == 1

        app._run_palette_command("sync-now")
        await pilot.pause()
        assert "Sync completed manifest manifest-1" in _status_text(app)
        assert sync.sync_calls == 1

        app._run_palette_command("sync-bg")
        await pilot.pause()
        assert "Background sync started" in _status_text(app)
        assert sync.bg_calls == 1

        app._run_palette_command("checksum-verify")
        await pilot.pause()
        assert utility.verify_calls == 1
        assert "Checksum verification complete" in _status_text(app)

        app._run_palette_command("checksum-update")
        await pilot.pause()
        assert utility.update_calls == 1
        assert "Checksum updated" in _status_text(app)

        app._run_palette_command("totp-export /tmp/seedpass-totp-export.json")
        await pilot.pause()
        assert "Exported TOTP entries to" in _status_text(app)

        app._run_palette_command("db-export /tmp/seedpass-db-export.enc")
        await pilot.pause()
        assert Path("/tmp/seedpass-db-export.enc") in vault.exported
        assert "Database exported to /tmp/seedpass-db-export.enc" in _status_text(app)

        app._run_palette_command("db-import /tmp/seedpass-db-export.enc")
        await pilot.pause()
        assert Path("/tmp/seedpass-db-export.enc") in vault.imported
        assert "Database imported from /tmp/seedpass-db-export.enc" in _status_text(app)

        app._run_palette_command(
            "parent-seed-backup /tmp/seedpass-parent-backup.enc pass123"
        )
        await pilot.pause()
        assert vault.parent_seed_backups[-1] == (
            Path("/tmp/seedpass-parent-backup.enc"),
            "pass123",
        )
        assert (
            "Parent seed backup written to /tmp/seedpass-parent-backup.enc"
            in _status_text(app)
        )


@pytest.mark.anyio
async def test_tui2_textual_managed_account_session_palette_commands() -> None:
    service = FakeEntryService(
        [
            {"id": 1, "kind": "managed_account", "label": "Acct"},
            {"id": 2, "kind": "document", "label": "Doc"},
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("managed-load")
        await pilot.pause()
        assert "Loaded managed account session from entry #1" in _status_text(app)
        assert service.managed_load_calls == [1]
        assert "Managed: #1" in _filters_text(app)

        app._run_palette_command("managed-exit")
        await pilot.pause()
        assert "Exited managed account session" in _status_text(app)
        assert service.managed_exit_calls == 1
        assert "Managed: (none)" in _filters_text(app)

        app._run_palette_command("open 2")
        app._run_palette_command("managed-load")
        await pilot.pause()
        assert "Selected entry is not a managed account" in _status_text(app)

        app._run_palette_command("managed-load nope")
        await pilot.pause()
        assert "managed-load entry_id must be an integer" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_profiles_and_settings_palette_validation() -> None:
    service = FakeEntryService([{"id": 1, "kind": "document", "label": "Doc"}])
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        app._run_palette_command("profiles-list")
        await pilot.pause()
        assert "Profile service unavailable" in _status_text(app)

        app._run_palette_command("profile-switch")
        await pilot.pause()
        assert "Profile service unavailable" in _status_text(app)

        app._run_palette_command("setting-secret on")
        await pilot.pause()
        assert "Config service unavailable" in _status_text(app)

        app._run_palette_command("checksum-verify")
        await pilot.pause()
        assert "Utility service unavailable" in _status_text(app)

        app._run_palette_command("semantic-status")
        await pilot.pause()
        assert "Semantic service unavailable" in _status_text(app)

        app._run_palette_command("db-export /tmp/x")
        await pilot.pause()
        assert "Vault service unavailable" in _status_text(app)

        app._run_palette_command("lock")
        await pilot.pause()
        assert "Vault service unavailable" in _status_text(app)

        app._run_palette_command("unlock secret")
        await pilot.pause()
        assert "Vault service unavailable" in _status_text(app)

        app._run_palette_command("totp-export")
        await pilot.pause()
        assert "Usage: totp-export <path>" in _status_text(app)

    profiles = FakeProfileService(["fp-a"])
    config = FakeConfigService()
    app = _build_app(service, profile_service=profiles, config_service=config)
    async with app.run_test() as pilot:
        await pilot.pause()
        app._run_palette_command("profile-switch")
        await pilot.pause()
        assert (
            "Usage: profile-switch <fingerprint> (optional: password)"
            in _status_text(app)
        )

        app._run_palette_command("setting-offline maybe")
        await pilot.pause()
        assert "invalid toggle value 'maybe'" in _status_text(app)

        app._run_palette_command("setting-secret on nope")
        await pilot.pause()
        assert "setting-secret delay must be an integer" in _status_text(app)

        app._run_palette_command("setting-quick-unlock")
        await pilot.pause()
        assert "Usage: setting-quick-unlock <on|off>" in _status_text(app)

        app._run_palette_command("profile-add nope")
        await pilot.pause()
        assert "Usage: profile-add" in _status_text(app)

        app._run_palette_command("profile-remove")
        await pilot.pause()
        assert "Usage: profile-remove <fingerprint>" in _status_text(app)

        app._run_palette_command("profile-rename fp-a")
        await pilot.pause()
        assert "Usage: profile-rename <fingerprint> <name>" in _status_text(app)

        app._run_palette_command("profile-tree-next now")
        await pilot.pause()
        assert "Usage: profile-tree-next" in _status_text(app)

        app._run_palette_command("profile-tree-prev now")
        await pilot.pause()
        assert "Usage: profile-tree-prev" in _status_text(app)

        app._run_palette_command("profile-tree-open now")
        await pilot.pause()
        assert "Usage: profile-tree-open" in _status_text(app)

        app._run_palette_command("relay-list")
        await pilot.pause()
        assert "Nostr service unavailable" in _status_text(app)

        app._run_palette_command("semantic-enable now")
        await pilot.pause()
        assert "Semantic service unavailable" in _status_text(app)

        app._run_palette_command("search-mode semantic")
        await pilot.pause()
        assert "Semantic service unavailable" in _status_text(app)

        app._run_palette_command("semantic-search")
        await pilot.pause()
        assert "Semantic service unavailable" in _status_text(app)

        app._run_palette_command("npub")
        await pilot.pause()
        assert "Nostr service unavailable" in _status_text(app)

        app._run_palette_command("relay-reset")
        await pilot.pause()
        assert "Nostr service unavailable" in _status_text(app)

        app._run_palette_command("nostr-reset-sync-state")
        await pilot.pause()
        assert "Nostr service unavailable" in _status_text(app)

        app._run_palette_command("nostr-fresh-namespace")
        await pilot.pause()
        assert "Nostr service unavailable" in _status_text(app)

        app._run_palette_command("sync-now")
        await pilot.pause()
        assert "Sync service unavailable" in _status_text(app)

    utility = FakeUtilityService()
    vault = FakeVaultService()
    nostr = FakeNostrService(["wss://r1"])
    sync = FakeSyncService()
    semantic = FakeSemanticService()
    app = _build_app(
        service,
        profile_service=profiles,
        config_service=config,
        utility_service=utility,
        vault_service=vault,
        nostr_service=nostr,
        sync_service=sync,
        semantic_service=semantic,
    )
    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("setting-timeout nope")
        await pilot.pause()
        assert "setting-timeout requires numeric seconds" in _status_text(app)

        app._run_palette_command("setting-kdf-iterations nope")
        await pilot.pause()
        assert "setting-kdf-iterations requires integer value" in _status_text(app)

        app._run_palette_command("setting-kdf-mode")
        await pilot.pause()
        assert "Usage: setting-kdf-mode <mode>" in _status_text(app)

        app._run_palette_command("semantic-enable now")
        await pilot.pause()
        assert "Usage: semantic-enable" in _status_text(app)

        app._run_palette_command("search-mode")
        await pilot.pause()
        assert "Usage: search-mode <keyword|hybrid|semantic>" in _status_text(app)

        app._run_palette_command("search-mode nope")
        await pilot.pause()
        assert "search-mode must be one of: keyword, hybrid, semantic" in _status_text(
            app
        )

        app._run_palette_command("semantic-search")
        await pilot.pause()
        assert "Usage: semantic-search <query>" in _status_text(app)

        app._run_palette_command("checksum-update nope")
        await pilot.pause()
        assert "Usage: checksum-update" in _status_text(app)

        app._run_palette_command("db-export")
        await pilot.pause()
        assert "Usage: db-export <path>" in _status_text(app)

        app._run_palette_command("db-import")
        await pilot.pause()
        assert "Usage: db-import <path>" in _status_text(app)

        app._run_palette_command("parent-seed-backup a b c")
        await pilot.pause()
        assert (
            "Usage: parent-seed-backup (optional: path) (optional: password)"
            in _status_text(app)
        )

        app._run_palette_command("nostr-reset-sync-state now")
        await pilot.pause()
        assert "Usage: nostr-reset-sync-state" in _status_text(app)

        app._run_palette_command("nostr-fresh-namespace now")
        await pilot.pause()
        assert "Usage: nostr-fresh-namespace" in _status_text(app)

        app._run_palette_command("npub now")
        await pilot.pause()
        assert "Usage: npub" in _status_text(app)

        app._run_palette_command("managed-load 1 2")
        await pilot.pause()
        assert "Usage: managed-load (optional: entry_id)" in _status_text(app)

        app._run_palette_command("managed-exit now")
        await pilot.pause()
        assert "Usage: managed-exit" in _status_text(app)

        app._run_palette_command("session-status now")
        await pilot.pause()
        assert "Usage: session-status" in _status_text(app)

        app._run_palette_command("lock now")
        await pilot.pause()
        assert "Usage: lock" in _status_text(app)

        app._run_palette_command("unlock")
        await pilot.pause()
        assert "Usage: unlock <password>" in _status_text(app)

        app._run_palette_command("copy")
        await pilot.pause()
        assert "Usage: copy <field> (optional: confirm)" in _status_text(app)

        app._run_palette_command("copy password nope")
        await pilot.pause()
        assert "Usage: copy <field> (optional: confirm)" in _status_text(app)

        app._run_palette_command("export-field")
        await pilot.pause()
        assert "Usage: export-field <field> <path> (optional: confirm)" in _status_text(
            app
        )

        app._run_palette_command("export-field password /tmp/x nope")
        await pilot.pause()
        assert "Usage: export-field <field> <path> (optional: confirm)" in _status_text(
            app
        )

        app._run_palette_command("density")
        await pilot.pause()
        assert "Usage: density <compact|comfortable>" in _status_text(app)

        app._run_palette_command("density noisy")
        await pilot.pause()
        assert "density must be one of: compact, comfortable" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_palette_session_status_lock_and_unlock() -> None:
    service = FakeEntryService(
        [{"id": 1, "kind": "password", "label": "Demo", "username": "a"}]
    )
    vault = FakeVaultService()
    app = _build_app(service, vault_service=vault)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("session-status")
        await pilot.pause()
        assert "Displayed session status" in _status_text(app)
        assert "Vault lock state: unlocked" in _widget_text(app, "#entry-detail")
        assert "Session: unlocked" in _filters_text(app)

        app._run_palette_command("lock")
        await pilot.pause()
        assert "Vault locked" in _status_text(app)
        assert vault.lock_calls == 1
        assert "Session: locked" in _filters_text(app)

        app._run_palette_command("open 1")
        await pilot.pause()
        assert "Vault is locked. Run: unlock <password>" in _status_text(app)

        app._run_palette_command("reveal")
        await pilot.pause()
        assert "Vault is locked. Run: unlock <password>" in _status_text(app)

        app._run_palette_command("unlock wrong")
        await pilot.pause()
        assert "unlock failed: invalid password" in _status_text(app)
        assert vault.unlock_passwords[-1] == "wrong"

        app._run_palette_command("unlock hunter2")
        await pilot.pause()
        assert "Vault unlocked in 0.42s" in _status_text(app)
        assert vault.unlock_passwords[-1] == "hunter2"
        assert "Session: unlocked" in _filters_text(app)
