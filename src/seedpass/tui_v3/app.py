from __future__ import annotations
import time
from typing import Any, Callable

from constants import APP_DIR
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Static
from textual.containers import Horizontal, Vertical
from utils.fingerprint_manager import FingerprintManager

from .widgets.header import AtlasStrip, RibbonHeader
from .widgets.sidebar import SidebarContainer
from .widgets.grid import GridContainer
from .widgets.inspector import BoardContainer, LinkedItemsPanel
from .widgets.palette import CommandPalette
from .widgets.action_bar import ActionBar
from .screens.atlas import AtlasWayfinderScreen
from .screens.settings import SettingsScreen
from .screens.inspector import MaximizedInspectorScreen
from .screens.maintenance import format_status
from .screens.pubkey import NostrPubkeyScreen
from .screens.profile import ProfileManagementScreen
from .screens.relays import RelaysScreen
from .screens.security import BackupParentSeedScreen, ChangePasswordScreen


def render_qr_ascii(data: str) -> str:
    """Render ``data`` as an ASCII QR code."""
    import qrcode

    qr = qrcode.QRCode(border=1)
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    lines: list[str] = []
    for row in matrix:
        lines.append("".join("##" if cell else "  " for cell in row))
    return "\n".join(lines)


class CommandProcessor:
    """Handles logic for palette commands in TUI v3."""

    def __init__(self, app: SeedPassTuiV3):
        self.app = app

    def execute(self, raw: str) -> None:
        import shlex

        try:
            parts = shlex.split(raw)
        except Exception as e:
            self.app.notify(f"Parse error: {e}", severity="error")
            return

        if not parts:
            return
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "help":
            self.app.notify(
                "v3 commands: help, stats, atlas, wayfinder, session-status, lock, unlock <password>, refresh, "
                "search <query>, search-mode <keyword|hybrid|semantic>, sort <relevance|modified_desc|modified_asc|label_asc|kind|created_desc|most_linked>, "
                "filter <all|secrets|docs|keys|2fa>, archived, archive-filter <active|all|archived>, "
                "open <id>, settings, profiles, relay-list, relay-add <url>, relay-rm <idx>, relay-reset, "
                "npub, nostr-pubkey, nostr-reset-sync-state, nostr-fresh-namespace, "
                "sync-now, sync-bg, "
                "checksum-verify, checksum-update, totp-export [path], "
                "setting-secret <on|off>, setting-quick-unlock <on|off>, setting-offline <on|off>, "
                "setting-timeout <s>, setting-kdf-mode <mode>, setting-kdf-iterations <n>, "
                "density <compact|comfortable>, onboarding, "
                "change-password, backup-parent-seed <path> (optional: password), maximize, copy, edit, export, "
                "add, seed-plus, archive, restore, delete, ml, mx, db-export <path>, db-import <path>"
            )
        elif cmd == "stats":
            self.app.notify("Calculating stats...")
            # We reuse the existing stats logic
            if "vault" in self.app.services:
                stats = self.app.services["vault"].stats()
                self.app.notify(f"Total entries: {stats.get('total_entries', 0)}")
        elif cmd in {"atlas", "wayfinder"}:
            self.app.action_open_atlas_wayfinder()
        elif cmd == "session-status":
            self.app.action_session_status()
        elif cmd == "lock":
            self.app.action_lock()
        elif cmd == "unlock":
            if len(args) != 1:
                self.app.notify("Usage: unlock <password>", severity="warning")
                return
            self.app.action_unlock(args[0])
        elif cmd == "refresh":
            self.app.action_refresh()
        elif cmd == "search":
            query = " ".join(args)
            self.app.action_search(query)
        elif cmd == "search-mode":
            if not args:
                self.app.notify(
                    "Usage: search-mode <keyword|hybrid|semantic>", severity="warning"
                )
                return
            self.app.action_set_search_mode(args[0])
        elif cmd == "sort":
            if not args:
                self.app.notify(
                    "Usage: sort <relevance|modified_desc|modified_asc|label_asc|kind|created_desc|most_linked>",
                    severity="warning",
                )
                return
            self.app.action_set_search_sort(args[0])
        elif cmd == "filter":
            if not args:
                self.app.notify(
                    "Usage: filter <all|secrets|docs|keys|2fa>", severity="warning"
                )
                return
            self.app.action_set_kind_filter(args[0])
        elif cmd == "archived":
            self.app.action_toggle_archived_view()
        elif cmd == "open":
            if not args:
                self.app.notify("Usage: open <id>", severity="warning")
                return
            try:
                eid = int(args[0])
                self.app.selected_entry_id = eid
                self.app.notify(f"Opened Entry #{eid}")
            except ValueError:
                self.app.notify("Entry ID must be an integer", severity="error")
        elif cmd == "settings":
            self.app.action_toggle_settings()
        elif cmd == "profiles":
            self.app.action_open_profile_management()
        elif cmd == "relay-list":
            self.app.action_toggle_relays()
        elif cmd in {"npub", "nostr-pubkey"}:
            if args:
                self.app.notify("Usage: npub", severity="warning")
                return
            self.app.action_show_profile_pubkey()
        elif cmd == "nostr-reset-sync-state":
            if args:
                self.app.notify("Usage: nostr-reset-sync-state", severity="warning")
                return
            self.app.action_nostr_reset_sync_state()
        elif cmd == "nostr-fresh-namespace":
            if args:
                self.app.notify("Usage: nostr-fresh-namespace", severity="warning")
                return
            self.app.action_nostr_fresh_namespace()
        elif cmd == "change-password":
            if args:
                self.app.notify("Usage: change-password", severity="warning")
                return
            self.app.action_open_change_password()
        elif cmd == "backup-parent-seed":
            if not args:
                self.app.action_open_backup_parent_seed()
                return
            path = args[0]
            password = args[1] if len(args) > 1 else None
            self.app.action_backup_parent_seed(path, password)
        elif cmd == "maximize":
            self.app.action_maximize_inspector()
        elif cmd == "add":
            self.app.action_add_entry()
        elif cmd == "seed-plus":
            self.app.action_seed_plus()
        elif cmd == "copy":
            self.app.action_copy_selected()
        elif cmd == "edit":
            self.app.action_edit_selected()
        elif cmd == "export":
            self.app.action_export_selected()
        elif cmd == "ml":
            self.app.action_managed_load()
        elif cmd == "mx":
            self.app.action_managed_exit()
        elif cmd in {"archive", "restore"}:
            self.app.action_toggle_archive()
        elif cmd == "delete":
            self.app.action_delete_selected()
        elif cmd == "db-export":
            path = args[0] if args else "backup.enc"
            self.app.action_db_export(path)
        elif cmd == "db-import":
            if not args:
                self.app.notify("Usage: db-import <path>", severity="warning")
                return
            self.app.action_db_import(args[0])
        elif cmd == "checksum-verify":
            self.app.action_checksum_verify()
        elif cmd == "checksum-update":
            self.app.action_checksum_update()
        elif cmd == "totp-export":
            path = args[0] if args else None
            self.app.action_totp_export(path)
        elif cmd == "sync-now":
            self.app.action_sync_now()
        elif cmd == "sync-bg":
            self.app.action_sync_bg()
        elif cmd == "relay-add":
            if not args:
                self.app.notify("Usage: relay-add <url>", severity="warning")
                return
            self.app.action_relay_add(args[0])
        elif cmd == "relay-rm":
            if not args:
                self.app.notify("Usage: relay-rm <idx>", severity="warning")
                return
            try:
                idx = int(args[0])
            except ValueError:
                self.app.notify("relay-rm: index must be an integer", severity="error")
                return
            self.app.action_relay_rm(idx)
        elif cmd == "relay-reset":
            self.app.action_relay_reset()
        elif cmd == "setting-secret":
            if not args:
                self.app.notify("Usage: setting-secret <on|off>", severity="warning")
                return
            self.app.action_setting_secret(args[0])
        elif cmd == "setting-quick-unlock":
            if not args:
                self.app.notify(
                    "Usage: setting-quick-unlock <on|off>", severity="warning"
                )
                return
            self.app.action_setting_quick_unlock(args[0])
        elif cmd == "setting-offline":
            if not args:
                self.app.notify("Usage: setting-offline <on|off>", severity="warning")
                return
            self.app.action_setting_offline(args[0])
        elif cmd == "setting-timeout":
            if not args:
                self.app.notify("Usage: setting-timeout <seconds>", severity="warning")
                return
            self.app.action_setting_timeout(args[0])
        elif cmd == "setting-kdf-mode":
            if not args:
                self.app.notify("Usage: setting-kdf-mode <mode>", severity="warning")
                return
            self.app.action_setting_kdf_mode(args[0])
        elif cmd == "setting-kdf-iterations":
            if not args:
                self.app.notify(
                    "Usage: setting-kdf-iterations <n>", severity="warning"
                )
                return
            self.app.action_setting_kdf_iterations(args[0])
        elif cmd == "archive-filter":
            if not args:
                self.app.notify(
                    "Usage: archive-filter <active|all|archived>", severity="warning"
                )
                return
            self.app.action_archive_filter(args[0])
        elif cmd == "density":
            if not args:
                self.app.notify(
                    "Usage: density <compact|comfortable>", severity="warning"
                )
                return
            self.app.action_set_density(args[0])
        elif cmd in {"onboarding", "welcome", "quickstart"}:
            self.app.action_show_onboarding()
        else:
            self.app.notify(f"Unknown v3 command: {cmd}", severity="warning")


class BrandFingerprint(Static):
    """Placeholder for the top left fingerprint block matching mockups."""

    def render(self) -> str:
        app = self.app
        fp = app.active_breadcrumb or "No Profile"
        return f"{fp}"

    def on_mount(self) -> None:
        self.watch(self.app, "active_breadcrumb", self.refresh)


class MainScreen(Screen):
    def compose(self) -> ComposeResult:
        yield CommandPalette(id="palette")
        with Horizontal(id="body"):
            with Vertical(id="left-pane"):
                yield BrandFingerprint(id="brand-fingerprint")
                yield SidebarContainer(id="sidebar-container")
            with Vertical(id="right-pane"):
                yield RibbonHeader(id="ribbon-header")
                yield AtlasStrip(id="atlas-strip")
                yield GridContainer(id="grid-container")
                with Vertical(id="inspector-pane", classes="hidden"):
                    with Horizontal(id="inspector-header"):
                        yield Static("Inspector Board", id="inspector-heading")
                        yield Button("Close", id="inspector-close", variant="default")
                    yield BoardContainer(id="board-container")
                    yield LinkedItemsPanel(id="linked-items-panel")
        yield ActionBar(id="action-bar")

    def on_mount(self) -> None:
        """Keep keyboard navigation on the main entry grid by default."""
        try:
            self.query_one("#entry-data-table").focus()
        except Exception:
            pass


class StartupScreen(Screen):
    """Profile-selection and unlock screen for TUI v3 startup."""

    BINDINGS = [
        Binding("enter", "submit", "Unlock", show=False),
        Binding("escape", "app.quit", "Quit", show=False),
    ]

    def __init__(
        self,
        *,
        selected_fingerprint: str | None = None,
        prompt: str | None = None,
    ) -> None:
        super().__init__()
        self.selected_fingerprint = selected_fingerprint
        self.prompt = prompt or "Select a seed profile and unlock to continue."

    def compose(self) -> ComposeResult:
        with Vertical(id="startup-shell"):
            yield Label("SeedPass TUI v3", id="startup-title")
            yield Static(self.prompt, id="startup-prompt")
            yield Static("", id="startup-profiles")
            yield Input(placeholder="Profile number", id="startup-profile-choice")
            yield Input(
                placeholder="Master password",
                password=True,
                id="startup-password",
            )
            with Horizontal(id="startup-actions"):
                yield Button("Unlock", id="startup-unlock", variant="primary")
                yield Button("Refresh", id="startup-refresh")
                yield Button("Add New", id="startup-add")
                yield Button("Recover", id="startup-recover")
            yield Static("", id="startup-status")

    def on_mount(self) -> None:
        self.refresh_profiles()

    def refresh_profiles(self) -> None:
        profiles = self.app._list_boot_profiles()
        lines = ["Available Seed Profiles:"]
        if profiles:
            for idx, profile in enumerate(profiles, start=1):
                marker = (
                    " *" if profile["fingerprint"] == self.selected_fingerprint else ""
                )
                lines.append(f"{idx}. {profile['label']}{marker}")
        else:
            lines.append("No existing seed profiles found.")
        lines.append(f"{len(profiles) + 1}. Add a new seed profile")
        lines.append(
            f"{len(profiles) + 2}. Recover existing profile with blank local index"
        )
        lines.append("Q. Exit")
        self.query_one("#startup-profiles", Static).update("\n".join(lines))
        profile_input = self.query_one("#startup-profile-choice", Input)
        if self.selected_fingerprint:
            for idx, profile in enumerate(profiles, start=1):
                if profile["fingerprint"] == self.selected_fingerprint:
                    profile_input.value = str(idx)
                    break
        elif len(profiles) == 1 and not profile_input.value:
            profile_input.value = "1"

    def action_submit(self) -> None:
        self._submit_unlock()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self._submit_unlock()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "startup-unlock":
            self._submit_unlock()
            return
        if button_id == "startup-refresh":
            self.refresh_profiles()
            self._set_status("Profile list refreshed.")
            return
        if button_id == "startup-add":
            self.app.push_screen(CreateProfileScreen())
            return
        if button_id == "startup-recover":
            self.app.push_screen(RecoverProfileScreen())
            return

    def _set_status(self, message: str) -> None:
        self.query_one("#startup-status", Static).update(message)

    def _submit_unlock(self) -> None:
        profiles = self.app._list_boot_profiles()
        choice = self.query_one("#startup-profile-choice", Input).value.strip()
        password = self.query_one("#startup-password", Input).value
        if choice.lower() in {"q", "quit", "exit"}:
            self.app.exit()
            return
        if not choice.isdigit():
            self._set_status("Enter the profile number from the list above.")
            return
        selected = int(choice)
        add_idx = len(profiles) + 1
        recover_idx = len(profiles) + 2
        if selected == add_idx:
            self.app.push_screen(CreateProfileScreen())
            return
        if selected == recover_idx:
            self.app.push_screen(RecoverProfileScreen())
            return
        if not (1 <= selected <= len(profiles)):
            self._set_status("Invalid selection.")
            return
        if not password:
            self._set_status("Enter the master password for the selected profile.")
            return
        fingerprint = profiles[selected - 1]["fingerprint"]
        self.app._bootstrap_profile_session(fingerprint, password)

    DEFAULT_CSS = """
    StartupScreen {
        align: center middle;
        background: #999999;
    }
    #startup-shell {
        width: 90;
        max-width: 90;
        border: heavy black;
        background: #000000;
        color: #ffffff;
        padding: 1 2;
    }
    #startup-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #startup-prompt {
        color: #cccccc;
        margin-bottom: 1;
    }
    #startup-profiles {
        border: solid #ffffff;
        padding: 1;
        margin-bottom: 1;
        min-height: 10;
    }
    #startup-profile-choice, #startup-password {
        margin-bottom: 1;
    }
    #startup-actions {
        height: auto;
        margin-bottom: 1;
    }
    #startup-actions Button {
        margin-right: 1;
    }
    #startup-status {
        min-height: 2;
        color: #daf2e5;
    }
    """


class CreateProfileScreen(Screen):
    """Create a new profile or import an existing seed inside TUI v3."""

    def compose(self) -> ComposeResult:
        with Vertical(id="startup-shell"):
            yield Label("Create Seed Profile", id="startup-title")
            yield Static(
                "Modes: existing, words, generate, nostr, backup. This screen now covers the main legacy onboarding branches inside v3.",
                id="startup-prompt",
            )
            yield Input(
                placeholder="Mode: existing | words | generate | nostr | backup",
                id="create-mode",
            )
            yield Input(
                placeholder="Seed phrase (paste full phrase; for 'words' you can type the 12 words space-separated)",
                id="create-seed",
            )
            yield Input(
                placeholder="Backup path (required for backup mode)",
                id="create-backup-path",
            )
            yield Input(
                placeholder="Continue without remote backup? yes | no (used for nostr mode)",
                id="create-nostr-empty-ok",
            )
            yield Input(
                placeholder="Master password",
                password=True,
                id="create-password",
            )
            with Horizontal(id="startup-actions"):
                yield Button("Word Entry", id="create-words")
                yield Button("Generate Seed", id="create-generate")
                yield Button("Create Profile", id="create-submit", variant="primary")
                yield Button("Back", id="create-back")
            yield Static("", id="create-status")

    def on_mount(self) -> None:
        self.query_one("#create-mode", Input).value = "existing"
        self.query_one("#create-nostr-empty-ok", Input).value = "no"
        self._set_status(
            "Import an existing seed, generate a new one, or restore from Nostr/local backup."
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "create-back":
            self.app.pop_screen()
            return
        if button_id == "create-words":
            self.app.push_screen(SeedWordsScreen(on_done=self._apply_seed_words))
            return
        if button_id == "create-generate":
            self._generate_seed()
            return
        if button_id == "create-submit":
            self._submit()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self._submit()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "create-mode":
            return
        mode = event.value.strip().lower()
        guidance = {
            "existing": "Import an existing seed phrase to create a local profile.",
            "words": "Use guided word entry or paste the full phrase once all 12 words are confirmed.",
            "generate": "Generate a new deterministic seed, then store it safely before finishing setup.",
            "nostr": "Restore from Nostr using the seed phrase. Use 'yes' only if you want to continue without a remote backup present.",
            "backup": "Restore from a local encrypted backup. Provide both the seed phrase and the backup file path.",
        }
        self._set_status(
            guidance.get(
                mode, "Choose a mode: existing, words, generate, nostr, or backup."
            )
        )

    def _set_status(self, message: str) -> None:
        self.query_one("#create-status", Static).update(message)

    def _apply_seed_words(self, seed_phrase: str) -> None:
        self.query_one("#create-mode", Input).value = "words"
        self.query_one("#create-seed", Input).value = seed_phrase
        self._set_status("Seed phrase captured from word-by-word entry.")

    def _generate_seed(self) -> None:
        try:
            seed = self.app._generate_bootstrap_seed()
            self.query_one("#create-mode", Input).value = "generate"
            self.query_one("#create-seed", Input).value = seed
            self._set_status(
                "Generated new seed. Review it carefully and store it before creating the profile."
            )
        except Exception as e:
            self._set_status(f"Seed generation failed: {e}")

    def _submit(self) -> None:
        mode = self.query_one("#create-mode", Input).value.strip().lower() or "existing"
        seed = self.query_one("#create-seed", Input).value.strip()
        backup_path = self.query_one("#create-backup-path", Input).value.strip()
        continue_without_backup = self.query_one(
            "#create-nostr-empty-ok", Input
        ).value.strip().lower() in {"y", "yes", "true", "1"}
        password = self.query_one("#create-password", Input).value
        if not password:
            self._set_status("Enter a master password.")
            return
        try:
            if mode == "generate":
                if not seed:
                    seed = self.app._generate_bootstrap_seed()
                fingerprint = self.app._create_generated_profile(
                    password=password, seed=seed
                )
            elif mode == "nostr":
                if not seed:
                    self._set_status("Enter the seed phrase for Nostr restore.")
                    return
                self._set_status(
                    "Restoring from Nostr — this replays remote events onto the seed. "
                    "Your entries will be recovered from the network. This may take a moment..."
                )
                fingerprint = self.app._restore_from_nostr_profile(
                    seed=seed,
                    password=password,
                    continue_without_backup=continue_without_backup,
                )
                self._set_status(
                    f"Nostr restore complete ({fingerprint[:12]}) — launching session."
                )
            elif mode == "backup":
                if not seed:
                    self._set_status("Enter the seed phrase for backup restore.")
                    return
                if not backup_path:
                    self._set_status("Enter the encrypted backup path for backup mode.")
                    return
                self._set_status(
                    f"Restoring from local backup at {backup_path} — decrypting with your seed and password..."
                )
                fingerprint = self.app._restore_from_backup_profile(
                    seed=seed,
                    password=password,
                    backup_path=backup_path,
                )
                self._set_status(
                    f"Backup restore complete ({fingerprint[:12]}) — launching session."
                )
            else:
                if not seed:
                    self._set_status("Enter the seed phrase to import.")
                    return
                fingerprint = self.app._create_existing_profile(
                    seed=seed,
                    password=password,
                )
                self._set_status(
                    f"Profile imported ({fingerprint[:12]}) — launching session."
                )
            self.app._bootstrap_profile_session(fingerprint, password)
        except Exception as e:
            self._set_status(f"Profile creation failed: {e}")


class SeedWordsScreen(Screen):
    """Guided word-by-word seed entry for onboarding parity."""

    def __init__(self, *, on_done: Callable[[str], None]) -> None:
        super().__init__()
        self._on_done = on_done
        from mnemonic import Mnemonic

        self._mnemonic = Mnemonic("english")

    def compose(self) -> ComposeResult:
        with Vertical(id="startup-shell"):
            yield Label("Enter Seed Words", id="startup-title")
            yield Static(
                "Enter the 12-word seed phrase one word per field, following the legacy flow.",
                id="startup-prompt",
            )
            yield Static("Progress: 0/12 words entered", id="seed-words-progress")
            for idx in range(12):
                yield Input(placeholder=f"Word {idx + 1}", id=f"seed-word-{idx + 1}")
            with Horizontal(id="startup-actions"):
                yield Button("Use Phrase", id="seed-words-submit", variant="primary")
                yield Button("Back", id="seed-words-back")
            yield Static("", id="seed-words-status")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "seed-words-back":
            self.app.pop_screen()
            return
        if event.button.id == "seed-words-submit":
            self._submit()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self._submit()

    def on_input_changed(self, event: Input.Changed) -> None:
        input_id = event.input.id or ""
        if not input_id.startswith("seed-word-"):
            return
        self._refresh_progress()
        value = event.value.strip().lower()
        if not value:
            self.query_one("#seed-words-status", Static).update(
                f"{input_id.replace('seed-word-', 'Word ')} is empty."
            )
            return
        if value not in self._mnemonic.wordlist:
            self.query_one("#seed-words-status", Static).update(
                f"{input_id.replace('seed-word-', 'Word ')} is not in the BIP-39 wordlist."
            )
            return
        self.query_one("#seed-words-status", Static).update(
            f"{input_id.replace('seed-word-', 'Word ')} accepted."
        )

    def _refresh_progress(self) -> None:
        count = 0
        invalid = 0
        for idx in range(12):
            value = self.query_one(f"#seed-word-{idx + 1}", Input).value.strip().lower()
            if not value:
                continue
            count += 1
            if value not in self._mnemonic.wordlist:
                invalid += 1
        suffix = f" | invalid: {invalid}" if invalid else ""
        self.query_one("#seed-words-progress", Static).update(
            f"Progress: {count}/12 words entered{suffix}"
        )

    def _submit(self) -> None:
        words: list[str] = []
        for idx in range(12):
            value = self.query_one(f"#seed-word-{idx + 1}", Input).value.strip().lower()
            if not value:
                self.query_one("#seed-words-status", Static).update(
                    f"Word {idx + 1} is required."
                )
                return
            if value not in self._mnemonic.wordlist:
                self.query_one("#seed-words-status", Static).update(
                    f"Word {idx + 1} is not in the BIP-39 wordlist."
                )
                return
            words.append(value)
        phrase = " ".join(words)
        if not self._mnemonic.check(phrase):
            self.query_one("#seed-words-status", Static).update(
                "The full 12-word phrase failed BIP-39 validation."
            )
            return
        self.app.push_screen(
            SeedWordsReviewScreen(
                phrase=phrase,
                on_confirm=self._confirm_phrase,
            )
        )

    def _confirm_phrase(self, phrase: str) -> None:
        self._on_done(phrase)
        self.app.pop_screen()
        self.app.pop_screen()


class SeedWordsReviewScreen(Screen):
    """Confirmation screen for the assembled seed phrase."""

    def __init__(self, *, phrase: str, on_confirm: Callable[[str], None]) -> None:
        super().__init__()
        self._phrase = phrase
        self._on_confirm = on_confirm

    def compose(self) -> ComposeResult:
        with Vertical(id="startup-shell"):
            yield Label("Review Seed Phrase", id="startup-title")
            yield Static(
                "Confirm this phrase before it is applied to the create flow.",
                id="startup-prompt",
            )
            yield Static(self._phrase, id="seed-review-phrase")
            with Horizontal(id="startup-actions"):
                yield Button(
                    "Confirm Phrase", id="seed-review-confirm", variant="primary"
                )
                yield Button("Edit Words", id="seed-review-back")
            yield Static("", id="seed-review-status")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "seed-review-back":
            self.app.pop_screen()
            return
        if event.button.id == "seed-review-confirm":
            self._on_confirm(self._phrase)


class RecoverProfileScreen(Screen):
    """Recover an existing profile with a blank local index inside TUI v3."""

    def compose(self) -> ComposeResult:
        with Vertical(id="startup-shell"):
            yield Label("Recover Existing Profile", id="startup-title")
            yield Static(
                "This matches the legacy recovery path: select an existing profile, provide the matching seed, and reset the local index.",
                id="startup-prompt",
            )
            yield Static("", id="recover-profiles")
            yield Input(placeholder="Profile number", id="recover-choice")
            yield Input(placeholder="Seed phrase", id="recover-seed")
            yield Input(
                placeholder="Master password",
                password=True,
                id="recover-password",
            )
            with Horizontal(id="startup-actions"):
                yield Button("Recover Profile", id="recover-submit", variant="primary")
                yield Button("Back", id="recover-back")
            yield Static("", id="recover-status")

    def on_mount(self) -> None:
        self.refresh_profiles()
        self._set_status(
            "Recovery resets the local index for the selected profile and rebinds it to the supplied seed phrase."
        )

    def refresh_profiles(self) -> None:
        profiles = self.app._list_boot_profiles()
        lines = ["Available Seed Profiles:"]
        for idx, profile in enumerate(profiles, start=1):
            lines.append(f"{idx}. {profile['label']}")
        self.query_one("#recover-profiles", Static).update("\n".join(lines))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "recover-back":
            self.app.pop_screen()
            return
        if button_id == "recover-submit":
            self._submit()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self._submit()

    def _set_status(self, message: str) -> None:
        self.query_one("#recover-status", Static).update(message)

    def _submit(self) -> None:
        profiles = self.app._list_boot_profiles()
        choice = self.query_one("#recover-choice", Input).value.strip()
        seed = self.query_one("#recover-seed", Input).value.strip()
        password = self.query_one("#recover-password", Input).value
        if not choice.isdigit():
            self._set_status("Enter the profile number to recover.")
            return
        idx = int(choice)
        if not (1 <= idx <= len(profiles)):
            self._set_status("Invalid profile selection.")
            return
        if not seed or not password:
            self._set_status("Seed phrase and master password are required.")
            return
        fingerprint = profiles[idx - 1]["fingerprint"]
        try:
            self.app._recover_profile(
                fingerprint=fingerprint,
                seed=seed,
                password=password,
            )
            self._set_status(
                f"Recovery successful for {fingerprint[:12]} — launching profile session."
            )
            self.app._bootstrap_profile_session(fingerprint, password)
        except Exception as e:
            self._set_status(f"Recovery failed: {e}")


class SeedPassTuiV3(App[None]):
    """
    SeedPass TUI v3 - Rebuilt from scratch for modularity and mockup fidelity.
    """

    CSS = """
    #brand-fingerprint {
        background: #000000;
        color: #ffffff;
        text-style: bold;
        height: 3;
        content-align: center middle;
        border: solid #000000;
        padding: 0;
    }
    #body { height: 1fr; margin: 0 1; }
    #left-pane { width: 35; border: solid black; background: #999999; }
    #right-pane { width: 1fr; border: solid black; background: #999999; margin-left: 0; }
    #inspector-pane { height: 5fr; border-top: heavy black; background: #000000; margin-top: 0; }
    #inspector-pane.hidden { display: none; }
    #inspector-header {
        height: 3;
        layout: horizontal;
        background: #000000;
        color: #ffffff;
        border-bottom: solid #ffffff;
    }
    #inspector-heading {
        width: 1fr;
        background: #000000;
        color: #ffffff;
        padding: 1 1 0 1;
        text-style: bold;
    }
    #inspector-close {
        width: 10;
        min-width: 10;
        height: 1;
        margin: 1 1 0 0;
        background: #ffffff;
        color: #000000;
        border: none;
        text-style: bold;
    }
    
    /* Global classes that might be used by children */
    #sidebar-placeholder, #grid-placeholder, #inspector-placeholder {
        height: 1fr;
        content-align: center middle;
        color: #3ce79c;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("ctrl+p", "open_palette", "Palette", show=True),
        Binding("w", "open_atlas_wayfinder", "Wayfinder", show=True),
        Binding("shift+s", "toggle_settings", "Settings", show=True),
        Binding("shift+a", "add_entry", "Add", show=True),
        Binding("shift+c", "seed_plus", "Seed+", show=True),
        Binding("z", "maximize_inspector", "Maximize", show=True),
        Binding("m", "managed_load", "Load", show=True),
        Binding("shift+m", "managed_exit", "Exit", show=True),
        Binding("e", "edit_selected", "Edit", show=True),
        Binding("x", "export_selected", "Export", show=True),
        Binding("d", "delete_selected", "Delete", show=False),
        Binding("v", "reveal_selected", "Reveal", show=False),
        Binding("g", "show_qr", "QR", show=False),
        Binding("a", "toggle_archive", "Archive", show=False),
        Binding("c", "copy_selected", "Copy", show=False),
    ]

    # Shared Reactive State
    active_fingerprint = reactive("")
    active_breadcrumb = reactive("")
    selected_entry_id = reactive[int | None](None)
    session_locked = reactive(False)
    search_query = reactive("")
    search_mode = reactive("keyword")
    search_sort = reactive("relevance")
    filter_kind = reactive("all")
    show_archived = reactive(False)
    filter_archived_only = reactive(False)
    density_mode = reactive("comfortable")

    # Internal state for sensitive actions
    _pending_sensitive_confirm: tuple[str, int, float] | None = None

    @staticmethod
    def render_qr_ascii(data: str) -> str:
        return render_qr_ascii(data)

    def __init__(
        self,
        fingerprint: str | None = None,
        entry_service_factory: Callable | None = None,
        profile_service_factory: Callable | None = None,
        config_service_factory: Callable | None = None,
        nostr_service_factory: Callable | None = None,
        sync_service_factory: Callable | None = None,
        utility_service_factory: Callable | None = None,
        vault_service_factory: Callable | None = None,
        semantic_service_factory: Callable | None = None,
        atlas_service_factory: Callable | None = None,
        search_service_factory: Callable | None = None,
    ) -> None:
        super().__init__()
        # Store factories
        self.factories = {
            "entry": entry_service_factory,
            "profile": profile_service_factory,
            "config": config_service_factory,
            "nostr": nostr_service_factory,
            "sync": sync_service_factory,
            "utility": utility_service_factory,
            "vault": vault_service_factory,
            "semantic": semantic_service_factory,
            "atlas": atlas_service_factory,
            "search": search_service_factory,
        }
        # Initialized services
        self.services: dict[str, Any] = {}
        self._initial_fingerprint = fingerprint
        self._main_screen_initialized = False

    def on_mount(self) -> None:
        """Initialize provided services or start in profile-unlock mode."""
        self.processor = CommandProcessor(self)
        self._initialize_factory_services()
        if self.services:
            self._enter_main_workspace(initial=True)
        else:
            self.present_startup_screen(
                selected_fingerprint=self._initial_fingerprint,
                prompt="Select a seed profile and unlock to enter SeedPass.",
            )
        # Global UI Heartbeat (for 2FA ticking etc)
        self.set_interval(1.0, self.action_refresh_ui_quiet)

    def _initialize_factory_services(self) -> None:
        for name, factory in self.factories.items():
            if factory:
                try:
                    service = factory()
                except Exception as e:
                    self.log(f"Failed to init service {name}: {e}")
                    continue
                if service is not None:
                    self.services[name] = service

    def _list_boot_profiles(self) -> list[dict[str, str]]:
        try:
            manager = FingerprintManager(APP_DIR)
            return [
                {"fingerprint": fp, "label": manager.display_name(fp)}
                for fp in manager.list_fingerprints()
            ]
        except Exception as e:
            self.log(f"Failed to list startup profiles: {e}")
            return []

    def present_startup_screen(
        self,
        *,
        selected_fingerprint: str | None = None,
        prompt: str | None = None,
    ) -> None:
        self.push_screen(
            StartupScreen(
                selected_fingerprint=selected_fingerprint,
                prompt=prompt,
            )
        )

    def _bootstrap_profile_session(self, fingerprint: str, password: str) -> None:
        try:
            from seedpass.core.api import (
                ConfigService,
                EntryService,
                NostrService,
                ProfileService,
                SearchService,
                SemanticIndexService,
                SyncService,
                UtilityService,
                VaultService,
                AtlasService,
            )
            from seedpass.core.manager import PasswordManager

            pm = PasswordManager(fingerprint=fingerprint, password=password)
            self.services = {
                "entry": EntryService(pm),
                "profile": ProfileService(pm),
                "config": ConfigService(pm),
                "nostr": NostrService(pm),
                "sync": SyncService(pm),
                "utility": UtilityService(pm),
                "vault": VaultService(pm),
                "semantic": SemanticIndexService(pm),
                "atlas": AtlasService(pm),
                "search": SearchService(pm),
            }
            self.active_fingerprint = pm.current_fingerprint or fingerprint
            self.session_locked = False
            self._enter_main_workspace(initial=not self._main_screen_initialized)
            self.notify(f"Unlocked profile {self.active_fingerprint[:12]}")
        except Exception as e:
            try:
                if isinstance(self.screen, StartupScreen):
                    self.screen._set_status(f"Unlock failed: {e}")
            except Exception:
                pass
            self.notify(f"Unlock failed: {e}", severity="error")

    def _make_bootstrap_manager(self):
        from seedpass.core.manager import PasswordManager

        return PasswordManager(bootstrap_only=True)

    def _generate_bootstrap_seed(self) -> str:
        manager = self._make_bootstrap_manager()
        return manager.generate_bip85_seed()

    def _create_existing_profile(self, *, seed: str, password: str) -> str:
        manager = self._make_bootstrap_manager()
        fingerprint = manager.setup_existing_seed(seed=seed, password=password)
        if not fingerprint:
            raise RuntimeError("Profile creation did not return a fingerprint.")
        return fingerprint

    def _create_generated_profile(
        self, *, password: str, seed: str | None = None
    ) -> str:
        manager = self._make_bootstrap_manager()
        fingerprint, _generated_seed = manager.create_profile_from_generated_seed(
            password=password,
            seed=seed,
        )
        return fingerprint

    def _recover_profile(self, *, fingerprint: str, seed: str, password: str) -> None:
        manager = self._make_bootstrap_manager()
        manager.recover_profile_with_blank_index_data(
            fingerprint=fingerprint,
            parent_seed=seed,
            password=password,
        )

    def _restore_from_nostr_profile(
        self,
        *,
        seed: str,
        password: str,
        continue_without_backup: bool,
    ) -> str:
        manager = self._make_bootstrap_manager()
        fingerprint, _have_backup = manager.restore_from_nostr_with_guidance_data(
            seed_phrase=seed,
            password=password,
            continue_without_backup=continue_without_backup,
        )
        return fingerprint

    def _restore_from_backup_profile(
        self,
        *,
        seed: str,
        password: str,
        backup_path: str,
    ) -> str:
        manager = self._make_bootstrap_manager()
        return manager.restore_from_local_backup_data(
            seed_phrase=seed,
            password=password,
            backup_path=backup_path,
        )

    def _resolve_active_fingerprint(self) -> str:
        try:
            manager = self.services["vault"]._manager
            current = getattr(manager, "current_fingerprint", None)
            if current:
                return str(current)
        except Exception:
            pass
        return self._initial_fingerprint or self.active_fingerprint or ""

    def _enter_main_workspace(self, *, initial: bool) -> None:
        self.active_fingerprint = self._resolve_active_fingerprint()
        if initial or not self._main_screen_initialized:
            self.push_screen(MainScreen())
            self._main_screen_initialized = True
            return
        if isinstance(self.screen, StartupScreen):
            self.pop_screen()
        self.action_refresh()

    def on_command_palette_command_executed(
        self, message: CommandPalette.CommandExecuted
    ) -> None:
        """Handle command from palette."""
        self.processor.execute(message.command)

    def action_refresh_ui_quiet(self) -> None:
        """Background refresh for dynamic elements (2FA)."""
        try:
            board = self.screen.query_one("#board-container")
            if board and hasattr(board, "children") and board.children:
                current_board = board.children[0]
                # Ensure selection/inspector stay synchronized if a selection is set
                # but the board is still idle after screen transitions.
                if (
                    self.selected_entry_id is not None
                    and current_board.__class__.__name__ == "IdleBoard"
                ):
                    board.update_entry(self.selected_entry_id)
                    return
                # Refresh dynamic TOTP countdown only for the active TOTP board.
                if current_board.__class__.__name__ == "TotpBoard":
                    current_board.refresh()
        except Exception:
            pass

    def watch_active_fingerprint(self, old_fp: str, new_fp: str) -> None:
        """Refresh components when the profile changes."""
        if not new_fp:
            return

        try:
            mgr = self.services["vault"]._manager
            paths = []
            for fp, _, _ in getattr(mgr, "profile_stack", []):
                paths.append(fp[:8])
            current = mgr.current_fingerprint[:8] if mgr.current_fingerprint else "???"

            if paths:
                paths.append(current)
                self.active_breadcrumb = " > ".join(paths)
            else:
                self.active_breadcrumb = (
                    mgr.current_fingerprint[:24]
                    if mgr.current_fingerprint
                    else "No Profile"
                )
        except Exception:
            self.active_breadcrumb = new_fp[:24]

        # Notify sidebar and grid to refresh
        try:
            self.screen.query_one("#profile-tree")._refresh_tree()
            self.screen.query_one("#entry-data-table")._refresh_data()
        except Exception:
            pass

    def watch_selected_entry_id(self, old_id: int | None, new_id: int | None) -> None:
        """Update inspectors when an entry is selected."""
        try:
            inspector = self.screen.query_one("#inspector-pane")
            if new_id is None:
                inspector.add_class("hidden")
            else:
                inspector.remove_class("hidden")
            self.screen.query_one("#board-container").update_entry(new_id)
            self.screen.query_one("#linked-items-panel").update_entry(new_id)
        except Exception:
            pass

    def action_close_inspector(self) -> None:
        """Collapse the inspector and clear the active selection."""
        self.selected_entry_id = None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle local button actions that should not require a full screen."""
        if event.button.id == "inspector-close":
            self.action_close_inspector()
            event.stop()

    def action_refresh(self) -> None:
        """Force a global UI refresh."""
        if not self._main_screen_initialized:
            return
        try:
            self.screen.query_one("#profile-tree")._refresh_tree()
            self.screen.query_one("#entry-data-table")._refresh_data()
        except Exception:
            pass
        self.notify("UI Refreshed")

    def action_search(self, query: str) -> None:
        """Search entries and update grid."""
        try:
            self.search_query = str(query or "")
            self.screen.query_one("#entry-data-table")._refresh_data()
            self.notify(f"Search results for: {query}")
        except Exception:
            pass

    def action_set_search_mode(self, mode: str) -> None:
        """Set the active search mode and refresh the grid."""
        normalized = str(mode or "").strip().lower()
        if normalized not in {"keyword", "hybrid", "semantic"}:
            self.notify(f"Invalid search mode: {mode}", severity="error")
            return
        self.search_mode = normalized
        self.notify(f"Search mode set to: {normalized}")
        self.action_refresh()

    def action_set_search_sort(self, sort_key: str) -> None:
        """Set the active grid sort mode and refresh the grid."""
        normalized = str(sort_key or "").strip().lower()
        allowed = {
            "relevance",
            "modified_desc",
            "modified_asc",
            "label_asc",
            "kind",
            "created_desc",
            "most_linked",
        }
        if normalized not in allowed:
            self.notify(f"Invalid sort mode: {sort_key}", severity="error")
            return
        self.search_sort = normalized
        self.notify(f"Grid sort set to: {normalized}")
        self.action_refresh()

    def action_toggle_archived_view(self) -> None:
        """Toggle between active entries and archived entries."""
        self.show_archived = not self.show_archived
        self.notify(f"Showing archived entries: {self.show_archived}")
        self.action_refresh()

    def action_set_kind_filter(self, kind: str) -> None:
        """Set a specific entry kind filter (all, secrets, docs, keys, 2fa)."""
        self.filter_kind = kind.lower()
        self.notify(f"Applied filter: {self.filter_kind}")
        self.action_refresh()

    def action_open_palette(self) -> None:
        """Toggle the command palette."""
        try:
            self.screen.query_one("#palette").toggle()
        except Exception:
            pass

    def action_toggle_settings(self) -> None:
        """Push the full-screen settings screen."""
        self.push_screen(SettingsScreen())

    def action_open_atlas_wayfinder(self) -> None:
        atlas = self.services.get("atlas")
        if atlas is None:
            self.notify("Atlas service unavailable.", severity="warning")
            return
        try:
            payload = atlas.wayfinder()
        except Exception as exc:
            self.notify(f"Atlas load failed: {exc}", severity="error")
            return
        self.push_screen(AtlasWayfinderScreen(payload))

    def action_open_profile_management(self) -> None:
        """Open the in-app profile management screen."""
        if "profile" not in self.services:
            self.notify("Profile service offline", severity="error")
            return
        self.push_screen(ProfileManagementScreen())

    def action_switch_profile(
        self, fingerprint: str | None, password: str | None = None
    ) -> None:
        """Switch the active profile through the service layer."""
        if not fingerprint:
            return
        profile_service = self.services.get("profile")
        if not profile_service:
            self.notify("Profile service offline", severity="error")
            return
        try:
            from seedpass.core.api import ProfileSwitchRequest

            profile_service.switch_profile(
                ProfileSwitchRequest(fingerprint=fingerprint, password=password)
            )
            self.active_fingerprint = fingerprint
            self.notify(f"Switched to profile {fingerprint[:12]}")
            if isinstance(self.screen, ProfileManagementScreen):
                self.screen._set_status(
                    format_status(
                        "success",
                        f"Switched to profile {fingerprint[:12]}. Refreshing workspace...",
                    )
                )
            self.action_refresh()
        except Exception as e:
            self.notify(f"Profile switch failed: {e}", severity="error")
            if isinstance(self.screen, ProfileManagementScreen):
                self.screen._set_status(
                    format_status("error", f"Profile switch failed: {e}")
                )

    def action_remove_profile(self, fingerprint: str | None) -> None:
        """Remove a profile through the service layer."""
        if not fingerprint:
            return
        current = self.active_fingerprint
        if fingerprint == current:
            self.notify("Cannot remove the active profile", severity="warning")
            return
        profile_service = self.services.get("profile")
        if not profile_service:
            self.notify("Profile service offline", severity="error")
            return
        try:
            from seedpass.core.api import ProfileRemoveRequest

            profile_service.remove_profile(
                ProfileRemoveRequest(fingerprint=fingerprint)
            )
            self.notify(f"Removed profile {fingerprint[:12]}")
            if isinstance(self.screen, ProfileManagementScreen):
                self.screen._set_status(
                    format_status(
                        "success",
                        f"Removed profile {fingerprint[:12]}. List refreshed.",
                    )
                )
                self.screen.action_refresh_profiles()
        except Exception as e:
            self.notify(f"Profile removal failed: {e}", severity="error")
            if isinstance(self.screen, ProfileManagementScreen):
                self.screen._set_status(
                    format_status("error", f"Profile removal failed: {e}")
                )

    def action_toggle_relays(self) -> None:
        """Push the Nostr Relay Management screen."""
        self.push_screen(RelaysScreen())

    def action_show_profile_pubkey(self) -> None:
        """Show the active profile npub and public QR payload."""
        if "nostr" not in self.services:
            self.notify("Nostr service offline", severity="error")
            return
        self.push_screen(NostrPubkeyScreen())

    def action_open_change_password(self) -> None:
        """Open the vault password-change flow."""
        if "vault" not in self.services:
            self.notify("Vault service offline", severity="error")
            return
        self.push_screen(ChangePasswordScreen())

    def action_change_password(self, old_password: str, new_password: str) -> None:
        """Change the active vault password via the service layer."""
        vault = self.services.get("vault")
        if not vault:
            self.notify("Vault service offline", severity="error")
            return
        try:
            from seedpass.core.api import ChangePasswordRequest

            vault.change_password(
                ChangePasswordRequest(
                    old_password=old_password,
                    new_password=new_password,
                )
            )
            self.notify("Vault password updated")
            if isinstance(self.screen, ChangePasswordScreen):
                self.screen._set_status(
                    format_status(
                        "success",
                        "Vault password updated successfully. Returning to the previous screen.",
                    )
                )
                self.pop_screen()
        except Exception as e:
            self.notify(f"Change password failed: {e}", severity="error")
            if isinstance(self.screen, ChangePasswordScreen):
                self.screen._set_status(
                    format_status("error", f"Change password failed: {e}")
                )

    def action_open_backup_parent_seed(self) -> None:
        """Open the encrypted parent-seed backup flow."""
        if "vault" not in self.services:
            self.notify("Vault service offline", severity="error")
            return
        self.push_screen(BackupParentSeedScreen())

    def action_backup_parent_seed(
        self, path: str | None, password: str | None = None
    ) -> None:
        """Export an encrypted parent-seed backup via the service layer."""
        vault = self.services.get("vault")
        if not vault:
            self.notify("Vault service offline", severity="error")
            return
        try:
            from pathlib import Path
            from seedpass.core.api import BackupParentSeedRequest

            req = BackupParentSeedRequest(
                path=Path(path) if path else None,
                password=password,
            )
            vault.backup_parent_seed(req)
            target = str(req.path) if req.path is not None else "(default path)"
            self.notify(f"Parent seed backup exported to {target}")
            if isinstance(self.screen, BackupParentSeedScreen):
                self.screen._set_status(
                    format_status(
                        "success",
                        f"Parent seed backup exported to {target}. Returning to the previous screen.",
                    )
                )
                self.pop_screen()
        except Exception as e:
            self.notify(f"Parent seed backup failed: {e}", severity="error")
            if isinstance(self.screen, BackupParentSeedScreen):
                self.screen._set_status(
                    format_status("error", f"Parent seed backup failed: {e}")
                )

    def action_nostr_reset_sync_state(self) -> None:
        """Reset manifest and delta sync metadata for the active profile."""
        nostr = self.services.get("nostr")
        if not nostr:
            self.notify("Nostr service offline", severity="error")
            return
        try:
            idx = nostr.reset_sync_state()
            self.notify(f"Reset Nostr sync state at account index {idx}")
        except Exception as e:
            self.notify(f"Reset sync state failed: {e}", severity="error")

    def action_nostr_fresh_namespace(self) -> None:
        """Advance to a fresh deterministic Nostr namespace."""
        nostr = self.services.get("nostr")
        if not nostr:
            self.notify("Nostr service offline", severity="error")
            return
        try:
            idx = nostr.start_fresh_namespace()
            self.notify(f"Started fresh Nostr namespace at account index {idx}")
        except Exception as e:
            self.notify(f"Fresh namespace failed: {e}", severity="error")

    def action_add_entry(self) -> None:
        """Open the add entry wizard."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        from .screens.add import AddEntryScreen

        self.push_screen(AddEntryScreen())

    def action_seed_plus(self) -> None:
        """Open the Seed+ / BIP-85 derivation screen."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        from .screens.add import SeedPlusScreen

        self.push_screen(SeedPlusScreen())

    def action_maximize_inspector(self) -> None:
        """Push the full-screen maximized entry detail screen."""
        if self.selected_entry_id is None:
            self.notify("Select an entry to maximize", severity="warning")
            return
        self.push_screen(MaximizedInspectorScreen())

    def action_session_status(self) -> None:
        """Display vault lock status."""
        state = "locked" if self.session_locked else "unlocked"
        self.notify(f"Session status: {state}")

    def action_lock(self) -> None:
        """Lock the vault if service support is available."""
        vault = self.services.get("vault")
        if vault is None:
            self.notify("Vault service unavailable", severity="error")
            return
        locker = getattr(vault, "lock", None)
        if not callable(locker):
            self.notify("Vault service does not support lock", severity="error")
            return
        try:
            locker()
            self.session_locked = True
            self.notify("Vault locked")
            self.present_startup_screen(
                selected_fingerprint=self.active_fingerprint or None,
                prompt="Vault locked. Re-enter your master password to continue.",
            )
        except Exception as e:
            self.notify(f"Lock failed: {e}", severity="error")

    def action_unlock(self, password: str) -> None:
        """Unlock the vault with a password."""
        vault = self.services.get("vault")
        if vault is None:
            self.notify("Vault service unavailable", severity="error")
            return
        unlocker = getattr(vault, "unlock", None)
        if not callable(unlocker):
            self.notify("Vault service does not support unlock", severity="error")
            return
        try:
            try:
                from seedpass.core.api import UnlockRequest

                unlocker(UnlockRequest(password=password))
            except Exception:
                unlocker(password)
            self.session_locked = False
            if isinstance(self.screen, StartupScreen) and self._main_screen_initialized:
                self.pop_screen()
                self.action_refresh()
            self.notify("Vault unlocked")
        except Exception as e:
            self.notify(f"Unlock failed: {e}", severity="error")

    def action_reveal_selected(self, confirm: bool = False) -> None:
        """Handle reveal shortcut (v)."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        # Check confirmation
        if not confirm:
            confirm = self._consume_confirm("reveal_selected", self.selected_entry_id)

        self._show_sensitive_view(include_qr=False, confirm=confirm)

    def action_show_qr(self, mode: str = "default", confirm: bool = False) -> None:
        """Handle QR shortcut (g)."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        if not confirm:
            confirm = self._consume_confirm("show_qr", self.selected_entry_id)

        self._show_sensitive_view(include_qr=True, qr_mode=mode, confirm=confirm)

    def action_toggle_archive(self) -> None:
        """Toggle archived status for selected entry."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        try:
            entry = self.services["entry"].retrieve_entry(self.selected_entry_id)
            is_archived = entry.get("archived", False)

            if is_archived:
                self.services["entry"].restore_entry(self.selected_entry_id)
                self.notify(f"Restored Entry #{self.selected_entry_id}")
            else:
                self.services["entry"].archive_entry(self.selected_entry_id)
                self.notify(f"Archived Entry #{self.selected_entry_id}")

            # Refresh UI
            self.action_refresh()
        except Exception as e:
            self.notify(f"Archive failed: {e}", severity="error")

    def action_copy_selected(self) -> None:
        """Copy the primary sensitive field of the selected entry to the clipboard."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        try:
            payload = self._resolve_sensitive_payload()
            # payload is (title, body, qr_data, secret_value, kind)
            secret = payload[3]
            if secret:
                success = self.services["entry"].copy_to_clipboard(secret)
                if success:
                    self.notify(f"Copied {payload[4]} value to clipboard")
                else:
                    self.notify("Clipboard copy failed", severity="warning")
            else:
                self.notify("No value to copy", severity="warning")
        except Exception as e:
            self.notify(f"Copy failed: {e}", severity="error")

    def action_delete_selected(self, confirm: bool = False) -> None:
        """Delete the selected entry after explicit confirmation."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        try:
            entry = self.services["entry"].retrieve_entry(self.selected_entry_id)
            kind = str(entry.get("kind") or entry.get("type") or "entry").lower()
            label = str(entry.get("label") or f"Entry #{self.selected_entry_id}")

            if not confirm:
                confirm = self._consume_confirm(
                    "delete_selected", self.selected_entry_id
                )

            if not confirm:
                self._pending_sensitive_confirm = (
                    "delete_selected",
                    self.selected_entry_id,
                    time.time(),
                )
                self._update_board_sensitive(
                    prompt=(
                        "CONFIRMATION REQUIRED\n\n"
                        f"Delete '{label}' ({kind}).\n"
                        "Press 'd' again within 8s to permanently delete."
                    )
                )
                self.notify("Press 'd' again to confirm deletion")
                return

            delete_id = self.selected_entry_id
            self.services["entry"].delete_entry(delete_id)
            self.selected_entry_id = None
            self.notify(f"Deleted Entry #{delete_id}")
            self.action_refresh()
        except Exception as e:
            self.notify(f"Delete failed: {e}", severity="error")

    def action_managed_load(self) -> None:
        """Load the selected managed account or seed profile as the active session."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        try:
            entry = self.services["entry"].retrieve_entry(self.selected_entry_id)
            kind = str(entry.get("kind") or entry.get("type") or "").lower()
            if kind not in {"managed_account", "seed"}:
                self.notify(
                    "Selected entry is not a loadable profile", severity="warning"
                )
                return

            self.services["entry"].load_managed_account(self.selected_entry_id)
            # Update reactive state to trigger UI refresh
            self.active_fingerprint = self.services[
                "vault"
            ]._manager.current_fingerprint
            self.notify(f"Loaded session: {self.active_fingerprint[:8]}...")
            self.action_refresh()
        except Exception as e:
            self.notify(f"Load failed: {e}", severity="error")

    def action_managed_exit(self) -> None:
        """Exit the current managed session and return to the parent profile."""
        try:
            self.services["entry"].exit_managed_account()
            # Update reactive state
            self.active_fingerprint = self.services[
                "vault"
            ]._manager.current_fingerprint
            self.notify(f"Exited session. Back to: {self.active_fingerprint[:8]}...")
            self.action_refresh()
        except Exception as e:
            self.notify(f"Exit failed: {e}", severity="error")

    def action_edit_selected(self) -> None:
        """Open the appropriate edit screen for the selected entry."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        try:
            from .screens.edit import EditEntryScreen

            self.push_screen(EditEntryScreen(self.selected_entry_id))
        except Exception as e:
            self.notify(f"Edit failed: {e}", severity="error")

    def action_export_selected(self) -> None:
        """Export the selected entry to a file if supported."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        try:
            entry = self.services["entry"].retrieve_entry(self.selected_entry_id)
            kind = str(entry.get("kind") or entry.get("type") or "").lower()

            if kind in {"document", "note"}:
                path = self.services["entry"].export_document_file(
                    self.selected_entry_id
                )
                self.notify(f"Document exported to: {path}")
            elif kind in {"ssh", "pgp", "nostr"}:
                payload = self._resolve_sensitive_payload()
                if not payload:
                    return
                # format: [copy_val, label, public_prefix, sec, pub_prefix, pub]
                _, label, _, sec, _, pub = payload
                safe_label = (
                    "".join(
                        c for c in str(label) if c.isalnum() or c in ("-", "_")
                    ).strip()
                    or f"entry_{self.selected_entry_id}"
                )
                from pathlib import Path

                base_path = Path.cwd() / f"{safe_label}_{kind}"
                Path(f"{base_path}_pub.txt").write_text(str(pub), encoding="utf-8")
                Path(f"{base_path}_sec.txt").write_text(str(sec), encoding="utf-8")
                self.notify(f"Exported {kind} keypair to current directory")
            elif kind == "totp":
                payload = self._resolve_sensitive_payload()
                if not payload:
                    return
                # format: [copy_val, label, pub_p, secret, sec_p, uri]
                _, label, _, secret, _, uri = payload
                safe_label = (
                    "".join(
                        c for c in str(label) if c.isalnum() or c in ("-", "_")
                    ).strip()
                    or f"entry_{self.selected_entry_id}"
                )
                from pathlib import Path

                path = Path.cwd() / f"{safe_label}_totp.txt"
                path.write_text(f"Secret: {secret}\nURI: {uri}", encoding="utf-8")
                self.notify(f"Exported TOTP info to {path.name}")
            else:
                self.notify(
                    f"Export not supported for kind '{kind}'", severity="warning"
                )
        except Exception as e:
            self.notify(f"Export failed: {e}", severity="error")

    def action_db_export(self, path: str) -> None:
        """Export the entire vault database."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        try:
            from seedpass.core.api import VaultExportRequest

            req = VaultExportRequest(path=path)
            self.services["vault"].export_vault(req)
            self.notify(f"Exported DB to {path}")
        except Exception as e:
            self.notify(f"Export DB failed: {e}", severity="error")

    def action_db_import(self, path: str) -> None:
        """Import a vault database."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        try:
            from seedpass.core.api import VaultImportRequest

            req = VaultImportRequest(path=path)
            self.services["vault"].import_vault(req)
            self.notify(f"Imported DB from {path}")
            self.action_refresh()
        except Exception as e:
            self.notify(f"Import DB failed: {e}", severity="error")

    def _consume_confirm(self, action: str, eid: int) -> bool:
        if self._pending_sensitive_confirm is None:
            return False
        p_action, p_eid, p_ts = self._pending_sensitive_confirm
        now = time.time()
        if p_action == action and p_eid == eid and (now - p_ts) <= 8.0:
            self._pending_sensitive_confirm = None
            return True
        self._pending_sensitive_confirm = None
        return False

    def _show_sensitive_view(
        self, include_qr: bool, qr_mode: str = "default", confirm: bool = False
    ) -> None:
        try:
            payload = self._resolve_sensitive_payload(qr_mode=qr_mode)
            title, body, qr_data, secret, kind = payload
        except Exception as e:
            self.notify(f"Reveal failed: {e}", severity="error")
            return

        # Check if confirmation is required
        requires = False
        if include_qr:
            requires = kind in {
                "seed",
                "managed_account",
                "nostr",
            }  # for nostr qr we often show nsec if mode is private
        else:
            requires = kind in {"seed", "managed_account", "ssh", "pgp", "nostr"}

        if requires and not confirm:
            key = "g" if include_qr else "v"
            self._pending_sensitive_confirm = (
                "show_qr" if include_qr else "reveal_selected",
                self.selected_entry_id,
                time.time(),
            )
            # Update the board with confirmation prompt
            self._update_board_sensitive(
                prompt=f"CONFIRMATION REQUIRED\n\nHigh-risk action for '{kind}'.\nPress '{key}' again within 8s to proceed."
            )
            self.notify(f"Press '{key}' again to confirm")
            return

        # Success - Update Board
        if include_qr:
            try:
                qr_rendered = render_qr_ascii(qr_data)
                self._update_board_sensitive(content=qr_rendered, title=title)
            except Exception as e:
                self.notify(f"QR Render failed: {e}", severity="error")
        else:
            self._update_board_sensitive(content=body, title=title)

    def _resolve_sensitive_payload(self, qr_mode="default"):
        if "entry" not in self.services:
            raise ValueError("Service offline")
        eid = self.selected_entry_id
        entry = self.services["entry"].retrieve_entry(eid)
        if not entry:
            raise ValueError("Entry not found")

        kind = str(entry.get("kind") or entry.get("type") or "").lower()
        label = entry.get("label", "")

        if kind == "password":
            val = self.services["entry"].generate_password(
                int(entry.get("length", 16)), eid
            )
            return ("Password Revealed", val, None, val, kind)
        if kind == "totp":
            secret = self.services["entry"].get_totp_secret(eid)
            from seedpass.core.totp import TotpManager

            uri = TotpManager.make_otpauth_uri(label, secret)
            return ("TOTP Secret Revealed", secret, uri, secret, kind)
        if kind in {"seed", "managed_account"}:
            parent_seed = self.services["vault"]._manager.parent_seed
            if kind == "seed":
                try:
                    phrase = self.services["entry"].get_seed_phrase(eid, parent_seed)
                except TypeError:
                    phrase = self.services["entry"].get_seed_phrase(eid)
            else:
                try:
                    phrase = self.services["entry"].get_managed_account_seed(
                        eid, parent_seed
                    )
                except TypeError:
                    phrase = self.services["entry"].get_managed_account_seed(eid)
            from seedpass.core.seedqr import encode_seedqr

            return ("Seed Words Revealed", phrase, encode_seedqr(phrase), phrase, kind)

        if kind == "ssh":
            priv, pub = self.services["entry"].get_ssh_key_pair(eid)
            return ("SSH Private Key Revealed", priv, pub, pub, kind)

        if kind == "pgp":
            pgp_payload = self.services["entry"].get_pgp_key(eid)
            if isinstance(pgp_payload, tuple) and len(pgp_payload) == 3:
                priv, pub, _fp = pgp_payload
            elif isinstance(pgp_payload, tuple) and len(pgp_payload) == 2:
                priv, pub = pgp_payload
            else:
                raise ValueError("Invalid PGP payload from entry service")
            return ("PGP Private Key Revealed", priv, pub, pub, kind)

        if kind == "nostr":
            npub, nsec = self.services["entry"].get_nostr_key_pair(eid)
            qr_data = nsec if qr_mode == "private" else f"nostr:{npub}"
            return ("Nostr Secret Revealed", nsec, qr_data, nsec, kind)

        if kind == "key_value":
            val = entry.get("value", "")
            return ("Key-Value Revealed", val, None, val, kind)

        if kind in {"document", "note"}:
            content = entry.get("content", "")
            return ("Document Content", content, None, content, kind)

        # Fallback
        return ("Data Revealed", f"Label: {label}\nDetails: {entry}", None, None, kind)

    def _update_board_sensitive(
        self, content: str = None, title: str = None, prompt: str = None
    ):
        """Push sensitive data to the currently active board or screen."""
        data = {"content": content, "title": title, "prompt": prompt}

        # 1. Update full-screen inspector if active
        if isinstance(self.screen, MaximizedInspectorScreen):
            self.screen.reveal_data = data
            return

        # 2. Update standard inspector board
        try:
            board_cont = self.screen.query_one("#board-container")
            if board_cont.children:
                board = board_cont.children[0]
                if hasattr(board, "reveal_data"):
                    board.reveal_data = data
        except Exception:
            pass

    # ---------------------------------------------------------------------------
    # Utility / maintenance actions (legacy parity)
    # ---------------------------------------------------------------------------

    def action_checksum_verify(self) -> None:
        """Verify the application checksum."""
        utility = self.services.get("utility")
        if not utility:
            self.notify("Utility service offline", severity="error")
            return
        try:
            utility.verify_checksum()
            self.notify("Checksum verified")
        except Exception as e:
            self.notify(f"Checksum verify failed: {e}", severity="error")

    def action_checksum_update(self) -> None:
        """Update / regenerate the application checksum."""
        utility = self.services.get("utility")
        if not utility:
            self.notify("Utility service offline", severity="error")
            return
        try:
            utility.update_checksum()
            self.notify("Checksum updated")
        except Exception as e:
            self.notify(f"Checksum update failed: {e}", severity="error")

    def action_totp_export(self, path: str | None = None) -> None:
        """Export all TOTP entries, optionally writing to a file."""
        entry = self.services.get("entry")
        if not entry:
            self.notify("Entry service offline", severity="error")
            return
        try:
            data = entry.export_totp_entries()
            if path:
                import json
                from pathlib import Path

                Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
                self.notify(f"TOTP entries exported to {path}")
            else:
                count = len(data) if isinstance(data, dict) else 0
                self.notify(
                    f"TOTP export: {count} entries (provide a path to save to file)"
                )
        except Exception as e:
            self.notify(f"TOTP export failed: {e}", severity="error")

    def action_sync_now(self) -> None:
        """Synchronise vault to Nostr immediately."""
        sync = self.services.get("sync")
        if not sync:
            self.notify("Sync service offline", severity="error")
            return
        try:
            self.notify("Syncing vault to Nostr…")
            result = sync.sync()
            if result:
                self.notify("Sync complete")
            else:
                self.notify("Sync returned no events", severity="warning")
        except Exception as e:
            self.notify(f"Sync failed: {e}", severity="error")

    def action_sync_bg(self) -> None:
        """Start a background Nostr vault sync."""
        sync = self.services.get("sync")
        if not sync:
            self.notify("Sync service offline", severity="error")
            return
        try:
            sync.start_background_vault_sync()
            self.notify("Background sync started")
        except Exception as e:
            self.notify(f"Background sync failed: {e}", severity="error")

    def action_relay_add(self, url: str) -> None:
        """Add a Nostr relay."""
        nostr = self.services.get("nostr")
        if not nostr:
            self.notify("Nostr service offline", severity="error")
            return
        try:
            nostr.add_relay(url)
            self.notify(f"Relay added: {url}")
        except Exception as e:
            self.notify(f"Relay add failed: {e}", severity="error")

    def action_relay_rm(self, idx: int) -> None:
        """Remove a Nostr relay by index."""
        nostr = self.services.get("nostr")
        if not nostr:
            self.notify("Nostr service offline", severity="error")
            return
        try:
            nostr.remove_relay(idx)
            self.notify(f"Relay #{idx} removed")
        except Exception as e:
            self.notify(f"Relay remove failed: {e}", severity="error")

    def action_relay_reset(self) -> None:
        """Reset Nostr relays to built-in defaults."""
        nostr = self.services.get("nostr")
        if not nostr:
            self.notify("Nostr service offline", severity="error")
            return
        try:
            relays = nostr.reset_relays()
            self.notify(f"Relays reset to defaults ({len(relays)} relays)")
        except Exception as e:
            self.notify(f"Relay reset failed: {e}", severity="error")

    def action_setting_secret(self, value: str) -> None:
        """Toggle secret mode on or off."""
        config = self.services.get("config")
        if not config:
            self.notify("Config service offline", severity="error")
            return
        try:
            enabled = value.lower() in {"on", "1", "true", "yes", "y"}
            delay = config.get_clipboard_clear_delay()
            config.set_secret_mode(enabled, delay)
            self.notify(f"Secret mode: {'on' if enabled else 'off'}")
        except Exception as e:
            self.notify(f"Setting failed: {e}", severity="error")

    def action_setting_quick_unlock(self, value: str) -> None:
        """Enable or disable quick-unlock."""
        config = self.services.get("config")
        if not config:
            self.notify("Config service offline", severity="error")
            return
        try:
            config.set("quick_unlock", value)
            self.notify(f"Quick unlock: {value}")
        except Exception as e:
            self.notify(f"Setting failed: {e}", severity="error")

    def action_setting_offline(self, value: str) -> None:
        """Enable or disable offline mode."""
        config = self.services.get("config")
        if not config:
            self.notify("Config service offline", severity="error")
            return
        try:
            enabled = value.lower() in {"on", "1", "true", "yes", "y"}
            config.set_offline_mode(enabled)
            self.notify(f"Offline mode: {'on' if enabled else 'off'}")
        except Exception as e:
            self.notify(f"Setting failed: {e}", severity="error")

    def action_setting_timeout(self, seconds: str) -> None:
        """Set the inactivity auto-lock timeout in seconds."""
        config = self.services.get("config")
        if not config:
            self.notify("Config service offline", severity="error")
            return
        try:
            config.set("inactivity_timeout", seconds)
            self.notify(f"Inactivity timeout: {seconds}s")
        except Exception as e:
            self.notify(f"Setting failed: {e}", severity="error")

    def action_setting_kdf_mode(self, mode: str) -> None:
        """Set the KDF algorithm (e.g. argon2id, pbkdf2)."""
        config = self.services.get("config")
        if not config:
            self.notify("Config service offline", severity="error")
            return
        try:
            config.set("kdf_mode", mode)
            self.notify(f"KDF mode: {mode}")
        except Exception as e:
            self.notify(f"Setting failed: {e}", severity="error")

    def action_setting_kdf_iterations(self, n: str) -> None:
        """Set the number of KDF iterations."""
        config = self.services.get("config")
        if not config:
            self.notify("Config service offline", severity="error")
            return
        try:
            config.set("kdf_iterations", n)
            self.notify(f"KDF iterations: {n}")
        except Exception as e:
            self.notify(f"Setting failed: {e}", severity="error")

    def action_archive_filter(self, mode: str) -> None:
        """Set the archive visibility scope: active, all, or archived."""
        normalized = mode.lower()
        if normalized not in {"active", "all", "archived"}:
            self.notify(
                "Usage: archive-filter <active|all|archived>", severity="warning"
            )
            return
        if normalized == "archived":
            self.show_archived = True
            self.filter_archived_only = True
        elif normalized == "all":
            self.show_archived = True
            self.filter_archived_only = False
        else:
            self.show_archived = False
            self.filter_archived_only = False
        self.notify(f"Archive filter: {normalized}")
        self.action_refresh()

    def action_set_density(self, mode: str) -> None:
        """Switch display density between compact and comfortable."""
        normalized = mode.lower()
        if normalized not in {"compact", "comfortable"}:
            self.notify(
                "Usage: density <compact|comfortable>", severity="warning"
            )
            return
        self.density_mode = normalized
        self.notify(f"Density: {normalized}")

    def action_show_onboarding(self) -> None:
        """Show onboarding / quickstart guidance."""
        self.notify(
            "Onboarding: add your first entry with 'add', reveal it with 'v', "
            "inspect fields in the inspector pane, and use Ctrl+P to open the "
            "command palette for all available operations."
        )
