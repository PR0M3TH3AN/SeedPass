import pytest
from types import SimpleNamespace
from pathlib import Path
from typer.testing import CliRunner

from seedpass.cli import app
from seedpass.cli import common as cli_common
from helpers import TEST_SEED

runner = CliRunner()


@pytest.mark.parametrize(
    "command,method,cli_args,expected_args,expected_kwargs,stdout",
    [
        (
            "add",
            "add_entry",
            [
                "Label",
                "--length",
                "16",
                "--username",
                "user",
                "--url",
                "https://example.com",
                "--no-special",
                "--allowed-special-chars",
                "!@",
                "--special-mode",
                "safe",
                "--exclude-ambiguous",
                "--min-uppercase",
                "1",
                "--min-lowercase",
                "2",
                "--min-digits",
                "3",
                "--min-special",
                "4",
            ],
            ("Label", 16, "user", "https://example.com"),
            {
                "include_special_chars": False,
                "allowed_special_chars": "!@",
                "special_mode": "safe",
                "exclude_ambiguous": True,
                "min_uppercase": 1,
                "min_lowercase": 2,
                "min_digits": 3,
                "min_special": 4,
            },
            "1",
        ),
        (
            "add-totp",
            "add_totp",
            [
                "Label",
                "--index",
                "1",
                "--secret",
                "abc",
                "--period",
                "45",
                "--digits",
                "7",
            ],
            ("Label", None),
            {
                "index": 1,
                "secret": "abc",
                "period": 45,
                "digits": 7,
                "deterministic": False,
            },
            "otpauth://uri",
        ),
        (
            "add-ssh",
            "add_ssh_key",
            ["Label", "--index", "2", "--notes", "n"],
            ("Label", "seed"),
            {"index": 2, "notes": "n"},
            "3",
        ),
        (
            "add-pgp",
            "add_pgp_key",
            [
                "Label",
                "--index",
                "3",
                "--key-type",
                "rsa",
                "--user-id",
                "uid",
                "--notes",
                "n",
            ],
            ("Label", "seed"),
            {"index": 3, "key_type": "rsa", "user_id": "uid", "notes": "n"},
            "4",
        ),
        (
            "add-nostr",
            "add_nostr_key",
            ["Label", "--index", "4", "--notes", "n"],
            ("Label", "seed"),
            {"index": 4, "notes": "n"},
            "5",
        ),
        (
            "add-seed",
            "add_seed",
            ["Label", "--index", "5", "--words", "12", "--notes", "n"],
            ("Label", "seed"),
            {"index": 5, "words_num": 12, "notes": "n"},
            "6",
        ),
        (
            "add-key-value",
            "add_key_value",
            ["Label", "--key", "k1", "--value", "val", "--notes", "note"],
            ("Label", "k1", "val"),
            {"notes": "note"},
            "7",
        ),
        (
            "add-managed-account",
            "add_managed_account",
            ["Label", "--index", "7", "--notes", "n"],
            ("Label", "seed"),
            {"index": 7, "notes": "n"},
            "8",
        ),
        (
            "add-document",
            "add_document",
            ["Doc", "--content", "hello", "--file-type", "md", "--notes", "n"],
            ("Doc", "hello"),
            {"file_type": "md", "notes": "n", "tags": None, "archived": False},
            "9",
        ),
    ],
)
def test_entry_add_commands(
    monkeypatch, command, method, cli_args, expected_args, expected_kwargs, stdout
):
    called = {}

    def func(*args, **kwargs):
        called["args"] = args
        called["kwargs"] = kwargs
        return stdout

    def start_background_vault_sync():
        called["sync"] = True

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(**{method: func}),
        parent_seed="seed",
        select_fingerprint=lambda fp: None,
        start_background_vault_sync=start_background_vault_sync,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", command] + cli_args)
    assert result.exit_code == 0
    assert stdout in result.stdout
    assert called["args"] == expected_args
    assert called["kwargs"] == expected_kwargs
    assert called.get("sync") is True


def test_entry_import_document_command(monkeypatch, tmp_path):
    called = {}

    def import_document_file(path, **kwargs):
        called["args"] = (path,)
        called["kwargs"] = kwargs
        return 123

    def start_background_vault_sync():
        called["sync"] = True

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(import_document_file=import_document_file),
        parent_seed="seed",
        select_fingerprint=lambda fp: None,
        start_background_vault_sync=start_background_vault_sync,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    source = tmp_path / "doc.md"
    source.write_text("hello", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "entry",
            "import-document",
            "--file",
            str(source),
            "--label",
            "Doc",
            "--notes",
            "n",
        ],
    )
    assert result.exit_code == 0
    assert "123" in result.stdout
    assert called["args"] == (str(source),)
    assert called["kwargs"] == {
        "label": "Doc",
        "notes": "n",
        "tags": None,
        "archived": False,
    }
    assert called.get("sync") is True


def test_entry_export_document_command(monkeypatch):
    called = {}

    def export_document_file(entry_id, output_path=None, **kwargs):
        called["args"] = (entry_id, output_path)
        called["kwargs"] = kwargs
        return Path("/tmp/doc.txt")

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(export_document_file=export_document_file),
        parent_seed="seed",
        select_fingerprint=lambda fp: None,
        start_background_vault_sync=lambda: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)

    result = runner.invoke(
        app,
        [
            "entry",
            "export-document",
            "--entry-id",
            "9",
            "--out",
            "/tmp/outdir",
            "--overwrite",
        ],
    )
    assert result.exit_code == 0
    assert "/tmp/doc.txt" in result.stdout
    assert called["args"] == (9, "/tmp/outdir")
    assert called["kwargs"] == {"overwrite": True}


def test_entry_link_commands(monkeypatch):
    called = {}

    def add_link(entry_id, target_id, **kwargs):
        called["add"] = (entry_id, target_id, kwargs)
        return [
            {
                "target_id": target_id,
                "relation": kwargs["relation"],
                "note": kwargs["note"],
            }
        ]

    def remove_link(entry_id, target_id, **kwargs):
        called["remove"] = (entry_id, target_id, kwargs)
        return []

    def get_links(entry_id):
        called["get"] = entry_id
        return [
            {
                "target_id": 3,
                "relation": "references",
                "note": "",
                "target_label": "X",
                "target_kind": "document",
            }
        ]

    def start_background_vault_sync():
        called["sync"] = called.get("sync", 0) + 1

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(
            add_link=add_link,
            remove_link=remove_link,
            get_links=get_links,
        ),
        parent_seed="seed",
        select_fingerprint=lambda fp: None,
        start_background_vault_sync=start_background_vault_sync,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)

    add_res = runner.invoke(
        app,
        [
            "entry",
            "link-add",
            "--entry-id",
            "1",
            "--target-id",
            "3",
            "--relation",
            "references",
            "--note",
            "note",
        ],
    )
    assert add_res.exit_code == 0
    assert called["add"] == (1, 3, {"relation": "references", "note": "note"})

    list_res = runner.invoke(app, ["entry", "links", "--entry-id", "1"])
    assert list_res.exit_code == 0
    assert '"target_id": 3' in list_res.stdout
    assert called["get"] == 1

    rm_res = runner.invoke(
        app,
        [
            "entry",
            "link-remove",
            "--entry-id",
            "1",
            "--target-id",
            "3",
            "--relation",
            "references",
        ],
    )
    assert rm_res.exit_code == 0
    assert called["remove"] == (1, 3, {"relation": "references"})
