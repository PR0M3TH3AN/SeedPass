import pytest
from types import SimpleNamespace
from typer.testing import CliRunner

from seedpass.cli import app
from seedpass import cli

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
            ],
            ("Label", 16, "user", "https://example.com"),
            {},
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
            ("Label", "seed"),
            {"index": 1, "secret": "abc", "period": 45, "digits": 7},
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
            ("Label",),
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
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", command] + cli_args)
    assert result.exit_code == 0
    assert stdout in result.stdout
    assert called["args"] == expected_args
    assert called["kwargs"] == expected_kwargs
    assert called.get("sync") is True
