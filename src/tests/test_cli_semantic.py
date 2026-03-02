from types import SimpleNamespace

from typer.testing import CliRunner

from seedpass.cli import app
from seedpass.cli import semantic as semantic_cli

runner = CliRunner()


class _DummySemanticService:
    def __init__(self) -> None:
        self.mode = "keyword"

    def status(self):
        return {"enabled": True, "built": True, "records": 2, "mode": self.mode}

    def set_enabled(self, enabled: bool):
        return {"enabled": bool(enabled), "built": True, "records": 2}

    def set_mode(self, mode: str):
        self.mode = str(mode)
        return self.status()

    def build(self):
        return {"enabled": True, "built": True, "records": 3}

    def rebuild(self):
        return {"enabled": True, "built": True, "records": 3}

    def search(
        self,
        query: str,
        *,
        k: int = 10,
        kind: str | None = None,
        mode: str | None = None,
    ):
        if not query:
            return []
        return [
            {
                "entry_id": 7,
                "kind": kind or "document",
                "label": "Runbook",
                "score": 0.8,
                "excerpt": f"query={query} k={k}",
            }
        ]


def test_semantic_cli_commands(monkeypatch):
    monkeypatch.setattr(
        semantic_cli,
        "_get_semantic_service",
        lambda _ctx: _DummySemanticService(),
    )
    monkeypatch.setattr(semantic_cli, "_get_pm", lambda _ctx: SimpleNamespace())

    result = runner.invoke(app, ["semantic", "status"])
    assert result.exit_code == 0
    assert '"enabled": true' in result.stdout.lower()

    result = runner.invoke(app, ["semantic", "enable"])
    assert result.exit_code == 0
    assert "semantic index enabled" in result.stdout.lower()

    result = runner.invoke(app, ["semantic", "disable"])
    assert result.exit_code == 0
    assert "semantic index disabled" in result.stdout.lower()

    result = runner.invoke(app, ["semantic", "build"])
    assert result.exit_code == 0
    assert "semantic index built" in result.stdout.lower()

    result = runner.invoke(app, ["semantic", "rebuild"])
    assert result.exit_code == 0
    assert "semantic index rebuilt" in result.stdout.lower()

    result = runner.invoke(app, ["semantic", "search", "relay recovery"])
    assert result.exit_code == 0
    assert "Runbook" in result.stdout
    assert "score=0.800" in result.stdout

    result = runner.invoke(
        app,
        [
            "semantic",
            "search",
            "relay",
            "--k",
            "3",
            "--kind",
            "document",
            "--mode",
            "hybrid",
            "--json",
        ],
    )
    assert result.exit_code == 0
    assert '"entry_id": 7' in result.stdout

    result = runner.invoke(
        app,
        ["semantic", "config", "--enabled", "true", "--mode", "semantic"],
    )
    assert result.exit_code == 0
    assert '"mode": "semantic"' in result.stdout
