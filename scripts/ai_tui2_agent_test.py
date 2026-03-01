#!/usr/bin/env python3
"""
Deterministic AI-agent harness for SeedPass TUI v2.

This harness uses Textual's test pilot API to simulate user/agent behavior and
produces a machine-readable report for CI and local regressions.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from seedpass.tui_v2.app import check_tui2_runtime, launch_tui2


@dataclass
class StepResult:
    step_id: str
    description: str
    status: str
    duration_sec: float
    detail: str | None = None


class HarnessError(RuntimeError):
    pass


class HarnessEntryService:
    def __init__(self) -> None:
        self.entries = {
            1: {
                "id": 1,
                "kind": "document",
                "label": "Runbook",
                "content": "alpha",
                "file_type": "md",
                "tags": ["ops"],
                "archived": False,
            },
            2: {
                "id": 2,
                "kind": "password",
                "label": "Console Login",
                "archived": False,
            },
        }
        self.links = {
            1: [{"target": 2, "relation": "references", "note": "credential"}],
            2: [],
        }

    def search_entries(self, query: str, kinds: list[str] | None = None):
        q = (query or "").strip().lower()
        out = []
        for idx in sorted(self.entries.keys()):
            entry = self.entries[idx]
            kind = str(entry.get("kind", "password"))
            if kinds and kind not in kinds:
                continue
            label = str(entry.get("label", ""))
            if q and q not in label.lower():
                continue
            out.append(
                (
                    idx,
                    label,
                    None,
                    None,
                    bool(entry.get("archived", False)),
                    SimpleNamespace(value=kind),
                )
            )
        return out

    def retrieve_entry(self, entry_id: int):
        return dict(self.entries.get(int(entry_id), {}))

    def modify_entry(self, entry_id: int, **kwargs):
        entry = self.entries[int(entry_id)]
        for key, value in kwargs.items():
            if value is not None:
                entry[key] = value

    def archive_entry(self, entry_id: int):
        self.entries[int(entry_id)]["archived"] = True

    def restore_entry(self, entry_id: int):
        self.entries[int(entry_id)]["archived"] = False

    def get_links(self, entry_id: int):
        return [dict(link) for link in self.links.get(int(entry_id), [])]

    def add_link(
        self,
        entry_id: int,
        target_id: int,
        *,
        relation: str = "related_to",
        note: str = "",
    ):
        links = self.links.setdefault(int(entry_id), [])
        links.append({"target": int(target_id), "relation": relation, "note": note})
        return [dict(link) for link in links]

    def remove_link(
        self, entry_id: int, target_id: int, *, relation: str | None = None
    ):
        src = self.links.setdefault(int(entry_id), [])
        kept = []
        for link in src:
            if int(link.get("target", -1)) != int(target_id):
                kept.append(link)
                continue
            if relation is not None and str(link.get("relation")) != relation:
                kept.append(link)
        self.links[int(entry_id)] = kept
        return [dict(link) for link in kept]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run deterministic TUI v2 agent validation harness."
    )
    parser.add_argument(
        "--scenario",
        choices=("core", "extended"),
        default="extended",
        help="Validation scenario profile (default: extended).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/agent_tui2_test"),
        help="Directory for report artifacts.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print step progress.",
    )
    return parser.parse_args()


def _status(app) -> str:
    return str(app.query_one("#status").render())


def _assert_contains(haystack: str, needle: str, context: str) -> None:
    if needle not in haystack:
        raise HarnessError(f"{context}: expected {needle!r} in {haystack!r}")


async def _scenario_core(
    app, service: HarnessEntryService, coverage: dict[str, bool], pilot
) -> None:
    from textual.widgets import Input

    await pilot.pause()
    coverage["startup"] = True

    app.query_one("#search", Input).value = "runbook"
    app._load_entries(query="runbook", reset_page=True)
    await pilot.pause()
    coverage["search"] = True

    app._run_palette_command("open 1")
    await pilot.pause()
    app.action_edit_document()
    await pilot.pause()
    app.query_one("#doc-edit-label", Input).value = "Runbook Updated"
    app.query_one("#doc-edit-file-type", Input).value = "txt"
    app.query_one("#doc-edit-tags", Input).value = "ops,core"
    if len(app.query("#doc-edit-content")) > 0:
        area = app.query_one("#doc-edit-content")
        if hasattr(area, "load_text"):
            area.load_text("alpha\nbeta")
        else:
            area.text = "alpha\nbeta"
    else:
        app.query_one("#doc-edit-content-single", Input).value = "alpha\nbeta"
    app.action_save_document()
    await pilot.pause()
    _assert_contains(_status(app), "Saved document", "save-doc")
    coverage["document_edit"] = True

    app._run_palette_command("link-add 2 references auth")
    await pilot.pause()
    app.action_open_link_target()
    await pilot.pause()
    _assert_contains(_status(app), "Opened linked entry 2", "link-open")
    coverage["graph_navigation"] = True

    app._run_palette_command("open 1")
    await pilot.pause()
    app.action_toggle_archive()
    await pilot.pause()
    if "archived" not in _status(app):
        raise HarnessError(f"archive: expected archived status, got {_status(app)!r}")
    app._run_palette_command("open 1")
    await pilot.pause()
    app.action_toggle_archive()
    await pilot.pause()
    if service.entries[1].get("archived", False):
        raise HarnessError(
            "restore: expected entry 1 to be unarchived after second toggle"
        )
    coverage["archive_restore"] = True


async def _scenario_extended(
    app, service: HarnessEntryService, coverage: dict[str, bool], pilot
) -> None:
    await _scenario_core(app, service, coverage, pilot)
    app.action_open_palette()
    await pilot.pause()
    app._run_palette_command("unknown-cmd")
    await pilot.pause()
    _assert_contains(_status(app), "Unknown command", "palette-unknown")

    app._run_palette_command("page 1")
    await pilot.pause()
    coverage["palette_navigation"] = True

    app.action_toggle_help()
    await pilot.pause()
    _assert_contains(_status(app), "Help opened", "help-open")
    app.action_cancel_document_edit()
    await pilot.pause()
    _assert_contains(_status(app), "Help closed", "help-close")
    coverage["help_overlay"] = True


async def _run_scenario(
    app, service: HarnessEntryService, coverage: dict[str, bool], scenario: str
) -> None:
    async with app.run_test() as pilot:
        if scenario == "core":
            await _scenario_core(app, service, coverage, pilot)
        else:
            await _scenario_extended(app, service, coverage, pilot)


def _run_step(
    step_id: str,
    description: str,
    fn,
    results: list[StepResult],
    *,
    verbose: bool = False,
):
    start = time.monotonic()
    try:
        asyncio.run(fn())
    except Exception as exc:
        duration = time.monotonic() - start
        results.append(
            StepResult(
                step_id=step_id,
                description=description,
                status="failed",
                duration_sec=duration,
                detail=str(exc),
            )
        )
        raise
    duration = time.monotonic() - start
    results.append(
        StepResult(
            step_id=step_id,
            description=description,
            status="passed",
            duration_sec=duration,
        )
    )
    if verbose:
        print(f"[PASS] {step_id} ({duration:.2f}s)")


def main() -> int:
    args = _parse_args()
    runtime = check_tui2_runtime()
    if not runtime.get("textual_available", False):
        print("Error: TUI v2 runtime unavailable. Install textual.")
        return 2

    artifact_dir = args.output_dir / datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)

    service = HarnessEntryService()
    holder: dict[str, object] = {}

    def _hook(app):
        holder["app"] = app

    launched = launch_tui2(entry_service_factory=lambda: service, app_hook=_hook)
    if not launched:
        print("Error: failed to launch TUI v2 app")
        return 2
    app = holder.get("app")
    if app is None:
        print("Error: app hook did not receive app")
        return 2

    coverage = {
        "startup": False,
        "search": False,
        "document_edit": False,
        "graph_navigation": False,
        "archive_restore": False,
        "palette_navigation": False,
        "help_overlay": False,
    }
    results: list[StepResult] = []
    start = time.monotonic()
    status = "passed"
    failure = ""
    try:
        if args.scenario == "core":
            _run_step(
                "core",
                "Drive core TUI v2 user/agent workflow.",
                lambda: _run_scenario(app, service, coverage, "core"),
                results,
                verbose=args.verbose,
            )
        else:
            _run_step(
                "extended",
                "Drive extended TUI v2 user/agent workflow.",
                lambda: _run_scenario(app, service, coverage, "extended"),
                results,
                verbose=args.verbose,
            )
    except Exception as exc:
        status = "failed"
        failure = str(exc)

    report = {
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "scenario": args.scenario,
        "status": status,
        "failure": failure,
        "duration_sec": round(time.monotonic() - start, 3),
        "coverage_points": coverage,
        "steps": [asdict(item) for item in results],
        "activity_log": list(getattr(app, "_activity_log", [])),
    }
    report_file = artifact_dir / "report.json"
    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"AI agent TUI v2 report: {report_file}")
    print(f"Status: {status}")
    if failure:
        print(f"Failure: {failure}")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
