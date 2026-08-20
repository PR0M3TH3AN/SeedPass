#!/usr/bin/env python3
"""Prove the local toolchain matches the lockfiles, before anything trusts it.

WHY THIS EXISTS

A local CI gate is only worth running if it reaches the same verdict CI would.
On 2026-08-20 this repository's local environment disagreed with its own
lockfile on every pinned tool:

    black     local 26.1.0   locked 24.10.0
    pytest    local  9.0.2   locked  8.4.1
    coverage  local 7.10.1   locked 7.10.2

`poetry run black --check .` passed locally and failed on GitHub, and an
earlier commit titled "satisfy the black gate" had already reformatted five
files with the WRONG black -- making the gate worse while looking like a fix.
A green local gate that disagrees with CI is not a weak check, it is a
harmful one: people stop reading the real result.

So this runs first, and everything downstream is meaningless without it.

TWO RULES IT ENFORCES

1. Tools are executed through the repository-controlled environment
   (`poetry run ...`, `pnpm exec ...`), never by bare name off PATH. This
   script therefore inspects those environments, not PATH.
2. It CHECKS and never REPAIRS. `scripts/dev_sync.sh` repairs. A gate that
   silently mutates your environment hides the drift it exists to surface.

It is deliberately stdlib-only and run by the system interpreter, because it
has to work when the environment it is checking is broken -- which is exactly
when it is needed.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
JS = REPO / "js"

# Tools whose version changes what CI decides. A mismatch here means a local
# run and a CI run can disagree about the same source.
VERDICT_TOOLS = ("black", "pytest", "coverage")

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = DIM = RESET = ""

failures: list[str] = []


def ok(label: str, detail: str = "") -> None:
    print(
        f"  {GREEN}ok{RESET}   {label}" + (f" {DIM}{detail}{RESET}" if detail else "")
    )


def bad(label: str, detail: str, fix: str) -> None:
    print(f"  {RED}FAIL{RESET} {label} {DIM}{detail}{RESET}")
    failures.append(f"{label}: {detail}\n         fix: {fix}")


def run(cmd: list[str], cwd: Path = REPO) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=180)
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "timed out"


def parse_lock_versions(lock: Path) -> dict[str, str]:
    """name -> version from poetry.lock, without needing a toml parser."""
    out: dict[str, str] = {}
    name = None
    for line in lock.read_text().splitlines():
        if m := re.match(r'^name = "([^"]+)"', line):
            name = m.group(1)
        elif name and (m := re.match(r'^version = "([^"]+)"', line)):
            out[name] = m.group(1)
            name = None
    return out


def check_python_env() -> None:
    print("\nPython (poetry-controlled environment)")

    code, out = run(["poetry", "check", "--lock"])
    if code == 0:
        ok("poetry.lock agrees with pyproject.toml")
    else:
        bad(
            "poetry.lock disagrees with pyproject.toml",
            out.splitlines()[-1] if out else "",
            "poetry lock",
        )

    locked = parse_lock_versions(REPO / "poetry.lock")
    code, out = run(
        [
            "poetry",
            "run",
            "python",
            "-c",
            "import json;from importlib.metadata import distributions;"
            "print(json.dumps({d.metadata['Name'].lower(): d.version "
            "for d in distributions() if d.metadata['Name']}))",
        ]
    )
    if code != 0:
        bad(
            "cannot inspect the poetry environment",
            out.splitlines()[-1] if out else "",
            "./scripts/dev_sync.sh",
        )
        return
    installed = json.loads(out.splitlines()[-1])

    drift = []
    for tool in VERDICT_TOOLS:
        want, have = locked.get(tool), installed.get(tool)
        if want is None:
            continue
        if have is None:
            drift.append(f"{tool} missing (locked {want})")
        elif have != want:
            drift.append(f"{tool} {have} != locked {want}")
    if drift:
        bad(
            "installed tools disagree with poetry.lock",
            "; ".join(drift),
            "./scripts/dev_sync.sh",
        )
    else:
        ok(
            "black, pytest and coverage match poetry.lock",
            " ".join(f"{t}={locked.get(t,'?')}" for t in VERDICT_TOOLS),
        )


def check_js_env() -> None:
    print("\nJavaScript (pnpm-controlled environment)")
    pkg = json.loads((JS / "package.json").read_text())

    want_node = str(pkg.get("engines", {}).get("node", "")).lstrip("^>=~ ")
    have_node = sys.version and run(["node", "--version"])[1].lstrip("v")
    if not want_node:
        bad(
            "js/package.json declares no engines.node",
            "nothing to check against",
            'add "engines": {"node": ">=22"} to js/package.json',
        )
    elif have_node.split(".")[0] != want_node.split(".")[0]:
        bad(
            "node major differs from engines.node",
            f"have {have_node}, want {want_node}",
            f"install Node {want_node.split('.')[0]}",
        )
    else:
        ok("node matches engines.node", f"v{have_node}")

    want_pnpm = str(pkg.get("packageManager", "")).removeprefix("pnpm@")
    have_pnpm = run(["pnpm", "--version"])[1]
    if want_pnpm and have_pnpm != want_pnpm:
        bad(
            "pnpm differs from packageManager",
            f"have {have_pnpm}, want {want_pnpm}",
            "corepack enable && corepack prepare --activate",
        )
    else:
        ok("pnpm matches packageManager", have_pnpm)

    # --dry-run so the check cannot become the repair.
    code, out = run(["pnpm", "install", "--frozen-lockfile", "--dry-run"], cwd=JS)
    if code == 0:
        ok("node_modules satisfies pnpm-lock.yaml")
    else:
        bad(
            "pnpm-lock.yaml not satisfied",
            out.splitlines()[-1] if out else "",
            "./scripts/dev_sync.sh",
        )


def main() -> int:
    print("SeedPass CI preflight — does this machine agree with the lockfiles?")
    check_python_env()
    check_js_env()

    print()
    if failures:
        print(
            f"{RED}preflight failed{RESET} — a local gate run now could disagree with CI.\n"
        )
        for f in failures:
            print(f"  - {f}")
        print("\nRepair with:  ./scripts/dev_sync.sh")
        return 1
    print(f"{GREEN}preflight passed{RESET} — local checks can be trusted to match CI.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
