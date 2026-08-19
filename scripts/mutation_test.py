#!/usr/bin/env python3
"""Mutation testing for the TypeScript surfaces that have no second implementation.

WHY THIS EXISTS
---------------
Differential fuzzing (scripts/differential_fuzz.py) uses Python as an oracle,
so it can only reach code both implementations have. The session agent, the
API's HTTP layer, high-risk session handling and the secret sinks exist only
in TypeScript — and they are where the security properties live. For those,
the question "would the suite notice if this broke?" has no oracle at all, so
it has to be answered by breaking things on purpose.

A passing suite proves the code works on the cases someone wrote down. It says
nothing about whether a REGRESSION would be caught. This deliberately breaks
one security predicate at a time and checks that some test goes red. A mutant
that survives is a place where the code could silently stop enforcing
something and every test would still pass.

WHAT IT MUTATES
---------------
Security predicates specifically, not arbitrary syntax: comparison and
equality operators, boolean connectives, and guard conditions forced to always
allow. Mutating a log message would produce a survivor that means nothing;
mutating `if (!tokenValid)` means something exact.

Three outcomes per mutant:
  killed     the suite failed. Good: a regression here would be caught.
  SURVIVED   the suite passed. A gap, or an equivalent mutant. Needs triage.
  invalid    the mutant does not typecheck. Not a real mutant; skipped.

Usage:
    .venv/bin/python scripts/mutation_test.py --target agent
    .venv/bin/python scripts/mutation_test.py --target all --limit 40

Survivors are reported with file, line, and the exact edit, so each can be
judged by hand. The script never leaves a mutation behind: the original file
is restored after every run, including on interrupt.
"""

from __future__ import annotations

import argparse
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLI = REPO / "js" / "packages" / "cli"

# This script deliberately writes broken security code into the working tree,
# one file at a time, and restores it after each mutant. That is safe on its
# own and NOT safe alongside anything else touching the repository: a `git
# add -A` while a mutant is live commits a deliberately inverted security
# check. That happened once during development -- an inverted fingerprint
# check reached a commit -- so the guard below exists to make it structurally
# impossible rather than a thing to remember.
LOCK = REPO / ".mutation-test-running"


def acquire_lock() -> None:
    if LOCK.exists():
        raise SystemExit(
            f"{LOCK.name} exists: another mutation run is in progress, or a "
            f"previous one died with a mutant still applied. Check "
            f"`git diff` before deleting it."
        )
    LOCK.write_text(
        "A mutation test is running. The working tree contains deliberately\n"
        "broken code. Do not commit. Do not run `git add -A`.\n"
    )


def release_lock() -> None:
    LOCK.unlink(missing_ok=True)

# Each target names the source file and the tests that should defend it.
# Running only the relevant suites keeps a full pass tractable; a mutant that
# survives its own suite but would be caught by another is still a finding,
# because the defending test is not where anyone would look for it.
TARGETS: dict[str, tuple[str, list[str]]] = {
    # agent.ts also holds the high-risk session, whose tests live in
    # highRisk.test.ts. Leaving it out scored the agent at 38% and blamed the
    # code for gaps that were really a gap in this mapping.
    "agent": (
        "src/agent.ts",
        ["test/agentSecurity.test.ts", "test/tokens.test.ts", "test/highRisk.test.ts"],
    ),
    "server": ("src/api/server.ts", ["test/api.test.ts"]),
    "routes": ("src/api/routes.ts", ["test/api.test.ts"]),
    "highrisk": ("src/highRisk.ts", ["test/highRisk.test.ts"]),
    "sinks": ("src/sinks.ts", ["test/sinks.test.ts", "test/tokens.test.ts"]),
    "approvals": ("src/approvals.ts", ["test/highRisk.test.ts"]),
}

# Operator swaps that change a decision rather than a value's shape.
OPERATORS: list[tuple[str, str]] = [
    ("!==", "==="),
    ("===", "!=="),
    (" >= ", " > "),
    (" <= ", " < "),
    (" > ", " >= "),
    (" < ", " <= "),
    (" && ", " || "),
    (" || ", " && "),
]

# Lines worth mutating: they decide whether something is permitted, expired,
# within a limit, or authentic. A mutation anywhere else mostly produces noise.
SECURITY_HINTS = re.compile(
    r"\b("
    r"auth|token|cap|capab|scope|permit|allow|deny|refus|valid|verif|"
    r"expire|expires|ttl|limit|rate|uses|remaining|owner|secret|password|"
    r"factor|unlock|lock|held|fingerprint|hash|equal|match|forbidden"
    r")",
    re.IGNORECASE,
)

SKIP_LINE = re.compile(r"^\s*(//|\*|/\*)")


@dataclass
class Mutant:
    line_no: int
    original: str
    mutated: str
    description: str


def generate(source: str) -> list[Mutant]:
    mutants: list[Mutant] = []
    for i, line in enumerate(source.splitlines(), start=1):
        if SKIP_LINE.match(line) or not SECURITY_HINTS.search(line):
            continue
        for old, new in OPERATORS:
            if old not in line:
                continue
            mutated = line.replace(old, new, 1)
            if mutated == line:
                continue
            mutants.append(
                Mutant(i, line, mutated, f"{old.strip()} -> {new.strip()}")
            )
        # Force a guard to always allow. This is the single most informative
        # mutation for security code: if no test notices a check being removed
        # entirely, that check is unverified.
        guard = re.match(r"^(\s*)if \((.+)\) \{\s*$", line)
        if guard and SECURITY_HINTS.search(guard.group(2)):
            mutants.append(
                Mutant(
                    i,
                    line,
                    f"{guard.group(1)}if (false) {{",
                    "guard disabled (always allow)",
                )
            )
    return mutants


def run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        # A hang counts as killed: the suite noticed, however unhappily.
        return 1, "TIMEOUT"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target", default="all", choices=[*sorted(TARGETS), "all"]
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="cap mutants per target (0 = all)"
    )
    parser.add_argument("--timeout", type=int, default=420)
    args = parser.parse_args()

    targets = sorted(TARGETS) if args.target == "all" else [args.target]
    overall_survivors: list[tuple[str, Mutant]] = []
    overall_counts = {"killed": 0, "survived": 0, "invalid": 0}

    acquire_lock()
    print(
        "NOTE: the working tree will contain deliberately broken code until "
        "this finishes.\n      Do not commit from another shell while it runs.\n"
    )

    for name in targets:
        rel, tests = TARGETS[name]
        path = CLI / rel
        original = path.read_text()
        mutants = generate(original)
        if args.limit:
            mutants = mutants[: args.limit]
        print(f"\n=== {name} ({rel}): {len(mutants)} mutants ===")

        # Restore the file whatever happens, including Ctrl-C. Leaving a
        # deliberate security hole in the tree would be a spectacular own goal.
        def restore(*_: object) -> None:
            path.write_text(original)

        signal.signal(
            signal.SIGINT, lambda *a: (restore(), release_lock(), sys.exit(130))
        )

        try:
            for idx, mutant in enumerate(mutants, start=1):
                lines = original.splitlines(keepends=True)
                ending = "\n" if lines[mutant.line_no - 1].endswith("\n") else ""
                lines[mutant.line_no - 1] = mutant.mutated + ending
                path.write_text("".join(lines))

                code, _ = run(
                    ["npx", "tsc", "--noEmit"], CLI, timeout=args.timeout
                )
                if code != 0:
                    overall_counts["invalid"] += 1
                    print(f"  [{idx}/{len(mutants)}] line {mutant.line_no}: invalid (does not typecheck)")
                    continue

                code, _ = run(
                    ["npx", "vitest", "run", *tests], CLI, timeout=args.timeout
                )
                if code != 0:
                    overall_counts["killed"] += 1
                    print(f"  [{idx}/{len(mutants)}] line {mutant.line_no}: killed  ({mutant.description})")
                else:
                    overall_counts["survived"] += 1
                    overall_survivors.append((f"{rel}:{mutant.line_no}", mutant))
                    print(f"  [{idx}/{len(mutants)}] line {mutant.line_no}: SURVIVED ({mutant.description})")
        finally:
            restore()
            # Prove the restore worked rather than assuming it: a mutant left
            # behind is a deliberately broken security check sitting in the
            # tree waiting to be committed.
            if path.read_text() != original:
                release_lock()
                raise SystemExit(f"FAILED TO RESTORE {rel} -- fix this before committing")

    release_lock()

    total = sum(overall_counts.values())
    viable = overall_counts["killed"] + overall_counts["survived"]
    print(f"\n{'=' * 70}")
    print(
        f"{overall_counts['killed']} killed, {overall_counts['survived']} survived, "
        f"{overall_counts['invalid']} invalid (of {total})"
    )
    if viable:
        print(f"mutation score: {overall_counts['killed'] / viable:.0%} of viable mutants caught")

    if overall_survivors:
        print(f"\nSURVIVORS — each is either a gap or an equivalent mutant, and needs judging:\n")
        for where, mutant in overall_survivors:
            print(f"  {where}  [{mutant.description}]")
            print(f"    was: {mutant.original.strip()[:110]}")
            print(f"    now: {mutant.mutated.strip()[:110]}")
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
