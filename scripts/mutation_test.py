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
    r"factor|unlock|lock|held|fingerprint|hash|equal|match|forbidden|"
    # `kind` is an authorization dimension in its own right -- a token's
    # `kinds` list is half of what it may reach -- and leaving it out hid the
    # shape check that stops a string `kinds` becoming a substring match.
    # `mnemonic`/`seed` guard the material everything else protects.
    r"kind|mnemonic|seed"
    r")",
    re.IGNORECASE,
)

SKIP_LINE = re.compile(r"^\s*(//|\*|/\*)")

# A line preceded by this marker has been triaged as an EQUIVALENT mutant:
# the mutation provably cannot change behaviour, so no test can kill it and
# chasing it is wasted effort. Marking it keeps future survivor lists
# meaningful -- a survivor should mean "look at this", not "this again".
# The marker must say WHY, so the judgement can be re-checked rather than
# trusted.
EQUIVALENT_MARKER = "mutation-equivalent:"


@dataclass
class Mutant:
    line_no: int
    original: str
    mutated: str
    description: str


def _marked_equivalent(lines: list[str], line_no: int) -> bool:
    """Is the code at `line_no` (1-based) preceded by an equivalence marker?"""
    idx = line_no - 2  # the line directly above, 0-based
    while idx >= 0 and SKIP_LINE.match(lines[idx]):
        if EQUIVALENT_MARKER in lines[idx]:
            return True
        idx -= 1
    return False


def generate(source: str) -> list[Mutant]:
    mutants: list[Mutant] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, start=1):
        if SKIP_LINE.match(line) or not SECURITY_HINTS.search(line):
            continue
        # Skip lines a human has already judged unkillable, with a reason.
        # Scans the whole contiguous comment block above, not just the line
        # immediately before: the marker belongs at the START of an
        # explanation, and requiring it on the last line would mean writing
        # the reason upside down.
        if _marked_equivalent(lines, i):
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
        # Block form: `if (cond) {`
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
        # Single-statement form: `if (cond) throw ...;` / `if (cond) return ...;`
        # Missed for a long time, and it is the shape a short refusal takes --
        # src/highRisk.ts generated NO mutants at all because its only guard
        # is written this way.
        # Greedy, so the condition runs to the LAST `) ` on the line -- a
        # non-greedy match splits `if (a(b)) return x;` in the wrong place and
        # produces garbage that only shows up as "invalid". Lines ending in
        # `{` are the block form, already handled above.
        inline = re.match(r"^(\s*)if \((.+)\) (\S.*)$", line)
        if (
            inline
            and not line.rstrip().endswith("{")
            and SECURITY_HINTS.search(inline.group(2))
        ):
            mutants.append(
                Mutant(
                    i,
                    line,
                    f"{inline.group(1)}if (false) {inline.group(3)}",
                    "inline guard disabled (always allow)",
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
    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help=(
            "skip the first N mutants. With --limit this runs a slice, so a "
            "long target can be measured in foreground-sized pieces rather "
            "than backgrounded -- this script writes broken security code "
            "into the tree, and must not run unattended alongside commits."
        ),
    )
    parser.add_argument("--timeout", type=int, default=420)
    parser.add_argument(
        "--kind",
        default="",
        help=(
            "only run mutants whose description contains this substring, e.g. "
            "--kind inline. Lets a newly added mutation rule be swept across "
            "every target without re-running the ones already judged."
        ),
    )
    args = parser.parse_args()

    targets = sorted(TARGETS) if args.target == "all" else [args.target]
    overall_survivors: list[tuple[str, Mutant]] = []
    overall_counts = {"killed": 0, "survived": 0, "invalid": 0}
    # A target the generator cannot reach scores 0 killed / 0 survived, which
    # prints identically to a clean sweep. That is the one result that must
    # never be mistaken for a pass: it means the file was NOT MEASURED.
    unmeasured: list[str] = []

    acquire_lock()
    print(
        "NOTE: the working tree will contain deliberately broken code until "
        "this finishes.\n      Do not commit from another shell while it runs.\n"
    )

    for name in targets:
        rel, tests = TARGETS[name]
        path = CLI / rel
        original = path.read_text()
        all_mutants = generate(original)
        if args.kind:
            all_mutants = [m for m in all_mutants if args.kind in m.description]
        mutants = all_mutants[args.offset :]
        if args.limit:
            mutants = mutants[: args.limit]
        span = f"{args.offset + 1}-{args.offset + len(mutants)} of {len(all_mutants)}"
        print(f"\n=== {name} ({rel}): mutants {span} ===")
        if not all_mutants:
            unmeasured.append(f"{name} ({rel})")
            print(
                "  NOT MEASURED: this file produced no mutants. Its security\n"
                "  logic is not in comparisons the generator can reach (or the\n"
                "  generator has a blind spot). Do not read this as a pass."
            )

        # Restore the file whatever happens, including Ctrl-C. Leaving a
        # deliberate security hole in the tree would be a spectacular own goal.
        def restore(*_: object) -> None:
            path.write_text(original)

        signal.signal(
            signal.SIGINT, lambda *a: (restore(), release_lock(), sys.exit(130))
        )

        try:
            for idx, mutant in enumerate(mutants, start=args.offset + 1):
                lines = original.splitlines(keepends=True)
                ending = "\n" if lines[mutant.line_no - 1].endswith("\n") else ""
                lines[mutant.line_no - 1] = mutant.mutated + ending
                path.write_text("".join(lines))

                code, _ = run(
                    ["npx", "tsc", "--noEmit"], CLI, timeout=args.timeout
                )
                if code != 0:
                    overall_counts["invalid"] += 1
                    print(f"  [{idx}/{len(all_mutants)}] line {mutant.line_no}: invalid (does not typecheck)")
                    continue

                code, _ = run(
                    ["npx", "vitest", "run", *tests], CLI, timeout=args.timeout
                )
                if code != 0:
                    overall_counts["killed"] += 1
                    print(f"  [{idx}/{len(all_mutants)}] line {mutant.line_no}: killed  ({mutant.description})")
                else:
                    overall_counts["survived"] += 1
                    overall_survivors.append((f"{rel}:{mutant.line_no}", mutant))
                    print(f"  [{idx}/{len(all_mutants)}] line {mutant.line_no}: SURVIVED ({mutant.description})")
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

    if unmeasured:
        print(
            "\nNOT MEASURED — no mutants generated, so these files were not\n"
            "tested at all by this run:\n"
        )
        for where in unmeasured:
            print(f"  {where}")

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
