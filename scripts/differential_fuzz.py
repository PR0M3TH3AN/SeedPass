#!/usr/bin/env python3
"""Differential fuzzing: Python SeedPass vs the TypeScript port.

WHY THIS EXISTS
---------------
The cutover plan's last open gate is an independent security review. There is
no third party to hand the branch to, and the author reviewing their own work
has a known failure mode: you cannot see what you did not think of. Two
earlier review rounds each found criticals that self-review had missed.

The substitute for another pair of eyes is not more self-review. It is an
ORACLE THAT IS NOT THE AUTHOR'S JUDGEMENT. This project happens to have the
best such oracle available: two independent implementations that are required
to agree. Feed both the same randomly generated input and any disagreement is
a bug in one of them, established without anyone having to know in advance
which answer is right or what to look for.

Fixtures already prove agreement on inputs a human chose. This proves it on
inputs nobody chose, which is the whole point — the bugs that survive to
production are the ones outside the cases someone thought to write down.

WHAT IT COVERS
--------------
The surfaces where a disagreement would be silent and expensive:

  canonical    canonical JSON + hashing. Underpins every other hash, so a
               divergence here is a divergence everywhere.
  password     deterministic password derivation, v1 and v2, random policies.
               A mismatch means a user gets the wrong password after migrating.
  merge        the sync CRDT. A mismatch means two clients converge to
               DIFFERENT vaults, permanently.
  index0       the activity ledger's hashes, checkpoints, views and merge.
  recovery     threshold share split/recover, cross-implementation.
  semantic     retrieval index records and ranking.
  entry        entry normalization and modification.

Usage:
    .venv/bin/python scripts/differential_fuzz.py [--cases 200] [--seed 1]
    .venv/bin/python scripts/differential_fuzz.py --only merge --cases 5000

Exits non-zero on any divergence, printing the seed and the exact input needed
to reproduce it.
"""

from __future__ import annotations

import argparse
import json
import random
import string
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

CORE_DIR = REPO / "js" / "packages" / "core"
RUNNER = CORE_DIR / "_fuzz_runner.ts"

# Characters chosen to exercise the encoders rather than to look tidy:
# non-ASCII (ensure_ascii escaping), a surrogate pair (UTF-16 vs code-point
# ordering), quotes and backslashes (JSON escaping), and control characters.
INTERESTING_TEXT = [
    "",
    " ",
    "a",
    "simple",
    "with space",
    'quote"inside',
    "back\\slash",
    "new\nline",
    "tab\there",
    "\x00null-byte",
    "\x1b[31mansi",
    "\u00fcn\u00efcod\u00e9",
    "\u65e5\u672c\u8a9e",
    "\u2713",
    "\U0001f600",
    "\ufffd",
    " pad ",
    "0",
    "-1",
    "1e5",
    "null",
    "True",
]

# Bounds the generator deliberately reaches. Kept in sync with the
# implementations by the caps test in js/packages/core/test/.
TOMBSTONE_CAP = 2048
SUBJECT_CAP = 64

KINDS = [
    "password",
    "totp",
    "key_value",
    "document",
    "ssh",
    "pgp",
    "nostr",
    "seed",
    "managed_account",
]


def rand_text(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return rng.choice(INTERESTING_TEXT)
    return "".join(
        rng.choice(string.ascii_letters + string.digits + " -_.")
        for _ in range(rng.randint(0, 12))
    )


def rand_scalar(rng: random.Random) -> Any:
    roll = rng.random()
    if roll < 0.30:
        return rand_text(rng)
    if roll < 0.50:
        return rng.randint(-(2**31), 2**31)
    if roll < 0.60:
        return rng.choice([True, False])
    if roll < 0.68:
        return None
    if roll < 0.76:
        # Floats are where CPython's repr and JS's toString diverge most.
        return rng.choice([0.0, -0.0, 1.5, 1e16, 1e-7, 3.141592653589793])
    if roll < 0.88:
        return [rand_text(rng) for _ in range(rng.randint(0, 3))]
    return {rand_text(rng): rand_text(rng) for _ in range(rng.randint(0, 3))}


def rand_entry(rng: random.Random) -> dict[str, Any]:
    kind = rng.choice(KINDS)
    entry: dict[str, Any] = {
        "kind": kind,
        "type": kind,
        "label": rand_text(rng),
        "notes": rand_text(rng),
        "tags": [rand_text(rng) for _ in range(rng.randint(0, 4))],
        "archived": rng.choice([True, False]),
        "modified_ts": rng.randint(0, 2_000_000_000),
    }
    if rng.random() < 0.5:
        entry["username"] = rand_text(rng)
    if rng.random() < 0.4:
        entry["url"] = rand_text(rng)
    if rng.random() < 0.4:
        entry["length"] = rng.randint(8, 128)
    if rng.random() < 0.3:
        entry["index"] = rng.randint(0, 50)
    if rng.random() < 0.3:
        entry["links"] = [
            {
                "target_id": str(rng.randint(0, 20)),
                "relation": rand_text(rng),
                "note": rand_text(rng),
            }
            for _ in range(rng.randint(0, 3))
        ]
    if rng.random() < 0.2:
        entry["custom_fields"] = [{"label": rand_text(rng), "value": rand_text(rng)}]
    if rng.random() < 0.15:
        # A field neither implementation knows: both must carry it through.
        entry[rand_text(rng) or "x"] = rand_scalar(rng)
    return entry


def rand_entries(rng: random.Random, max_entries: int = 6) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for _ in range(rng.randint(0, max_entries)):
        # Mostly numeric ids, occasionally not — non-numeric ids are exactly
        # the input that used to break view building.
        key = str(rng.randint(0, 30)) if rng.random() < 0.85 else rand_text(rng) or "k"
        out[key] = rand_entry(rng)
    return out


def rand_payload(rng: random.Random) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 4,
        "entries": rand_entries(rng),
    }
    if rng.random() < 0.7:
        tombstones = {}
        # Occasionally generate past the retention cap. Without this the
        # eviction path is never reached: a mutation testing run proved the
        # fuzzer could not see an off-by-one in the cap, because random small
        # payloads never trip it. Bounded code is only tested at its bound.
        count = (
            rng.randint(TOMBSTONE_CAP - 2, TOMBSTONE_CAP + 4)
            if rng.random() < 0.04
            else rng.randint(0, 3)
        )
        for n in range(count):
            # Keys must be DISTINCT to reach the cap: drawing from a small id
            # range produced 2050 writes into 31 slots, so the cap was never
            # crossed and the eviction path stayed unreachable.
            key = str(rng.randint(0, 30)) if count <= 3 else str(n)
            tombstones[key] = {
                "deleted_ts": rng.randint(0, 2_000_000_000),
                "entry_hash": rand_text(rng),
                "event_hash": rand_text(rng),
                "source": rand_text(rng),
            }
        payload["_sync_meta"] = {
            "next_index": rng.randint(0, 40),
            "last_merge_ts": rng.randint(0, 2_000_000_000),
            "tombstones": tombstones,
        }
    return payload


def rand_policy(rng: random.Random) -> dict[str, Any]:
    policy: dict[str, Any] = {}
    for key in ("min_uppercase", "min_lowercase", "min_digits", "min_special"):
        if rng.random() < 0.6:
            policy[key] = rng.randint(0, 4)
    if rng.random() < 0.4:
        policy["include_special_chars"] = rng.choice([True, False])
    if rng.random() < 0.3:
        policy["exclude_ambiguous"] = rng.choice([True, False])
    if rng.random() < 0.25:
        policy["allowed_special_chars"] = rng.choice(["!@#", "$%^", "!@#$%^*-_+=?"])
    return policy


# --------------------------------------------------------------- case builders
# Each builder returns (name, python_result, ts_request). The TS request is
# executed by the node runner; results are compared as canonical JSON so the
# comparison itself cannot paper over an ordering difference.


def case_canonical(rng: random.Random) -> tuple[str, Any, dict[str, Any]]:
    from utils.checksum import canonical_json_dumps

    value = rand_scalar(rng) if rng.random() < 0.4 else rand_entry(rng)
    return (
        "canonical",
        canonical_json_dumps(value),
        {"op": "canonical", "value": value},
    )


def case_password(rng: random.Random) -> tuple[str, Any, dict[str, Any]]:
    from bip_utils import Bip39SeedGenerator
    from local_bip85.bip85 import BIP85
    from seedpass.core.password_generation import PasswordGenerator, PasswordPolicy

    class _Deriver:
        def derive_seed_from_mnemonic(self, mnemonic, passphrase=""):
            return Bip39SeedGenerator(mnemonic).Generate(passphrase)

    mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    policy_kwargs = rand_policy(rng)
    length = rng.randint(8, 64)
    index = rng.randint(0, 5000)
    version = rng.choice([1, 2])
    bip85 = BIP85(Bip39SeedGenerator(mnemonic).Generate(""))
    pg = PasswordGenerator(
        _Deriver(), mnemonic, bip85, policy=PasswordPolicy(**policy_kwargs)
    )
    kwargs = {} if version == 1 else {"gen_version": version}
    try:
        result: Any = pg.generate_password(length=length, index=index, **kwargs)
    except Exception as exc:  # a refusal is a result too, and must match
        result = "ERROR:Refused"
    return (
        "password",
        result,
        {
            "op": "password",
            "mnemonic": mnemonic,
            "length": length,
            "index": index,
            "genVersion": version,
            "policy": policy_kwargs,
        },
    )


def case_merge(rng: random.Random) -> tuple[str, Any, dict[str, Any]]:
    from seedpass.core.sync_conflict import merge_index_payloads

    current = rand_payload(rng)
    incoming = rand_payload(rng)
    source = rand_text(rng)
    try:
        result: Any = merge_index_payloads(current, incoming, source_tag=source)
    except Exception as exc:
        result = "ERROR:Refused"
    return (
        "merge",
        result,
        {"op": "merge", "current": current, "incoming": incoming, "sourceTag": source},
    )


def case_index0(rng: random.Random) -> tuple[str, Any, dict[str, Any]]:
    from seedpass.core import index0 as index0_mod

    fp_dir = (
        f"/tmp/seedpass/{''.join(rng.choice('0123456789ABCDEF') for _ in range(16))}"
    )
    payload: dict[str, Any] = {"schema_version": 4, "entries": rand_entries(rng)}
    events = []
    # Same reasoning as the tombstone cap: occasionally produce enough events,
    # with enough distinct subjects, to reach INDEX0_CHECKPOINT_SUBJECT_CAP
    # and the per-writer checkpoint retention limit.
    big = rng.random() < 0.10
    # Well PAST the cap, not at it. A first attempt generated 62-72 events and
    # peaked at 63 distinct subjects across 250 cases -- one short -- so the
    # eviction path stayed unreachable and a deliberate off-by-one there went
    # undetected. Bounded code has to be driven past its bound, with margin.
    event_count = (
        rng.randint(SUBJECT_CAP + 20, SUBJECT_CAP + 60) if big else rng.randint(0, 5)
    )
    # A large run is clustered into one day half the time, so both the subject
    # cap (per checkpoint) and the checkpoint retention limit get reached.
    day_spread = not big or rng.random() < 0.5
    for _i in range(event_count):
        events.append(
            {
                "event_type": rand_text(rng) or "entry_created",
                "subject_type": "entry",
                # Distinct by construction for the large runs: collisions in a
                # random id space are what kept the distinct count below the cap.
                "subject_id": str(rng.randint(0, 400)) if not big else f"s{_i}",
                "subject_kind": rng.choice(KINDS),
                # Two shapes on purpose. Spread across days exercises
                # checkpoint grouping and the per-writer retention limit;
                # clustered into ONE day is what reaches the subject cap,
                # since subjects are capped per checkpoint and a day with one
                # event has one subject.
                "modified_ts": (
                    rng.randint(1, 2_000_000_000)
                    if day_spread
                    else 1_700_000_000 + rng.randint(0, 86_000)
                ),
                "tags": [rand_text(rng) for _ in range(rng.randint(0, 3))],
                "summary": rand_text(rng),
            }
        )
    try:
        for spec in events:
            payload = index0_mod.append_index0_event(
                payload,
                event_type=spec["event_type"],
                subject_type=spec["subject_type"],
                subject_id=spec["subject_id"],
                subject_kind=spec["subject_kind"],
                modified_ts=spec["modified_ts"],
                fingerprint_dir=fp_dir,
                tags=spec["tags"],
                summary=spec["summary"],
            )
        result: Any = index0_mod.compact_index0_payload(payload, fingerprint_dir=fp_dir)
    except Exception as exc:
        result = "ERROR:Refused"
    return (
        "index0",
        result,
        {
            "op": "index0",
            "fingerprintDir": fp_dir,
            "entries": payload.get("entries", {}),
            "events": events,
        },
    )


def case_recovery(rng: random.Random) -> tuple[str, Any, dict[str, Any]]:
    """Split in Python, recover in TypeScript.

    Shares are randomized by design, so the two implementations cannot produce
    identical tokens. What must hold is that each can recover the other's --
    which is the property that actually matters.
    """
    from seedpass.core.agent_recovery import split_secret

    secret = rand_text(rng) or "fallback secret"
    threshold = rng.randint(2, 4)
    total = rng.randint(threshold, threshold + 3)
    try:
        shares = split_secret(secret, total_shares=total, threshold=threshold)
        chosen = rng.sample(shares, threshold)
    except Exception as exc:
        return ("recovery", "ERROR:Refused", {"op": "noop"})
    return ("recovery", secret, {"op": "recover", "shares": chosen})


def case_semantic(rng: random.Random) -> tuple[str, Any, dict[str, Any]]:
    from seedpass.core.semantic_index import SemanticIndex

    entries = []
    for entry_id in range(rng.randint(0, 6)):
        entry = rand_entry(rng)
        entry["id"] = entry_id
        entries.append(entry)
    query = rand_text(rng)
    with tempfile.TemporaryDirectory() as tmpdir:
        index = SemanticIndex(Path(tmpdir))
        try:
            index.build(entries)
            records = json.loads(
                (Path(tmpdir) / "semantic_index" / "records.json").read_text(
                    encoding="utf-8"
                )
            )
            hits = index.search(query, k=10)
        except Exception as exc:
            return ("semantic", "ERROR:Refused", {"op": "noop"})
    return (
        "semantic",
        {"records": records, "hits": hits},
        {"op": "semantic", "entries": entries, "query": query},
    )


def case_entry(rng: random.Random) -> tuple[str, Any, dict[str, Any]]:
    """Entry hashing, which decides merge winners."""
    from seedpass.core.sync_conflict import _entry_event_hash  # type: ignore

    entry = rand_entry(rng)
    try:
        result: Any = _entry_event_hash(entry)
    except Exception as exc:
        result = "ERROR:Refused"
    return ("entry", result, {"op": "entryHash", "entry": entry})


BUILDERS: dict[str, Callable[[random.Random], tuple[str, Any, dict[str, Any]]]] = {
    "canonical": case_canonical,
    "password": case_password,
    "merge": case_merge,
    "index0": case_index0,
    "recovery": case_recovery,
    "semantic": case_semantic,
    "entry": case_entry,
}


def _float_literals(value: Any) -> bool:
    """Does this value contain a float that JavaScript cannot distinguish?

    Python's json keeps int and float apart; JavaScript has one number type.
    An integral float (0.0, 1.0, 2e3) therefore cannot survive the round trip,
    and neither can a value outside the safe-integer range, which JSON.parse
    has already rounded. Both are documented limitations of
    js/packages/core/src/sync/canonical.ts, not new bugs -- but they must be
    recognized precisely, or "known limitation" becomes a place to hide real
    divergences.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, float):
        return value.is_integer() or abs(value) > 2**53
    if isinstance(value, int):
        return abs(value) > 2**53
    if isinstance(value, dict):
        return any(_float_literals(v) for v in value.values()) or any(
            _float_literals(k) for k in value
        )
    if isinstance(value, list):
        return any(_float_literals(v) for v in value)
    return False


def is_known_limitation(python_result: Any, request: Any) -> bool:
    """True when a divergence is one of the two documented number limitations.

    Checks the INPUT as well as the Python result, because some surfaces
    return a string (canonical JSON) in which the offending float is no longer
    a float. Deliberately narrow otherwise: a divergence with no
    unrepresentable number anywhere in it is a real finding and must never be
    filtered away -- "known limitation" is exactly the kind of category that
    quietly grows to hide real bugs.
    """
    return _float_literals(request) or _float_literals(python_result)


def canonical(value: Any) -> str:
    from utils.checksum import canonical_json_dumps

    return canonical_json_dumps(value)


def run_ts(requests: list[dict[str, Any]]) -> list[Any]:
    """Execute every TS-side request in one node process."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(requests, fh)
        input_path = fh.name
    try:
        proc = subprocess.run(
            ["npx", "tsx", str(RUNNER), input_path],
            cwd=CORE_DIR,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if proc.returncode != 0:
            print(proc.stdout[-4000:], file=sys.stderr)
            print(proc.stderr[-4000:], file=sys.stderr)
            raise SystemExit("TypeScript runner failed")
        return json.loads(proc.stdout)
    finally:
        Path(input_path).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=int, default=200, help="cases per surface")
    parser.add_argument(
        "--seed", type=int, default=1, help="RNG seed (reproduces a run)"
    )
    parser.add_argument(
        "--only",
        action="append",
        choices=sorted(BUILDERS),
        help="restrict to one or more surfaces (repeatable)",
    )
    args = parser.parse_args()

    surfaces = args.only or sorted(BUILDERS)
    rng = random.Random(args.seed)

    print(
        f"differential fuzz: seed={args.seed} cases={args.cases} surfaces={','.join(surfaces)}"
    )

    expected: list[tuple[str, int, Any]] = []
    requests: list[dict[str, Any]] = []
    for surface in surfaces:
        builder = BUILDERS[surface]
        for i in range(args.cases):
            name, python_result, ts_request = builder(rng)
            expected.append((name, i, python_result))
            requests.append(ts_request)

    print(f"  generated {len(requests)} cases; running the TypeScript side...")
    ts_results = run_ts(requests)
    if len(ts_results) != len(expected):
        raise SystemExit(
            f"runner returned {len(ts_results)} results for {len(expected)} cases"
        )

    divergences: list[tuple[str, int, str, str, dict[str, Any]]] = []
    known: list[tuple[str, int]] = []
    skipped = 0
    for (name, idx, python_result), ts_result, request in zip(
        expected, ts_results, requests
    ):
        if request.get("op") == "noop":
            skipped += 1
            continue
        py_canon = canonical(python_result)
        ts_canon = canonical(ts_result)
        if py_canon == ts_canon:
            continue
        if is_known_limitation(python_result, request):
            known.append((name, idx))
            continue
        divergences.append((name, idx, py_canon, ts_canon, request))

    by_surface: dict[str, int] = {}
    for name, _, _ in expected:
        by_surface[name] = by_surface.get(name, 0) + 1
    for surface in sorted(by_surface):
        failures = sum(1 for d in divergences if d[0] == surface)
        mark = "PASS" if failures == 0 else "FAIL"
        print(
            f"  [{mark}] {surface}: {by_surface[surface] - failures}/{by_surface[surface]} agree"
        )

    if skipped:
        print(f"  ({skipped} cases skipped: the Python side refused the input)")
    if known:
        by_known: dict[str, int] = {}
        for name, _ in known:
            by_known[name] = by_known.get(name, 0) + 1
        detail = ", ".join(f"{k}={v}" for k, v in sorted(by_known.items()))
        print(
            f"  ({len(known)} known number-representation limitations: {detail} "
            f"-- see canonical.ts, findAmbiguousNumbers)"
        )

    if divergences:
        print(
            f"\n{len(divergences)} DIVERGENCE(S) — reproduce with --seed {args.seed}\n"
        )
        dump = Path(
            "/tmp/claude-1000/-home-user/4efd790e-427f-430a-b379-ef8391e6744f/scratchpad/divergences.json"
        )
        dump.write_text(
            json.dumps(
                [
                    {"surface": n, "case": i, "python": p_, "ts": t, "input": r}
                    for n, i, p_, t, r in divergences
                ],
                indent=1,
            )
        )
        print(f"  (full list written to {dump})\n")
        for name, idx, py_canon, ts_canon, request in divergences[:5]:
            print(f"--- {name} case {idx} ---")
            print(f"  input : {json.dumps(request)[:600]}")
            print(f"  python: {py_canon[:600]}")
            print(f"  ts    : {ts_canon[:600]}")
            print()
        if len(divergences) > 5:
            print(f"  ... and {len(divergences) - 5} more")
        return 1

    print(f"\nno divergences across {len(requests) - skipped} compared cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
