#!/usr/bin/env python3
"""Emit canonical-JSON differential cases from the Python reference.

Entry hashes decide merge winners, so if the two implementations serialize
the same value differently they can pick different winners and never
converge. A security review found several such disagreements (number
formatting, key ordering) that the existing fixtures missed because they
only ever used ASCII keys and integer values.

Writes js/packages/test-vectors/fixtures/canonical_json.json.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "js" / "packages" / "test-vectors" / "fixtures" / "canonical_json.json"

# Values a vault can realistically contain, plus the edges that broke.
CASES: list = [
    {},
    {"a": 1},
    {"b": 2, "a": 1},
    {"modified_ts": 1700000000, "label": "site"},
    {"tags": ["b", "a"], "notes": ""},
    # Key ordering: supplementary plane vs BMP above U+E000
    {"\U0001f600": 1, "！": 2},
    {"z": 1, "é": 2, "中": 3, "\U0001f600": 4},
    # Escaping
    {'quote"': "back\\slash"},
    {"ctrl": "\x00\x01\x1f"},
    {"nl": "line\nbreak\ttab"},
    {"unicode": "café 中文 \U0001f512"},
    # Numbers
    {"n": 0},
    {"n": -0},
    {"n": 1},
    {"n": -17},
    {"n": 9007199254740991},
    {"n": 0.5},
    {"n": -0.25},
    {"n": 1e-7},
    {"n": 1.5e-9},
    # Values above 2**53 are deliberately absent: JSON gives no way to tell a
    # Python int from a float there, so the two implementations cannot agree
    # on a canonical form. canonicalJson refuses them rather than guessing;
    # see the "unsupported" list below.
    # Nesting and arrays
    {"links": [{"target_id": 1, "relation": "totp", "note": ""}]},
    [1, "two", None, True, False],
    {"deep": {"a": [{"b": {"c": [1, 2, 3]}}]}},
    # Entry-shaped, the actual hashed object
    {
        "type": "password",
        "kind": "password",
        "label": "example.com",
        "length": 16,
        "archived": False,
        "notes": "",
        "tags": ["web"],
        "modified_ts": 1700000000,
        "links": [],
        "custom_fields": [],
    },
]


# Values TypeScript must refuse rather than serialize ambiguously.
UNSUPPORTED = [
    {"n": 10**20},
    {"n": 12345678901234567890},
]


def main() -> None:
    cases = []
    for value in CASES:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
        cases.append({"value": value, "canonical": canonical})
    OUT.write_text(
        json.dumps(
            {
                "description": (
                    "canonicalJson must match json.dumps(sort_keys=True, "
                    "separators=(',',':')) exactly: entry hashes derived from "
                    "it decide merge winners across implementations."
                ),
                "cases": cases,
                "unsupported": UNSUPPORTED,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print(f"wrote {OUT.relative_to(REPO)} ({len(cases)} cases)")


if __name__ == "__main__":
    main()
