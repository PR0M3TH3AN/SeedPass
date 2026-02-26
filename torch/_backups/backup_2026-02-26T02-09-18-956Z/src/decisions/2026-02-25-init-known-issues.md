# Decision: Initialize KNOWN_ISSUES.md

## Context
Multiple agent failures were observed in `torch/task-logs/daily/`, and scattered issue files existed in `torch/src/issues/`.
No central `KNOWN_ISSUES.md` existed.

## Decision
Create `KNOWN_ISSUES.md` and populate it with the investigation results of the recent failures and issue files.
Since all investigated issues (lint config, scheduler config, innerHTML usage) were found to be resolved or environment-specific, they are marked as [Resolved] in the initial file.

## Consequences
- A central source of truth for known issues now exists.
- Future agents can check this file before reporting duplicate issues.
- The `known-issues-agent` now has a file to triage daily.
