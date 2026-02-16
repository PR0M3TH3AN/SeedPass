---
title: InnerHTML violations in landing/index.html
status: open
severity: medium
agent: style-agent
cadence: daily
created: 2026-02-15T08:00:00Z
---

# Issue: InnerHTML usage detected

The `style-agent` detected usage of `innerHTML` in `landing/index.html`, which violates the project's style guidelines for security reasons.

## Violations
- `landing/index.html`: 3 assignments

## Recommendation
Refactor the code to use `document.createElement` or `textContent` where possible.

## Reproduction Attempt (2026-02-16T11:47:38Z)
Ran reproduction script: `torch/examples/reproducers/ISSUE_daily_style-agent_innerhtml/repro.py`
```
Checking torch/landing/index.html for innerHTML usage...
FAILURE: innerHTML found in file.
Line 865: contentDiv.innerHTML = marked.parse(text);
Line 869: contentDiv.innerHTML = `<p class="text-danger">Error loading documentation: ${error.message}</p>`;
Line 931: const originalContent = btn.innerHTML;
Line 937: btn.innerHTML = originalContent;
```
