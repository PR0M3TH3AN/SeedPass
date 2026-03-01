# Audit Report — 2026-02-27 (default branch)

**Summary**

* Commit: db9ff1e419d0a3a3c6d8bb03d364acf059664d27
* Date: 2026-02-27 03:20 UTC
* Node: v22.0.0 / OS: Linux

**Metrics**

* Grandfathered oversized files: 0 files (total excess lines: 0)
* New oversized files: 13 files (total excess lines: 4181)
  (Note: Many of these are in `torch/` and likely structural or config files.)
* Total innerHTML assignments: 26

  * Top offenders:
    1. docs/assets/theme.js — 5
    2. landing/docs.js — 3
    3. torch/dashboard/app.js — 1
    4. torch/landing/index.html — 1
    (Plus 22 others in `torch/_backups/`)

* Lint failures: 0 (files: 0)

**Delta vs previous (N/A - First Run)**

* Grandfathered: +0 files, +0 excess lines
* innerHTML: +26 total assignments
* lint: +0 failures

**High-priority items**

* Remove or trim oversized file `torch/landing/index.html` (excess lines: 1341)
* Review `docs/assets/theme.js` for innerHTML usage — consider sanitized templates.
* Note: `torch/_backups` folder is contributing significantly to noise in reports. Suggest adding to exclusion list.

**Artifacts**

* file-size-report.json
* innerhtml-report.json
* lint-report.json
* raw logs
