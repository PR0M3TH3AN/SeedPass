# Test Audit Report

Date: 2026-03-01
Agent: test-audit-agent

## Overview

The test-audit-agent ran a static analysis of tests using `run_python_static_analysis.py` and discovered multiple test files that utilized `time.sleep()`, causing flaky behavior, non-determinism, and slowing down the overall test suite. The agent modified several tests to replace explicit sleeping with active polling or deterministic thread joins.

## Changes

1. **`src/tests/test_unlock_sync.py`**
   - In `test_unlock_triggers_sync`, replaced `time.sleep(0.05)` with `pm._sync_task.join(timeout=1.0)`.

2. **`src/tests/test_nostr_sdk_workflow.py`**
   - Replaced `time.sleep(0.5)` with a polling loop that attempts to connect using `create_connection` up to 40 times (with 0.05s interval), raising an exception if the fake relay doesn't start.

3. **`src/tests/test_background_relay_check.py`**
   - In both async checks, replaced `time.sleep(0.05)` with `pm._relay_thread.join(timeout=1.0)`.

4. **`src/tests/test_offline_mode_behavior.py`**
   - Removed `time.sleep(0.05)` entirely from `test_start_background_sync_offline` because the early return on offline mode makes synchronization instantaneous, rendering the sleep useless.

5. **`src/tests/test_nostr_index_size.py`**
   - The test was missing an assertion (reported by static analysis). Added `assert len(results) > 0` to verify results collection.
   - Replaced `time.sleep(delay)` during propagation waiting with an asynchronous polling retry logic inside `fetch_with_retry` loop.

## Notes

No remaining flakiness detected in the modified files.
