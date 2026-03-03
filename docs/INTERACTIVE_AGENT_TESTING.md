# Interactive Agent TUI Testing Protocol

This document defines how AI agents should perform exploratory and regression testing on the SeedPass TUI v2 using the `scripts/interactive_agent_tui_test.py` harness.

## 1. Overview
The testing harness uses **Dependency Injection** to replace the real SeedPass service layer with a `MockService`. This allows agents to:
1.  **Bypass Encryption:** Test the UI without knowing passwords or seeds.
2.  **Avoid Side Effects:** No changes are made to the real vault or filesystem.
3.  **Simulate Edge Cases:** Mock specific failures (e.g., sync errors) to see how the UI recovers.

## 2. How to Run
Execute the harness using the project's virtual environment:
```bash
.venv/bin/python scripts/interactive_agent_tui_test.py
```

## 3. How to Extend
To add a new test case:
1.  **Update the Mock:** If testing a new service method, add it to `AgentMockService`.
2.  **Add a Step:** In `run_full_walkthrough`, use `app._run_palette_command("your-command")` or direct action calls (e.g., `app.action_toggle_archive()`).
3.  **Verify State:** Use `pilot.pause()` to let the TUI update, then query widgets:
    ```python
    status = str(app.query_one("#status").render())
    assert "Expected" in status
    ```

## 4. Key Testing Areas
*   **Palette Commands:** Ensure `_run_palette_command` correctly routes inputs to services.
*   **Selection Persistence:** Verify that the "Selected Entry" remains correct after archiving or refreshing.
*   **Layout Adaptability:** Test compact vs. comfortable density.
*   **Reactive UI:** Verify that `_load_entries` is called automatically after mutations.

## 5. Agent Instructions for Future Runs
If you are an agent tasked with "looking for bugs":
1.  **Run the script:** Confirm the baseline walkthrough passes.
2.  **Introduce Chaos:** Modify the mock to throw exceptions randomly.
3.  **Check Transitions:** Rapidly switch between entries and layouts.
4.  **Document Failures:** If a widget isn't found or a status message is wrong, report the line number in `app.py`.
