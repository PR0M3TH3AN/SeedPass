from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest

pytest.importorskip("pty")
pytest.importorskip("termios")


def _load_harness_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "ai_tui_agent_test.py"
    spec = importlib.util.spec_from_file_location("ai_tui_agent_test", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


harness = _load_harness_module()


def test_run_step_records_passed_result():
    results = []
    called = {"value": False}

    def _ok():
        called["value"] = True

    harness._run_step("step_a", "happy path", _ok, results, verbose=False)

    assert called["value"] is True
    assert len(results) == 1
    assert results[0].step_id == "step_a"
    assert results[0].status == "passed"
    assert results[0].detail is None


def test_run_step_records_failed_result_and_reraises():
    results = []

    def _boom():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        harness._run_step("step_b", "failing path", _boom, results, verbose=False)

    assert len(results) == 1
    assert results[0].step_id == "step_b"
    assert results[0].status == "failed"
    assert results[0].detail == "boom"


def test_add_entry_menu_open_waits_when_choice_omitted():
    class Runner:
        def __init__(self):
            self.sent = []
            self.waited = []

        def sendline(self, value=""):
            self.sent.append(value)

        def wait_for(self, pattern, timeout):
            self.waited.append((pattern, timeout))

    runner = Runner()
    harness._add_entry_menu_open(runner, timeout=5.0, choice=None)
    assert runner.sent == ["1"]
    assert len(runner.waited) == 1
    assert "Select entry type or press Enter to go back:" in runner.waited[0][0]


def test_add_entry_menu_open_sends_choice_when_provided():
    class Runner:
        def __init__(self):
            self.sent = []
            self.expect_calls = []

        def sendline(self, value=""):
            self.sent.append(value)

        def expect_and_send(self, pattern, value, timeout):
            self.expect_calls.append((pattern, value, timeout))

    runner = Runner()
    harness._add_entry_menu_open(runner, timeout=5.0, choice="7")
    assert runner.sent == ["1"]
    assert runner.expect_calls == [
        ("Select entry type or press Enter to go back:", "7", 5.0)
    ]


def test_complete_onboarding_reaches_main_menu_and_sends_password():
    class Runner:
        def __init__(self):
            self.calls = [
                (r"Enter your choice \(1-8\) or press Enter to exit:", False),
                (r"Enter a new password:", True),
                (r"Enter your choice \(1-8\) or press Enter to exit:", False),
                (r"Enter a new password:", False),
                (r"Confirm your password:", True),
                (r"Enter your choice \(1-8\) or press Enter to exit:", True),
            ]
            self.sent = []

        def try_wait_for(self, pattern, timeout):
            expected_pattern, ret = self.calls.pop(0)
            assert pattern == expected_pattern
            return ret

        def sendline(self, value=""):
            self.sent.append(value)

        def pump(self, duration):
            return None

    runner = Runner()
    harness._complete_onboarding_to_main_menu(runner, timeout=1.0, password="pw123")
    assert runner.sent == ["pw123", "pw123"]
    assert runner.calls == []


def test_complete_onboarding_times_out_without_expected_prompts():
    class Runner:
        def try_wait_for(self, pattern, timeout):
            return False

        def sendline(self, value=""):
            return None

        def pump(self, duration):
            return None

    runner = Runner()
    with pytest.raises(harness.TUIHarnessError, match="Onboarding did not reach main"):
        harness._complete_onboarding_to_main_menu(runner, timeout=0.0, password="pw")


def test_drain_to_main_menu_uses_helper_prompt_then_returns():
    class Runner:
        def __init__(self):
            self.main_attempts = 0
            self.helper_calls = []

        def wait_for(self, pattern, timeout):
            self.main_attempts += 1
            if self.main_attempts == 1:
                raise harness.TUIHarnessError("not yet")
            return None

        def expect_and_send(self, pattern, value, timeout):
            self.helper_calls.append((pattern, value, timeout))
            return None

        def pump(self, duration):
            return None

    runner = Runner()
    harness._drain_to_main_menu(runner, timeout=1.0)
    assert runner.main_attempts == 2
    assert len(runner.helper_calls) == 1
    assert runner.helper_calls[0][1] == ""


def test_drain_to_main_menu_times_out_when_no_prompt_progress(monkeypatch):
    class Runner:
        def wait_for(self, pattern, timeout):
            raise harness.TUIHarnessError("missing")

        def expect_and_send(self, pattern, value, timeout):
            raise harness.TUIHarnessError("missing helper")

        def pump(self, duration):
            return None

    timeline = iter([0.0, 0.05, 0.15])
    monkeypatch.setattr(harness.time, "monotonic", lambda: next(timeline))

    with pytest.raises(
        harness.TUIHarnessError, match="Unable to return to main menu within timeout"
    ):
        harness._drain_to_main_menu(Runner(), timeout=0.1)
