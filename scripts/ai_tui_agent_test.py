#!/usr/bin/env python3
"""
Deterministic AI-agent harness for SeedPass TUI testing.

This script drives the interactive CLI like a user and records:
1. step-level pass/fail status
2. coverage checkpoints for key menu flows
3. full terminal transcript

Usage example:
    source .venv/bin/activate
    python scripts/ai_tui_agent_test.py
"""

from __future__ import annotations

import argparse
import json
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from datetime import datetime, UTC
from pathlib import Path
from typing import Pattern

ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


@dataclass
class StepResult:
    step_id: str
    description: str
    status: str
    duration_sec: float
    detail: str | None = None


class TUIHarnessError(RuntimeError):
    """Raised when the interactive harness cannot advance as expected."""


class TUIRunner:
    def __init__(
        self, proc: subprocess.Popen[bytes], master_fd: int, read_chunk: int = 4096
    ):
        self.proc = proc
        self.master_fd = master_fd
        self.read_chunk = read_chunk
        self.raw_output = ""
        self.clean_output = ""
        self.search_pos = 0
        self._fd_closed = False

    def _refresh_clean_output(self) -> None:
        self.clean_output = ANSI_RE.sub("", self.raw_output)

    def _read_available(self, timeout: float) -> bool:
        if self._fd_closed:
            return False
        ready, _, _ = select.select([self.master_fd], [], [], timeout)
        if not ready:
            return False
        try:
            chunk = os.read(self.master_fd, self.read_chunk)
        except OSError:
            return False
        if not chunk:
            return False
        self.raw_output += chunk.decode("utf-8", errors="ignore")
        self._refresh_clean_output()
        return True

    def wait_for(self, pattern: str | Pattern[str], timeout: float) -> re.Match[str]:
        end = time.monotonic() + timeout
        compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
        while time.monotonic() < end:
            match = compiled.search(self.clean_output, self.search_pos)
            if match:
                self.search_pos = match.end()
                return match
            if self.proc.poll() is not None:
                raise TUIHarnessError(
                    f"Process exited before pattern appeared: {compiled.pattern!r}"
                )
            self._read_available(0.2)
        preview = self.clean_output[max(0, len(self.clean_output) - 1200) :]
        raise TUIHarnessError(
            f"Timed out waiting for pattern: {compiled.pattern!r}\n"
            f"Recent output:\n{preview}"
        )

    def try_wait_for(self, pattern: str | Pattern[str], timeout: float) -> bool:
        try:
            self.wait_for(pattern, timeout)
            return True
        except TUIHarnessError:
            return False

    def sendline(self, value: str = "") -> None:
        os.write(self.master_fd, (value + "\n").encode("utf-8"))

    def expect_and_send(
        self, pattern: str | Pattern[str], value: str = "", timeout: float = 20.0
    ) -> None:
        self.wait_for(pattern, timeout)
        self.sendline(value)

    def pump(self, duration: float = 0.2) -> None:
        self._read_available(duration)

    def close(self, kill_after: float = 1.5) -> int:
        end = time.monotonic() + kill_after
        while time.monotonic() < end:
            code = self.proc.poll()
            if code is not None:
                if not self._fd_closed:
                    try:
                        os.close(self.master_fd)
                    except Exception:
                        pass
                    self._fd_closed = True
                return code
            self.pump(0.1)
        if not self._fd_closed:
            try:
                os.close(self.master_fd)
            except Exception:
                pass
            self._fd_closed = True
        self.proc.kill()
        return self.proc.wait(timeout=2.0)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run deterministic, repeatable TUI coverage checks for SeedPass."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="SeedPass repository root (default: script parent repo).",
    )
    parser.add_argument(
        "--python-bin",
        default=sys.executable,
        help="Python executable used to launch SeedPass (default: current interpreter).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=25.0,
        help="Per-prompt timeout in seconds.",
    )
    parser.add_argument(
        "--password",
        default="AgentPass123!",
        help="Master password used during the run.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/agent_tui_test"),
        help="Directory for transcript/report artifacts.",
    )
    parser.add_argument(
        "--keep-home",
        action="store_true",
        help="Keep the temporary HOME directory after the test run.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print step progress while running.",
    )
    return parser.parse_args()


def _run_step(
    step_id: str,
    description: str,
    fn,
    results: list[StepResult],
    *,
    verbose: bool = False,
) -> None:
    start = time.monotonic()
    try:
        fn()
    except Exception as exc:
        duration = time.monotonic() - start
        results.append(
            StepResult(
                step_id=step_id,
                description=description,
                status="failed",
                duration_sec=duration,
                detail=str(exc),
            )
        )
        raise
    duration = time.monotonic() - start
    results.append(
        StepResult(
            step_id=step_id,
            description=description,
            status="passed",
            duration_sec=duration,
        )
    )
    if verbose:
        print(f"[PASS] {step_id} ({duration:.2f}s) - {description}")


def _drain_to_main_menu(runner: TUIRunner, timeout: float) -> None:
    main_menu_prompt = r"Enter your choice \(1-8\) or press Enter to exit:"
    helper_prompts: list[tuple[str, str]] = [
        (r"Press Enter to continue\.?", ""),
        (r"Select an action or press Enter to return:", ""),
        (r"Enter index to view details or press Enter to go back:", ""),
        (
            r"Enter 'v' to view details, 'r' to restore, or press Enter to go back:",
            "",
        ),
        (r"Select an option or press Enter to go back:", ""),
        (r"Enter index to manage or press Enter to go back:", ""),
    ]

    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            runner.wait_for(main_menu_prompt, timeout=1.0)
            return
        except TUIHarnessError:
            progressed = False
            for pattern, value in helper_prompts:
                try:
                    runner.expect_and_send(pattern, value, timeout=0.25)
                    progressed = True
                    break
                except TUIHarnessError:
                    continue
            if progressed:
                continue
            runner.pump(0.2)
    raise TUIHarnessError("Unable to return to main menu within timeout.")


def _complete_onboarding_to_main_menu(
    runner: TUIRunner, timeout: float, password: str
) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if runner.try_wait_for(
            r"Enter your choice \(1-8\) or press Enter to exit:", timeout=0.4
        ):
            return
        if runner.try_wait_for(r"Enter a new password:", timeout=0.2):
            runner.sendline(password)
            continue
        if runner.try_wait_for(r"Confirm your password:", timeout=0.2):
            runner.sendline(password)
            continue
        if runner.try_wait_for(r"Passwords do not match\.", timeout=0.2):
            continue
        if runner.try_wait_for(r"Press Enter to continue\.?", timeout=0.2):
            runner.sendline("")
            continue
        runner.pump(0.1)
    raise TUIHarnessError("Onboarding did not reach main menu within timeout.")


def _add_entry_menu_open(
    runner: TUIRunner, timeout: float, choice: str | None = None
) -> None:
    runner.sendline("1")
    if choice is None:
        runner.wait_for(r"Select entry type or press Enter to go back:", timeout)
    else:
        runner.expect_and_send(
            r"Select entry type or press Enter to go back:", choice, timeout
        )


def _scenario(
    runner: TUIRunner, timeout: float, password: str, coverage: dict[str, bool]
) -> None:
    # First-run onboarding.
    runner.expect_and_send(r"Select an option:\s*$", "1", timeout)
    runner.expect_and_send(r"Enter choice \(1/2/3/4/5\):", "3", timeout)
    runner.expect_and_send(
        r"Do you want to use this generated seed\? \(Y/N\):", "Y", timeout
    )
    _complete_onboarding_to_main_menu(runner, timeout, password)
    coverage["startup_onboarding"] = True
    coverage["main_menu"] = True

    # Invalid input resilience checks.
    runner.sendline("99")
    runner.wait_for(r"Invalid choice\. Please select a valid option\.", timeout)
    _add_entry_menu_open(runner, timeout, "9")
    runner.wait_for(r"Invalid choice\.", timeout)
    runner.expect_and_send(r"Select entry type or press Enter to go back:", "", timeout)
    _drain_to_main_menu(runner, timeout)
    runner.sendline("2")
    runner.expect_and_send(
        r"Enter the index number of the entry to retrieve:", "abc", timeout
    )
    runner.wait_for(r"Error: Index must be a number\.", timeout)
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    coverage["invalid_input_resilience"] = True

    # Add password in quick mode, including validation checks.
    _add_entry_menu_open(runner, timeout, "1")
    runner.expect_and_send(r"Choose mode: \[Q\]uick or \[A\]dvanced\?", "q", timeout)
    runner.expect_and_send(
        r"Enter the label or website name:", "agent.example", timeout
    )
    runner.expect_and_send(r"Enter the username \(optional\):", "agent", timeout)
    runner.expect_and_send(
        r"Enter the URL \(optional\):", "https://agent.example", timeout
    )
    runner.expect_and_send(r"Enter desired password length .*:", "3", timeout)
    runner.wait_for(r"Password length must be between 8 and 128", timeout)
    coverage["invalid_length_validation"] = True
    runner.expect_and_send(r"Enter desired password length .*:", "12", timeout)
    runner.expect_and_send(r"Include special characters\? \(Y/n\):", "", timeout)
    runner.wait_for(r"Password generated and indexed with ID 0", timeout)
    coverage["add_password_quick"] = True
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    _drain_to_main_menu(runner, timeout)

    # Retrieve and action menu.
    runner.sendline("2")
    runner.expect_and_send(
        r"Enter the index number of the entry to retrieve:", "0", timeout
    )
    runner.wait_for(r"Retrieved Password for agent\.example", timeout)
    if runner.try_wait_for(r"Reveal hidden fields\? \(y/N\):", timeout=0.4):
        runner.sendline("")
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    runner.wait_for(r"Entry Actions:", timeout)
    coverage["retrieve_entry"] = True
    runner.expect_and_send(r"Select an action or press Enter to return:", "", timeout)
    _drain_to_main_menu(runner, timeout)

    # Search.
    runner.sendline("3")
    runner.expect_and_send(r"Enter search string:", "agent", timeout)
    runner.wait_for(r"Search Results", timeout)
    runner.wait_for(r"0\. Password - agent\.example", timeout)
    coverage["search_entries"] = True
    runner.expect_and_send(
        r"Enter index to view details or press Enter to go back:", "", timeout
    )
    _drain_to_main_menu(runner, timeout)

    # List entries.
    runner.sendline("4")
    runner.expect_and_send(
        r"Select entry type or press Enter to go back:", "1", timeout
    )
    runner.wait_for(r"\[\+\] Entries:", timeout)
    runner.wait_for(r"0\. Password - agent\.example", timeout)
    coverage["list_entries"] = True
    runner.expect_and_send(
        r"Enter index to view details or press Enter to go back:", "", timeout
    )
    runner.expect_and_send(r"Select entry type or press Enter to go back:", "", timeout)
    _drain_to_main_menu(runner, timeout)

    # Add generated TOTP and verify 2FA screen shows non-empty codes.
    _add_entry_menu_open(runner, timeout, "2")
    runner.expect_and_send(r"Select option or press Enter to go back:", "1", timeout)
    runner.expect_and_send(r"Label:", "agent-totp", timeout)
    runner.expect_and_send(r"Period \(default 30\):", "", timeout)
    runner.expect_and_send(r"Digits \(default 6\):", "", timeout)
    runner.expect_and_send(r"Notes \(optional\):", "", timeout)
    runner.expect_and_send(r"Enter tags \(comma-separated, optional\):", "", timeout)
    runner.wait_for(r"TOTP entry added with ID", timeout)
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    _drain_to_main_menu(runner, timeout)
    coverage["add_totp"] = True

    runner.sendline("6")
    runner.wait_for(r"Press Enter to return to the menu\.", timeout)
    runner.wait_for(r"(Generated|Imported) 2FA Codes:", timeout)
    runner.wait_for(r"agent-totp", timeout)
    runner.sendline("")
    _drain_to_main_menu(runner, timeout)

    # Add all remaining entry types and verify they appear in listing.
    _add_entry_menu_open(runner, timeout, "3")
    runner.expect_and_send(r"Label \(key\):", "agent-ssh", timeout)
    runner.expect_and_send(r"Notes \(optional\):", "", timeout)
    runner.expect_and_send(r"Enter tags \(comma-separated, optional\):", "", timeout)
    runner.expect_and_send(
        r"WARNING: Displaying SSH keys reveals sensitive information\. Continue\? \(Y/N\):",
        "y",
        timeout,
    )
    runner.wait_for(r"SSH key entry added with ID", timeout)
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    _drain_to_main_menu(runner, timeout)

    _add_entry_menu_open(runner, timeout, "4")
    runner.expect_and_send(r"Label:", "agent-seed", timeout)
    runner.expect_and_send(r"Word count \(12 or 24, default 24\):", "12", timeout)
    runner.expect_and_send(r"Notes \(optional\):", "", timeout)
    runner.expect_and_send(r"Enter tags \(comma-separated, optional\):", "", timeout)
    runner.expect_and_send(
        r"WARNING: Displaying the seed phrase reveals sensitive information\. Continue\? \(Y/N\):",
        "y",
        timeout,
    )
    runner.wait_for(r"Seed entry 'agent-seed' added with ID", timeout)
    runner.expect_and_send(r"Show Compact Seed QR\? \(Y/N\):", "n", timeout)
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    _drain_to_main_menu(runner, timeout)

    _add_entry_menu_open(runner, timeout, "5")
    runner.expect_and_send(r"Label:", "agent-nostr", timeout)
    runner.expect_and_send(r"Notes \(optional\):", "", timeout)
    runner.expect_and_send(r"Enter tags \(comma-separated, optional\):", "", timeout)
    runner.wait_for(r"Nostr key entry added with ID", timeout)
    runner.expect_and_send(r"Show QR code for npub\? \(Y/N\):", "n", timeout)
    runner.expect_and_send(
        r"WARNING: Displaying the nsec QR reveals your private key\. Continue\? \(Y/N\):",
        "n",
        timeout,
    )
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    _drain_to_main_menu(runner, timeout)

    _add_entry_menu_open(runner, timeout, "6")
    runner.expect_and_send(r"Label:", "agent-pgp", timeout)
    runner.expect_and_send(
        r"Key type \(ed25519 or rsa, default ed25519\):", "", timeout
    )
    runner.expect_and_send(r"User ID \(optional\):", "", timeout)
    runner.expect_and_send(r"Notes \(optional\):", "", timeout)
    runner.expect_and_send(r"Enter tags \(comma-separated, optional\):", "", timeout)
    runner.expect_and_send(
        r"WARNING: Displaying the PGP key reveals sensitive information\. Continue\? \(Y/N\):",
        "y",
        timeout,
    )
    runner.wait_for(r"PGP key entry added with ID", timeout)
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    _drain_to_main_menu(runner, timeout)

    _add_entry_menu_open(runner, timeout, "7")
    runner.expect_and_send(r"Label:", "agent-kv", timeout)
    runner.expect_and_send(r"Key:", "token", timeout)
    runner.expect_and_send(r"Value:", "abc123", timeout)
    runner.expect_and_send(r"Notes \(optional\):", "", timeout)
    runner.expect_and_send(r"Enter tags \(comma-separated, optional\):", "", timeout)
    runner.expect_and_send(r"Add custom field\? \(y/N\):", "n", timeout)
    runner.wait_for(r"Key/Value entry added with ID", timeout)
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    _drain_to_main_menu(runner, timeout)

    _add_entry_menu_open(runner, timeout, "8")
    runner.expect_and_send(r"Label:", "agent-managed", timeout)
    runner.expect_and_send(r"Notes \(optional\):", "", timeout)
    runner.expect_and_send(r"Enter tags \(comma-separated, optional\):", "", timeout)
    runner.wait_for(r"Managed account 'agent-managed' added with ID", timeout)
    runner.expect_and_send(r"Reveal seed now\? \(y/N\):", "n", timeout)
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    _drain_to_main_menu(runner, timeout)

    runner.sendline("4")
    runner.expect_and_send(
        r"Select entry type or press Enter to go back:", "1", timeout
    )
    runner.wait_for(r"agent\.example", timeout)
    runner.wait_for(r"agent-totp", timeout)
    runner.wait_for(r"agent-ssh", timeout)
    runner.wait_for(r"agent-seed", timeout)
    runner.wait_for(r"agent-nostr", timeout)
    runner.wait_for(r"agent-pgp", timeout)
    runner.wait_for(r"agent-kv", timeout)
    runner.wait_for(r"agent-managed", timeout)
    runner.expect_and_send(
        r"Enter index to view details or press Enter to go back:", "", timeout
    )
    runner.expect_and_send(r"Select entry type or press Enter to go back:", "", timeout)
    _drain_to_main_menu(runner, timeout)
    coverage["add_all_entry_types"] = True

    # Modify entry.
    runner.sendline("5")
    runner.expect_and_send(
        r"Enter the index number of the entry to modify:", "0", timeout
    )
    runner.expect_and_send(r"Enter new label .*:", "", timeout)
    runner.expect_and_send(r"Enter new username .*:", "agent2", timeout)
    runner.expect_and_send(r"Enter new URL .*:", "", timeout)
    runner.expect_and_send(r"Archive this password\? .*:", "n", timeout)
    runner.expect_and_send(r"Enter new notes .*:", "", timeout)
    runner.expect_and_send(r"Edit custom fields\? \(y/N\):", "n", timeout)
    runner.expect_and_send(
        r"Enter tags \(comma-separated, leave blank to keep current\):", "", timeout
    )
    runner.wait_for(r"Entry updated successfully for index 0", timeout)
    coverage["modify_entry"] = True
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    _drain_to_main_menu(runner, timeout)

    # Archive + restore via archived menu.
    runner.sendline("2")
    runner.expect_and_send(
        r"Enter the index number of the entry to retrieve:", "0", timeout
    )
    if runner.try_wait_for(r"Reveal hidden fields\? \(y/N\):", timeout=0.4):
        runner.sendline("")
    runner.expect_and_send(r"Press Enter to continue\.\.\.", "", timeout)
    runner.expect_and_send(r"Select an action or press Enter to return:", "A", timeout)
    runner.wait_for(r"Entry at index 0 modified successfully", timeout)
    runner.expect_and_send(r"Select an action or press Enter to return:", "", timeout)
    _drain_to_main_menu(runner, timeout)

    runner.sendline("8")
    runner.wait_for(r"Archived Entries", timeout)
    runner.wait_for(r"0\. agent\.example", timeout)
    runner.expect_and_send(
        r"Enter index to manage or press Enter to go back:", "0", timeout
    )
    runner.expect_and_send(
        r"Enter 'v' to view details, 'r' to restore, or press Enter to go back:",
        "r",
        timeout,
    )
    runner.wait_for(r"Entry at index 0 modified successfully", timeout)
    coverage["archive_restore"] = True
    _drain_to_main_menu(runner, timeout)

    # 2FA codes view remains accessible after mixed operations.
    runner.sendline("6")
    runner.wait_for(r"Press Enter to return to the menu\.", timeout)
    runner.wait_for(r"(Generated|Imported) 2FA Codes:", timeout)
    runner.wait_for(r"agent-totp", timeout)
    runner.sendline("")
    coverage["totp_codes_view"] = True
    _drain_to_main_menu(runner, timeout)

    # Settings toggles and lock/unlock flow.
    runner.sendline("7")
    runner.expect_and_send(
        r"Select an option or press Enter to go back:", "15", timeout
    )
    runner.expect_and_send(
        r"Enable secret mode\? \(y/n, blank to keep\):", "y", timeout
    )
    runner.expect_and_send(r"Clipboard clear delay in seconds \[[0-9]+\]:", "", timeout)
    runner.expect_and_send(r"Press Enter to continue\.?", "", timeout)
    runner.expect_and_send(
        r"Select an option or press Enter to go back:", "16", timeout
    )
    runner.expect_and_send(
        r"Enable offline mode\? \(y/n, blank to keep\):", "n", timeout
    )
    runner.expect_and_send(r"Press Enter to continue\.?", "", timeout)
    runner.expect_and_send(
        r"Select an option or press Enter to go back:", "17", timeout
    )
    runner.expect_and_send(
        r"Enable Quick Unlock\? \(y/n, blank to keep\):", "y", timeout
    )
    runner.expect_and_send(r"Press Enter to continue\.?", "", timeout)
    runner.expect_and_send(
        r"Select an option or press Enter to go back:", "13", timeout
    )
    # Unlock prompt text can vary; accept either and submit password.
    if runner.try_wait_for(r"Enter your master password to continue:", timeout=timeout):
        runner.sendline(password)
    elif runner.try_wait_for(r"Enter your master password:", timeout=timeout):
        runner.sendline(password)
    elif runner.try_wait_for(r"Enter your password:", timeout=timeout):
        runner.sendline(password)
    runner.expect_and_send(r"Press Enter to continue\.?", "", timeout)
    runner.expect_and_send(r"Select an option or press Enter to go back:", "", timeout)
    _drain_to_main_menu(runner, timeout)
    coverage["settings_toggles_lock_unlock"] = True

    # Settings -> Stats and back.
    runner.sendline("7")
    runner.expect_and_send(
        r"Select an option or press Enter to go back:", "14", timeout
    )
    runner.wait_for(r"=== Seed Profile Stats ===", timeout)
    runner.expect_and_send(r"Press Enter to continue\.?", "", timeout)
    runner.expect_and_send(r"Select an option or press Enter to go back:", "", timeout)
    coverage["settings_stats"] = True
    _drain_to_main_menu(runner, timeout)

    # Graceful exit.
    runner.sendline("")
    runner.wait_for(r"Exiting the program\.", timeout)
    coverage["graceful_exit"] = True


def main() -> int:
    args = _parse_args()
    repo_root = args.repo_root.resolve()
    src_main = repo_root / "src" / "main.py"
    if not src_main.exists():
        print(f"Error: cannot find {src_main}", file=sys.stderr)
        return 2

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    artifact_dir = args.output_dir.resolve() / timestamp
    artifact_dir.mkdir(parents=True, exist_ok=True)

    temp_home_dir = Path(tempfile.mkdtemp(prefix="seedpass-agent-home-"))
    env = os.environ.copy()
    env["HOME"] = str(temp_home_dir)
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("TERM", "xterm")

    cmd = [args.python_bin, str(src_main), "--no-clipboard"]
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        cmd,
        cwd=str(repo_root),
        env=env,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
    )
    os.close(slave_fd)
    runner = TUIRunner(proc, master_fd)

    results: list[StepResult] = []
    coverage = {
        "startup_onboarding": False,
        "main_menu": False,
        "invalid_input_resilience": False,
        "add_password_quick": False,
        "invalid_length_validation": False,
        "add_totp": False,
        "add_all_entry_types": False,
        "retrieve_entry": False,
        "search_entries": False,
        "list_entries": False,
        "modify_entry": False,
        "archive_restore": False,
        "totp_codes_view": False,
        "settings_toggles_lock_unlock": False,
        "settings_stats": False,
        "graceful_exit": False,
    }

    failure: str | None = None
    start_time = time.monotonic()
    try:
        _run_step(
            "full_scenario",
            "Drive end-to-end deterministic TUI coverage workflow.",
            lambda: _scenario(runner, args.timeout, args.password, coverage),
            results,
            verbose=args.verbose,
        )
    except Exception as exc:
        failure = str(exc)
    finally:
        exit_code = runner.close()
        total_duration = time.monotonic() - start_time

    transcript_clean = artifact_dir / "transcript.clean.txt"
    transcript_raw = artifact_dir / "transcript.raw.txt"
    transcript_clean.write_text(runner.clean_output, encoding="utf-8")
    transcript_raw.write_text(runner.raw_output, encoding="utf-8")

    report = {
        "timestamp_utc": timestamp,
        "command": cmd,
        "repo_root": str(repo_root),
        "home_dir": str(temp_home_dir),
        "duration_sec": round(total_duration, 3),
        "seedpass_exit_code": exit_code,
        "status": "passed" if failure is None and all(coverage.values()) else "failed",
        "failure": failure,
        "steps": [asdict(item) for item in results],
        "coverage_points": coverage,
        "transcript_clean": str(transcript_clean),
        "transcript_raw": str(transcript_raw),
    }
    report_file = artifact_dir / "report.json"
    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if not args.keep_home:
        shutil.rmtree(temp_home_dir, ignore_errors=True)

    print(f"AI agent TUI report: {report_file}")
    print(f"Status: {report['status']}")
    if failure:
        print(f"Failure: {failure}")
    if report["status"] != "passed":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
