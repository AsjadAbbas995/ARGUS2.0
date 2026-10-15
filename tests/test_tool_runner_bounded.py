"""Tool Runner bounded streaming-capture tests (``PHASE_24_PROPOSAL.md`` §13.9).

Every command runs through ``sys.executable`` against a deterministic in-process
child; no test contacts a live external target or requires a third-party binary.

The guarantee under test is a hard cap on **retained captured bytes** per stream
(``<= 2 * DEFAULT_MAX_OUTPUT_BYTES``), *not* total process RSS (§7).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from core.tool_runner import (
    CommandResult,
    ToolRunner,
    ToolTimeoutError,
)

PY = sys.executable


def _pid_alive(pid: int) -> bool:
    """Whether ``pid`` is still running (platform-appropriate)."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return bool(ok) and code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _wait_gone(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.1)
    return not _pid_alive(pid)


_CAP = 4096


def _runner(tmp_path: Path) -> ToolRunner:
    return ToolRunner(
        raw_dir=tmp_path / "storage" / "raw",
        timeout=5.0,
        max_output_bytes=_CAP,
    )


# -- simultaneous stdout/stderr flood ---------------------------------------


def test_simultaneous_stdout_stderr_flood(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    script = (
        "import sys\n"
        "buf = b'x' * 65536\n"
        "while True:\n"
        "    sys.stdout.buffer.write(buf); sys.stdout.buffer.flush()\n"
        "    sys.stderr.buffer.write(buf); sys.stderr.buffer.flush()\n"
    )
    result = runner.run_command([PY, "-c", script], tool="flood")
    assert result.truncated is True
    assert len(result.stdout.encode("utf-8")) <= _CAP
    assert len(result.stderr.encode("utf-8")) <= _CAP
    assert len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")) <= 2 * _CAP
    # The bounded partial is preserved on disk and never exceeds the cap.
    assert result.raw_output_ref
    assert Path(result.raw_output_ref).stat().st_size <= 2 * _CAP


# -- exactly at the limit ----------------------------------------------------


def test_output_exactly_at_limit_not_truncated(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    script = f"import sys; sys.stdout.buffer.write(b'a' * {_CAP})"
    result = runner.run_command([PY, "-c", script], tool="atlimit")
    assert result.exit_code == 0
    assert result.truncated is False
    assert len(result.stdout) == _CAP


# -- over the limit ----------------------------------------------------------


def test_output_over_limit_truncated_and_capped(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    script = f"import sys; sys.stdout.buffer.write(b'a' * {_CAP * 4})"
    result = runner.run_command([PY, "-c", script], tool="over")
    assert result.truncated is True
    assert len(result.stdout.encode("utf-8")) <= _CAP


# -- timeout during output ---------------------------------------------------


def test_timeout_during_output_keeps_partial(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    script = (
        "import sys, time\n"
        "sys.stdout.write('partial-line-'); sys.stdout.flush()\n"
        "time.sleep(30)\n"
    )
    with pytest.raises(ToolTimeoutError):
        runner.run_command([PY, "-c", script], tool="slow", timeout=0.4)
    refs = list((tmp_path / "storage" / "raw" / "slow").glob("*.out"))
    assert refs, "expected partial raw output preserved on timeout"
    assert refs[0].read_text(encoding="utf-8") == "partial-line-"


# -- child-process cleanup (overflow and timeout) ----------------------------

_FLOOD_PRELUDE = (
    "import os, subprocess, sys\n"
    "kid = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
    "with open(os.environ['ARGUS_TEST_PIDFILE'], 'w') as fh:\n"
    "    fh.write(str(kid.pid)); fh.flush()\n"
)


def test_child_tree_cleanup_on_overflow(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    pidfile = tmp_path / "grandchild.pid"
    script = _FLOOD_PRELUDE + (
        "buf = b'x' * 65536\n"
        "out = sys.stdout.buffer\n"
        "while True:\n"
        "    out.write(buf); out.flush()\n"
    )
    result = runner.run_command(
        [PY, "-c", script], tool="tree-overflow", env={"ARGUS_TEST_PIDFILE": str(pidfile)}
    )
    assert result.truncated is True
    assert pidfile.exists(), "child did not record its grandchild pid"
    grandchild = int(pidfile.read_text().strip())
    assert _wait_gone(grandchild), "grandchild survived the process-tree termination"


def test_child_tree_cleanup_on_timeout(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    pidfile = tmp_path / "grandchild.pid"
    script = _FLOOD_PRELUDE + "import time; time.sleep(30)\n"
    with pytest.raises(ToolTimeoutError):
        runner.run_command(
            [PY, "-c", script],
            tool="tree-timeout",
            timeout=1.5,
            env={"ARGUS_TEST_PIDFILE": str(pidfile)},
        )
    assert pidfile.exists(), "child did not record its grandchild pid"
    grandchild = int(pidfile.read_text().strip())
    assert _wait_gone(grandchild), "grandchild survived the process-tree termination"


def test_command_result_has_truncated_default() -> None:
    assert CommandResult(tool="t", command=["t"]).truncated is False
