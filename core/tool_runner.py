"""Safe Tool Runner (``06_TOOL_CONTRACTS.md`` §Tool Runner).

Executes approved commands as argument arrays via ``subprocess.Popen(..., shell=False)``
**never** as shell strings, captures stdout/stderr/exit code, enforces per-invocation
timeouts, controls environment and working directory, preserves raw output under
``storage/raw/<tool>/``, and returns structured error objects on failure.

Output capture is **bounded and streaming**: stdout and stderr are read incrementally
from their pipes and each stream retains at most :data:`DEFAULT_MAX_OUTPUT_BYTES`
decoded bytes. On overflow the child's process tree is terminated, the bounded partial
is kept, and :attr:`CommandResult.truncated` is set. This bounds *retained captured
output* (and therefore disk), **not** total process RSS — see the bounded-capture notes.

Secrets are never written to logs: the runner only logs the tool name, timeout,
exit code, duration, and (redacted) diagnostics.
"""

from __future__ import annotations

import os
import secrets as _secrets_module
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from core.logging_setup import get_logger

#: Per-stream retained-output cap for the bounded streaming capture. Retained stdout
#: (and, independently, stderr) never exceeds this many bytes; on overflow the child's
#: process tree is terminated and :attr:`CommandResult.truncated` is ``True``. The
#: retained stdout+stderr is therefore hard-bounded at ``2 * DEFAULT_MAX_OUTPUT_BYTES``.
#: This caps *retained captured output*, not total process memory (RSS).
DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024

#: Fixed read-chunk size for the streaming capture. A small, constant read keeps the
#: reader's own buffers independent of the tool's total output.
_READ_CHUNK_BYTES = 64 * 1024

#: How long the reader threads and the process reap are allowed to linger after the
#: tool has exited or been terminated, so a wedged pipe can never wedge the run.
_DRAIN_JOIN_TIMEOUT = 10.0
_REAP_TIMEOUT = 5.0


class ToolRunnerError(Exception):
    """Base structured failure produced by the Tool Runner."""


class ToolUnavailableError(ToolRunnerError):
    """The executable could not be found/invoked."""


class ToolTimeoutError(ToolRunnerError):
    """The command exceeded its configured timeout and was terminated."""


@dataclass(frozen=True)
class CommandResult:
    """Captured outcome of one tool invocation.

    Non-zero exit codes are *reported, not raised*: the caller (adapter/
    orchestrator) logs and continues, per the degrade-gracefully policy.

    ``truncated`` is ``True`` iff the bounded capture omitted bytes from either
    stream (the retained output was capped at :data:`DEFAULT_MAX_OUTPUT_BYTES` per
    stream and the child's process tree was terminated).
    """

    tool: str
    command: list[str]
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_ms: float = 0.0
    raw_output_ref: Optional[str] = None
    truncated: bool = False


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _read_stream_bounded(stream, cap: int) -> tuple[bytes, bool]:
    """Read ``stream`` incrementally, retaining at most ``cap`` bytes.

    Returns ``(data, truncated)`` where ``truncated`` is ``True`` iff bytes were
    omitted (``len(data) == cap`` and the stream was not exhausted at exactly the
    cap). Reading in fixed-size chunks keeps the reader's memory independent of the
    tool's total output; a tool emitting exactly ``cap`` bytes is **not** truncated.
    """
    retained = bytearray()
    while True:
        try:
            chunk = stream.read(_READ_CHUNK_BYTES)
        except (ValueError, OSError):
            # The pipe was closed underneath the reader (e.g. after a tree kill).
            break
        if not chunk:
            break
        remaining = cap - len(retained)
        if remaining <= 0:
            return bytes(retained), True
        if len(chunk) > remaining:
            retained.extend(chunk[:remaining])
            return bytes(retained), True
        retained.extend(chunk)
    return bytes(retained), False


@dataclass
class ToolRunner:
    """Controlled ``subprocess`` boundary.

    ``raw_dir`` is the preservation root (default ``storage/raw`` from
    ``14_CONFIG_EXAMPLE.md`` §storage.raw). ``timeout`` is the default per
    invocation; callers may override. ``env``/``cwd`` default to the current
    process environment / working directory but are always overridable so the
    caller fully controls what the tool sees. ``max_output_bytes`` is the
    per-stream retained-output cap of the bounded streaming capture.
    """

    raw_dir: Path = Path("storage/raw")
    timeout: float = 60.0
    env: Optional[dict] = None
    cwd: Optional[Path] = None
    secrets: Iterable[str] = ()
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    logger: object = field(default_factory=lambda: get_logger("argus.tool_runner"))

    def __post_init__(self) -> None:
        # Keep the field iterable regardless of whether a tuple/list/... was passed.
        self.secrets = tuple(s for s in (self.secrets or ()) if s)
        self.max_output_bytes = max(1, int(self.max_output_bytes))

    # -- execution ----------------------------------------------------------

    def run_command(
        self,
        command: list[str],
        *,
        tool: str,
        timeout: Optional[float] = None,
        env: Optional[dict] = None,
        cwd: Optional[Path] = None,
    ) -> CommandResult:
        """Execute ``command`` as an argument array and capture its outcome.

        Raw output (stdout + stderr) is preserved under ``storage/raw/<tool>/``
        and referenced by ``result.raw_output_ref``. Raises
        :class:`ToolUnavailableError` if the executable is missing and
        :class:`ToolTimeoutError` if ``timeout`` is exceeded (partial output is
        still preserved). Non-zero exits are returned in
        :class:`CommandResult.exit_code` (not raised). Output over the per-stream
        cap is bounded, the child's process tree is terminated, and
        :attr:`CommandResult.truncated` is ``True``.
        """
        self._validate_command(command, tool)
        effective_timeout = self.timeout if timeout is None else timeout
        effective_env = self._merge_env(env)
        effective_cwd = cwd or self.cwd

        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                command,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=effective_env,
                cwd=str(effective_cwd) if effective_cwd else None,
                # POSIX: a fresh session/process group so the whole tree can be
                # signalled. Ignored on Windows (tree killed via ``taskkill /T``).
                start_new_session=(os.name != "nt"),
            )
        except FileNotFoundError as exc:
            raise ToolUnavailableError(
                f"{tool}: executable not found for command {self.redact(' '.join(command))}"
            ) from exc
        except PermissionError as exc:
            raise ToolUnavailableError(
                f"{tool}: executable not invokable for command {self.redact(' '.join(command))}"
            ) from exc

        captured: dict[str, object] = {"stdout": b"", "stderr": b""}
        overflow = threading.Event()

        def drain(name: str, stream) -> None:
            data, clipped = _read_stream_bounded(stream, self.max_output_bytes)
            captured[name] = data
            captured[f"{name}_truncated"] = clipped
            if clipped:
                overflow.set()

        out_thread = threading.Thread(
            target=drain, args=("stdout", proc.stdout), daemon=True
        )
        err_thread = threading.Thread(
            target=drain, args=("stderr", proc.stderr), daemon=True
        )
        out_thread.start()
        err_thread.start()

        timed_out = False
        while True:
            if proc.poll() is not None:
                break
            if overflow.is_set():
                # A stream hit the retained-output cap: terminate the tree so the
                # child cannot block on a pipe we are no longer draining.
                self._terminate_tree(proc)
                break
            if time.monotonic() - started >= effective_timeout:
                timed_out = True
                self._terminate_tree(proc)
                break
            time.sleep(0.02)

        # The child has exited or been terminated; the reader threads now hit EOF.
        out_thread.join(timeout=_DRAIN_JOIN_TIMEOUT)
        err_thread.join(timeout=_DRAIN_JOIN_TIMEOUT)
        try:
            proc.wait(timeout=_REAP_TIMEOUT)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            proc.kill()
            proc.wait()

        stdout = bytes(captured.get("stdout", b"") or b"").decode("utf-8", errors="replace")
        stderr = bytes(captured.get("stderr", b"") or b"").decode("utf-8", errors="replace")
        truncated = bool(
            captured.get("stdout_truncated") or captured.get("stderr_truncated")
        )

        raw_ref: Optional[str] = None
        raw_content = stdout + stderr
        if raw_content:
            raw_ref = self.save_raw(
                tool,
                raw_content,
                extension="out",
                tag="timeout" if timed_out else ("truncated" if truncated else "tool"),
            )

        duration_ms = (time.monotonic() - started) * 1000.0
        if timed_out:
            self._log_timeout(tool, effective_timeout, duration_ms, raw_ref)
            raise ToolTimeoutError(
                f"{tool}: timed out after {effective_timeout:g}s during "
                f"{self.redact(' '.join(command))}"
            )

        result = CommandResult(
            tool=tool,
            command=list(command),
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
            duration_ms=duration_ms,
            raw_output_ref=raw_ref,
            truncated=truncated,
        )
        self._log_result(result, effective_timeout)
        return result

    # -- process-tree termination -------------------------------------------

    def _terminate_tree(self, proc: "subprocess.Popen") -> None:
        """Terminate ``proc`` and its descendants, platform-appropriately.

        Windows has no process groups; ``taskkill /F /T`` reaps the whole tree. On
        POSIX the child was started in its own session, so its process group is
        signalled. A direct ``kill`` is always attempted as a fallback.
        """
        if proc.poll() is not None:
            return
        try:
            if os.name == "nt":
                self._terminate_tree_windows(proc)
            else:
                self._terminate_tree_posix(proc)
        finally:
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass

    @staticmethod
    def _terminate_tree_windows(proc: "subprocess.Popen") -> None:
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                shell=False,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass

    @staticmethod
    def _terminate_tree_posix(proc: "subprocess.Popen") -> None:
        import signal

        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    # -- raw output preservation ---------------------------------------------

    def save_raw(
        self,
        tool: str,
        content: str,
        *,
        extension: str = "out",
        tag: str = "tool",
    ) -> str:
        """Persist raw tool output under ``storage/raw/<tool>/``.

        Returns the reference string stored in ``tool_runs.raw_output_ref``
        (``storage/raw/<tool>/<timestamp>_<tag>_<nonce>.out``).
        """
        safe_tool = _sanitize_filename(tool)
        safe_tag = _sanitize_filename(tag)
        directory = self.raw_dir / safe_tool
        directory.mkdir(parents=True, exist_ok=True)
        filename = (
            f"{_utcnow().strftime('%Y%m%dT%H%M%SZ')}_{safe_tag}_"
            f"{_secrets_module.token_hex(4)}.{_sanitize_filename(extension)}"
        )
        path = directory / filename
        path.write_text(content, encoding="utf-8")
        return str(path)

    # -- diagnostics ---------------------------------------------------------

    def redact(self, text: str) -> str:
        """Mask configured secrets before any text reaches a log."""
        result = text
        for secret in self.secrets or ():
            if secret:
                result = result.replace(secret, "<redacted>")
        return result

    # -- internals -----------------------------------------------------------

    def _validate_command(self, command: list[str], tool: str) -> None:
        if not isinstance(command, list) or not command:
            raise ToolRunnerError(
                f"{tool}: command must be a non-empty argument array (list[str]), "
                f"got {command!r}"
            )
        for arg in command:
            if not isinstance(arg, str):
                raise ToolRunnerError(
                    f"{tool}: command arguments must be strings, got {arg!r}"
                )

    def _merge_env(self, env: Optional[dict]) -> dict:
        base = dict(os.environ if self.env is None else self.env)
        if env:
            base.update(env)
        merged: dict = {}
        for key, value in base.items():
            merged[str(key)] = str(value)
        return merged

    def _log_result(self, result: CommandResult, timeout: float) -> None:
        details = (
            f"tool={result.tool} exit={result.exit_code} "
            f"duration_ms={result.duration_ms:,.0f} timeout={timeout:g}"
        )
        if result.truncated:
            details += " truncated=True"
        if result.raw_output_ref:
            details += f" raw={result.raw_output_ref}"
        if result.timed_out or (result.exit_code is not None and result.exit_code != 0):
            self.logger.warning(f"tool run non-zero/failed: {details}")
        else:
            self.logger.info(f"tool run ok: {details}")

    def _log_timeout(
        self, tool: str, timeout: float, duration_ms: float, raw_ref: Optional[str]
    ) -> None:
        details = (
            f"tool run timeout: tool={tool} timeout={timeout:g} "
            f"duration_ms={duration_ms:,.0f}"
        )
        if raw_ref:
            details += f" raw={raw_ref}"
        self.logger.warning(details)


def is_executable_on_path(name: str) -> bool:
    """Whether ``name`` resolves to an executable on ``PATH`` (platform-neutral)."""
    return shutil.which(name) is not None


def _sanitize_filename(value: str) -> str:
    """Keep a value safe for use as a filename/path segment."""
    cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in value)
    return cleaned.strip("._") or "tool"
