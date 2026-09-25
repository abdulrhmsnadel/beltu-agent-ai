from __future__ import annotations

import asyncio
import os
import shutil
import signal
import time
from dataclasses import dataclass

from beltu.execution.resource_governor import ResourceSnapshot


@dataclass(frozen=True, slots=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    resource_before: ResourceSnapshot | None = None
    resource_after: ResourceSnapshot | None = None


class ProcessManager:
    """Run allowlisted argv vectors without invoking a shell."""

    def __init__(self, max_output_bytes: int = 1_000_000) -> None:
        self.max_output_bytes = max(1024, max_output_bytes)

    @staticmethod
    def resolve_binary(binary: str) -> str:
        path = shutil.which(binary)
        if path is None:
            raise FileNotFoundError(f"Required tool not installed or not in PATH: {binary}")
        return path

    @staticmethod
    def _safe_environment() -> dict[str, str]:
        source = os.environ
        env = {"PATH": source.get("PATH", "")}
        for key in ("HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "XDG_CACHE_HOME", "PLAYWRIGHT_BROWSERS_PATH"):
            value = source.get(key)
            if value:
                env[key] = value
        return env

    @staticmethod
    async def _terminate_process_group(proc: asyncio.subprocess.Process, *, grace_seconds: float = 3.0) -> None:
        if proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except PermissionError:
            try:
                proc.terminate()
            except ProcessLookupError:
                return
        try:
            await asyncio.wait_for(proc.wait(), timeout=max(0.25, grace_seconds))
            return
        except asyncio.TimeoutError:
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except ProcessLookupError:
                return
        await asyncio.gather(proc.wait(), return_exceptions=True)

    async def run(
        self,
        argv: list[str],
        timeout_seconds: float,
        *,
        resource_before: ResourceSnapshot | None = None,
        resource_monitor=None,
        resource_governor=None,
        tool_name: str | None = None,
    ) -> ProcessResult:
        if not argv:
            raise ValueError("argv cannot be empty")
        binary = self.resolve_binary(argv[0])
        safe_argv = [binary, *argv[1:]]
        started = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *safe_argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._safe_environment(),
            start_new_session=True,
        )
        if resource_governor is not None and tool_name:
            resource_governor.register_process(proc.pid, tool_name)
        timed_out = False
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            timed_out = True
            await self._terminate_process_group(proc)
            stdout_b, stderr_b = await proc.communicate()
        except asyncio.CancelledError:
            await self._terminate_process_group(proc)
            if resource_governor is not None:
                resource_governor.unregister_process(proc.pid)
            raise
        duration = time.monotonic() - started
        if resource_governor is not None:
            resource_governor.unregister_process(proc.pid)
        stdout_b = stdout_b[: self.max_output_bytes]
        stderr_b = stderr_b[: self.max_output_bytes]
        resource_after = resource_monitor.snapshot() if resource_monitor else None
        return ProcessResult(
            tuple(safe_argv),
            proc.returncode,
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
            duration,
            timed_out,
            resource_before,
            resource_after,
        )
