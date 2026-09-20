from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request


@dataclass(frozen=True, slots=True)
class GpuSnapshot:
    available: bool
    name: str | None
    total_bytes: int
    used_bytes: int
    free_bytes: int
    utilization_percent: float
    freetoken_used_bytes: int

    @property
    def used_percent(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return (self.used_bytes / self.total_bytes) * 100.0

    @property
    def freetoken_percent(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return (self.freetoken_used_bytes / self.total_bytes) * 100.0


@dataclass(frozen=True, slots=True)
class FreeTokenSnapshot:
    configured: bool
    reachable: bool
    pid: int | None
    model: str | None
    cpu_percent: float
    rss_bytes: int
    vram_bytes: int
    moe_backend: str | None
    requests: int | None


@dataclass(frozen=True, slots=True)
class ToolRuntimeLimits:
    tool: str
    thread_limit: int
    max_parallel_processes: int
    affinity_cpus: tuple[int, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    timestamp: float
    beltu_cpu_percent: float
    beltu_memory_percent: float
    host_cpu_percent: float
    host_memory_percent: float
    memory_total_bytes: int
    memory_available_bytes: int
    load1: float
    cpu_count: int
    beltu_rss_bytes: int
    active_processes: int
    gpu: GpuSnapshot | None = None
    freetoken: FreeTokenSnapshot | None = None


class LinuxResourceMonitor:
    """Linux telemetry using /proc plus optional NVIDIA/FreeToken telemetry."""

    def __init__(self, *, freetoken_pid_file: str | Path = "data/runtime/freetoken.pid", freetoken_url: str = "http://127.0.0.1:8000") -> None:
        self.cpu_count = max(1, os.cpu_count() or 1)
        self.freetoken_pid_file = Path(freetoken_pid_file)
        self.freetoken_url = freetoken_url.rstrip("/")
        self._prev_proc: tuple[int, float] | None = None
        self._prev_host: tuple[int, int] | None = None
        self._prev_gpu_util: float = 0.0

    def snapshot(self, active_processes: int = 0) -> ResourceSnapshot:
        now = time.monotonic()
        proc_cpu = self._process_cpu_percent(now)
        host_cpu = self._host_cpu_percent()
        total, available = self._memory()
        beltu_rss = self._process_rss()
        beltu_memory = 0.0 if total <= 0 else (beltu_rss / total) * 100.0
        host_memory = 0.0 if total <= 0 else ((total - available) / total) * 100.0
        try:
            load1 = os.getloadavg()[0]
        except (AttributeError, OSError):
            load1 = 0.0
        gpu = self._gpu_snapshot()
        freetoken = self._freetoken_snapshot(gpu)
        return ResourceSnapshot(
            timestamp=time.time(),
            beltu_cpu_percent=round(max(0.0, min(100.0, proc_cpu)), 2),
            beltu_memory_percent=round(max(0.0, min(100.0, beltu_memory)), 2),
            host_cpu_percent=round(max(0.0, min(100.0, host_cpu)), 2),
            host_memory_percent=round(max(0.0, min(100.0, host_memory)), 2),
            memory_total_bytes=total,
            memory_available_bytes=available,
            load1=round(load1, 2),
            cpu_count=self.cpu_count,
            beltu_rss_bytes=beltu_rss,
            active_processes=active_processes,
            gpu=gpu,
            freetoken=freetoken,
        )

    def _process_cpu_percent(self, now: float) -> float:
        try:
            with open("/proc/self/stat", "r", encoding="utf-8") as handle:
                parts = handle.read().split()
            ticks = int(parts[13]) + int(parts[14])
        except (OSError, ValueError, IndexError):
            return 0.0
        if self._prev_proc is None:
            self._prev_proc = (ticks, now)
            return 0.0
        prev_ticks, prev_time = self._prev_proc
        self._prev_proc = (ticks, now)
        dt = max(now - prev_time, 1e-6)
        try:
            hz = max(1, int(os.sysconf("SC_CLK_TCK")))
        except (OSError, ValueError):
            hz = 100
        return ((ticks - prev_ticks) / hz) / dt * 100.0

    def _pid_cpu_percent(self, pid: int) -> float:
        try:
            uptime = float(open("/proc/uptime", "r", encoding="utf-8").read().split()[0])
            stat = open(f"/proc/{pid}/stat", "r", encoding="utf-8").read().split()
            ticks = int(stat[13]) + int(stat[14])
            start_ticks = int(stat[21])
            hz = max(1, int(os.sysconf("SC_CLK_TCK")))
            process_age = max(1e-3, uptime - (start_ticks / hz))
            return max(0.0, min(100.0 * self.cpu_count, (ticks / hz) / process_age * 100.0))
        except (OSError, ValueError, IndexError):
            return 0.0

    def _host_cpu_percent(self) -> float:
        try:
            parts = [int(x) for x in open('/proc/stat', 'r', encoding='utf-8').readline().split()[1:8]]
            total = sum(parts)
            idle = parts[3] + parts[4]
        except (OSError, ValueError, IndexError):
            return 0.0
        if self._prev_host is None:
            self._prev_host = (total, idle)
            return 0.0
        prev_total, prev_idle = self._prev_host
        self._prev_host = (total, idle)
        dt_total = total - prev_total
        dt_idle = idle - prev_idle
        if dt_total <= 0:
            return 0.0
        return (1.0 - dt_idle / dt_total) * 100.0

    @staticmethod
    def _memory() -> tuple[int, int]:
        try:
            values: dict[str, int] = {}
            with open('/proc/meminfo', 'r', encoding='utf-8') as handle:
                for line in handle:
                    key, value, *_ = line.split()
                    if key in {'MemTotal:', 'MemAvailable:'}:
                        values[key] = int(value) * 1024
            return values.get('MemTotal:', 0), values.get('MemAvailable:', 0)
        except (OSError, ValueError):
            return 0, 0

    @staticmethod
    def _process_rss(pid: int | None = None) -> int:
        target = pid or 'self'
        try:
            with open(f'/proc/{target}/status', 'r', encoding='utf-8') as handle:
                for line in handle:
                    if line.startswith('VmRSS:'):
                        return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            pass
        return 0

    def _read_pid_file(self) -> int | None:
        try:
            pid = int(self.freetoken_pid_file.read_text(encoding="utf-8").strip())
            if pid > 1 and Path(f"/proc/{pid}").exists():
                return pid
        except (OSError, ValueError):
            pass
        return None

    def _query_nvidia(self) -> tuple[GpuSnapshot, dict[int, int]] | None:
        try:
            info = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total,memory.used,memory.free,utilization.gpu", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=2.0, check=False,
            )
            apps = subprocess.run(
                ["nvidia-smi", "--query-compute-apps=pid,used_gpu_memory", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=2.0, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if info.returncode != 0 or not info.stdout.strip():
            return None
        first = info.stdout.splitlines()[0]
        pieces = [p.strip() for p in first.split(",")]
        if len(pieces) < 5:
            return None
        def mib(value: str) -> int:
            try:
                return max(0, int(float(value))) * 1024 * 1024
            except ValueError:
                return 0
        try:
            gpu = GpuSnapshot(True, pieces[0], mib(pieces[1]), mib(pieces[2]), mib(pieces[3]), float(pieces[4]), 0)
        except ValueError:
            return None
        apps_by_pid: dict[int, int] = {}
        for row in apps.stdout.splitlines():
            left = [p.strip() for p in row.split(",")]
            if len(left) < 2:
                continue
            try:
                apps_by_pid[int(left[0])] = mib(left[1])
            except ValueError:
                continue
        return gpu, apps_by_pid

    def _gpu_snapshot(self) -> GpuSnapshot | None:
        result = self._query_nvidia()
        if result is None:
            return None
        gpu, apps = result
        pid = self._read_pid_file()
        freetoken_used = apps.get(pid, 0) if pid else 0
        return GpuSnapshot(gpu.available, gpu.name, gpu.total_bytes, gpu.used_bytes, gpu.free_bytes, gpu.utilization_percent, freetoken_used)

    def _freetoken_snapshot(self, gpu: GpuSnapshot | None) -> FreeTokenSnapshot | None:
        pid = self._read_pid_file()
        configured = bool(self.freetoken_url)
        reachable = False
        model = None
        backend = None
        requests = None
        if configured:
            try:
                with request.urlopen(f"{self.freetoken_url}/v1/models", timeout=0.8) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                items = payload.get("data", []) if isinstance(payload, dict) else []
                if isinstance(items, list) and items and isinstance(items[0], dict):
                    model = items[0].get("id")
                reachable = True
            except (OSError, ValueError, urlerror.URLError, urlerror.HTTPError):
                reachable = False
            if reachable:
                try:
                    with request.urlopen(f"{self.freetoken_url}/v1/stats", timeout=0.8) as response:
                        stats = json.loads(response.read().decode("utf-8"))
                    if isinstance(stats, dict):
                        backend = str(stats.get("moe_backend") or stats.get("moe_backend_name") or "") or None
                        requests_raw = stats.get("running_requests") or stats.get("active_requests")
                        requests = int(requests_raw) if requests_raw is not None else None
                except (OSError, ValueError, urlerror.URLError, urlerror.HTTPError, TypeError):
                    pass
        if not configured and pid is None:
            return None
        return FreeTokenSnapshot(
            configured=configured,
            reachable=reachable,
            pid=pid,
            model=str(model) if model is not None else None,
            cpu_percent=round(self._pid_cpu_percent(pid), 2) if pid else 0.0,
            rss_bytes=self._process_rss(pid) if pid else 0,
            vram_bytes=gpu.freetoken_used_bytes if gpu is not None else 0,
            moe_backend=backend,
            requests=requests,
        )


class ResourceGovernor:
    """Adaptive CPU/RAM/GPU governor.

    It continuously samples host load and FreeToken pressure while BELTU runs.
    New tool invocations receive conservative concurrency/thread limits. Existing
    child processes also have their CPU affinity reduced when pressure rises.
    This avoids assuming that arbitrary third-party tools expose a runtime thread
    reconfiguration API.
    """

    def __init__(
        self,
        max_concurrent_processes: int = 2,
        cpu_budget_percent: float = 30.0,
        memory_budget_percent: float = 30.0,
        min_concurrent_processes: int = 1,
        poll_interval: float = 0.5,
        *,
        freetoken_pid_file: str | Path = "data/runtime/freetoken.pid",
        freetoken_url: str = "http://127.0.0.1:8000",
        gpu_vram_budget_percent: float = 45.0,
    ) -> None:
        self.max_concurrent_processes = max(1, int(max_concurrent_processes))
        self.min_concurrent_processes = max(1, min(int(min_concurrent_processes), self.max_concurrent_processes))
        self.cpu_budget_percent = max(1.0, min(100.0, float(cpu_budget_percent)))
        self.memory_budget_percent = max(1.0, min(100.0, float(memory_budget_percent)))
        self.gpu_vram_budget_percent = max(10.0, min(100.0, float(gpu_vram_budget_percent)))
        self.poll_interval = max(0.05, float(poll_interval))
        self.monitor = LinuxResourceMonitor(freetoken_pid_file=freetoken_pid_file, freetoken_url=freetoken_url)
        self._active = 0
        self._condition = asyncio.Condition()
        self._last_snapshot = self.monitor.snapshot()
        self._watch_task: asyncio.Task[None] | None = None
        self._managed_pids: dict[int, str] = {}

    async def start(self) -> None:
        if self._watch_task is None or self._watch_task.done():
            self._watch_task = asyncio.create_task(self._watch_loop())

    async def stop(self) -> None:
        task = self._watch_task
        self._watch_task = None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self._managed_pids.clear()

    async def _watch_loop(self) -> None:
        while True:
            await asyncio.sleep(self.poll_interval)
            self._last_snapshot = self.monitor.snapshot(self._active)
            self._apply_affinity_limits(self._last_snapshot)
            async with self._condition:
                self._condition.notify_all()

    def _pressure(self, snap: ResourceSnapshot) -> tuple[float, float, float]:
        beltu_pressure = max(
            snap.beltu_cpu_percent / max(self.cpu_budget_percent, 1.0),
            snap.beltu_memory_percent / max(self.memory_budget_percent, 1.0),
        )
        host_pressure = max(snap.host_cpu_percent / 90.0, snap.host_memory_percent / 90.0)
        gpu_pressure = 0.0
        if snap.gpu is not None:
            gpu_pressure = max(gpu_pressure, snap.gpu.used_percent / 95.0)
            gpu_pressure = max(gpu_pressure, snap.gpu.freetoken_percent / max(self.gpu_vram_budget_percent, 1.0))
        return beltu_pressure, host_pressure, gpu_pressure

    def effective_capacity(self, snapshot: ResourceSnapshot | None = None) -> int:
        snap = snapshot or self._last_snapshot
        beltu_pressure, host_pressure, gpu_pressure = self._pressure(snap)
        if beltu_pressure >= 1.25 or host_pressure >= 1.0 or gpu_pressure >= 1.15:
            return self.min_concurrent_processes
        if beltu_pressure >= 1.0 or host_pressure >= 0.85 or gpu_pressure >= 1.0:
            return max(self.min_concurrent_processes, self.max_concurrent_processes // 2)
        return self.max_concurrent_processes

    def tool_runtime_limits(self, tool: str) -> ToolRuntimeLimits:
        snap = self._last_snapshot
        beltu_pressure, host_pressure, gpu_pressure = self._pressure(snap)
        hard = max(beltu_pressure, host_pressure, gpu_pressure)
        if hard >= 1.25:
            thread_limit = 1
            reason = "critical resource pressure"
        elif hard >= 1.0:
            thread_limit = 2
            reason = "high resource pressure"
        elif hard >= 0.85:
            thread_limit = 4
            reason = "elevated resource pressure"
        else:
            thread_limit = 8
            reason = "normal resource pressure"
        if tool in {"nuclei", "nmap", "httpx", "subfinder"} and gpu_pressure >= 1.0:
            thread_limit = min(thread_limit, 2)
            reason += "; FreeToken VRAM pressure clamp"
        cpus = max(1, min(self.monitor.cpu_count, thread_limit))
        return ToolRuntimeLimits(tool, thread_limit, self.effective_capacity(snap), tuple(range(cpus)), reason)

    def register_process(self, pid: int, tool: str) -> None:
        if pid > 1:
            self._managed_pids[pid] = tool
            self._apply_affinity_limits(self._last_snapshot)

    def unregister_process(self, pid: int) -> None:
        self._managed_pids.pop(pid, None)

    def _apply_affinity_limits(self, snap: ResourceSnapshot) -> None:
        _, _, gpu_pressure = self._pressure(snap)
        for pid, tool in list(self._managed_pids.items()):
            if not Path(f"/proc/{pid}").exists():
                self._managed_pids.pop(pid, None)
                continue
            limits = self.tool_runtime_limits(tool)
            if gpu_pressure >= 1.0 or snap.host_cpu_percent >= 85.0:
                try:
                    os.sched_setaffinity(pid, set(limits.affinity_cpus))
                except (OSError, PermissionError):
                    pass

    async def acquire_process(self, priority: int = 50) -> ResourceSnapshot:
        del priority
        await self.start()
        while True:
            async with self._condition:
                self._last_snapshot = self.monitor.snapshot(self._active)
                capacity = self.effective_capacity(self._last_snapshot)
                if self._active < capacity:
                    self._active += 1
                    return self.monitor.snapshot(self._active)
            await asyncio.sleep(self.poll_interval)

    def release_process(self) -> None:
        self._active = max(0, self._active - 1)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._notify_waiters())

    async def _notify_waiters(self) -> None:
        async with self._condition:
            self._condition.notify_all()

    def snapshot(self) -> ResourceSnapshot:
        self._last_snapshot = self.monitor.snapshot(self._active)
        return self._last_snapshot
