from __future__ import annotations

import asyncio
from pathlib import Path

from beltu.common.enums import ScanStatus
from beltu.common.exceptions import ScopeViolation
from beltu.execution.adapters.base import ToolAdapter
from beltu.execution.capability_dispatcher import CapabilityDispatcher
from beltu.execution.models import ExecutionRequest
from beltu.execution.process_manager import ProcessManager
from beltu.execution.registry import CapabilityRegistry, ToolRegistry
from beltu.execution.resource_governor import ResourceGovernor
from beltu.policy.scope_guard import ScopeGuard
from beltu.storage.database import Database
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository


class TrueAdapter(ToolAdapter):
    name = "fixture-true"
    capability = "fixture.passthrough"
    binary = "true"
    risk_level = "low"

    def build_argv(self, request: ExecutionRequest) -> list[str]:
        self.validate_request(request)
        return [self.binary, request.target]

    def parse_output(self, request, stdout, stderr):
        return [{
            "kind": "fixture.result",
            "subject": request.target,
            "data": {"ok": True},
            "source": self.name,
            "confidence": 1.0,
        }]


class ApprovalAdapter(TrueAdapter):
    name = "fixture-approval"
    capability = "fixture.approval"
    requires_approval = True
    risk_level = "high"


def build(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    observations = ObservationRepository(db)
    scans = ScanRepository(db)
    targets = TargetRepository(db)
    target = targets.add("example.com")
    scan = scans.create(target.id, ScanStatus.RUNNING)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("targets:\n  - example.com\n", encoding="utf-8")
    tools = ToolRegistry()
    tools.register(TrueAdapter())
    tools.register(ApprovalAdapter())
    dispatcher = CapabilityDispatcher(
        ScopeGuard(scope_file),
        CapabilityRegistry(tools),
        ProcessManager(),
        ResourceGovernor(1),
        observations,
        scans,
        targets,
    )
    return dispatcher, observations, scan


def test_dispatcher_executes_argv_without_shell_and_persists_observation(tmp_path: Path):
    dispatcher, observations, scan = build(tmp_path)

    async def run():
        return await dispatcher.execute(ExecutionRequest(scan.id, "example.com", "fixture.passthrough"))

    result = asyncio.run(run())
    assert result.succeeded
    assert result.argv[0].endswith("/true")
    assert result.observations[0]["subject"] == "example.com"
    assert len(observations.list_for_scan(scan.id)) == 1


def test_scope_is_checked_before_execution(tmp_path: Path):
    dispatcher, _, scan = build(tmp_path)

    async def run():
        return await dispatcher.execute(ExecutionRequest(scan.id, "not-allowed.example", "fixture.passthrough"))

    try:
        asyncio.run(run())
    except ScopeViolation:
        return
    raise AssertionError("out-of-scope execution was not rejected")


def test_approval_metadata_blocks_execution(tmp_path: Path):
    dispatcher, _, scan = build(tmp_path)

    async def run():
        return await dispatcher.execute(ExecutionRequest(scan.id, "example.com", "fixture.approval"))

    try:
        asyncio.run(run())
    except PermissionError:
        return
    raise AssertionError("approval-gated capability executed without approval")


def test_tool_registry_resolves_capability():
    tools = ToolRegistry()
    tools.register(TrueAdapter())
    registry = CapabilityRegistry(tools)
    assert registry.resolve("fixture.passthrough").name == "fixture-true"


def test_process_manager_does_not_invoke_shell(tmp_path: Path):
    marker = tmp_path / "shell-marker"
    manager = ProcessManager()

    async def run():
        return await manager.run(["true", f"&& touch {marker}"], 5)

    result = asyncio.run(run())
    assert result.returncode == 0
    assert not marker.exists()
