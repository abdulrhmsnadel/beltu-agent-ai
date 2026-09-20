from __future__ import annotations

import asyncio
from pathlib import Path

from beltu.analysis.correlator import ObservationCorrelator
from beltu.brain.attack_graph import AttackSurfaceGraph
from beltu.brain.context_builder import ContextBuilder
from beltu.brain.observation_pipeline import ObservationPipeline
from beltu.brain.observer import Observer
from beltu.brain.planner import Planner
from beltu.brain.schemas import ActionProposal, ObservationInput
from beltu.common.enums import ScanStatus
from beltu.control.approval_service import ApprovalService
from beltu.core.event_bus import EventBus
from beltu.core.orchestrator import Orchestrator
from beltu.execution.adapters import HttpxAdapter, NmapAdapter, NucleiAdapter, SubfinderAdapter
from beltu.execution.registry import CapabilityRegistry, ToolRegistry
from beltu.execution.service import ExecutionService
from beltu.feedback.replanner import AutonomousReplanner
from beltu.feedback.repository import ReasoningCycleRepository
from beltu.selection.engine import IntelligentCapabilitySelector
from beltu.storage.database import Database
from beltu.storage.repositories.approval_repository import ApprovalRepository
from beltu.storage.repositories.capability_selection_repository import CapabilitySelectionRepository
from beltu.storage.repositories.decision_repository import DecisionRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.llm_run_repository import LLMRunRepository
from beltu.storage.repositories.observation_link_repository import ObservationLinkRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.task_repository import TaskRepository
from beltu.policy.scope_guard import ScopeGuard


def build_context(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    observations = ObservationRepository(db)
    hypotheses = HypothesisRepository(db)
    target = targets.add("example.com")
    scan = scans.create(target.id, ScanStatus.RUNNING)
    context = ContextBuilder(scans, targets, observations, hypotheses, AttackSurfaceGraph())
    links = ObservationLinkRepository(db)
    pipeline = ObservationPipeline(Observer(observations, scans, targets), ObservationCorrelator(links))
    return db, target, scan, observations, hypotheses, context, pipeline


def make_registry() -> CapabilityRegistry:
    tools = ToolRegistry()
    for item in (SubfinderAdapter(), HttpxAdapter(), NmapAdapter(), NucleiAdapter()):
        tools.register(item)
    return CapabilityRegistry(tools)


def test_selector_prefers_low_cost_discovery_when_surface_is_empty(tmp_path: Path):
    _, _, scan, _, _, context_builder, _ = build_context(tmp_path)
    decision = IntelligentCapabilitySelector(make_registry()).select(context_builder.build(scan.id), executable_only=True)
    assert decision.selected is not None
    assert decision.selected.profile.name == "asset.discovery.subdomains"
    assert decision.selected.tool == "subfinder"
    assert decision.candidates[0].score >= decision.candidates[-1].score


def test_selector_moves_to_web_verification_after_subdomain_evidence(tmp_path: Path):
    _, _, scan, _, _, context_builder, pipeline = build_context(tmp_path)
    pipeline.ingest(scan.id, [ObservationInput("asset.subdomain", "api.example.com", {}, "fixture", 0.95)])
    decision = IntelligentCapabilitySelector(make_registry()).select(context_builder.build(scan.id), executable_only=True)
    assert decision.selected is not None
    assert decision.selected.profile.name in {"web.verify", "service.discovery"}
    assert any(item.profile.name == "web.verify" for item in decision.candidates)


def test_selector_accounts_for_expected_information_gain_and_risk(tmp_path: Path):
    _, _, scan, _, _, context_builder, pipeline = build_context(tmp_path)
    pipeline.ingest(scan.id, [ObservationInput("asset.subdomain", "api.example.com", {}, "fixture", 0.95)])
    pipeline.ingest(scan.id, [ObservationInput("web.http_probe", "https://api.example.com", {}, "fixture", 0.9)])
    decision = IntelligentCapabilitySelector(make_registry()).select(context_builder.build(scan.id), executable_only=True)
    assert decision.selected is not None
    assert decision.selected.profile.name != "asset.discovery.subdomains"
    assert decision.selected.profile.risk_level in {"medium", "high"}


def test_action_selection_adds_capability_and_tool_to_persisted_decision(tmp_path: Path):
    db, _, scan, observations, hypotheses, context_builder, _ = build_context(tmp_path)
    pipeline = ObservationPipeline(Observer(observations, ScanRepository(db), TargetRepository(db)), ObservationCorrelator(ObservationLinkRepository(db)))
    pipeline.ingest(scan.id, [ObservationInput("asset.subdomain", "api.example.com", {}, "fixture", 0.95)])
    decisions = DecisionRepository(db)
    tasks = TaskRepository(db)
    cycles = ReasoningCycleRepository(db)
    selector = IntelligentCapabilitySelector(make_registry())
    replanner = AutonomousReplanner(
        context_builder=context_builder,
        observations=observations,
        hypotheses=hypotheses,
        decisions=decisions,
        tasks=tasks,
        cycles=cycles,
        llm_runs=LLMRunRepository(db),
        capability_selector=selector,
        selections=CapabilitySelectionRepository(db),
        reasoning_engine=None,
        planner=Planner(),
        auto_execute_low_risk=False,
    )
    result = asyncio.run(replanner.replan(scan.id, trigger="manual", trigger_task_id=0))
    assert result.decision_ids
    decision = decisions.get(result.decision_ids[0])
    assert decision is not None
    assert decision.action_payload.get("capability")
    assert decision.action_payload.get("tool") in {"httpx", "nmap"}
    history = CapabilitySelectionRepository(db).list_for_scan(scan.id)
    assert history and history[-1]["decision_id"] == decision.id


def test_execution_service_rejects_incompatible_selected_capability(tmp_path: Path):
    db, target, scan, _, _, _, _ = build_context(tmp_path)
    decisions = DecisionRepository(db)
    decision = decisions.create(
        scan.id, None, "endpoint_mapping",
        {"target": target.value, "capability": "service.discovery"},
        "test", 0.8, "medium", False, status="accepted",
    )
    # We only need the request-building guard here; no external process is launched.
    class DummyDispatcher:
        async def execute(self, request):
            return None
    service = ExecutionService(decisions, DummyDispatcher(), None)
    try:
        service.request_from_decision(decision.id)
    except ValueError as exc:
        assert "incompatible" in str(exc)
    else:
        raise AssertionError("incompatible capability was accepted")
