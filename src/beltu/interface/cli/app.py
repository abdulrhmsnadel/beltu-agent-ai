from __future__ import annotations

import asyncio
import json
from pathlib import Path
import yaml

import typer
from rich.console import Console
from rich.table import Table

from beltu.common.exceptions import BeltuError
from beltu.common.types import Task
from beltu.brain.attack_graph import AttackSurfaceGraph
from beltu.brain.context_builder import ContextBuilder
from beltu.brain.schemas import ObservationInput
from beltu.control.approval_service import ApprovalService
from beltu.integrations.whatsapp.client import WhatsAppCloudClient, WhatsAppConfig
from beltu.integrations.whatsapp.server import serve as serve_whatsapp
from beltu.integrations.whatsapp.webhook import WhatsAppWebhookHandler
from beltu.storage.repositories.approval_repository import ApprovalRepository
from beltu.storage.repositories.api_repository import ApiRepository
from beltu.storage.repositories.decision_repository import DecisionRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.evidence_repository import EvidenceRepository
from beltu.storage.repositories.observation_link_repository import ObservationLinkRepository
from beltu.core.agent import Agent
from beltu.brain.observation_pipeline import ObservationPipeline
from beltu.brain.observer import Observer
from beltu.analysis.correlator import ObservationCorrelator
from beltu.core.event_bus import EventBus
from beltu.core.orchestrator import Orchestrator
from beltu.execution.scheduler import Scheduler
from beltu.execution.adapters import (
    AmassPassiveAdapter,
    AssetfinderAdapter,
    HttpxAdapter,
    NmapAdapter,
    NucleiAdapter,
    SubfinderAdapter,
    BrowserAutomationAdapter,
    HttpWorkflowAdapter,
    SessionReplayAdapter,
    ApiManipulationAdapter,
    AuthorizationTestingAdapter,
    BusinessLogicWorkflowAdapter,
    RaceConditionAdapter,
)
from beltu.execution.registry import CapabilityRegistry, ToolRegistry
from beltu.execution.capability_dispatcher import CapabilityDispatcher
from beltu.execution.process_manager import ProcessManager
from beltu.execution.resource_governor import ResourceGovernor
from beltu.execution.retry_manager import RetryManager
from beltu.execution.service import ExecutionService
from beltu.policy.scope_guard import ScopeGuard
from beltu.storage.database import Database
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.task_repository import TaskRepository
from beltu.feedback.replanner import AutonomousReplanner
from beltu.feedback.repository import ReasoningCycleRepository
from beltu.storage.repositories.llm_run_repository import LLMRunRepository
from beltu.storage.repositories.capability_selection_repository import CapabilitySelectionRepository
from beltu.selection.engine import IntelligentCapabilitySelector
from beltu.intelligence.service import AssetIntelligenceService
from beltu.intelligence.prioritizer import SurfacePrioritizer
from beltu.storage.repositories.asset_repository import AssetRepository
from beltu.api_intelligence.service import ApiIntelligenceService
from beltu.auth_intelligence.service import AuthIntelligenceService
from beltu.access_control.service import AccessControlIntelligenceService
from beltu.business_logic.service import BusinessLogicIntelligenceService
from beltu.analysis.finding_intelligence import FindingIntelligenceService
from beltu.storage.repositories.finding_repository import FindingRepository
from beltu.storage.repositories.auth_repository import AuthRepository
from beltu.brain.hypothesis_engine import HeuristicHypothesisEngine
from beltu.brain.planner import Planner
from beltu.brain.prioritizer import HypothesisPrioritizer
from beltu.brain.reasoning_engine import HybridReasoningEngine
from beltu.brain.llm import Altar1LocalProvider, DisabledLLMProvider, FreeTokenLocalProvider, LLMConfig, LLMReasoningEngine, LLMRouter, OpenAICompatibleProvider
from beltu.version import __version__
from beltu.release.audit import run_audit
from beltu.reporting.engine import ReportEngine
from beltu.storage.repositories.report_repository import ReportRepository

app = typer.Typer(no_args_is_help=True, help="BELTU — agentic security testing platform")
target_app = typer.Typer(help="Manage explicitly authorized targets")
scan_app = typer.Typer(help="Manage persistent scan lifecycles")
app.add_typer(target_app, name="target-admin", hidden=True)
app.add_typer(scan_app, name="scan")
console = Console()


def paths() -> tuple[Path, Path]:
    root = Path.cwd()
    return root / "data" / "beltu.db", root / "config" / "scope.yaml"


def load_agent_config() -> dict:
    path = Path.cwd() / "config" / "agent.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid config/agent.yaml: {exc}") from exc
    return data if isinstance(data, dict) else {}


def build_components():
    db_path, scope_path = paths()
    db = Database(db_path)
    db.initialize()
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    tasks = TaskRepository(db)
    observations = ObservationRepository(db)
    evidence = EvidenceRepository(db)
    links = ObservationLinkRepository(db)
    hypotheses = HypothesisRepository(db)
    decisions = DecisionRepository(db)
    approvals_repo = ApprovalRepository(db)
    approvals = ApprovalService(decisions, approvals_repo)
    cycles = ReasoningCycleRepository(db)
    llm_runs = LLMRunRepository(db)
    selections = CapabilitySelectionRepository(db)
    events = EventBus()

    tools = ToolRegistry()
    for adapter in (
        SubfinderAdapter(),
        AssetfinderAdapter(),
        AmassPassiveAdapter(),
        HttpxAdapter(),
        NmapAdapter(),
        NucleiAdapter(),
        BrowserAutomationAdapter(),
        HttpWorkflowAdapter(),
        SessionReplayAdapter(),
        ApiManipulationAdapter(),
        AuthorizationTestingAdapter(),
        BusinessLogicWorkflowAdapter(),
        RaceConditionAdapter(),
    ):
        tools.register(adapter)
    capabilities = CapabilityRegistry(tools)
    dispatcher = CapabilityDispatcher(
        ScopeGuard(scope_path),
        capabilities,
        ProcessManager(),
        ResourceGovernor(
            max_concurrent_processes=2,
            cpu_budget_percent=30,
            memory_budget_percent=30,
            min_concurrent_processes=1,
            poll_interval=0.5,
            freetoken_pid_file=Path.cwd() / "data" / "runtime" / "freetoken.pid",
            freetoken_url="http://127.0.0.1:8000",
            altar1_pid_file=Path.cwd() / "data" / "runtime" / "altar1.pid",
            altar1_activity_dir=Path.cwd() / "data" / "runtime" / "altar1.active",
            altar1_url="http://127.0.0.1:8001",
            gpu_vram_budget_percent=45,
        ),
        observations,
        scans,
        targets,
        evidence=evidence,
        links=links,
        evidence_root=str(Path.cwd() / "data" / "evidence"),
    )
    execution_service = ExecutionService(decisions, dispatcher, approvals)
    scheduler = Scheduler(
        tasks, scans, targets, events, workers=4,
        retry_manager=RetryManager(base_delay=0.25, max_delay=5, jitter=0),
    )

    asset_intelligence = AssetIntelligenceService(db)
    surface_intelligence = SurfacePrioritizer(db, asset_intelligence)
    api_intelligence = ApiIntelligenceService(db)
    auth_intelligence = AuthIntelligenceService(db)
    authorization_intelligence = AccessControlIntelligenceService(db)
    business_logic_intelligence = BusinessLogicIntelligenceService(db)
    finding_intelligence = FindingIntelligenceService(db)
    capability_selector = IntelligentCapabilitySelector(capabilities)
    feedback_holder = {"replanner": None}

    async def evaluate(task: Task):
        replanner = feedback_holder["replanner"]
        if replanner is None:
            raise RuntimeError("Feedback loop is not initialized")
        result = await replanner.replan(task.scan_id, trigger="initial_scan", trigger_task_id=task.id)
        return result.as_payload()

    async def execute_capability(task: Task):
        decision_id = int(task.payload["decision_id"])
        result = await execution_service.execute_decision(decision_id)
        decisions.set_status(decision_id, "executed" if result.succeeded else "execution_failed")
        return {
            "tool": result.tool,
            "argv": list(result.argv),
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_seconds": result.duration_seconds,
            "observation_count": len(result.observations),
        }

    scheduler.register("agent.evaluate", evaluate)
    scheduler.register("capability.execute", execute_capability)
    orchestrator = Orchestrator(targets, scans, tasks, scheduler, events)
    context_builder = ContextBuilder(scans, targets, observations, hypotheses, AttackSurfaceGraph(), asset_intelligence, surface_intelligence, api_intelligence, auth_intelligence, authorization_intelligence, business_logic_intelligence, finding_intelligence)
    agent_config = load_agent_config()
    llm_config = LLMConfig.from_project(Path.cwd())
    standard_provider = FreeTokenLocalProvider(llm_config) if llm_config.enabled else DisabledLLMProvider()
    altar_provider = Altar1LocalProvider(llm_config) if llm_config.altar_enabled else DisabledLLMProvider()
    llm_router = LLMRouter(
        standard_provider=standard_provider,
        altar_provider=altar_provider,
        enabled=llm_config.router_enabled,
    )
    llm_reasoner = LLMReasoningEngine(Path.cwd(), llm_config, llm_router)
    reasoning_engine = HybridReasoningEngine(
        heuristic=HeuristicHypothesisEngine(),
        prioritizer=HypothesisPrioritizer(),
        planner=Planner(),
        llm=llm_reasoner,
        enabled=llm_config.enabled,
        fallback_to_heuristic=llm_config.fallback_to_heuristic,
    )
    brain_config = agent_config.get("brain", {}) if isinstance(agent_config.get("brain", {}), dict) else {}
    execution_config = agent_config.get("execution", {}) if isinstance(agent_config.get("execution", {}), dict) else {}
    external_tools_enabled = bool(execution_config.get("external_tools_enabled", False))
    replanner = AutonomousReplanner(
        context_builder=context_builder,
        observations=observations,
        hypotheses=hypotheses,
        decisions=decisions,
        tasks=tasks,
        cycles=cycles,
        llm_runs=llm_runs,
        capability_selector=capability_selector,
        selections=selections,
        events=events,
        max_cycles_per_scan=20,
        max_auto_tasks_per_cycle=max(0, int(brain_config.get("max_actions_per_cycle", 3))),
        reasoning_engine=reasoning_engine,
        auto_execute_low_risk=external_tools_enabled,
        enqueue_task=scheduler.enqueue,
    )
    feedback_holder["replanner"] = replanner
    replanner.install()
    agent = Agent(
        targets, ScopeGuard(scope_path), orchestrator,
        observations=observations, hypotheses=hypotheses, decisions=decisions,
        context_builder=context_builder,
        reasoning_engine=reasoning_engine,
        observation_pipeline=ObservationPipeline(
            Observer(observations, scans, targets),
            ObservationCorrelator(links),
        ),
    )
    return agent, scans, tasks, orchestrator, decisions, tools, approvals


@app.command("target")
def target(value: str = typer.Argument(..., help="Domain/host that is already authorized and present in scope")) -> None:
    """Validate scope and register an explicitly authorized target."""
    try:
        agent, _, _, _, _, _, _ = build_components()
        target_obj = agent.register_target(value)
    except BeltuError as exc:
        console.print(f"[red]Blocked:[/red] {exc}")
        raise typer.Exit(code=2)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(f"Registered target #{target_obj.id}: {target_obj.value} ({target_obj.status})")


@app.command("targets")
def targets_list() -> None:
    """List registered targets."""
    agent, _, _, _, _, _, _ = build_components()
    targets = agent.targets.list_all()
    table = Table("ID", "Target", "Status", "Created")
    for item in targets:
        table.add_row(str(item.id), item.value, item.status, item.created_at)
    console.print(table)


@app.command("hunt")
def hunt(value: str = typer.Argument(..., help="Authorized target/domain to hunt")) -> None:
    """Start the full persistent BELTU reasoning lifecycle for a target."""
    async def run() -> tuple[int, int, str]:
        agent, scans, tasks, orchestrator, _, _, _ = build_components()
        target_obj = agent.register_target(value)
        await orchestrator.start()
        try:
            scan, task = await agent.start_scan(target_obj.id)
            await orchestrator.scheduler.queue.join()
            final_scan = scans.get(scan.id)
            final_task = tasks.get(task.id)
            return scan.id, task.id, final_scan.status if final_scan else (final_task.status if final_task else "unknown")
        finally:
            await orchestrator.stop()

    try:
        scan_id, task_id, scan_status = asyncio.run(run())
    except Exception as exc:
        console.print(f"[red]Hunt failed:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(f"BELTU hunt started/completed: target={value} scan=#{scan_id} task=#{task_id} status={scan_status}")
    console.print("Reasoning is local-first; active tool execution still follows scope/approval/resource policy.")


@target_app.command("list")
def target_list() -> None:
    """List registered targets."""
    agent, _, _, _, _, _, _ = build_components()
    targets = agent.targets.list_all()
    table = Table("ID", "Target", "Status", "Created")
    for target in targets:
        table.add_row(str(target.id), target.value, target.status, target.created_at)
    console.print(table)


@scan_app.command("start")
def scan_start(target_id: int = typer.Argument(..., min=1)) -> None:
    """Create and execute the persistent agent lifecycle task for a target."""
    async def run():
        agent, scans, tasks, orchestrator, _, _, _ = build_components()
        await orchestrator.start()
        scan, task = await agent.start_scan(target_id)
        await orchestrator.scheduler.queue.join()
        await orchestrator.stop()
        return scan, task, tasks.get(task.id), scans.get(scan.id)

    try:
        scan, task, final_task, final_scan = asyncio.run(run())
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(f"Scan #{scan.id} → {final_scan.status}")
    console.print(f"Task #{task.id} → {final_task.status}")


@scan_app.command("think")
def scan_think(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Run one offline reasoning cycle; no external tool is executed."""
    try:
        agent, _, _, _, _, _, _ = build_components()
        cycle = agent.think(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(f"Target: {cycle.context.target}")
    console.print(f"Observations: {len(cycle.context.observations)}")
    console.print("\n[bold]Hypotheses[/bold]")
    for hypothesis in cycle.hypotheses:
        console.print(f"- ({hypothesis.confidence:.2f}) {hypothesis.statement}")
    console.print("\n[bold]Decisions[/bold]")
    for result in cycle.decisions:
        state = "accepted" if result.accepted else "rejected"
        console.print(f"- {state}: {result.proposal.action_kind} — {result.reason}")


@scan_app.command("observe")
def scan_observe(
    scan_id: int = typer.Argument(..., min=1),
    kind: str = typer.Option(..., "--kind"),
    subject: str = typer.Option(..., "--subject"),
    source: str = typer.Option("manual", "--source"),
) -> None:
    """Add a simple manual observation for development/lab use."""
    try:
        agent, _, _, _, _, _, _ = build_components()
        observation = agent.ingest_observation(scan_id, ObservationInput(kind, subject, {}, source))
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(f"Observation #{observation.id} stored for scan #{scan_id}")


@scan_app.command("replan")
def scan_replan(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Run one persistent feedback/replanning cycle for a scan without executing tools directly."""
    async def run():
        agent, scans, tasks, orchestrator, decisions, tools, _ = build_components()
        db_path, _ = paths()
        cycles = ReasoningCycleRepository(Database(db_path))
        llm_runs = LLMRunRepository(Database(db_path))
        selector = IntelligentCapabilitySelector(CapabilityRegistry(tools))
        selections_repo = CapabilitySelectionRepository(Database(db_path))
        replanner = AutonomousReplanner(
            context_builder=agent.context_builder,
            observations=agent.observations,
            hypotheses=agent.hypotheses,
            decisions=decisions,
            tasks=tasks,
            cycles=cycles,
            llm_runs=llm_runs,
            capability_selector=selector,
            selections=selections_repo,
            events=orchestrator.events,
            max_cycles_per_scan=20,
            max_auto_tasks_per_cycle=2,
            auto_execute_low_risk=False,
            reasoning_engine=agent.reasoning_engine,
            enqueue_task=orchestrator.scheduler.enqueue,
        )
        result = await replanner.replan(scan_id, trigger="manual", trigger_task_id=0)
        return result
    try:
        result = asyncio.run(run())
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(f"Reasoning cycle #{result.cycle.id} → {result.cycle.status}")
    console.print(f"Hypotheses: {len(result.hypothesis_ids)} | Decisions: {len(result.decision_ids)} | Queued: {len(result.queued_task_ids)}")
    for note in result.notes:
        console.print(f"- {note}")


@scan_app.command("cycles")
def scan_cycles(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show persistent reasoning-cycle history for a scan."""
    db_path, _ = paths()
    repo = ReasoningCycleRepository(Database(db_path))
    table = Table("Cycle", "Trigger", "Task", "Status", "Context", "Created")
    for cycle in repo.list_for_scan(scan_id):
        table.add_row(str(cycle.id), cycle.trigger, str(cycle.trigger_task_id), cycle.status, cycle.context_fingerprint[:12] + "…", cycle.created_at)
    console.print(table)


@scan_app.command("list")
def scan_list(target_id: int | None = typer.Option(None, "--target")) -> None:
    """List scans and persisted lifecycle status."""
    _, scans, tasks, _, _, _, _ = build_components()
    rows = scans.list_for_target(target_id) if target_id else scans.list_resumable()
    table = Table("Scan", "Target", "Status", "Tasks")
    for scan in rows:
        table.add_row(str(scan.id), str(scan.target_id), scan.status, str(len(tasks.list_for_scan(scan.id))))
    console.print(table)


@scan_app.command("evidence")
def scan_evidence(scan_id: int = typer.Argument(..., min=1)) -> None:
    """List immutable evidence artifacts captured for a scan."""
    _, _, _, _, _, _, _ = build_components()
    db_path, _ = paths()
    evidence = EvidenceRepository(Database(db_path))
    rows = evidence.list_for_scan(scan_id)
    table = Table("ID", "Kind", "SHA256", "Bytes", "Path")
    for item in rows:
        table.add_row(str(item.id), item.kind, item.sha256[:16] + "…", str(item.size_bytes), item.path or "-")
    console.print(table)


@app.command("report")
def report_generate(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Generate the complete local report/workspace package for a persisted scan."""
    db_path, _ = paths()
    try:
        result = ReportEngine(Database(db_path), Path.cwd()).generate(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(f"Scan #{result.scan_id} — reports generated")
    console.print(f"Target: {result.target}")
    console.print(f"Workspace: {result.workspace}")
    console.print(f"Files: {len(result.files)} | Packages: {len(result.packages)}")

@app.command("report-list")
def report_list(scan_id: int = typer.Argument(..., min=1)) -> None:
    """List report packages recorded for a scan."""
    db_path, _ = paths()
    try:
        rows = ReportRepository(Database(db_path)).list_packages(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    table = Table("ID", "Type", "Path", "SHA256", "Bytes", "Generated")
    for row in rows:
        table.add_row(str(row.id), row.report_type, row.relative_path, row.sha256[:16] + "…", str(row.size_bytes), row.created_at)
    console.print(table)

@app.command("findings")
def finding_list(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Build and display finding candidates from stored evidence only."""
    try:
        result = FindingIntelligenceService(Database(paths()[0])).rebuild(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(f"Scan #{scan_id} — findings={result.summary['findings']} signals={result.summary['signals']}")
    table = Table("ID", "Severity", "Confidence", "Status", "Category", "Title")
    for f in result.findings:
        table.add_row(str(f.id), f.severity, f"{f.confidence:.2f}", f.status, f.category, f.title[:80])
    console.print(table)

@app.command("finding-validation")
def finding_validation(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show declarative validation plans; this command never executes validation."""
    svc = FindingIntelligenceService(Database(paths()[0]))
    result = svc.rebuild(scan_id)
    repo = FindingRepository(Database(paths()[0]))
    table = Table("Plan", "Finding", "Status", "Risk", "Approval", "Steps")
    for f in result.findings:
        plan = repo.get_plan(f.id)
        if plan:
            table.add_row(str(plan.id), str(f.id), plan.status, plan.risk_level, "required" if plan.requires_approval else "no", str(len(repo.list_steps(plan.id))))
    console.print(table)

@app.command("finding-context")
def finding_context(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Display finding intelligence supplied to the agent brain."""
    console.print(json.dumps(FindingIntelligenceService(Database(paths()[0])).context_payload(scan_id), indent=2, sort_keys=True))

@app.command("asset-inventory")
def asset_inventory(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Build and display the persistent asset inventory for a scan; no new network activity."""
    try:
        db_path, _ = paths()
        result = AssetIntelligenceService(Database(db_path)).rebuild(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(
        f"Scan #{scan_id} — assets={result.summary['assets']} services={result.summary['services']} "
        f"endpoints={result.summary['endpoints']} technologies={result.summary['technologies']} "
        f"relations={result.summary['relations']}"
    )
    table = Table("ID", "Type", "Asset", "Status", "Source", "Confidence")
    for asset in result.assets:
        table.add_row(
            str(asset.id), asset.asset_type, asset.normalized_value, asset.status,
            asset.source, f"{asset.confidence:.2f}",
        )
    console.print(table)


@app.command("asset-graph")
def asset_graph(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Display asset relationships for a scan; derived only from stored observations."""
    try:
        db_path, _ = paths()
        result = AssetIntelligenceService(Database(db_path)).rebuild(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    table = Table("Parent", "Relation", "Child")
    for parent, child, relation in result.graph.edges:
        table.add_row(parent, relation, child)
    console.print(table)


@app.command("surface-rank")
def surface_rank(scan_id: int = typer.Argument(..., min=1), limit: int = typer.Option(20, "--limit", min=1, max=200)) -> None:
    """Show explainable attack-surface priorities from stored inventory only."""
    db_path, _ = paths()
    try:
        service = SurfacePrioritizer(Database(db_path))
        result = service.rebuild(scan_id)
    except Exception as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Scan #{scan_id} — surface items={result.summary['total']} P1={result.summary['P1']} P2={result.summary['P2']} P3={result.summary['P3']} P4={result.summary['P4']}")
    table = Table("#", "Priority", "Type", "Value", "Score", "Exposure", "Sensitivity", "Confidence")
    for idx, row in enumerate(result.priorities[:limit], 1):
        table.add_row(str(idx), row.priority, row.entity_type, row.value[:80], f"{row.score:.3f}", f"{row.exposure:.2f}", f"{row.sensitivity:.2f}", f"{row.confidence:.2f}")
    console.print(table)

@app.command("surface")
def surface(scan_id: int = typer.Argument(..., min=1), limit: int = typer.Option(20, "--limit", min=1, max=200)) -> None:
    """Show the top-priority surface items and their reasoning signals."""
    db_path, _ = paths()
    result = SurfacePrioritizer(Database(db_path)).rebuild(scan_id)
    for row in result.priorities[:limit]:
        console.print(f"[{row.priority}] {row.entity_type} {row.value} score={row.score:.3f} — {row.rationale}")

@app.command("api-inventory")
def api_inventory(scan_id: int = typer.Argument(..., min=1), limit: int = typer.Option(100, "--limit", min=1, max=500)) -> None:
    """Build and display the persistent API/Web operation inventory from stored observations only."""
    try:
        db_path, _ = paths()
        result = ApiIntelligenceService(Database(db_path)).rebuild(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    summary = result.summary
    console.print(
        f"Scan #{scan_id} — operations={summary['operations']} parameters={summary['parameters']} "
        f"protected={summary['protected_operations']} graphql={summary['graphql_operations']} relations={summary['relations']}"
    )
    table = Table("ID", "Method", "Path", "Style", "Auth", "Params", "Confidence")
    repo = ApiRepository(Database(db_path))
    params_by_op = {}
    for param in repo.list_parameters(scan_id):
        params_by_op[param.operation_id] = params_by_op.get(param.operation_id, 0) + 1
    for op in result.operations[:limit]:
        table.add_row(str(op.id), op.method, op.path[:90], op.api_style, "yes" if op.auth_required else "no", str(params_by_op.get(op.id, 0)), f"{op.confidence:.2f}")
    console.print(table)


@app.command("api-relations")
def api_relations(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show stored API operation/workflow relationships; no new traffic is generated."""
    db_path, _ = paths()
    service = ApiIntelligenceService(Database(db_path))
    result = service.rebuild(scan_id)
    repo = ApiRepository(Database(db_path))
    operations = {op.id: op for op in repo.list_operations(scan_id)}
    table = Table("From", "Relation", "To", "Confidence", "Basis")
    for row in result.relations:
        src = operations.get(row["from_operation_id"])
        dst = operations.get(row["to_operation_id"])
        table.add_row(
            f"{src.method} {src.path}" if src else str(row["from_operation_id"]),
            row["relation"],
            f"{dst.method} {dst.path}" if dst else str(row["to_operation_id"]),
            f"{row['confidence']:.2f}", str(row.get("basis", {}))[:100],
        )
    console.print(table)


@app.command("api-context")
def api_context(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show a compact API context summary that is fed to the reasoning layer."""
    db_path, _ = paths()
    payload = ApiIntelligenceService(Database(db_path)).context_payload(scan_id, limit=30)
    console.print(payload.get("summary", {}))
    for op in payload.get("operations", []):
        console.print(f"- {op['method']} {op['path']} style={op['api_style']} auth={op['auth_required']} params={len(op.get('parameters', []))}")



@app.command("auth-inventory")
def auth_inventory(scan_id: int = typer.Argument(..., min=1), limit: int = typer.Option(100, "--limit", min=1, max=300)) -> None:
    """Build and display authentication/session intelligence from stored evidence only."""
    try:
        db_path, _ = paths()
        result = AuthIntelligenceService(Database(db_path)).rebuild(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    s = result.summary
    console.print(f"Scan #{scan_id} — principals={s['principals']} sessions={s['sessions']} controls={s['controls']} protected={s['protected_controls']} transitions={s['transitions']}")
    table = Table("ID", "Label", "Kind", "Role", "Confidence", "Source")
    for p in result.principals[:limit]:
        table.add_row(str(p.id), p.label, p.kind, p.role or "-", f"{p.confidence:.2f}", p.source)
    console.print(table)

    if result.sessions:
        console.print("\n[bold]Sessions[/bold]")
        table = Table("ID", "Label", "Transport", "Mechanism", "State", "Secure", "HttpOnly", "Value")
        for s_item in result.sessions[:limit]:
            table.add_row(str(s_item.id), s_item.label, s_item.transport, s_item.mechanism, s_item.state, str(s_item.secure), str(s_item.http_only), "present" if s_item.value_present else "not_observed")
        console.print(table)


@app.command("auth-boundaries")
def auth_boundaries(scan_id: int = typer.Argument(..., min=1), limit: int = typer.Option(100, "--limit", min=1, max=300)) -> None:
    """Show persisted operation/auth boundaries without generating traffic."""
    db_path, _ = paths()
    try:
        result = AuthIntelligenceService(Database(db_path)).rebuild(scan_id)
        api_repo = ApiRepository(Database(db_path))
        operations = {op.id: op for op in api_repo.list_operations(scan_id)}
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    table = Table("Operation", "Principal", "Access State", "Auth", "Schemes", "Confidence")
    for c in result.controls[:limit]:
        op = operations.get(c.operation_id)
        name = f"{op.method} {op.path}" if op else str(c.operation_id)
        table.add_row(name[:90], c.principal_label, c.access_state, "yes" if c.auth_required else "no", ", ".join(c.schemes) or "-", f"{c.confidence:.2f}")
    console.print(table)
    if result.transitions:
        console.print("\n[bold]Auth transitions[/bold]")
        for t in result.transitions[:limit]:
            op = operations.get(t.operation_id) if t.operation_id else None
            suffix = f" via {op.method} {op.path}" if op else ""
            console.print(f"- {t.from_state} -> {t.to_state} ({t.relation}, {t.confidence:.2f}){suffix}")


@app.command("auth-context")
def auth_context(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show the compact authentication context fed to the reasoning layer."""
    db_path, _ = paths()
    payload = AuthIntelligenceService(Database(db_path)).context_payload(scan_id, limit=30)
    console.print(payload.get("summary", {}))
    for row in payload.get("operation_controls", [])[:30]:
        console.print(f"- op={row['operation_id']} principal={row['principal_label']} state={row['access_state']} auth={row['auth_required']} schemes={row['schemes']}")



@app.command("authz-inventory")
def authz_inventory(scan_id: int = typer.Argument(..., min=1), limit: int = typer.Option(100, "--limit", min=1, max=400)) -> None:
    """Build and display the authorization matrix from stored evidence only."""
    try:
        db_path, _ = paths()
        result = AccessControlIntelligenceService(Database(db_path)).rebuild(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    s = result.summary
    console.print(f"Scan #{scan_id} — matrix={s['matrix_entries']} anomalies={s['anomalies']} high={s['high_anomalies']} conflicts={s['principal_state_conflicts']} anonymous_candidates={s['anonymous_access_candidates']}")
    table = Table("Operation ID", "Principal", "Role", "State", "Auth", "Confidence", "Evidence")
    for row in result.matrix[:limit]:
        table.add_row(str(row.operation_id), row.principal_label, row.role or "-", row.access_state, "yes" if row.auth_required else "no", f"{row.confidence:.2f}", ",".join(map(str, row.evidence_ids)) or "-")
    console.print(table)


@app.command("authz-anomalies")
def authz_anomalies(scan_id: int = typer.Argument(..., min=1), limit: int = typer.Option(100, "--limit", min=1, max=400)) -> None:
    """Show candidate authorization inconsistencies derived from stored evidence."""
    try:
        db_path, _ = paths()
        result = AccessControlIntelligenceService(Database(db_path)).rebuild(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    table = Table("Severity", "Kind", "Entity", "Confidence", "Statement")
    for row in result.anomalies[:limit]:
        table.add_row(row.severity, row.kind, f"{row.entity_type}#{row.entity_id}", f"{row.confidence:.2f}", row.statement[:120])
    console.print(table)


@app.command("authz-context")
def authz_context(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show the compact authorization context fed to the reasoning layer."""
    db_path, _ = paths()
    payload = AccessControlIntelligenceService(Database(db_path)).context_payload(scan_id, limit=50)
    console.print(payload.get("summary", {}))
    for row in payload.get("anomalies", [])[:50]:
        console.print(f"- [{row['severity']}] {row['kind']}: {row['statement']}")


@app.command("capability-rank")
def capability_rank(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show evidence-aware capability ranking without executing anything."""
    agent, _, _, _, _, tools, _ = build_components()
    selector = IntelligentCapabilitySelector(CapabilityRegistry(tools))
    context = agent.context_builder.build(scan_id)
    decision = selector.select(context)
    table = Table("Rank", "Capability", "Tool", "Score", "Info Gain", "Cost", "Risk", "Approval")
    for index, candidate in enumerate(decision.candidates, start=1):
        table.add_row(
            str(index), candidate.profile.name, candidate.tool or "internal",
            f"{candidate.score:.3f}", f"{candidate.expected_information_gain:.3f}",
            f"{candidate.cost:.2f}", candidate.profile.risk_level,
            "yes" if candidate.profile.requires_approval else "no",
        )
    console.print(table)


@app.command("capability-history")
def capability_history(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show persisted capability selections for a scan."""
    db_path, _ = paths()
    repo = CapabilitySelectionRepository(Database(db_path))
    table = Table("ID", "Cycle", "Decision", "Capability", "Tool", "Score", "Created")
    for row in repo.list_for_scan(scan_id):
        table.add_row(
            str(row["id"]), str(row["cycle_id"] or "-"), str(row["decision_id"] or "-"),
            row["capability"], row["tool"] or "internal", f"{float(row['score']):.3f}", row["created_at"],
        )
    console.print(table)


@app.command("observation-links")
def observation_links(observation_id: int = typer.Argument(..., min=1)) -> None:
    """Show deterministic relationships attached to one observation."""
    db_path, _ = paths()
    repo = ObservationLinkRepository(Database(db_path))
    rows = repo.list_for_observation(observation_id)
    table = Table("Related Observation", "Relation", "Score")
    for item in rows:
        table.add_row(str(item.related_observation_id), item.relation, f"{item.score:.2f}")
    console.print(table)


async def _queue_decision_execution(tasks: TaskRepository, orchestrator: Orchestrator, decision_id: int, scan_id: int) -> Task:
    existing = tasks.list_for_decision(scan_id, decision_id)
    active = [item for item in existing if item.status in {"pending", "running"}]
    if active:
        return active[-1]
    task = tasks.create(
        scan_id,
        "capability.execute",
        {"decision_id": decision_id},
        priority=80,
        max_attempts=2,
    )
    await orchestrator.scheduler.enqueue(task)
    return task


@app.command("decision-execute")
def decision_execute(decision_id: int = typer.Argument(..., min=1)) -> None:
    """Execute one non-approval decision through the allowlisted capability layer."""
    async def run():
        agent, scans, tasks, orchestrator, decisions, _, approvals = build_components()
        decision = decisions.get(decision_id)
        if decision is None:
            raise ValueError(f"Decision #{decision_id} not found")
        if decision.requires_approval and not approvals.has_valid_approved_decision(decision_id):
            raise PermissionError(f"Decision #{decision_id} requires a valid approved approval record")
        await orchestrator.start()
        task = await _queue_decision_execution(tasks, orchestrator, decision.id, decision.scan_id)
        await orchestrator.scheduler.queue.join()
        final = tasks.get(task.id)
        await orchestrator.stop()
        return final, decision

    try:
        task, decision = asyncio.run(run())
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(f"Decision #{decision.id} → {decision.status}")
    console.print(f"Execution task #{task.id} → {task.status}")


approval_app = typer.Typer(help="Manage persistent human-in-the-loop approvals")
app.add_typer(approval_app, name="approval")


@approval_app.command("request")
def approval_request(
    decision_id: int = typer.Argument(..., min=1),
    channel: str = typer.Option("cli", "--channel"),
    recipient: str | None = typer.Option(None, "--recipient"),
    ttl: int = typer.Option(600, "--ttl", min=30, max=86400),
) -> None:
    """Create or reuse an approval request for a decision."""
    try:
        _, _, _, _, _, _, approvals = build_components()
        req = approvals.request_for_decision(decision_id, channel=channel, recipient=recipient, ttl_seconds=ttl)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(f"Approval #{req.id} | decision #{req.decision_id} | status={req.status}")
    console.print(f"Token: {req.token}")
    console.print(f"Expires: {req.expires_at}")


@approval_app.command("list")
def approval_list() -> None:
    """List pending approvals."""
    _, _, _, _, _, _, approvals = build_components()
    rows = approvals.approvals.list_pending()
    table = Table("Approval", "Decision", "Action", "Channel", "Recipient", "Expires")
    for req in rows:
        table.add_row(str(req.id), str(req.decision_id), req.action_kind, req.channel, req.recipient or "-", req.expires_at)
    console.print(table)


@approval_app.command("approve")
def approval_approve(
    approval_id: int = typer.Argument(..., min=1),
    token: str = typer.Option(..., "--token"),
) -> None:
    """Approve exactly one persistent approval record."""
    try:
        _, scans, tasks, orchestrator, decisions, _, approvals = build_components()
        req = approvals.approve(approval_id, resolved_by="cli", token=token)
        decision = decisions.get(req.decision_id)
        if decision is None:
            raise ValueError(f"Approved decision #{req.decision_id} no longer exists")
        await orchestrator.start()
        task = await _queue_decision_execution(tasks, orchestrator, decision.id, decision.scan_id)
        await orchestrator.scheduler.queue.join()
        final_task = tasks.get(task.id)
    except Exception as exc:
        console.print(f"[red]Blocked:[/red] {exc}")
        raise typer.Exit(code=2)
    console.print(f"Approval #{req.id} → APPROVED (decision #{req.decision_id})")
    console.print(f"Execution task #{task.id} → {final_task.status}")


@approval_app.command("reject")
def approval_reject(
    approval_id: int = typer.Argument(..., min=1),
    token: str | None = typer.Option(None, "--token"),
) -> None:
    """Reject exactly one persistent approval record."""
    try:
        _, _, _, _, _, _, approvals = build_components()
        req = approvals.reject(approval_id, resolved_by="cli", token=token)
    except Exception as exc:
        console.print(f"[red]Blocked:[/red] {exc}")
        raise typer.Exit(code=2)
    console.print(f"Approval #{req.id} → REJECTED (decision #{req.decision_id})")


@app.command("whatsapp-webhook")
def whatsapp_webhook(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port", min=1, max=65535),
) -> None:
    """Serve the WhatsApp webhook adapter using environment configuration."""
    import os
    required = {
        "BELTU_WHATSAPP_VERIFY_TOKEN": os.getenv("BELTU_WHATSAPP_VERIFY_TOKEN", ""),
        "BELTU_WHATSAPP_APP_SECRET": os.getenv("BELTU_WHATSAPP_APP_SECRET", ""),
        "BELTU_WHATSAPP_CONTROLLER_NUMBERS": os.getenv("BELTU_WHATSAPP_CONTROLLER_NUMBERS", ""),
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        console.print(f"[red]Missing environment variables:[/red] {', '.join(missing)}")
        raise typer.Exit(code=2)
    _, _, _, _, _, _, approvals = build_components()
    handler = WhatsAppWebhookHandler(
        approvals,
        verify_token=required["BELTU_WHATSAPP_VERIFY_TOKEN"],
        app_secret=required["BELTU_WHATSAPP_APP_SECRET"],
        controller_numbers={x.strip() for x in required["BELTU_WHATSAPP_CONTROLLER_NUMBERS"].split(',') if x.strip()},
    )
    console.print(f"WhatsApp webhook listening on {host}:{port}")
    serve_whatsapp(handler, host, port)


@app.command("business-workflows")
def business_workflows(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show passive business-workflow/state-machine intelligence."""
    try:
        _, _, _, _, _, _, _ = build_components()
        db_path, _ = paths()
        service = BusinessLogicIntelligenceService(Database(db_path))
        result = service.rebuild(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    table = Table("Workflow", "States", "Transitions", "Anomalies", "High")
    for workflow in result.workflows:
        states = len(service.repo.list_states(workflow.id))
        transitions = sum(1 for t in result.transitions if t.workflow_id == workflow.id)
        anomalies = sum(1 for a in result.anomalies if a.workflow_id == workflow.id)
        high = sum(1 for a in result.anomalies if a.workflow_id == workflow.id and a.severity == "high")
        table.add_row(workflow.workflow_key, str(states), str(transitions), str(anomalies), str(high))
    console.print(table)


@app.command("business-anomalies")
def business_anomalies(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show candidate business-logic/workflow inconsistencies."""
    try:
        db_path, _ = paths()
        repo = BusinessLogicIntelligenceService(Database(db_path)).repo
        rows = repo.list_anomalies(scan_id)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    table = Table("Severity", "Kind", "Workflow", "Confidence", "Statement", "Status")
    for row in rows:
        workflow = next((w.workflow_key for w in repo.list_workflows(scan_id) if w.id == row.workflow_id), str(row.workflow_id))
        table.add_row(row.severity, row.kind, workflow, f"{row.confidence:.2f}", row.statement, row.status)
    console.print(table)


@app.command("business-context")
def business_context(scan_id: int = typer.Argument(..., min=1)) -> None:
    """Show the business-logic context passed to reasoning."""
    try:
        db_path, _ = paths()
        payload = BusinessLogicIntelligenceService(Database(db_path)).context_payload(scan_id, limit=100)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)
    console.print(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True))


@app.command("resources")
def resources() -> None:
    """Show CPU/RAM/GPU/FreeToken telemetry and adaptive tool capacity."""
    governor = ResourceGovernor(
        2, 30, 30, 1, 0.5,
        freetoken_pid_file=Path.cwd() / "data" / "runtime" / "freetoken.pid",
        freetoken_url="http://127.0.0.1:8000",
        altar1_pid_file=Path.cwd() / "data" / "runtime" / "altar1.pid",
        altar1_activity_dir=Path.cwd() / "data" / "runtime" / "altar1.active",
        altar1_url="http://127.0.0.1:8001",
        gpu_vram_budget_percent=45,
    )
    snap = governor.snapshot()
    console.print(f"BELTU CPU: {snap.beltu_cpu_percent:.2f}% / 30% budget")
    console.print(f"BELTU RSS: {snap.beltu_memory_percent:.2f}% RAM / 30% budget")
    console.print(f"Host CPU: {snap.host_cpu_percent:.2f}% | Host RAM: {snap.host_memory_percent:.2f}%")
    console.print(f"Load(1m): {snap.load1:.2f} | CPUs: {snap.cpu_count}")
    if snap.gpu:
        console.print(
            f"GPU: {snap.gpu.name or 'NVIDIA'} | VRAM {snap.gpu.used_percent:.2f}% used | "
            f"FreeToken {snap.gpu.freetoken_percent:.2f}% | Altar-1 {snap.gpu.altar1_percent:.2f}%"
        )
    else:
        console.print("GPU: unavailable (nvidia-smi not detected or no GPU telemetry)")
    if snap.freetoken:
        console.print(
            f"FreeToken: {'reachable' if snap.freetoken.reachable else 'not reachable'} | "
            f"PID={snap.freetoken.pid or '-'} | model={snap.freetoken.model or '-'} | "
            f"backend={snap.freetoken.moe_backend or '-'}"
        )
    if snap.altar1:
        console.print(
            f"Altar-1: {'active' if snap.altar1.active else 'idle'} | "
            f"reachable={'yes' if snap.altar1.reachable else 'no'} | "
            f"PID={snap.altar1.pid or '-'} | model={snap.altar1.model or '-'}"
        )
    else:
        console.print("FreeToken: not configured/running")
    console.print(f"Adaptive process capacity: {governor.effective_capacity(snap)}")
    for tool in ("subfinder", "httpx", "nmap", "nuclei"):
        limit = governor.tool_runtime_limits(tool)
        console.print(f"{tool}: concurrency={limit.max_parallel_processes} threads={limit.thread_limit} ({limit.reason})")


@app.command("tools")
def tools_list() -> None:
    """List the allowlisted tool adapters and their risk/approval metadata."""
    _, _, _, _, _, tools, _ = build_components()
    table = Table("Tool", "Capability", "Risk", "Approval")
    for tool in tools.list():
        table.add_row(tool.name, tool.capability, tool.risk_level, "yes" if tool.requires_approval else "no")
    console.print(table)


@app.command("llm")
def llm_status() -> None:
    """Show local AI reasoning configuration without exposing secrets."""
    config = LLMConfig.from_project(Path.cwd())
    console.print(f"LLM reasoning: {'enabled' if config.enabled else 'disabled'}")
    console.print(f"Provider: {config.provider}")
    console.print(f"Model: {config.model}")
    console.print(f"Base URL: {config.base_url}")
    console.print(f"Local-only: {'yes' if config.local_only else 'no'}")
    console.print(f"Loopback endpoint: {'yes' if config.is_loopback else 'NO — BLOCKED'}")
    console.print(f"Streaming: {'yes' if config.stream else 'no'}")
    console.print(f"API key configured: {'yes' if config.api_key() else 'no'}")
    console.print(f"Fallback to heuristic: {'yes' if config.fallback_to_heuristic else 'no'}")


@app.command("doctor")
def doctor(strict: bool = typer.Option(False, "--strict", help="Return failure when any release check fails")) -> None:
    """Run static/configuration safety checks without contacting targets."""
    checks = run_audit(Path.cwd())
    table = Table("Check", "Status", "Detail")
    failed = sum(1 for check in checks if not check.ok)
    for check in checks:
        table.add_row(check.name, "PASS" if check.ok else "FAIL", check.detail)
    console.print(table)
    console.print(f"Release audit: {len(checks)-failed}/{len(checks)} passed")
    if strict and failed:
        raise typer.Exit(code=2)


@app.command("status")
def status() -> None:
    """Show active scans plus CPU/RAM/GPU/FreeToken resource state."""
    agent, scans, tasks, _, _, _, _ = build_components()
    all_targets = agent.targets.list_all()
    pending = tasks.list_runnable()
    governor = ResourceGovernor(
        2, 30, 30, 1, 0.5,
        freetoken_pid_file=Path.cwd() / "data" / "runtime" / "freetoken.pid",
        freetoken_url="http://127.0.0.1:8000",
        altar1_pid_file=Path.cwd() / "data" / "runtime" / "altar1.pid",
        altar1_activity_dir=Path.cwd() / "data" / "runtime" / "altar1.active",
        altar1_url="http://127.0.0.1:8001",
        gpu_vram_budget_percent=45,
    )
    snap = governor.snapshot()
    console.print(f"BELTU {__version__} — Agent Core + Multi-Model Brain + Adaptive Execution + Mobile Control")
    console.print(f"Registered targets: {len(all_targets)}")
    console.print(f"Resumable scans: {len(scans.list_resumable())}")
    console.print(f"Runnable tasks: {len(pending)}")
    active = [item for item in scans.list_resumable() if item.status == "running"]
    if active:
        table = Table("Scan", "Target ID", "Status", "Updated")
        for item in active[:10]:
            table.add_row(f"#{item.id}", str(item.target_id), item.status, item.updated_at)
        console.print(table)
    console.print(f"CPU split: BELTU {snap.beltu_cpu_percent:.2f}% | Host {snap.host_cpu_percent:.2f}% | budget 30%")
    console.print(f"RAM split: BELTU RSS {snap.beltu_memory_percent:.2f}% | Host {snap.host_memory_percent:.2f}% | budget 30%")
    if snap.gpu:
        console.print(f"GPU split: {snap.gpu.name or 'NVIDIA'} VRAM {snap.gpu.used_percent:.2f}% | FreeToken {snap.gpu.freetoken_percent:.2f}%")
    else:
        console.print("GPU split: unavailable (nvidia-smi not present)")
    if snap.freetoken:
        console.print(f"FreeToken: {'ONLINE' if snap.freetoken.reachable else 'OFFLINE'} | model={snap.freetoken.model or '-'} | pid={snap.freetoken.pid or '-'} | backend={snap.freetoken.moe_backend or '-'}")
    else:
        console.print("FreeToken: not configured/running")
    console.print(f"Adaptive process capacity: {governor.effective_capacity(snap)}")
    console.print(f"Scope file: {agent.scope.scope_file}")
    external_tools = bool(load_agent_config().get("execution", {}).get("external_tools_enabled", False))
    llm_config = LLMConfig.from_project(Path.cwd())
    console.print(f"External tool autonomy: {'enabled' if external_tools else 'disabled'}; approvals remain enforced")
    console.print(f"LLM reasoning: {'enabled' if llm_config.enabled else 'disabled'} ({llm_config.provider}/{llm_config.model})")


@app.command("remote")
def remote(
    host: str = typer.Option(None, "--host"),
    port: int = typer.Option(None, "--port", min=1, max=65535),
) -> None:
    """Launch the authenticated Mobile Command Center / Remote Operations gateway."""
    import os
    from beltu.remote.server import serve
    final_host = host or os.getenv("BELTU_REMOTE_HOST", "127.0.0.1")
    final_port = port or int(os.getenv("BELTU_REMOTE_PORT", "8765"))
    try:
        from beltu.remote.app import _auth_from_env
        _auth_from_env()
    except Exception as exc:
        console.print(f"[red]Remote auth is not ready:[/red] {exc}")
        console.print("Set BELTU_REMOTE_USER, BELTU_REMOTE_PASSWORD and a 32+ character BELTU_REMOTE_SECRET.")
        raise typer.Exit(code=2)
    console.print(f"BELTU Remote Operations listening on {final_host}:{final_port}")
    try:
        serve(host=final_host, port=final_port, project_root=str(Path.cwd()))
    except KeyboardInterrupt:
        console.print("Remote gateway stopped.")


@app.command("remote-doctor")
def remote_doctor() -> None:
    """Validate remote authentication configuration without starting the gateway."""
    from beltu.remote.app import _auth_from_env
    try:
        auth = _auth_from_env()
    except Exception as exc:
        console.print(f"Remote auth: [red]not ready[/red] — {exc}")
        raise typer.Exit(code=2)
    console.print(f"Remote auth: configured (user={auth.username})")
    console.print(f"Remote bind: {__import__('os').environ.get('BELTU_REMOTE_HOST', '127.0.0.1')}:{__import__('os').environ.get('BELTU_REMOTE_PORT', '8765')}")
    console.print(f"Mobile files root: {(Path.cwd() / 'data' / 'targets').resolve()}")


if __name__ == "__main__":
    app()
