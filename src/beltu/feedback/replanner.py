from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from beltu.brain.context_builder import ContextBuilder
from beltu.brain.decision_engine import DecisionEngine
from beltu.brain.hypothesis_engine import HeuristicHypothesisEngine
from beltu.brain.planner import Planner
from beltu.brain.prioritizer import HypothesisPrioritizer
from beltu.brain.reasoning_engine import HybridReasoningEngine, ReasoningEngine, ReasoningProposalSet
from beltu.brain.schemas import AgentContext
from beltu.common.types import Event, Task
from beltu.core.event_bus import EventBus
from beltu.feedback.models import ReasoningCycle
from beltu.feedback.repository import ReasoningCycleRepository
from beltu.storage.models.brain import Hypothesis
from beltu.storage.repositories.decision_repository import DecisionRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.task_repository import TaskRepository
from beltu.storage.repositories.llm_run_repository import LLMRunRepository
from beltu.storage.repositories.capability_selection_repository import CapabilitySelectionRepository
from beltu.selection.engine import IntelligentCapabilitySelector


@dataclass(frozen=True, slots=True)
class ReplanResult:
    cycle: ReasoningCycle
    hypothesis_ids: tuple[int, ...] = ()
    superseded_hypothesis_ids: tuple[int, ...] = ()
    decision_ids: tuple[int, ...] = ()
    superseded_decision_ids: tuple[int, ...] = ()
    queued_task_ids: tuple[int, ...] = ()
    skipped_action_kinds: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def as_payload(self) -> dict[str, Any]:
        return {
            "cycle_id": self.cycle.id,
            "hypothesis_ids": list(self.hypothesis_ids),
            "superseded_hypothesis_ids": list(self.superseded_hypothesis_ids),
            "decision_ids": list(self.decision_ids),
            "superseded_decision_ids": list(self.superseded_decision_ids),
            "queued_task_ids": list(self.queued_task_ids),
            "skipped_action_kinds": list(self.skipped_action_kinds),
            "notes": list(self.notes),
        }


def action_fingerprint(action_kind: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"action_kind": action_kind, "payload": payload},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def context_fingerprint(context: AgentContext) -> str:
    observations = [
        {
            "id": item["id"],
            "kind": item["kind"],
            "subject": item["subject"],
            "data": item["data"],
            "source": item["source"],
            "confidence": item["confidence"],
        }
        for item in context.observations
    ]
    canonical = json.dumps(
        {"scan_id": context.scan_id, "target": context.target, "observations": observations},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


class AutonomousReplanner:
    """Reconcile new evidence with prior reasoning and create only non-duplicate next steps.

    The replanner is bounded and policy-aware: it can auto-queue only low-risk,
    non-approval decisions. Medium/high-risk decisions remain for the Control Plane.
    """

    def __init__(
        self,
        *,
        context_builder: ContextBuilder,
        observations: ObservationRepository,
        hypotheses: HypothesisRepository,
        decisions: DecisionRepository,
        tasks: TaskRepository,
        cycles: ReasoningCycleRepository,
        events: EventBus | None = None,
        hypothesis_engine: HeuristicHypothesisEngine | None = None,
        prioritizer: HypothesisPrioritizer | None = None,
        planner: Planner | None = None,
        decision_engine: DecisionEngine | None = None,
        reasoning_engine: ReasoningEngine | None = None,
        llm_runs: LLMRunRepository | None = None,
        capability_selector: IntelligentCapabilitySelector | None = None,
        selections: CapabilitySelectionRepository | None = None,
        max_cycles_per_scan: int = 20,
        max_auto_tasks_per_cycle: int = 2,
        auto_execute_low_risk: bool = True,
        enqueue_task: Callable[[Task], Awaitable[None]] | None = None,
    ) -> None:
        self.context_builder = context_builder
        self.observations = observations
        self.hypotheses = hypotheses
        self.decisions = decisions
        self.tasks = tasks
        self.cycles = cycles
        self.events = events
        self.hypothesis_engine = hypothesis_engine or HeuristicHypothesisEngine()
        self.prioritizer = prioritizer or HypothesisPrioritizer()
        self.planner = planner or Planner()
        self.decision_engine = decision_engine or DecisionEngine()
        self.reasoning_engine = reasoning_engine
        self.llm_runs = llm_runs
        self.capability_selector = capability_selector
        self.selections = selections
        self.max_cycles_per_scan = max(1, max_cycles_per_scan)
        self.max_auto_tasks_per_cycle = max(0, max_auto_tasks_per_cycle)
        self.auto_execute_low_risk = auto_execute_low_risk
        self.enqueue_task = enqueue_task

    def install(self) -> None:
        if self.events is None:
            return
        self.events.subscribe_sync("task.succeeded", self._on_task_event)
        self.events.subscribe_sync("task.failed", self._on_task_event)

    async def _on_task_event(self, event: Event) -> None:
        task_id = event.payload.get("task_id")
        if not isinstance(task_id, int):
            return
        task = self.tasks.get(task_id)
        if task is None or task.kind != "capability.execute":
            return
        trigger = "task_succeeded" if event.type == "task.succeeded" else "task_failed"
        try:
            result = await self.replan(task.scan_id, trigger=trigger, trigger_task_id=task.id)
            if self.events is not None:
                await self.events.publish("replan.completed", result.as_payload())
        except Exception as exc:
            if self.events is not None:
                await self.events.publish("replan.failed", {"scan_id": task.scan_id, "task_id": task.id, "error": str(exc)})

    async def replan(self, scan_id: int, *, trigger: str, trigger_task_id: int) -> ReplanResult:
        context = self.context_builder.build(scan_id)
        fingerprint = context_fingerprint(context)
        existing = self.cycles.find_existing(scan_id, trigger, trigger_task_id, fingerprint)
        if existing is not None:
            return ReplanResult(existing, notes=("Duplicate feedback event ignored; identical context already processed.",))
        if self.cycles.count_for_scan(scan_id) >= self.max_cycles_per_scan:
            cycle = self.cycles.create(scan_id, trigger, trigger_task_id, fingerprint, status="skipped", summary={"reason": "cycle_budget_exhausted"})
            return ReplanResult(cycle, notes=("Per-scan reasoning cycle budget exhausted.",))

        cycle = self.cycles.create(scan_id, trigger, trigger_task_id, fingerprint)
        hypothesis_ids: list[int] = []
        superseded_hypothesis_ids: list[int] = []
        decision_ids: list[int] = []
        superseded_decision_ids: list[int] = []
        queued_task_ids: list[int] = []
        skipped_action_kinds: list[str] = []
        notes: list[str] = []

        try:
            if self.reasoning_engine is not None:
                reasoning = self.reasoning_engine.generate(context)
                proposals = list(reasoning.hypotheses)
                plans = list(reasoning.actions) if reasoning.actions else self.planner.plan(context, proposals)
                reasoning_source = reasoning.source
            else:
                proposals = self.prioritizer.rank(self.hypothesis_engine.generate(context))
                plans = self.planner.plan(context, proposals)
                reasoning_source = "heuristic"

            llm_run_id = None
            last_llm_run = getattr(self.reasoning_engine, "last_llm_run", None)
            if last_llm_run is not None and self.llm_runs is not None:
                run = self.llm_runs.create(
                    scan_id, cycle.id,
                    self.reasoning_engine.llm.provider.name if getattr(self.reasoning_engine, "llm", None) is not None else "unknown",
                    self.reasoning_engine.llm.provider.model if getattr(self.reasoning_engine, "llm", None) is not None else "unknown",
                    "succeeded" if last_llm_run.ok else "failed",
                    last_llm_run.prompt_sha256, last_llm_run.response_sha256, last_llm_run.latency_ms,
                    last_llm_run.raw_text, last_llm_run.error,
                )
                llm_run_id = run.id
                if not last_llm_run.ok and last_llm_run.error:
                    notes.append(f"LLM reasoning failed; fallback source={reasoning_source}: {last_llm_run.error}")

            current_keys = {(p.statement.strip(), tuple(sorted(p.basis_observation_ids))) for p in proposals}
            persisted_by_key: dict[tuple[str, tuple[int, ...]], Hypothesis] = {}
            previous_hypotheses = self.hypotheses.list_for_scan(scan_id)
            for old in previous_hypotheses:
                key = (old.statement.strip(), tuple(sorted(old.basis_observation_ids)))
                if key not in current_keys and old.status not in {"superseded", "rejected"}:
                    self.hypotheses.update_status(old.id, "superseded")
                    superseded_hypothesis_ids.append(old.id)
                    await self._publish("hypothesis.superseded", {"scan_id": scan_id, "hypothesis_id": old.id})
                    for old_decision in self.decisions.list_for_hypothesis(old.id):
                        if old_decision.status in {"accepted", "pending_approval", "approved", "queued"}:
                            self.decisions.supersede(old_decision.id, "Underlying hypothesis was superseded by new evidence")
                            superseded_decision_ids.append(old_decision.id)
                            self.tasks.cancel_pending_for_decision(scan_id, old_decision.id)
                            await self._publish("decision.superseded", {"scan_id": scan_id, "decision_id": old_decision.id, "hypothesis_id": old.id})

            for proposal in proposals:
                key = (proposal.statement.strip(), tuple(sorted(proposal.basis_observation_ids)))
                existing_hyp = next((h for h in previous_hypotheses if (h.statement.strip(), tuple(sorted(h.basis_observation_ids))) == key), None)
                if existing_hyp is None:
                    hyp = self.hypotheses.create(
                        scan_id, proposal.statement, proposal.basis_observation_ids, proposal.confidence,
                    )
                else:
                    hyp = self.hypotheses.update_status(existing_hyp.id, "open", confidence=proposal.confidence)
                persisted_by_key[key] = hyp
                hypothesis_ids.append(hyp.id)

            for proposal in plans:
                selected = self.capability_selector.select_for_action(context, proposal) if self.capability_selector is not None else None
                if selected is not None and selected.selected is not None:
                    chosen = selected.selected
                    payload = dict(proposal.action_payload)
                    payload["capability"] = chosen.profile.name
                    if chosen.tool is not None:
                        payload["tool"] = chosen.tool
                    rationale = proposal.rationale + f" Capability selection: {chosen.rationale}"
                    risk_order = {"low": 0, "medium": 1, "high": 2}
                    selected_risk = max((proposal.risk_level, chosen.profile.risk_level), key=lambda value: risk_order[value])
                    proposal = type(proposal)(proposal.action_kind, payload, rationale, proposal.confidence, selected_risk, proposal.requires_approval or chosen.profile.requires_approval)
                elif selected is not None and selected.selected is None:
                    skipped_action_kinds.append(proposal.action_kind)
                    notes.append(f"No capability matched action: {proposal.action_kind}")
                    continue
                result = self.decision_engine.evaluate(proposal, expected_target=context.target)
                if not result.accepted:
                    skipped_action_kinds.append(proposal.action_kind)
                    notes.append(f"Rejected by DecisionEngine: {proposal.action_kind}: {result.reason}")
                    continue
                fp = action_fingerprint(proposal.action_kind, proposal.action_payload)
                prior = self.decisions.find_by_action_fingerprint(scan_id, fp)
                if prior is not None and prior.status != "superseded":
                    skipped_action_kinds.append(proposal.action_kind)
                    notes.append(f"Existing decision suppressed: {proposal.action_kind} (status={prior.status})")
                    continue
                hyp_key = (
                    str(proposal.action_payload.get("hypothesis", "")).strip(),
                    tuple(sorted(proposal.action_payload.get("basis_observation_ids", ())))
                )
                hypothesis = next(
                    (h for key, h in persisted_by_key.items() if key[0] == str(proposal.action_payload.get("hypothesis", "")).strip()),
                    None,
                )
                decision = self.decisions.create(
                    scan_id,
                    hypothesis.id if hypothesis else None,
                    proposal.action_kind,
                    proposal.action_payload,
                    proposal.rationale,
                    proposal.confidence,
                    proposal.risk_level,
                    proposal.requires_approval,
                    result.status,
                    cycle_id=cycle.id,
                    action_fingerprint=fp,
                )
                decision_ids.append(decision.id)
                if selected is not None and selected.selected is not None and self.selections is not None:
                    self.selections.record(
                        scan_id, cycle.id, decision.id, selected.selected.profile.name,
                        selected.selected.tool, selected.selected.score,
                        selected.selected.expected_information_gain, selected.selected.cost,
                        selected.selected.profile.risk_level, selected.selected.rationale,
                        [candidate.as_dict() for candidate in selected.candidates],
                    )
                await self._publish("decision.created", {"scan_id": scan_id, "decision_id": decision.id, "action": decision.action_kind, "cycle_id": cycle.id})

                if proposal.requires_approval or proposal.risk_level != "low" or not self.auto_execute_low_risk:
                    continue
                if len(queued_task_ids) >= self.max_auto_tasks_per_cycle:
                    notes.append("Per-cycle auto-task budget reached.")
                    continue
                if self.tasks.has_task_for_decision(scan_id, decision.id):
                    continue
                task = self.tasks.create(
                    scan_id,
                    "capability.execute",
                    {"decision_id": decision.id, "reasoning_cycle_id": cycle.id},
                    priority=max(50, int(proposal.confidence * 100)),
                    max_attempts=2,
                )
                self.decisions.set_status(decision.id, "queued")
                queued_task_ids.append(task.id)
                await self._publish("decision.queued", {"scan_id": scan_id, "decision_id": decision.id, "task_id": task.id, "cycle_id": cycle.id})
                if self.enqueue_task is not None:
                    await self.enqueue_task(task)
                if self.events is not None:
                    await self.events.publish("feedback.execution_requested", {"task_id": task.id, "scan_id": scan_id, "decision_id": decision.id})

            summary = {
                "trigger": trigger,
                "context_fingerprint": fingerprint,
                "observations": len(context.observations),
                "hypotheses_created_or_refreshed": len(hypothesis_ids),
                "hypotheses_superseded": len(superseded_hypothesis_ids),
                "decisions_created": len(decision_ids),
                "decisions_superseded": len(superseded_decision_ids),
                "tasks_queued": len(queued_task_ids),
                "max_cycles_per_scan": self.max_cycles_per_scan,
                "reasoning_source": reasoning_source,
                "llm_run_id": llm_run_id,
            }
            done = self.cycles.complete(cycle.id, status="succeeded", summary=summary)
            return ReplanResult(
                done,
                tuple(hypothesis_ids), tuple(superseded_hypothesis_ids), tuple(decision_ids),
                tuple(superseded_decision_ids), tuple(queued_task_ids), tuple(skipped_action_kinds), tuple(notes),
            )
        except Exception as exc:
            failed = self.cycles.complete(cycle.id, status="failed", summary={"error": str(exc)})
            raise RuntimeError(f"Reasoning cycle #{cycle.id} failed: {exc}") from exc

    async def _publish(self, event_type: str, payload: dict[str, Any]) -> None:
        if self.events is not None:
            await self.events.publish(event_type, payload)
