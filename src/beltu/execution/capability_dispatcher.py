from __future__ import annotations

from beltu.brain.observation_pipeline import ObservationPipeline
from beltu.brain.observer import Observer
from beltu.analysis.correlator import ObservationCorrelator
from beltu.brain.schemas import ObservationInput
from beltu.execution.models import ExecutionRequest, ExecutionResult
from beltu.execution.process_manager import ProcessManager
from beltu.execution.registry.capability_registry import CapabilityRegistry
from beltu.execution.resource_governor import ResourceGovernor
from beltu.policy.scope_guard import ScopeGuard
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.evidence_repository import EvidenceRepository
from beltu.storage.repositories.observation_link_repository import ObservationLinkRepository
from beltu.evidence.collector import EvidenceCollector
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository


class CapabilityDispatcher:
    """Resolve a semantic capability, enforce policy/resources, then execute it."""

    def __init__(
        self,
        scope: ScopeGuard,
        registry: CapabilityRegistry,
        process_manager: ProcessManager,
        governor: ResourceGovernor,
        observations: ObservationRepository,
        scans: ScanRepository,
        targets: TargetRepository,
        evidence: EvidenceRepository | None = None,
        links: ObservationLinkRepository | None = None,
        evidence_root: str = "data/evidence",
    ) -> None:
        self.scope = scope
        self.registry = registry
        self.process_manager = process_manager
        self.governor = governor
        self.observations = observations
        self.scans = scans
        self.targets = targets
        self.evidence = evidence
        self.links = links
        self.evidence_collector = EvidenceCollector(evidence, evidence_root) if evidence is not None else None

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        normalized = request.target.strip()
        if not normalized:
            raise ValueError("Execution target cannot be empty")
        scan = self.scans.get(request.scan_id)
        if scan is None:
            raise ValueError(f"Scan #{request.scan_id} not found")
        target = self.targets.get(scan.target_id)
        if target is None or target.value.strip().lower() != normalized.lower():
            raise ValueError("Execution target does not match the scan's registered target")
        adapter = self.registry.resolve(request.capability, request.options.get("tool"))
        if adapter.requires_approval and not request.approval_verified:
            raise PermissionError(
                f"Capability {request.capability!r} via {adapter.name!r} requires explicit approval"
            )
        limits = self.governor.tool_runtime_limits(adapter.name)
        runtime_options = dict(request.options)
        runtime_options["_runtime_limits"] = {
            "thread_limit": limits.thread_limit,
            "max_parallel_processes": limits.max_parallel_processes,
            "affinity_cpus": list(limits.affinity_cpus),
            "reason": getattr(limits, "reason", ""),
        }
        effective_request = ExecutionRequest(
            request.scan_id,
            normalized,
            request.capability,
            runtime_options,
            approval_verified=request.approval_verified,
        )
        argv: list[str] = []
        before = None
        try:
            argv = adapter.build_argv(effective_request)
            before = await self.governor.acquire_process()
            proc = await self.process_manager.run(
                argv,
                adapter.timeout_seconds,
                resource_before=before,
                resource_monitor=self.governor.monitor,
                resource_governor=self.governor,
                tool_name=adapter.name,
            )
            parsed = adapter.parse_output(effective_request, proc.stdout, proc.stderr)
        finally:
            if before is not None:
                self.governor.release_process()
            adapter.cleanup_argv(argv)

        evidence_ids: list[int] = []
        if self.evidence_collector is not None:
            out_ev = self.evidence_collector.collect_text(
                request.scan_id, None, "tool.stdout", proc.stdout,
                metadata={"tool": adapter.name, "argv": list(proc.argv), "returncode": proc.returncode},
            )
            evidence_ids.append(out_ev.id)
            if proc.stderr:
                err_ev = self.evidence_collector.collect_text(
                    request.scan_id, None, "tool.stderr", proc.stderr,
                    metadata={"tool": adapter.name, "argv": list(proc.argv), "returncode": proc.returncode},
                )
                evidence_ids.append(err_ev.id)
        observer = Observer(self.observations, self.scans, self.targets)
        correlator = ObservationCorrelator(self.links) if self.links is not None else None
        if correlator is not None:
            stored = ObservationPipeline(observer, correlator).ingest(
                request.scan_id,
                [ObservationInput(item["kind"], item["subject"], item.get("data", {}), item["source"], item.get("confidence", 0.5)) for item in parsed],
                evidence_ids=tuple(evidence_ids),
            )
        else:
            stored = []
            for item in parsed:
                stored.append(observer.ingest(
                    request.scan_id,
                    ObservationInput(item["kind"], item["subject"], item.get("data", {}), item["source"], item.get("confidence", 0.5)),
                ))
        del stored
        return ExecutionResult(
            request=request,
            tool=adapter.name,
            argv=proc.argv,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_seconds=proc.duration_seconds,
            timed_out=proc.timed_out,
            observations=tuple(parsed),
            resource_before=proc.resource_before,
            resource_after=proc.resource_after,
            evidence_ids=tuple(evidence_ids),
        )
