from __future__ import annotations

from beltu.execution.capability_dispatcher import CapabilityDispatcher
from beltu.execution.models import ExecutionRequest, ExecutionResult
from beltu.control.approval_service import ApprovalService
from beltu.storage.repositories.decision_repository import DecisionRepository


class ExecutionService:
    """Turn a validated decision into a persisted execution request."""

    def __init__(self, decisions: DecisionRepository, dispatcher: CapabilityDispatcher, approvals: ApprovalService | None = None) -> None:
        self.decisions = decisions
        self.dispatcher = dispatcher
        self.approvals = approvals

    def request_from_decision(self, decision_id: int) -> ExecutionRequest:
        decision = self.decisions.get(decision_id)
        if decision is None:
            raise KeyError(f"Decision #{decision_id} not found")
        approval_verified = False
        if decision.requires_approval:
            if decision.status != "approved":
                raise PermissionError(f"Decision #{decision_id} requires explicit approval")
            if self.approvals is None or not self.approvals.has_valid_approved_decision(decision.id):
                raise PermissionError(f"Decision #{decision_id} has no validated approval")
            approval_verified = True
        elif decision.status not in {"accepted", "queued"}:
            raise ValueError(f"Decision #{decision_id} is not executable from status {decision.status!r}")

        payload = dict(decision.action_payload)
        target = str(payload.pop("target", "")).strip()
        if not target:
            raise ValueError(f"Decision #{decision_id} has no target")
        mapped = self._map_action(decision.action_kind)
        requested = payload.pop("capability", None)
        capability = str(requested) if requested else mapped
        allowed_by_action = {
            "surface_inventory": {"asset.discovery.subdomains"},
            "service_enrichment": {"service.discovery"},
            "endpoint_mapping": {"web.verify", "browser.automation", "http.workflow"},
            "api_analysis": {"web.verify", "offline.api.structure_analysis"},
            "auth_analysis": {"web.verify", "offline.auth.surface_analysis", "session.replay", "browser.automation"},
            "access_control_analysis": {"web.verify", "offline.access_control.surface_analysis", "authorization.interactive"},
            "business_logic_analysis": {"web.verify", "offline.business_logic.workflow_analysis", "business_logic.workflow"},
            "finding_validation": {"web.vulnerability_detection", "offline.finding.validation", "api.manipulation"},
            "browser_automation": {"browser.automation"},
            "http_workflow": {"http.workflow"},
            "session_replay": {"session.replay"},
            "api_manipulation": {"api.manipulation"},
            "authorization_testing": {"authorization.interactive"},
            "business_logic_workflow": {"business_logic.workflow"},
            "race_condition_testing": {"race_condition.test"},
        }
        if capability not in allowed_by_action.get(decision.action_kind, set()):
            raise ValueError(f"Capability {capability!r} is incompatible with action {decision.action_kind!r}")
        return ExecutionRequest(decision.scan_id, target, capability, payload, approval_verified=approval_verified)

    @staticmethod
    def _map_action(action_kind: str) -> str:
        mapping = {
            "surface_inventory": "asset.discovery.subdomains",
            "service_enrichment": "service.discovery",
            "endpoint_mapping": "web.verify",
            "api_analysis": "web.verify",
            "auth_analysis": "web.verify",
            "access_control_analysis": "web.verify",
            "business_logic_analysis": "web.verify",
            "finding_validation": "web.vulnerability_detection",
            "browser_automation": "browser.automation",
            "http_workflow": "http.workflow",
            "session_replay": "session.replay",
            "api_manipulation": "api.manipulation",
            "authorization_testing": "authorization.interactive",
            "business_logic_workflow": "business_logic.workflow",
            "race_condition_testing": "race_condition.test",
        }
        try:
            return mapping[action_kind]
        except KeyError as exc:
            raise ValueError(f"No capability mapping for action: {action_kind}") from exc

    async def execute_decision(self, decision_id: int) -> ExecutionResult:
        request = self.request_from_decision(decision_id)
        return await self.dispatcher.execute(request)
