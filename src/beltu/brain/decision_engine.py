from __future__ import annotations

from beltu.brain.schemas import ALLOWED_ACTIONS, DecisionResult, ActionProposal, RISK_LEVELS


class DecisionEngine:
    """Validates planner output before an execution layer can consume it."""

    def evaluate(self, proposal: ActionProposal, *, expected_target: str | None = None) -> DecisionResult:
        if proposal.action_kind not in ALLOWED_ACTIONS:
            return DecisionResult(False, "rejected", "Unknown action kind", proposal)
        if proposal.risk_level not in RISK_LEVELS:
            return DecisionResult(False, "rejected", "Invalid risk level", proposal)
        if not 0.0 <= proposal.confidence <= 1.0:
            return DecisionResult(False, "rejected", "Invalid confidence", proposal)
        target = proposal.action_payload.get("target")
        if not isinstance(target, str) or not target.strip():
            return DecisionResult(False, "rejected", "Action target is required", proposal)
        if expected_target is not None and target != expected_target:
            return DecisionResult(False, "rejected", "Action target does not match the current scan target", proposal)
        if proposal.risk_level == "high" and not proposal.requires_approval:
            return DecisionResult(False, "rejected", "High-risk actions must require approval", proposal)
        status = "approval_required" if proposal.requires_approval else "accepted"
        return DecisionResult(True, status, "Policy/schema checks passed", proposal)
