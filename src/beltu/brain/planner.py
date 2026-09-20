from __future__ import annotations

from beltu.brain.schemas import ActionProposal, AgentContext, HypothesisProposal


class Planner:
    """Transforms hypotheses into declarative next-step proposals. No execution occurs here."""

    def plan(self, context: AgentContext, hypotheses: list[HypothesisProposal]) -> list[ActionProposal]:
        actions: list[ActionProposal] = []
        for hypothesis in hypotheses[:3]:
            text = hypothesis.statement.lower()
            if "not characterized" in text:
                actions.append(ActionProposal(
                    "surface_inventory",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Characterize the target before making specialized decisions.",
                    hypothesis.confidence,
                    "low",
                    False,
                ))
            elif "web/api surface" in text or "routes" in text:
                actions.append(ActionProposal(
                    "endpoint_mapping",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Map routes/endpoints because the evidence indicates a web or API surface.",
                    hypothesis.confidence,
                    "medium",
                    True,
                ))
            elif "authentication" in text or "session" in text:
                actions.append(ActionProposal(
                    "auth_analysis",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Analyze authentication/session boundaries before deeper control testing.",
                    hypothesis.confidence,
                    "medium",
                    True,
                ))
            elif "api surface" in text:
                actions.append(ActionProposal(
                    "api_analysis",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Analyze API structure and control boundaries identified by observations.",
                    hypothesis.confidence,
                    "medium",
                    True,
                ))
            elif "finding candidates" in text or ("validate" in text and "finding" in text):
                actions.append(ActionProposal(
                    "finding_validation",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Cross-check correlated finding candidates against stored evidence before any active validation.",
                    hypothesis.confidence, "medium", True,
                ))
            elif "authorization metadata" in text:
                actions.append(ActionProposal(
                    "access_control_analysis",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Focus analysis on authorization boundaries indicated by the evidence.",
                    hypothesis.confidence,
                    "medium",
                    True,
                ))
            else:
                actions.append(ActionProposal(
                    "surface_inventory",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Gather more structured evidence because the current evidence is insufficiently classified.",
                    hypothesis.confidence,
                    "low",
                    False,
                ))
        return actions
