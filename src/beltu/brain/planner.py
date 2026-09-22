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
                    hypothesis.confidence, "low", False,
                ))
            elif "race" in text or "concurrency" in text or "duplicate submission" in text:
                actions.append(ActionProposal(
                    "race_condition_testing",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Test a bounded concurrent request only when workflow evidence suggests a race.",
                    hypothesis.confidence, "high", True,
                ))
            elif "authorization" in text or "permission" in text or "access control" in text:
                actions.append(ActionProposal(
                    "authorization_testing",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Compare explicitly supplied principals on the same operation before concluding an authorization boundary is weak.",
                    hypothesis.confidence, "high", True,
                ))
            elif "business logic" in text or "workflow" in text or "state transition" in text:
                actions.append(ActionProposal(
                    "business_logic_workflow",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Execute a bounded workflow with state assertions to validate business-rule behavior.",
                    hypothesis.confidence, "high", True,
                ))
            elif "session" in text or "replay" in text or "token" in text:
                actions.append(ActionProposal(
                    "session_replay",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Replay a bounded in-scope workflow using an explicitly supplied local session profile.",
                    hypothesis.confidence, "high", True,
                ))
            elif "parameter" in text or "tamper" in text:
                actions.append(ActionProposal(
                    "api_manipulation",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Apply a small set of controlled API parameter mutations against an identified operation.",
                    hypothesis.confidence, "high", True,
                ))
            elif "browser" in text or "ui" in text or "client-side" in text:
                actions.append(ActionProposal(
                    "browser_automation",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Use the bounded browser worker to exercise UI state and capture in-scope network metadata.",
                    hypothesis.confidence, "medium", True,
                ))
            elif "request" in text or "http" in text or "burp" in text:
                actions.append(ActionProposal(
                    "http_workflow",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Replay a bounded HTTP sequence with explicit assertions to reduce uncertainty.",
                    hypothesis.confidence, "medium", True,
                ))
            elif "web/api surface" in text or "routes" in text:
                actions.append(ActionProposal(
                    "endpoint_mapping",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Map routes/endpoints because the evidence indicates a web or API surface.",
                    hypothesis.confidence, "medium", True,
                ))
            elif "authentication" in text:
                actions.append(ActionProposal(
                    "auth_analysis",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Analyze authentication/session boundaries before deeper control testing.",
                    hypothesis.confidence, "medium", True,
                ))
            elif "api surface" in text:
                actions.append(ActionProposal(
                    "api_analysis",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Analyze API structure and control boundaries identified by observations.",
                    hypothesis.confidence, "medium", True,
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
                    hypothesis.confidence, "medium", True,
                ))
            else:
                actions.append(ActionProposal(
                    "surface_inventory",
                    {"target": context.target, "hypothesis": hypothesis.statement},
                    "Gather more structured evidence because the current evidence is insufficiently classified.",
                    hypothesis.confidence, "low", False,
                ))
        return actions
