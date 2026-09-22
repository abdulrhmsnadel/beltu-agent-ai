from __future__ import annotations

from beltu.brain.schemas import AgentContext, HypothesisProposal


class HeuristicHypothesisEngine:
    """Deterministic offline reasoning baseline; later an LLM can augment proposals."""

    def generate(self, context: AgentContext) -> list[HypothesisProposal]:
        obs = context.observations
        kinds = {item["kind"] for item in obs}
        proposals: list[HypothesisProposal] = []

        finding_surface = context.finding_surface if isinstance(context.finding_surface, dict) else {}
        finding_items = finding_surface.get("findings", []) if isinstance(finding_surface, dict) else []

        if not obs and not finding_items:
            return [
                HypothesisProposal(
                    "The attack surface is not characterized yet; an inventory pass is required.",
                    (),
                    0.99,
                )
            ]

        endpoint_ids = tuple(item["id"] for item in obs if item["kind"] in {"endpoint", "api_endpoint"})
        if endpoint_ids:
            proposals.append(
                HypothesisProposal(
                    "A web/API surface exists and should be mapped before deeper analysis.",
                    endpoint_ids,
                    0.88,
                )
            )

        auth_ids = tuple(item["id"] for item in obs if item["kind"] in {"login", "auth", "session"})
        if auth_ids:
            proposals.append(
                HypothesisProposal(
                    "Authentication or session behavior is present and may affect later control analysis.",
                    auth_ids,
                    0.84,
                )
            )

        api_ids = tuple(item["id"] for item in obs if item["kind"] in {"api", "api_endpoint", "openapi"})
        if api_ids:
            proposals.append(
                HypothesisProposal(
                    "An API surface is present; API-specific analysis can reduce uncertainty about control boundaries.",
                    api_ids,
                    0.86,
                )
            )

        access_ids = tuple(item["id"] for item in obs if item["kind"] in {"access_control", "role", "authorization"})
        if access_ids:
            proposals.append(
                HypothesisProposal(
                    "Authorization metadata is available and warrants focused access-control analysis.",
                    access_ids,
                    0.82,
                )
            )

        authz = context.authorization_surface if isinstance(context.authorization_surface, dict) else {}
        authz_anomalies = authz.get("anomalies", []) if isinstance(authz, dict) else []
        if authz_anomalies:
            anomaly_ids = tuple(int(item["id"]) for item in authz_anomalies[:20] if isinstance(item, dict) and str(item.get("id", "")).isdigit())
            basis = anomaly_ids if anomaly_ids else access_ids
            proposals.append(
                HypothesisProposal(
                    "Stored authorization evidence contains boundary inconsistencies that require validation before stronger conclusions can be made.",
                    basis,
                    0.87,
                )
            )

        workflow_summary = context.business_logic_surface.get("summary", {}) if isinstance(context.business_logic_surface, dict) else {}
        if isinstance(workflow_summary, dict) and int(workflow_summary.get("workflows", 0) or 0) > 0:
            proposals.append(HypothesisProposal(
                "Business-logic workflows are modeled and may require active state-transition validation.",
                tuple(item["id"] for item in obs if item["kind"] in {"workflow", "state_transition", "order", "cart"}),
                0.83,
            ))

        authz_summary = context.authorization_surface.get("summary", {}) if isinstance(context.authorization_surface, dict) else {}
        if isinstance(authz_summary, dict) and int(authz_summary.get("anomalies", 0) or 0) > 0:
            proposals.append(HypothesisProposal(
                "Authorization anomalies are present and may require an interactive principal-to-operation comparison.",
                access_ids,
                0.86,
            ))

        if any(item["kind"] in {"api_endpoint", "openapi"} for item in obs):
            proposals.append(HypothesisProposal(
                "API operations are available for bounded parameter manipulation and response-difference analysis.",
                api_ids,
                0.80,
            ))

        if auth_ids:
            proposals.append(HypothesisProposal(
                "A local session replay workflow could test whether authenticated behavior remains consistent across selected requests.",
                auth_ids,
                0.77,
            ))

        if finding_items:
            ids = tuple(int(item["id"]) for item in finding_items[:10] if isinstance(item, dict) and str(item.get("id", "")).isdigit())
            proposals.append(HypothesisProposal(
                "Correlated finding candidates exist and should be validated against their linked evidence before stronger conclusions are made.",
                ids, 0.91,
            ))

        if "technology" in kinds and not endpoint_ids:
            tech_ids = tuple(item["id"] for item in obs if item["kind"] == "technology")
            proposals.append(
                HypothesisProposal(
                    "Technology fingerprints exist, but application routes remain insufficiently mapped.",
                    tech_ids,
                    0.76,
                )
            )

        if not proposals:
            ids = tuple(item["id"] for item in obs)
            proposals.append(
                HypothesisProposal(
                    "Additional surface classification is needed before specialized analysis can be selected.",
                    ids,
                    0.65,
                )
            )

        return proposals
