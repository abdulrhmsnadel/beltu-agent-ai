from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from beltu.brain.llm.provider import (
    Altar1LocalProvider,
    Altar1RequestProfile,
    CloudSanitizationError,
    DisabledLLMProvider,
    GeminiCloudError,
    GeminiCloudProvider,
    GeminiRateLimitError,
    GeminiSafetyBlockedError,
    LLMProvider,
)
from beltu.brain.schemas import AgentContext


RouteName = Literal["standard", "altar1"]
GeminiDecision = Literal["continue", "retry", "correct", "escalate_to_deep_review", "stop_escalation", "observe"]


@dataclass(frozen=True, slots=True)
class RouteDecision:
    route: RouteName
    score: float
    reasons: tuple[str, ...]
    profile: Altar1RequestProfile | None = None
    gemini_mode: str = "monitor"


@dataclass(frozen=True, slots=True)
@dataclass(frozen=True, slots=True)
class GeminiSuggestion:
    kind: str
    instruction: str
    reason: str
    capability: str | None = None
    confidence: float = 0.5


@dataclass(frozen=True, slots=True)
class GeminiAdvice:
    decision: GeminiDecision
    confidence: float
    reason: str
    focus: str
    recommended_capability: str | None
    notes: tuple[str, ...] = ()
    suggestions: tuple[GeminiSuggestion, ...] = ()
    alternative_hypotheses: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    status: str = "ok"


@dataclass(frozen=True, slots=True)
class RoutedCompletion:
    text: str
    latency_ms: float
    provider_name: str
    model: str
    decision: RouteDecision
    gemini_advice: GeminiAdvice | None = None
    altar_review: str | None = None
    trace: dict[str, Any] | None = None


class LLMRouter:
    """Classify BELTU contexts and route specialized work to Altar-1.

    Routing is deterministic and context-driven. General reconnaissance and raw
    tool output stay on the standard local model. Code review, exploit-proof
    generation/review, and authorization-matrix anomaly verification go to
    Altar-1 when that node is enabled. A disabled/unavailable Altar node does not
    create a cloud fallback; the caller can use the normal heuristic fallback.
    """

    _CODE_REVIEW = re.compile(
        r"\b(?:code[ _-]?review|source[ _-]?review|static[ _-]?analysis|secure[ _-]?code|patch[ _-]?review|code[ _-]?audit|source[ _-]?audit)\b",
        re.I,
    )
    _EXPLOIT_PROOF = re.compile(
        r"\b(?:exploit[ _-]?proof|proof[ _-]?of[ _-]?concept|poc|reproduction|repro[ _-]?case|exploit[ _-]?validation|vuln(?:erability)?[ _-]?proof)\b",
        re.I,
    )
    _AUTHZ_MATRIX = re.compile(
        r"\b(?:authorization[ _-]?matrix|access[ _-]?control[ _-]?matrix|permission[ _-]?matrix|authz[ _-]?matrix|role[ _-]?permission|privilege[ _-]?matrix|authorization[ _-]?anomal(?:y|ies)|authz[ _-]?anomal(?:y|ies))\b",
        re.I,
    )
    _RECON = re.compile(
        r"\b(?:recon|reconnaissance|subdomain|asset[ _-]?discovery|http[ _-]?probe|tool[ _-]?output|nmap|nuclei|subfinder|httpx|endpoint[ _-]?mapping|service[ _-]?discovery)\b",
        re.I,
    )

    def __init__(
        self,
        standard_provider: LLMProvider | None = None,
        altar_provider: Altar1LocalProvider | None = None,
        gemini_provider: GeminiCloudProvider | None = None,
        *,
        enabled: bool = True,
    ) -> None:
        self.standard_provider = standard_provider or DisabledLLMProvider()
        self.altar_provider = altar_provider or DisabledLLMProvider()  # type: ignore[assignment]
        self.gemini_provider = gemini_provider or DisabledLLMProvider()  # type: ignore[assignment]
        self.enabled = enabled
        self.last_decision: RouteDecision | None = None
        self.last_advice: GeminiAdvice | None = None
        self.last_trace: dict[str, Any] = {}

    def available(self) -> bool:
        providers = (self.standard_provider, self.altar_provider, self.gemini_provider)
        return self.enabled and any(not isinstance(p, DisabledLLMProvider) for p in providers)

    @staticmethod
    def _flatten_values(value: Any) -> list[str]:
        out: list[str] = []
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            for key, item in value.items():
                out.append(str(key))
                out.extend(LLMRouter._flatten_values(item))
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                out.extend(LLMRouter._flatten_values(item))
        elif value is not None:
            out.append(str(value))
        return out

    @classmethod
    def _context_text(cls, context: AgentContext) -> str:
        pieces: list[str] = [context.target]
        pieces.extend(cls._flatten_values(context.observations))
        pieces.extend(cls._flatten_values(context.known_hypotheses))
        pieces.extend(cls._flatten_values(context.api_surface))
        pieces.extend(cls._flatten_values(context.auth_surface))
        pieces.extend(cls._flatten_values(context.authorization_surface))
        pieces.extend(cls._flatten_values(context.business_logic_surface))
        pieces.extend(cls._flatten_values(context.finding_surface))
        pieces.extend(cls._flatten_values(context.surface_priorities))
        return " ".join(pieces)

    @staticmethod
    def _contains_structured_signal(container: dict[str, Any], names: tuple[str, ...]) -> bool:
        needles = {item.lower().replace("-", "_").replace(" ", "_") for item in names}
        for key in container:
            normalized = str(key).lower().replace("-", "_").replace(" ", "_")
            if normalized in needles:
                return True
        return False

    def classify(self, context: AgentContext) -> RouteDecision:
        text = self._context_text(context)
        reasons: list[str] = []
        score = 0.0
        profile: Altar1RequestProfile | None = None

        structured_code = self._contains_structured_signal(
            context.finding_surface,
            ("code_review", "source_review", "static_analysis", "code_audit"),
        )
        structured_proof = self._contains_structured_signal(
            context.finding_surface,
            ("exploit_proof", "proof_of_concept", "reproduction", "poc"),
        )
        structured_authz = any(
            self._contains_structured_signal(container, ("authorization_matrix", "access_control_matrix", "permission_matrix", "anomalies"))
            for container in (context.authorization_surface, context.finding_surface)
        )

        if structured_code or self._CODE_REVIEW.search(text):
            score += 1.0
            reasons.append("code-review signal")
            profile = Altar1RequestProfile("code_review", temperature=0.05, max_tokens=2600, top_p=0.90)
        if structured_proof or self._EXPLOIT_PROOF.search(text):
            score += 1.2
            reasons.append("exploit-proof/reproduction signal")
            profile = Altar1RequestProfile("exploit_proof", temperature=0.10, max_tokens=3200, top_p=0.92)
        if structured_authz or self._AUTHZ_MATRIX.search(text):
            score += 1.1
            reasons.append("authorization-matrix anomaly signal")
            profile = Altar1RequestProfile("authz_matrix", temperature=0.05, max_tokens=2400, top_p=0.90)

        context_size = len(json.dumps({
            "observations": context.observations,
            "assets": context.assets,
            "api": context.api_surface,
            "auth": context.auth_surface,
            "authorization": context.authorization_surface,
            "business_logic": context.business_logic_surface,
            "findings": context.finding_surface,
        }, ensure_ascii=True))
        if context_size > 80_000 or len(context.observations) > 40:
            gemini_mode = "heavy_recon_triage"
            reasons.append("large telemetry snapshot")
        elif self._RECON.search(text):
            gemini_mode = "monitor_recon"
            reasons.append("recon/tool-output signal")
        else:
            gemini_mode = "monitor_agent"

        route: RouteName = "altar1" if score >= 1.0 else "standard"
        if route == "altar1" and profile is None:
            profile = Altar1RequestProfile("altar1_specialized", temperature=0.08, max_tokens=2600, top_p=0.90)
        if not reasons:
            reasons.append("general agent monitoring")
        return RouteDecision(route, round(score, 3), tuple(reasons), profile, gemini_mode)

    @staticmethod
    def _parse_gemini_advice(raw: str) -> GeminiAdvice:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            if len(lines) >= 3:
                cleaned = "\n".join(lines[1:-1]).strip()
        try:
            payload = json.loads(cleaned)
        except json.JSONDecodeError:
            start, end = cleaned.find("{"), cleaned.rfind("}")
            if start < 0 or end <= start:
                raise ValueError("Gemini advisory response did not contain JSON")
            payload = json.loads(cleaned[start:end + 1])
        if not isinstance(payload, dict):
            raise ValueError("Gemini advisory root must be an object")
        allowed = {"continue", "retry", "correct", "escalate_to_deep_review", "stop_escalation", "observe"}
        decision = str(payload.get("decision", "observe")).strip()
        if decision not in allowed:
            decision = "observe"
        try:
            confidence = max(0.0, min(1.0, float(payload.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5
        reason = str(payload.get("reason", "")).strip()[:1200]
        focus = str(payload.get("focus", "")).strip()[:600]
        allowed_capabilities = {
            "asset.discovery.subdomains",
            "service.discovery",
            "web.verify",
            "browser.automation",
            "http.workflow",
            "session.replay",
            "api.manipulation",
            "authorization.interactive",
            "business_logic.workflow",
            "race_condition.test",
            "offline.api.structure_analysis",
            "offline.auth.surface_analysis",
            "offline.access_control.surface_analysis",
            "offline.authorization.matrix_analysis",
            "offline.business_logic.workflow_analysis",
            "offline.finding.validation",
        }
        recommended = payload.get("recommended_capability")
        recommended_capability = str(recommended).strip()[:160] if recommended else None
        if recommended_capability not in allowed_capabilities:
            recommended_capability = None
        raw_notes = payload.get("notes", [])
        notes = tuple(str(item).strip()[:400] for item in raw_notes[:8]) if isinstance(raw_notes, list) else ()
        allowed_suggestion_kinds = {"evidence", "correction", "alternate_hypothesis", "retry", "next_capability", "escalation", "stop"}
        raw_suggestions = payload.get("suggestions", [])
        parsed_suggestions: list[GeminiSuggestion] = []
        if isinstance(raw_suggestions, list):
            for item in raw_suggestions[:10]:
                if not isinstance(item, dict):
                    continue
                kind = str(item.get("kind", "evidence")).strip()
                if kind not in allowed_suggestion_kinds:
                    kind = "evidence"
                instruction = str(item.get("instruction", "")).strip()[:700]
                reason_item = str(item.get("reason", "")).strip()[:700]
                capability_item = str(item.get("capability", "")).strip()[:160] if item.get("capability") else None
                if capability_item not in allowed_capabilities:
                    capability_item = None
                try:
                    suggestion_confidence = max(0.0, min(1.0, float(item.get("confidence", 0.5))))
                except (TypeError, ValueError):
                    suggestion_confidence = 0.5
                if instruction:
                    parsed_suggestions.append(
                        GeminiSuggestion(kind, instruction, reason_item, capability_item, suggestion_confidence)
                    )
        suggestions = tuple(parsed_suggestions)
        raw_hypotheses = payload.get("alternative_hypotheses", [])
        alternative_hypotheses = tuple(str(item).strip()[:700] for item in raw_hypotheses[:8] if str(item).strip()) if isinstance(raw_hypotheses, list) else ()
        raw_missing = payload.get("missing_evidence", [])
        missing_evidence = tuple(str(item).strip()[:500] for item in raw_missing[:10] if str(item).strip()) if isinstance(raw_missing, list) else ()
        return GeminiAdvice(
            decision,
            confidence,
            reason,
            focus,
            recommended_capability,
            notes,
            suggestions,
            alternative_hypotheses,
            missing_evidence,
        )

    def _primary_local(self, *, decision: RouteDecision, system_prompt: str, user_prompt: str) -> tuple[str, float, str, str]:
        if not isinstance(self.standard_provider, DisabledLLMProvider):
            text, latency = self.standard_provider.complete(system_prompt=system_prompt, user_prompt=user_prompt)
            return text, latency, self.standard_provider.name, self.standard_provider.model
        if decision.route == "altar1" and not isinstance(self.altar_provider, DisabledLLMProvider):
            profile = decision.profile or Altar1RequestProfile("altar1_primary", 0.08, 2600, 0.90)
            text, latency = self.altar_provider.complete_with_profile(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                profile=profile,
                route="altar1_primary",
            )
            return text, latency, self.altar_provider.name, self.altar_provider.model
        raise RuntimeError("No local LLM provider is available")

    def complete_for_context(
        self,
        *,
        context: AgentContext,
        system_prompt: str,
        user_prompt: str,
    ) -> RoutedCompletion:
        decision = self.classify(context)
        self.last_decision = decision
        self.last_advice = None
        trace: dict[str, Any] = {
            "primary_role": "standard_local_operator",
            "gemini_role": "cloud_co_pilot",
            "altar1_role": "local_deep_reviewer",
            "gemini_mode": decision.gemini_mode,
            "gemini_status": "not_called",
        }

        local_text, latency, provider_name, model = self._primary_local(
            decision=decision,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        gemini_advice: GeminiAdvice | None = None
        gemini_latency = 0.0
        if not isinstance(self.gemini_provider, DisabledLLMProvider):
            try:
                advisory_raw, gemini_latency, meta = self.gemini_provider.advise(
                    context=context,
                    local_draft=local_text,
                    mode=decision.gemini_mode,
                    goal="monitor the agent, diagnose failed or weak reasoning, and identify useful evidence or a bounded next capability",
                )
                gemini_advice = self._parse_gemini_advice(advisory_raw)
                trace.update(meta)
                trace["gemini_status"] = "ok"
                trace["gemini_decision"] = gemini_advice.decision
            except GeminiRateLimitError as exc:
                trace["gemini_status"] = "fallback_to_standard_rate_limit"
                trace["gemini_error"] = str(exc)[:500]
            except GeminiSafetyBlockedError as exc:
                trace["gemini_status"] = "fallback_to_standard_safety_block"
                trace["gemini_error"] = str(exc)[:500]
            except (GeminiCloudError, CloudSanitizationError, ValueError) as exc:
                trace["gemini_status"] = "fallback_to_standard"
                trace["gemini_error"] = str(exc)[:500]
            except Exception as exc:
                trace["gemini_status"] = "fallback_to_standard"
                trace["gemini_error"] = str(exc)[:500]

        altar_review: str | None = None
        altar_latency = 0.0
        if decision.route == "altar1" and not isinstance(self.altar_provider, DisabledLLMProvider):
            advice_payload = {}
            if gemini_advice is not None:
                advice_payload = {
                    "decision": gemini_advice.decision,
                    "confidence": gemini_advice.confidence,
                    "reason": gemini_advice.reason,
                    "focus": gemini_advice.focus,
                    "recommended_capability": gemini_advice.recommended_capability,
                    "notes": list(gemini_advice.notes),
                    "suggestions": [
                        {
                            "kind": item.kind,
                            "instruction": item.instruction,
                            "reason": item.reason,
                            "capability": item.capability,
                            "confidence": item.confidence,
                        }
                        for item in gemini_advice.suggestions
                    ],
                    "alternative_hypotheses": list(gemini_advice.alternative_hypotheses),
                    "missing_evidence": list(gemini_advice.missing_evidence),
                }
            reviewer_prompt = (
                "Review the local operator draft and Gemini advisory below. "
                "You are a local deep security reviewer. Return concise review text only. "
                "Do not execute tools.\\n\\nLOCAL DRAFT:\\n" + local_text[:18000] +
                "\\n\\nGEMINI ADVISORY:\\n" + json.dumps(advice_payload, ensure_ascii=True)
            )
            profile = decision.profile or Altar1RequestProfile("altar1_review", 0.08, 2800, 0.90)
            try:
                altar_review, altar_latency = self.altar_provider.complete_with_profile(
                    system_prompt=system_prompt,
                    user_prompt=reviewer_prompt,
                    profile=profile,
                    route="altar1_review",
                )
                trace["altar_status"] = "ok"
            except Exception as exc:
                trace["altar_status"] = "failed"
                trace["altar_error"] = str(exc)[:500]

        final_text = local_text
        if gemini_advice is not None or altar_review is not None:
            sections = [user_prompt, "", "BELTU REVIEW PASS - LOCAL OPERATOR IS FINAL AUTHORITY."]
            if gemini_advice is not None:
                sections.extend([
                    "Gemini cloud advisory (sanitized and untrusted):",
                    json.dumps({
                        "decision": gemini_advice.decision,
                        "confidence": gemini_advice.confidence,
                        "reason": gemini_advice.reason,
                        "focus": gemini_advice.focus,
                        "recommended_capability": gemini_advice.recommended_capability,
                        "notes": list(gemini_advice.notes),
                    }, ensure_ascii=True),
                ])
            if altar_review is not None:
                sections.extend(["Altar-1 local deep review:", altar_review[:16000]])
            sections.append("Choose the final BELTU hypotheses and actions yourself. Reviewers only provide advisory evidence.")
            try:
                if not isinstance(self.standard_provider, DisabledLLMProvider):
                    final_text, final_latency = self.standard_provider.complete(
                        system_prompt=system_prompt,
                        user_prompt="\\n".join(sections),
                    )
                    latency += final_latency
                    trace["final_local_pass"] = True
            except Exception as exc:
                trace["final_local_pass"] = False
                trace["final_local_error"] = str(exc)[:500]

        total_latency = latency + gemini_latency + altar_latency
        trace["latency_ms"] = round(total_latency, 2)
        self.last_advice = gemini_advice
        self.last_trace = trace
        return RoutedCompletion(
            final_text,
            round(total_latency, 2),
            provider_name,
            model,
            decision,
            gemini_advice=gemini_advice,
            altar_review=altar_review,
            trace=trace,
        )

    # Backward-compatible provider-shaped interface for callers that don't pass context.
    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        text, latency = self.standard_provider.complete(system_prompt=system_prompt, user_prompt=user_prompt)
        self.last_decision = RouteDecision("standard", 0.0, ("no context supplied",), None)
        return text, latency