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
    _RECON_HEAVY = re.compile(
        r"\b(?:recon|reconnaissance|subdomain|asset|endpoint|directory|fuzz|crawler|crawl|amass|gau|katana|wayback|httpx|wordlist|dedup|parse|triage|log)\b",
        re.I,
    )
    _ROUTINE = re.compile(
        r"\b(?:state|lifecycle|orchestration|serialize|normaliz|summar|heartbeat|status|queue|bookkeep|housekeep)\b",
        re.I,
    )

    def __init__(
        self,
        *,
        standard: LLMProvider,
        altar1: Altar1LocalProvider | None = None,
        gemini: GeminiCloudProvider | None = None,
        enabled: bool = True,
    ) -> None:
        self.standard = standard
        self.altar1 = altar1
        self.gemini = gemini
        self.enabled = enabled
        self.last_trace: dict[str, Any] = {}

    @staticmethod
    def _joined(context: AgentContext) -> str:
        parts: list[str] = [
            str(context.target),
            json.dumps(context.observations, ensure_ascii=True, sort_keys=True, default=str),
            json.dumps(context.known_hypotheses, ensure_ascii=True, sort_keys=True, default=str),
            json.dumps(context.api_surface, ensure_ascii=True, sort_keys=True, default=str),
            json.dumps(context.auth_surface, ensure_ascii=True, sort_keys=True, default=str),
            json.dumps(context.authorization_surface, ensure_ascii=True, sort_keys=True, default=str),
            json.dumps(context.business_logic_surface, ensure_ascii=True, sort_keys=True, default=str),
            json.dumps(context.finding_surface, ensure_ascii=True, sort_keys=True, default=str),
        ]
        return " ".join(parts)

    def classify(self, context: AgentContext) -> RouteDecision:
        if not self.enabled:
            return RouteDecision("standard", 0.0, ("routing_disabled",), gemini_mode="off")
        joined = self._joined(context)
        reasons: list[str] = []
        if self._AUTHZ_MATRIX.search(joined):
            reasons.append("authorization_matrix_context")
        if self._CODE_REVIEW.search(joined):
            reasons.append("source_or_code_review_context")
        if self._EXPLOIT_PROOF.search(joined):
            reasons.append("exploit_verification_context")
        specialist = bool(reasons)
        if specialist and self.altar1 is not None:
            return RouteDecision("altar1", 1.0, tuple(reasons), self._altar_profile(context), gemini_mode="off")
        if specialist:
            reasons.append("altar1_unavailable")
        if self._RECON_HEAVY.search(joined):
            reasons.append("recon_heavy_context")
        if self._ROUTINE.search(joined) and not self._RECON_HEAVY.search(joined):
            reasons.append("routine_orchestration_context")
        gemini_mode = "monitor" if self.gemini is not None else "off"
        return RouteDecision("standard", 0.5, tuple(reasons or ["general_context"]), gemini_mode=gemini_mode)

    def _altar_profile(self, context: AgentContext) -> Altar1RequestProfile:
        joined = self._joined(context).lower()
        if self._CODE_REVIEW.search(joined):
            return Altar1RequestProfile("code_review", 0.05, 3072, 0.95)
        if self._EXPLOIT_PROOF.search(joined):
            return Altar1RequestProfile("exploit_validation", 0.05, 4096, 0.95)
        return Altar1RequestProfile("authorization_anomaly", 0.05, 3072, 0.95)

    @staticmethod
    def _advisory_system() -> str:
        return (
            "You are BELTU's cloud co-pilot. You receive only sanitized operational context. "
            "You are advisory-only: never execute tools, never emit shell commands, exploit payloads, "
            "PoC code, credentials, session secrets, or a final report. Return JSON matching the "
            "BELTU advisory contract. Focus on diagnosing the current agent state, missing evidence, "
            "wrong paths, retry/correction conditions, continuation, or escalation to the local deep reviewer."
        )

    @staticmethod
    def _safe_json(value: Any, limit: int = 12000) -> str:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)[:limit]

    def _parse_advice(self, raw: str) -> GeminiAdvice:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return GeminiAdvice("observe", 0.0, "Gemini returned non-JSON advisory content", "format_error", None, status="invalid")

        if not isinstance(payload, dict):
            return GeminiAdvice("observe", 0.0, "Gemini advisory was not an object", "format_error", None, status="invalid")
        decision = str(payload.get("decision", "observe"))
        allowed = {"continue", "retry", "correct", "escalate_to_deep_review", "stop_escalation", "observe"}
        if decision not in allowed:
            decision = "observe"
        confidence = payload.get("confidence", 0.5)
        try:
            confidence = min(1.0, max(0.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.5
        reason = str(payload.get("reason", ""))[:4000]
        focus = str(payload.get("focus", ""))[:2000]
        capability = payload.get("recommended_capability")
        capability = str(capability)[:200] if capability not in (None, "") else None
        notes = tuple(str(x)[:1000] for x in payload.get("notes", [])[:10]) if isinstance(payload.get("notes"), list) else ()
        suggestions: list[GeminiSuggestion] = []
        if isinstance(payload.get("suggestions"), list):
            for item in payload["suggestions"][:10]:
                if not isinstance(item, dict):
                    continue
                suggestions.append(
                    GeminiSuggestion(
                        kind=str(item.get("kind", "observe"))[:100],
                        instruction=str(item.get("instruction", ""))[:1500],
                        reason=str(item.get("reason", ""))[:1500],
                        capability=str(item.get("capability"))[:200] if item.get("capability") else None,
                        confidence=min(1.0, max(0.0, float(item.get("confidence", 0.5)))),
                    )
                )
        alternatives = tuple(str(x)[:1500] for x in payload.get("alternative_hypotheses", [])[:10]) if isinstance(payload.get("alternative_hypotheses"), list) else ()
        missing = tuple(str(x)[:1500] for x in payload.get("missing_evidence", [])[:10]) if isinstance(payload.get("missing_evidence"), list) else ()
        forbidden = re.compile(r"(?i)(?:\b(?:password|secret|session|cookie|authorization)\b.{0,40}(?:=|:)\s*\S+|(?:curl|wget|python|bash|sh|powershell)\b|-----BEGIN .*PRIVATE KEY-----)")
        if forbidden.search(raw):
            return GeminiAdvice("observe", 0.0, "Gemini advisory contained blocked material", "policy_block", None, status="invalid")
        return GeminiAdvice(decision, confidence, reason, focus, capability, notes, tuple(suggestions), alternatives, missing, status="ok")

    def complete_for_context(
        self,
        *,
        context: AgentContext,
        system_prompt: str,
        user_prompt: str,
    ) -> RoutedCompletion:
        decision = self.classify(context)
        trace: dict[str, Any] = {"primary_route": decision.route, "reasons": decision.reasons, "gemini": None, "altar1": None}
        primary = self.standard
        profile = None
        if decision.route == "altar1" and self.altar1 is not None:
            primary = self.altar1
            profile = decision.profile

        started = 0.0
        if profile is not None:
            text, latency = primary.complete_with_profile(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                profile=profile,
                route="altar1_specialist",
            )
        else:
            started = 0.0
            text, latency = primary.complete(system_prompt=system_prompt, user_prompt=user_prompt)

        advice = None
        if decision.route == "standard" and self.gemini is not None:
            try:
                advice_raw, advice_latency, advice_meta = self.gemini.advise(
                    context=context,
                    local_draft=text,
                    mode=decision.gemini_mode,
                    goal="Monitor the current BELTU cycle and identify useful corrections, retries, continuation, missing evidence, or local deep-review escalation.",
                )
                advice = self._parse_advice(advice_raw)
                trace["gemini"] = {
                    "status": advice.status,
                    "latency_ms": advice_latency,
                    **advice_meta,
                }
            except (GeminiRateLimitError, GeminiSafetyBlockedError, GeminiCloudError, CloudSanitizationError) as exc:
                trace["gemini"] = {"status": "fallback", "error_class": type(exc).__name__, "reason": str(exc)[:500]}
            except Exception as exc:
                trace["gemini"] = {"status": "fallback", "error_class": type(exc).__name__, "reason": str(exc)[:500]}

        self.last_trace = trace
        if advice is not None:
            trace["gemini_advice"] = {
                "decision": advice.decision,
                "confidence": advice.confidence,
                "focus": advice.focus,
                "recommended_capability": advice.recommended_capability,
                "suggestion_count": len(advice.suggestions),
            }

        # Gemini never replaces the primary local response. Its advice is returned
        # as separate metadata for the next local reasoning cycle.
        return RoutedCompletion(
            text=text,
            latency_ms=latency,
            provider_name=getattr(primary, "name", decision.route),
            model=getattr(primary, "model", decision.route),
            decision=decision,
            gemini_advice=advice,
            trace=trace,
        )

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        provider = self.standard
        return provider.complete(system_prompt=system_prompt, user_prompt=user_prompt)
