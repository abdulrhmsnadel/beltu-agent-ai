from __future__ import annotations

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
class GeminiAdvice:
    decision: GeminiDecision
    confidence: float
    reason: str
    focus: str
    recommended_capability: str | None
    notes: tuple[str, ...] = ()
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

        if not reasons and self._RECON.search(text):
            reasons.append("general recon/tool-output signal")

        route: RouteName = "altar1" if score >= 1.0 else "standard"
        if route == "altar1" and profile is None:
            profile = Altar1RequestProfile("altar1_specialized", temperature=0.08, max_tokens=2600, top_p=0.90)
        if route == "standard" and not reasons:
            reasons.append("no specialized signal; standard reasoning")
        return RouteDecision(route, round(score, 3), tuple(reasons), profile)

    def complete_for_context(
        self,
        *,
        context: AgentContext,
        system_prompt: str,
        user_prompt: str,
    ) -> RoutedCompletion:
        decision = self.classify(context)
        self.last_decision = decision

        if decision.route == "altar1" and not isinstance(self.altar_provider, DisabledLLMProvider):
            profile = decision.profile or Altar1RequestProfile("altar1_specialized", 0.08, 2600, 0.90)
            text, latency = self.altar_provider.complete_with_profile(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                profile=profile,
                route=decision.route,
            )
            return RoutedCompletion(text, latency, self.altar_provider.name, self.altar_provider.model, decision)

        text, latency = self.standard_provider.complete(system_prompt=system_prompt, user_prompt=user_prompt)
        return RoutedCompletion(text, latency, self.standard_provider.name, self.standard_provider.model, decision)

    # Backward-compatible provider-shaped interface for callers that don't pass context.
    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        text, latency = self.standard_provider.complete(system_prompt=system_prompt, user_prompt=user_prompt)
        self.last_decision = RouteDecision("standard", 0.0, ("no context supplied",), None)
        return text, latency