from __future__ import annotations

import json
import re
from typing import Any

from beltu.brain.llm.schemas import LLMReasoningResponse
from beltu.brain.schemas import ALLOWED_ACTIONS, ActionProposal, AgentContext, HypothesisProposal, RISK_LEVELS


MAX_STATEMENT = 600
MAX_RATIONALE = 800
MAX_SUMMARY = 1200
ALLOWED_PAYLOAD_KEYS = frozenset({"target", "hypothesis", "observation_ids", "capability", "tool"})
DANGEROUS_TEXT = re.compile(r"(^|\b)(?:bash|sh|shell|exec|system|os\.system|subprocess|curl|wget|nc|netcat|python\s+-c|powershell)\b", re.I)


def extract_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if len(lines) >= 3:
            cleaned = "\n".join(lines[1:-1]).strip()
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("LLM output does not contain a JSON object")
        try:
            value = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ValueError("LLM output contains invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("LLM output root must be a JSON object")
    return value


def _bounded_float(value: Any, field: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a number") from exc
    if not 0.0 <= parsed <= 1.0:
        raise ValueError(f"{field} must be between 0 and 1")
    return parsed


def validate_response(payload: dict[str, Any], context: AgentContext, *, provider: str, model: str, max_hypotheses: int, max_actions: int) -> LLMReasoningResponse:
    summary = payload.get("summary", "")
    if not isinstance(summary, str):
        raise ValueError("summary must be a string")
    if len(summary) > MAX_SUMMARY:
        raise ValueError("summary is too long")

    observations = {int(item["id"]) for item in context.observations if isinstance(item, dict) and "id" in item}
    hypotheses_raw = payload.get("hypotheses", [])
    actions_raw = payload.get("actions", [])
    if not isinstance(hypotheses_raw, list) or not isinstance(actions_raw, list):
        raise ValueError("hypotheses and actions must be arrays")
    if len(hypotheses_raw) > max_hypotheses or len(actions_raw) > max_actions:
        raise ValueError("LLM exceeded configured reasoning limits")

    hypotheses: list[HypothesisProposal] = []
    seen_hypotheses: set[tuple[str, tuple[int, ...]]] = set()
    for idx, item in enumerate(hypotheses_raw):
        if not isinstance(item, dict):
            raise ValueError(f"hypothesis[{idx}] must be an object")
        statement = item.get("statement")
        basis = item.get("basis_observation_ids", [])
        if not isinstance(statement, str) or not statement.strip() or len(statement) > MAX_STATEMENT:
            raise ValueError(f"hypothesis[{idx}].statement is invalid")
        if DANGEROUS_TEXT.search(statement):
            raise ValueError(f"hypothesis[{idx}] contains execution language")
        if not isinstance(basis, list) or any(int(x) not in observations for x in basis):
            raise ValueError(f"hypothesis[{idx}] references an unknown observation")
        basis_ids = tuple(sorted(set(int(x) for x in basis)))
        confidence = _bounded_float(item.get("confidence"), f"hypothesis[{idx}].confidence")
        key = (statement.strip(), basis_ids)
        if key in seen_hypotheses:
            continue
        seen_hypotheses.add(key)
        hypotheses.append(HypothesisProposal(statement.strip(), basis_ids, confidence))

    actions: list[ActionProposal] = []
    for idx, item in enumerate(actions_raw):
        if not isinstance(item, dict):
            raise ValueError(f"action[{idx}] must be an object")
        kind = item.get("action_kind")
        payload_data = item.get("action_payload", {})
        rationale = item.get("rationale", "")
        risk = item.get("risk_level", "medium")
        requires_approval = bool(item.get("requires_approval", True))
        confidence = _bounded_float(item.get("confidence"), f"action[{idx}].confidence")
        if kind not in ALLOWED_ACTIONS:
            raise ValueError(f"action[{idx}] uses unsupported action_kind")
        if risk not in RISK_LEVELS:
            raise ValueError(f"action[{idx}].risk_level is invalid")
        if not isinstance(payload_data, dict) or not set(payload_data).issubset(ALLOWED_PAYLOAD_KEYS):
            raise ValueError(f"action[{idx}] contains unsupported payload fields")
        target = payload_data.get("target")
        if target != context.target:
            raise ValueError(f"action[{idx}] target must exactly match the current target")
        basis = payload_data.get("observation_ids", [])
        if basis and (not isinstance(basis, list) or any(int(x) not in observations for x in basis)):
            raise ValueError(f"action[{idx}] references an unknown observation")
        hypothesis = payload_data.get("hypothesis")
        if hypothesis is not None and (not isinstance(hypothesis, str) or len(hypothesis) > MAX_STATEMENT):
            raise ValueError(f"action[{idx}].hypothesis is invalid")
        if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > MAX_RATIONALE:
            raise ValueError(f"action[{idx}].rationale is invalid")
        if DANGEROUS_TEXT.search(rationale) or DANGEROUS_TEXT.search(str(payload_data)):
            raise ValueError(f"action[{idx}] contains execution-oriented text")
        if risk in {"medium", "high"}:
            requires_approval = True
        actions.append(ActionProposal(kind, dict(payload_data), rationale.strip(), confidence, risk, requires_approval))

    return LLMReasoningResponse(summary.strip(), tuple(hypotheses), tuple(actions), provider, model, payload)
