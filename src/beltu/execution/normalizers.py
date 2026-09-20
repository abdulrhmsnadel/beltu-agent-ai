from __future__ import annotations

import json
from typing import Any


def normalize_jsonl_or_lines(
    kind: str,
    source: str,
    stdout: str,
    *,
    confidence: float = 0.5,
) -> list[dict[str, Any]]:
    """Prefer structured JSONL when present; safely fall back to line observations."""
    results: list[dict[str, Any]] = []
    for raw in stdout.splitlines():
        value = raw.strip()
        if not value or value.startswith("["):
            continue
        payload: Any = None
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            pass
        if isinstance(payload, dict):
            subject = str(
                payload.get("host")
                or payload.get("url")
                or payload.get("matched-at")
                or payload.get("template-id")
                or payload.get("name")
                or value
            ).strip()
            if not subject:
                continue
            results.append({
                "kind": kind,
                "subject": subject,
                "data": {"structured": payload},
                "source": source,
                "confidence": confidence,
            })
            continue
        results.append({
            "kind": kind,
            "subject": value,
            "data": {"raw": value},
            "source": source,
            "confidence": confidence,
        })
    return results
