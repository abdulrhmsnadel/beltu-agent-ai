from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from beltu.policy.scope_guard import ScopeGuard

SESSION_ROOT = Path.cwd() / "data" / "runtime" / "sessions"


def safe_session_path(name: str) -> Path:
    value = str(name).strip()
    if not value or "/" in value or "\\\\" in value or value in {".", ".."} or ".." in value:
        raise ValueError("session_profile must be a simple local profile name")
    if not value.endswith(".json"):
        value += ".json"
    path = (SESSION_ROOT / value).resolve()
    root = SESSION_ROOT.resolve()
    if path.parent != root:
        raise ValueError("session_profile path escaped the runtime session directory")
    return path


def load_session_profile(name: str | None) -> dict[str, Any]:
    if not name:
        return {}
    path = safe_session_path(name)
    if not path.exists():
        raise FileNotFoundError(f"Session profile not found: {path.name}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Session profile must be a JSON object")
    return data


def scope_url(scope: ScopeGuard, url: str) -> str:
    parsed = urlparse(str(url).strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only http:// and https:// URLs are supported")
    host = parsed.hostname.rstrip(".").lower()
    if not scope.allowed(host):
        raise PermissionError(f"URL host is outside explicit BELTU scope: {host}")
    return parsed.geturl()


def apply_template(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):
        result = value
        for key, item in variables.items():
            result = result.replace("{{" + key + "}}", str(item))
        return result
    if isinstance(value, list):
        return [apply_template(item, variables) for item in value]
    if isinstance(value, dict):
        return {str(k): apply_template(v, variables) for k, v in value.items()}
    return value


def extract_dotted(value: Any, path: str) -> Any:
    current = value
    for part in str(path).strip(".").split("."):
        if not part:
            continue
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def redact_text(value: str) -> str:
    text = str(value)
    patterns = (
        (re.compile(r"(?i)(authorization\s*:\s*)([^\r\n]+)"), r"\1<REDACTED>"),
        (re.compile(r"(?i)(cookie\s*:\s*)([^\r\n]+)"), r"\1<REDACTED>"),
        (re.compile(r"(?i)(set-cookie\s*:\s*)([^\r\n]+)"), r"\\1<REDACTED>"),
        (re.compile(r"(?i)\b(bearer|token|api[_-]?key|secret)[=:]\s*[A-Za-z0-9._~+/=-]{8,}"), r"\1=<REDACTED>"),
    )
    for pattern, replacement in patterns:
        text = pattern.sub(replacement, text)
    return text


def session_headers(profile: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    raw_headers = profile.get("headers", {})
    if isinstance(raw_headers, dict):
        for key, value in raw_headers.items():
            if isinstance(key, str) and isinstance(value, (str, int, float)):
                headers[key] = str(value)
    cookies = profile.get("cookies", [])
    cookie_pairs: list[str] = []
    if isinstance(cookies, list):
        for item in cookies:
            if isinstance(item, dict) and item.get("name") is not None and item.get("value") is not None:
                cookie_pairs.append(f"{item['name']}={item['value']}")
    if cookie_pairs and not any(k.lower() == "cookie" for k in headers):
        headers["Cookie"] = "; ".join(cookie_pairs)
    return headers


def bounded_int(value: Any, *, default: int, minimum: int, maximum: int, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed
