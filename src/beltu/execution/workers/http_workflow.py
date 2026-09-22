from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import sys
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from beltu.policy.scope_guard import ScopeGuard
from beltu.execution.workers.common import (
    apply_template, bounded_int, extract_dotted, load_session_profile,
    redact_text, redact_url, scope_url, session_headers,
)

MAX_BODY_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 512_000


class ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, scope: ScopeGuard):
        self.scope = scope

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        scope_url(self.scope, newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _url_with_query(url: str, query: dict[str, Any] | list[tuple[str, Any]] | None) -> str:
    if not query:
        return url
    parts = urlparse(url)
    pairs = list(parse_qsl(parts.query, keep_blank_values=True))
    if isinstance(query, dict):
        pairs.extend((str(k), str(v)) for k, v in query.items())
    else:
        pairs.extend((str(k), str(v)) for k, v in query)
    return urlunparse(parts._replace(query=urlencode(pairs)))


def _json_set(value: Any, path: str, replacement: Any) -> Any:
    parts = [p for p in str(path).strip(".").split(".") if p]
    if not parts:
        return replacement
    root = json.loads(json.dumps(value))
    current = root
    for part in parts[:-1]:
        if not isinstance(current, dict):
            raise ValueError(f"JSON mutation path is not an object: {path}")
        current = current.setdefault(part, {})
    if not isinstance(current, dict):
        raise ValueError(f"JSON mutation path is not an object: {path}")
    current[parts[-1]] = replacement
    return root


def _request(scope: ScopeGuard, target: str, spec: dict[str, Any], variables: dict[str, Any]) -> dict[str, Any]:
    spec = apply_template(spec, variables)
    url = scope_url(scope, str(spec.get("url", "")))
    url = _url_with_query(url, spec.get("query"))
    method = str(spec.get("method", "GET")).upper()
    headers = {str(k): str(v) for k, v in (spec.get("headers") or {}).items()}
    profile = load_session_profile(spec.get("session_profile"))
    for key, value in session_headers(profile).items():
        headers.setdefault(key, value)

    body_bytes: bytes | None = None
    if "json_body" in spec:
        encoded = json.dumps(spec["json_body"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        body_bytes = encoded
        headers.setdefault("Content-Type", "application/json")
    elif "body" in spec and spec["body"] is not None:
        body_bytes = str(spec["body"]).encode("utf-8")
    if body_bytes is not None and len(body_bytes) > MAX_BODY_BYTES:
        raise ValueError("Request body exceeds BELTU worker limit")

    req = urllib.request.Request(url, data=body_bytes, method=method, headers=headers)
    timeout = min(float(spec.get("timeout_seconds", 20.0)), 60.0)
    opener = urllib.request.build_opener(ScopedRedirectHandler(scope))
    started = __import__("time").monotonic()
    try:
        with opener.open(req, timeout=timeout) as response:
            data = response.read(MAX_RESPONSE_BYTES)
            status = int(response.status)
            final_url = scope_url(scope, response.geturl())
            content_type = str(response.headers.get("Content-Type", ""))
            body = data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        data = exc.read(MAX_RESPONSE_BYTES)
        status = int(exc.code)
        final_url = scope_url(scope, exc.geturl())
        content_type = str(exc.headers.get("Content-Type", "")) if exc.headers else ""
        body = data.decode("utf-8", errors="replace")
    elapsed = __import__("time").monotonic() - started
    safe_body = redact_text(body[:2000])
    body_hash = hashlib.sha256(data).hexdigest()
    return {
        "method": method,
        "url": redact_url(url),
        "final_url": redact_url(final_url),
        "status": status,
        "content_type": content_type,
        "body_length": len(data),
        "body_sha256": body_hash,
        "body_sample": safe_body,
        "duration_seconds": round(elapsed, 4),
        "target": target,
    }


def _emit(kind: str, subject: str, data: dict[str, Any], confidence: float = 0.88) -> None:
    print(json.dumps({
        "kind": kind, "subject": subject, "data": redact_text(json.dumps(data, ensure_ascii=False)),
        "source": "beltu-http-worker", "confidence": confidence,
    }, ensure_ascii=False))


def _normalize_data(raw: str) -> dict[str, Any]:
    parsed = json.loads(raw)
    if isinstance(parsed, dict):
        return parsed
    return {"value": parsed}


def run_sequence(scope: ScopeGuard, job: dict[str, Any], *, kind: str) -> None:
    requests = job.get("requests") or []
    if not isinstance(requests, list) or not requests:
        raise ValueError("workflow requires a non-empty requests list")
    if len(requests) > 25:
        raise ValueError("workflow request count exceeds BELTU limit of 25")
    variables: dict[str, Any] = {}
    for index, raw_spec in enumerate(requests, start=1):
        if not isinstance(raw_spec, dict):
            raise ValueError(f"workflow request #{index} must be an object")
        spec = dict(raw_spec)
        result = _request(scope, job["target"], spec, variables)
        assertions = spec.get("assert") or {}
        expected = assertions.get("status")
        ok = expected is None or int(expected) == result["status"]
        contains = assertions.get("body_contains")
        if contains is not None:
            ok = ok and str(contains) in result["body_sample"]
        result["assertion_ok"] = bool(ok)
        _emit("http.response", result["final_url"], result)
        for name, rule in (spec.get("extract") or {}).items():
            if isinstance(rule, dict) and rule.get("json_path"):
                try:
                    parsed = json.loads(result["body_sample"])
                except json.JSONDecodeError:
                    parsed = None
                extracted = extract_dotted(parsed, str(rule["json_path"]))
                if extracted is not None:
                    variables[str(name)] = extracted
        if not ok:
            _emit("workflow.assertion_failed", result["final_url"], {"step": index, "assert": assertions, "result_status": result["status"]}, 0.92)
            raise RuntimeError(f"workflow assertion failed at step {index}")
    _emit(kind, job["target"], {"steps": len(requests), "variables": sorted(variables)})


def run_api(scope: ScopeGuard, job: dict[str, Any]) -> None:
    base = job.get("request")
    mutations = job.get("mutations") or []
    if not isinstance(base, dict) or not isinstance(mutations, list):
        raise ValueError("api manipulation requires request + mutations")
    mutations = mutations[:20]
    for index, mutation in enumerate(mutations, start=1):
        if not isinstance(mutation, dict):
            raise ValueError("each API mutation must be an object")
        spec = dict(base)
        location = str(mutation.get("location", "query"))
        name = str(mutation.get("name", ""))
        value = mutation.get("value")
        if not name:
            raise ValueError("API mutation name is required")
        if location == "query":
            spec["query"] = {**(spec.get("query") or {}), name: value}
        elif location == "header":
            spec["headers"] = {**(spec.get("headers") or {}), name: value}
        elif location == "json":
            spec["json_body"] = _json_set(spec.get("json_body") or {}, name, value)
        else:
            raise ValueError(f"Unsupported API mutation location: {location}")
        result = _request(scope, job["target"], spec, {})
        result["mutation_index"] = index
        result["mutation"] = {"location": location, "name": name}
        _emit("api.manipulation_result", result["final_url"], result, 0.86)


def run_matrix(scope: ScopeGuard, job: dict[str, Any]) -> None:
    principals = job.get("principals") or []
    requests = job.get("requests") or []
    if not isinstance(principals, list) or not principals or not isinstance(requests, list) or not requests:
        raise ValueError("authorization matrix requires principals + requests")
    if len(principals) > 6 or len(requests) > 15:
        raise ValueError("authorization matrix exceeds BELTU limits")
    for step, raw_spec in enumerate(requests, start=1):
        if not isinstance(raw_spec, dict):
            continue
        observations: list[dict[str, Any]] = []
        for principal in principals:
            if not isinstance(principal, dict) or not principal.get("name"):
                raise ValueError("principal entries require name")
            spec = dict(raw_spec)
            if principal.get("session_profile"):
                spec["session_profile"] = principal["session_profile"]
            result = _request(scope, job["target"], spec, {})
            result["principal"] = str(principal["name"])
            result["expected"] = str(principal.get("expected", "unknown"))
            observations.append(result)
            _emit("authorization.response", result["final_url"], result, 0.9)
        allowed = [x for x in observations if x["expected"] == "allow"]
        denied = [x for x in observations if x["expected"] == "deny"]
        if allowed and denied:
            ref = allowed[0]
            for candidate in denied:
                same = candidate["status"] == ref["status"] and candidate["body_sha256"] == ref["body_sha256"]
                _emit("authorization.comparison", candidate["final_url"], {
                    "step": step,
                    "allow_principal": ref["principal"],
                    "deny_principal": candidate["principal"],
                    "same_response_fingerprint": same,
                    "allow_status": ref["status"],
                    "deny_status": candidate["status"],
                }, 0.82)


def run_race(scope: ScopeGuard, job: dict[str, Any]) -> None:
    spec = job.get("request")
    if not isinstance(spec, dict):
        raise ValueError("race condition testing requires a request object")
    count = bounded_int(job.get("count"), default=6, minimum=2, maximum=20, name="count")
    concurrency = bounded_int(job.get("concurrency"), default=min(6, count), minimum=2, maximum=8, name="concurrency")
    def one(_: int) -> dict[str, Any]:
        return _request(scope, job["target"], dict(spec), {})
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(one, range(count)))
    distribution: dict[str, int] = {}
    for result in results:
        key = str(result["status"])
        distribution[key] = distribution.get(key, 0) + 1
        _emit("race.response", result["final_url"], result, 0.86)
    _emit("race.summary", job["target"], {
        "requests": count, "concurrency": concurrency, "status_distribution": distribution,
        "success_responses": sum(1 for item in results if 200 <= item["status"] < 300),
        "body_fingerprints": len({item["body_sha256"] for item in results}),
    }, 0.78)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-file", required=True)
    args = parser.parse_args()
    job = _normalize_data(__import__("pathlib").Path(args.job_file).read_text(encoding="utf-8"))
    target = str(job.get("target", "")).strip()
    if not target:
        raise ValueError("job target is required")
    scope = ScopeGuard(__import__("pathlib").Path.cwd() / "config" / "scope.yaml")
    scope.allowed(target)  # validate target configuration is readable before any request
    mode = str(job.get("mode", "sequence"))
    if mode == "sequence":
        run_sequence(scope, job, kind="workflow.execution")
    elif mode == "session":
        run_sequence(scope, job, kind="session.replay")
    elif mode == "api":
        run_api(scope, job)
    elif mode == "matrix":
        run_matrix(scope, job)
    elif mode == "race":
        run_race(scope, job)
    else:
        raise ValueError(f"Unsupported HTTP worker mode: {mode}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"error": str(exc), "source": "beltu-http-worker"}), file=sys.stderr)
        raise
