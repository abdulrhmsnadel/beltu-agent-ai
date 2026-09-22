from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from beltu.brain.llm.config import LLMConfig
from beltu.brain.llm.privacy import CloudSanitizationError, CloudPrivacyFilter
from beltu.brain.llm.provider import (
    GeminiCloudProvider,
    GeminiRateLimitError,
    GeminiSafetyBlockedError,
)
from beltu.brain.llm.router import GeminiAdvice, LLMRouter
from beltu.brain.schemas import AgentContext


class GeminiFixtureHandler(BaseHTTPRequestHandler):
    response_mode = "ok"
    requests: list[dict] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).requests.append({
            "path": self.path,
            "body": json.loads(body.decode("utf-8")),
            "api_key": self.headers.get("x-goog-api-key"),
        })
        if self.path.endswith(":generateContent"):
            if type(self).response_mode == "429":
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b'{"error":{"status":"RESOURCE_EXHAUSTED"}}')
                return
            if type(self).response_mode == "safety":
                self.send_response(200)
                body = b'{"promptFeedback":{"blockReason":"SAFETY"}}'
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200)
            payload = {
                "candidates": [{
                    "finishReason": "STOP",
                    "content": {
                        "parts": [{
                            "text": json.dumps({
                                "decision": "correct",
                                "confidence": 0.92,
                                "reason": "The local operator should verify the state transition before escalating.",
                                "focus": "state transition",
                                "recommended_capability": "business_logic.workflow",
                                "notes": ["preserve the state created by the previous step"],
                            })
                        }]
                    },
                }]
            }
            body = json.dumps(payload).encode("utf-8")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *_args):
        return


@pytest.fixture
def gemini_server():
    GeminiFixtureHandler.requests = []
    GeminiFixtureHandler.response_mode = "ok"
    server = ThreadingHTTPServer(("127.0.0.1", 0), GeminiFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1beta"
    finally:
        server.shutdown()
        thread.join()


def config_for(base_url: str) -> LLMConfig:
    return LLMConfig.from_mapping({
        "enabled": True,
        "provider": "freetoken_local",
        "gemini": {
            "enabled": True,
            "api_key_env": "GEMINI_API_KEY",
            "model": "gemini-3.8-flash",
            "base_url": base_url,
            "requests_per_minute": 15,
            "burst": 1,
            "scrub_before_send": True,
        },
    })


def test_privacy_filter_removes_secrets_and_prohibited_fields():
    policy = CloudPrivacyFilter()
    cleaned = policy.scrub_object({
        "Authorization": "Bearer SECRET_TOKEN_123456",
        "cookies": {"Cookie": "session=PRIVATE_123456"},
        "password": "supersecret",
        "final_report": "do not send this",
        "observation": "GET /orders returned 200",
    })
    encoded = json.dumps(cleaned, ensure_ascii=True)
    assert "SECRET_TOKEN" not in encoded
    assert "PRIVATE_123456" not in encoded
    assert "do not send this" not in encoded
    assert "GET /orders" in encoded


def test_privacy_filter_rejects_final_report_marker():
    with pytest.raises(CloudSanitizationError):
        CloudPrivacyFilter().ensure_allowed_text("final vulnerability report")


def test_gemini_provider_redacts_context_and_uses_env_key(gemini_server, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fixture-secret-key")
    provider = GeminiCloudProvider(config_for(gemini_server))
    context = AgentContext(
        scan_id=1,
        target="example.com",
        observations=(
            {
                "id": 10,
                "kind": "http.response",
                "subject": "https://example.com/orders",
                "data": {
                    "Authorization": "Bearer SECRET_TOKEN_123456",
                    "Cookie": "session=PRIVATE_123456",
                    "status": 200,
                },
                "source": "http-workflow",
                "confidence": 0.9,
            },
        ),
        finding_surface={"summary": {"findings": 0}, "final_report": "must not leave local host"},
    )
    raw, _, meta = provider.advise(
        context=context,
        local_draft=json.dumps({
            "summary": "Review the workflow",
            "hypotheses": [],
            "actions": [{
                "action_kind": "business_logic_workflow",
                "action_payload": {"target": "example.com", "capability": "business_logic.workflow"},
                "rationale": "Check ordering state",
                "confidence": 0.8,
                "risk_level": "high",
                "requires_approval": True,
            }],
        }),
        mode="monitor_agent",
        goal="monitor the current agent",
    )
    assert '"decision": "correct"' in raw
    sent = json.dumps(GeminiFixtureHandler.requests[-1]["body"], ensure_ascii=True)
    assert "SECRET_TOKEN_123456" not in sent
    assert "PRIVATE_123456" not in sent
    assert "must not leave local host" not in sent
    assert GeminiFixtureHandler.requests[-1]["api_key"] == "fixture-secret-key"
    assert meta["execution_authority"] == "local_operator_only"
    assert meta["tool_execution"] == "local_only"
    sent_payload = GeminiFixtureHandler.requests[-1]["body"]["contents"][0]["parts"][0]["text"]
    assert "recent_tool_sources" in sent_payload
    assert "http-workflow" in sent_payload


def test_gemini_rate_limiter_blocks_second_request(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fixture-secret-key")
    config = LLMConfig.from_mapping({
        "gemini": {
            "enabled": True,
            "requests_per_minute": 1,
            "burst": 1,
        }
    })
    provider = GeminiCloudProvider(config)
    provider._limiter.try_acquire()
    with pytest.raises(GeminiRateLimitError):
        provider._post(system_prompt="system", user_prompt="safe")


def test_gemini_safety_block_is_distinguishable(gemini_server, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fixture-secret-key")
    GeminiFixtureHandler.response_mode = "safety"
    provider = GeminiCloudProvider(config_for(gemini_server))
    with pytest.raises(GeminiSafetyBlockedError):
        provider._post(system_prompt="safe", user_prompt="safe telemetry")


def test_router_uses_gemini_advice_but_local_operator_finishes(gemini_server, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fixture-secret-key")

    class Standard:
        name = "standard"
        model = "fixture-local"

        def __init__(self):
            self.calls = []

        def complete(self, *, system_prompt: str, user_prompt: str):
            self.calls.append(user_prompt)
            if len(self.calls) == 1:
                return '{"summary":"draft","hypotheses":[],"actions":[]}', 1.0
            return '{"summary":"final","hypotheses":[],"actions":[]}', 1.0

    standard = Standard()
    router = LLMRouter(
        standard_provider=standard,
        gemini_provider=GeminiCloudProvider(config_for(gemini_server)),
        enabled=True,
    )
    result = router.complete_for_context(
        context=AgentContext(
            scan_id=1,
            target="example.com",
            observations=({"id": 1, "kind": "workflow", "subject": "checkout", "data": {}, "source": "fixture"},),
        ),
        system_prompt="Return BELTU JSON.",
        user_prompt="Current operator context.",
    )
    assert result.text == '{"summary":"final","hypotheses":[],"actions":[]}'
    assert result.gemini_advice is not None
    assert result.gemini_advice.decision == "correct"
    assert result.provider_name == "standard"
    assert len(standard.calls) == 2
    assert "Gemini cloud advisory" in standard.calls[1]
    assert result.trace is not None
    assert result.trace["gemini_status"] == "ok"
    assert result.trace["final_local_pass"] is True


def test_router_falls_back_to_local_when_gemini_hits_429(gemini_server, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fixture-secret-key")
    GeminiFixtureHandler.response_mode = "429"

    class Standard:
        name = "standard"
        model = "fixture-local"

        def __init__(self):
            self.calls = 0

        def complete(self, *, system_prompt: str, user_prompt: str):
            self.calls += 1
            return '{"summary":"local","hypotheses":[],"actions":[]}', 1.0

    standard = Standard()
    router = LLMRouter(
        standard_provider=standard,
        gemini_provider=GeminiCloudProvider(config_for(gemini_server)),
        enabled=True,
    )
    result = router.complete_for_context(
        context=AgentContext(scan_id=1, target="example.com"),
        system_prompt="Return BELTU JSON.",
        user_prompt="safe",
    )
    assert result.text.startswith('{"summary":"local"')
    assert result.gemini_advice is None
    assert result.trace is not None
    assert result.trace["gemini_status"] == "fallback_to_standard_rate_limit"
    assert standard.calls == 1


def test_router_marks_deep_security_route_for_altar_and_keeps_gemini_as_advisor():
    class Standard:
        name = "standard"
        model = "fixture-local"

        def complete(self, *, system_prompt: str, user_prompt: str):
            return '{"summary":"draft","hypotheses":[],"actions":[]}', 1.0

    decision = LLMRouter(standard_provider=Standard(), enabled=True).classify(
        AgentContext(
            scan_id=1,
            target="example.com",
            finding_surface={"code_review": {"files": ["app.py"]}},
        )
    )
    assert decision.route == "altar1"
    assert decision.gemini_mode == "monitor_agent"
