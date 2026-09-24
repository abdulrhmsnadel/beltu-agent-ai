from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from beltu.brain.llm.config import LLMConfig
from beltu.brain.llm.privacy import CloudPrivacyFilter
from beltu.brain.llm.provider import (
    GeminiCloudProvider,
    GeminiRateLimitError,
    GeminiSafetyBlockedError,
)
from beltu.brain.llm.router import LLMRouter
from beltu.brain.schemas import AgentContext


def test_cloud_privacy_removes_secrets_and_prohibited_artifacts():
    context = AgentContext(
        scan_id=7,
        target="example.com",
        observations=(
            {
                "source": "httpx",
                "url": "https://example.com/account",
                "headers": {
                    "Authorization": "Bearer SECRET-ACCESS-TOKEN",
                    "Cookie": "session=SECRET-COOKIE; theme=dark",
                    "X-Api-Key": "SECRET-API-KEY",
                },
                "final_report": "do not send this",
                "confirmed_finding": {"title": "private finding"},
                "exploit_payload": "PAYLOAD-123",
            },
        ),
    )
    payload = CloudPrivacyFilter().context_payload(context)
    serialized = json.dumps(payload, ensure_ascii=True)
    assert "SECRET-ACCESS-TOKEN" not in serialized
    assert "SECRET-COOKIE" not in serialized
    assert "SECRET-API-KEY" not in serialized
    assert "do not send this" not in serialized
    assert "PAYLOAD-123" not in serialized


def test_cloud_privacy_rejects_final_report_marker():
    with pytest.raises(ValueError):
        CloudPrivacyFilter().ensure_allowed_text("final vulnerability report")


def test_gemini_rate_limiter_caps_at_configured_rpm():
    provider = GeminiCloudProvider(
        LLMConfig.from_mapping(
            {
                "gemini": {
                    "enabled": True,
                    "api_key_env": "TEST_GEMINI_API_KEY",
                    "requests_per_minute": 15,
                    "burst": 1,
                }
            }
        )
    )
    limiter = provider._limiter
    for _ in range(15):
        assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False


class GeminiHandler(BaseHTTPRequestHandler):
    mode = "ok"
    last_body: dict = {}
    last_api_key: str | None = None

    def do_POST(self):
        if not self.path.endswith(":generateContent"):
            self.send_response(404)
            self.end_headers()
            return
        GeminiHandler.last_api_key = self.headers.get("x-goog-api-key")
        size = int(self.headers.get("Content-Length", "0"))
        GeminiHandler.last_body = json.loads(self.rfile.read(size).decode())
        if GeminiHandler.mode == "429":
            body = b'{"error":{"code":429,"message":"quota"}}'
            self.send_response(429)
        elif GeminiHandler.mode == "safety":
            body = json.dumps({"promptFeedback": {"blockReason": "SAFETY"}}).encode()
            self.send_response(200)
        else:
            body = json.dumps(
                {
                    "candidates": [
                        {
                            "content": {
                                "parts": [
                                    {
                                        "text": json.dumps(
                                            {
                                                "decision": "continue",
                                                "confidence": 0.9,
                                                "reason": "state is consistent",
                                                "focus": "continue mapped workflow",
                                                "recommended_capability": "http.workflow",
                                                "notes": [],
                                                "suggestions": [],
                                                "alternative_hypotheses": [],
                                                "missing_evidence": [],
                                            }
                                        )
                                    }
                                ]
                            },
                            "finishReason": "STOP",
                        }
                    ]
                }
            ).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        return


def _gemini_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), GeminiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _config(server_port: int) -> LLMConfig:
    return LLMConfig.from_mapping(
        {
            "gemini": {
                "enabled": True,
                "api_key_env": "TEST_GEMINI_API_KEY",
                "model": "gemini-3.8-flash",
                "base_url": f"http://127.0.0.1:{server_port}/v1beta",
                "timeout_seconds": 5,
                "requests_per_minute": 15,
                "scrub_before_send": True,
                "allow_final_reports": False,
                "allow_exploit_payloads": False,
                "allow_poc_code": False,
                "allow_session_data": False,
                "allow_credentials": False,
            }
        }
    )


def test_gemini_provider_sends_sanitized_context(monkeypatch):
    server, thread = _gemini_server()
    monkeypatch.setenv("TEST_GEMINI_API_KEY", "fixture-key")
    GeminiHandler.mode = "ok"
    try:
        provider = GeminiCloudProvider(_config(server.server_port))
        context = AgentContext(
            scan_id=1,
            target="example.com",
            observations=(
                {
                    "source": "httpx",
                    "url": "https://example.com/me",
                    "headers": {
                        "Authorization": "Bearer SECRET",
                        "Cookie": "session=COOKIESECRET",
                    },
                },
            ),
        )
        raw, latency, meta = provider.advise(
            context=context,
            local_draft='{"summary":"ok","hypotheses":[],"actions":[]}',
            mode="monitor_recon",
            goal="monitor the agent and suggest a next bounded capability",
        )
        assert "continue" in raw
        assert latency >= 0
        assert meta["execution_authority"] == "local_operator_only"
        serialized = json.dumps(GeminiHandler.last_body)
        assert "SECRET" not in serialized
        assert "COOKIESECRET" not in serialized
        assert GeminiHandler.last_api_key == "fixture-key"
    finally:
        server.shutdown()
        thread.join()


def test_gemini_provider_classifies_http_429_as_rate_limit(monkeypatch):
    server, thread = _gemini_server()
    monkeypatch.setenv("TEST_GEMINI_API_KEY", "fixture-key")
    GeminiHandler.mode = "429"
    try:
        provider = GeminiCloudProvider(_config(server.server_port))
        with pytest.raises(GeminiRateLimitError):
            provider._post(system_prompt="system", user_prompt="safe context")
    finally:
        server.shutdown()
        thread.join()


def test_gemini_provider_classifies_safety_block(monkeypatch):
    server, thread = _gemini_server()
    monkeypatch.setenv("TEST_GEMINI_API_KEY", "fixture-key")
    GeminiHandler.mode = "safety"
    try:
        provider = GeminiCloudProvider(_config(server.server_port))
        with pytest.raises(GeminiSafetyBlockedError):
            provider._post(system_prompt="system", user_prompt="safe context")
    finally:
        server.shutdown()
        thread.join()


def test_router_falls_back_to_standard_on_gemini_rate_limit():
    class Standard:
        name = "standard"
        model = "local"

        def complete(self, *, system_prompt: str, user_prompt: str):
            return '{"summary":"local","hypotheses":[],"actions":[]}', 1.0

    class GeminiBlocked:
        name = "gemini_cloud"
        model = "gemini-3.8-flash"

        def advise(self, **kwargs):
            raise GeminiRateLimitError("local rate limit")

    router = LLMRouter(
        standard_provider=Standard(),
        gemini_provider=GeminiBlocked(),
        enabled=True,
    )
    result = router.complete_for_context(
        context=AgentContext(
            scan_id=1,
            target="example.com",
            observations=({"source": "nuclei", "kind": "tool_output", "subject": "ok"},),
        ),
        system_prompt="system",
        user_prompt="user",
    )
    assert result.provider_name == "standard"
    assert result.gemini_advice is None
    assert result.trace is not None
    assert result.trace["gemini_status"] == "fallback_to_standard_rate_limit"


def test_shell_scripts_parse_with_bash():
    scripts = [
        "scripts/install.sh",
        "scripts/install_local_ai.sh",
        "scripts/start_local_ai.sh",
        "scripts/start_altar1.sh",
        "scripts/stop_local_ai.sh",
        "scripts/stop_altar1.sh",
        "scripts/backup.sh",
        "scripts/release.sh",
    ]
    import subprocess
    for script in scripts:
        result = subprocess.run(["bash", "-n", script], capture_output=True, text=True)
        assert result.returncode == 0, f"{script}: {result.stderr}"


def test_start_scripts_require_loopback_and_local_models():
    # Documentation-level regression guard: launcher defaults remain local-only.
    altar = Path("scripts/start_altar1.sh").read_text(encoding="utf-8")
    freetoken = Path("scripts/start_local_ai.sh").read_text(encoding="utf-8")
    assert "Refusing non-loopback Altar-1 host" in altar
    assert "Refusing non-loopback FreeToken host" in freetoken
    assert "HF_HUB_OFFLINE=1" in altar
    assert "BELTU_ALTAR1_MODEL_PATH" in altar
    assert "BELTU_FREETOKEN_MODEL" in freetoken
