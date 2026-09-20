from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from beltu.brain.llm.config import LLMConfig
from beltu.brain.llm.provider import FreeTokenLocalProvider
from beltu.execution.resource_governor import ResourceGovernor


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/models":
            payload = {"data": [{"id": "local-test-model"}]}
            body = json.dumps(payload).encode()
            self.send_response(200); self.end_headers(); self.wfile.write(body); return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_response(404); self.end_headers(); return
        _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        chunks = [
            {"choices": [{"delta": {"reasoning_content": "hidden"}}]},
            {"choices": [{"delta": {"content": "{\"summary\":"}}]},
            {"choices": [{"delta": {"content": "\"ok\",\"hypotheses\":[],\"actions\":[]}"}}]},
        ]
        for chunk in chunks:
            self.wfile.write(("data: " + json.dumps(chunk) + "\n\n").encode()); self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n"); self.wfile.flush()

    def log_message(self, *_):
        return


def test_freetoken_provider_streams_locally(tmp_path: Path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        port = server.server_address[1]
        config = LLMConfig.from_mapping({"enabled": True, "provider": "freetoken_local", "base_url": f"http://127.0.0.1:{port}/v1", "model": "auto", "stream": True, "api_key_required": False, "local_only": True})
        provider = FreeTokenLocalProvider(config)
        text, latency = provider.complete(system_prompt="s", user_prompt="u")
        assert text == '{"summary":"ok","hypotheses":[],"actions":[]}'
        assert latency >= 0
    finally:
        server.shutdown(); thread.join()


def test_freetoken_provider_rejects_non_loopback():
    config = LLMConfig.from_mapping({"provider": "freetoken_local", "base_url": "https://api.openai.com/v1"})
    try:
        FreeTokenLocalProvider(config)
    except ValueError as exc:
        assert "loopback" in str(exc)
    else:
        raise AssertionError("provider accepted a non-loopback endpoint")


def test_resource_governor_reports_tool_limits():
    governor = ResourceGovernor(2, 30, 30, 1, 0.2)
    limits = governor.tool_runtime_limits("nuclei")
    assert limits.thread_limit >= 1
    assert limits.max_parallel_processes >= 1
