from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from beltu.brain.llm.config import LLMConfig
from beltu.brain.llm.provider import Altar1LocalProvider
from beltu.brain.llm.router import LLMRouter
from beltu.brain.schemas import AgentContext
from beltu.execution.resource_governor import Altar1Snapshot, ResourceGovernor, ResourceSnapshot


class AltarHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/models":
            body = json.dumps({"data": [{"id": "aikido/altar-1"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_response(404)
            self.end_headers()
            return
        _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = {"choices": [{"message": {"content": '{"summary":"ok","hypotheses":[],"actions":[]}'}}]}
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        return


def test_router_keeps_general_recon_on_standard_provider():
    class FixtureProvider:
        name = "standard"
        model = "standard-model"

        def complete(self, *, system_prompt: str, user_prompt: str):
            return '{"summary":"ok","hypotheses":[],"actions":[]}', 1.0

    router = LLMRouter(standard_provider=FixtureProvider(), enabled=True)
    decision = router.classify(
        AgentContext(
            scan_id=1,
            target="example.com",
            observations=({"kind": "nmap_tool_output", "subject": "host scan"},),
        )
    )
    assert decision.route == "standard"


def test_router_selects_altar_for_code_review():
    class FixtureProvider:
        name = "standard"
        model = "standard-model"

        def complete(self, *, system_prompt: str, user_prompt: str):
            return "standard", 1.0

    altar = object.__new__(Altar1LocalProvider)
    router = LLMRouter(standard_provider=FixtureProvider(), altar_provider=altar, enabled=True)
    decision = router.classify(
        AgentContext(
            scan_id=1,
            target="example.com",
            finding_surface={"code_review": {"files": ["app.py"]}},
        )
    )
    assert decision.route == "altar1"
    assert decision.profile is not None
    assert decision.profile.name == "code_review"


def test_altar_provider_creates_activity_lease(tmp_path: Path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), AltarHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    activity_dir = tmp_path / "altar1.active"
    try:
        config = LLMConfig.from_mapping(
            {
                "enabled": True,
                "altar1": {
                    "enabled": True,
                    "base_url": f"http://127.0.0.1:{server.server_port}/v1",
                    "model": "aikido/altar-1",
                    "local_only": True,
                    "stream": False,
                    "activity_dir": str(activity_dir),
                },
            }
        )
        provider = Altar1LocalProvider(config)
        text, latency = provider.complete(system_prompt="s", user_prompt="u")
        assert '"summary":"ok"' in text
        assert latency >= 0
        assert not activity_dir.exists() or not list(activity_dir.glob("*.json"))
    finally:
        server.shutdown()
        thread.join()


def test_governor_clamps_during_active_altar_request(tmp_path: Path):
    activity_dir = tmp_path / "altar1.active"
    activity_dir.mkdir()
    (activity_dir / "request.json").write_text("{\"route\":\"exploit_proof\"}\n", encoding="utf-8")
    governor = ResourceGovernor(
        max_concurrent_processes=4,
        min_concurrent_processes=1,
        poll_interval=0.1,
        altar1_activity_dir=activity_dir,
        altar1_url="http://127.0.0.1:65530",
    )
    snap = governor.snapshot()
    assert snap.altar1 is not None
    assert snap.altar1.active is True
    assert governor.effective_capacity(snap) == 1
    limits = governor.tool_runtime_limits("nuclei")
    assert limits.thread_limit == 1
    assert limits.max_parallel_processes == 1
    assert "Altar-1 active" in limits.reason


def test_resource_snapshot_altar_field_is_optional():
    snap = ResourceSnapshot(
        timestamp=0.0,
        beltu_cpu_percent=0.0,
        beltu_memory_percent=0.0,
        host_cpu_percent=0.0,
        host_memory_percent=0.0,
        memory_total_bytes=1,
        memory_available_bytes=1,
        load1=0.0,
        cpu_count=1,
        beltu_rss_bytes=0,
        active_processes=0,
        altar1=Altar1Snapshot(False, False, False, None, None, 0.0, 0, 0, 0),
    )
    assert snap.altar1 is not None
    assert not snap.altar1.active

def test_router_prefers_deterministic_highest_priority_on_overlap():
    router = LLMRouter(enabled=True)
    context = AgentContext(
        scan_id=1,
        target="example.test",
        finding_surface={
            "code_review": True,
            "exploit_proof": True,
            "poc": "reproduction",
            "summary": "review source and validate the exploit proof",
        },
    )
    decision = router.classify(context)
    assert decision.route == "altar1"
    assert decision.profile is not None
    assert decision.profile.name == "exploit_proof"
    assert decision.score == 1.2
