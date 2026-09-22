from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from beltu.execution.adapters.base import ToolAdapter
from beltu.execution.adapters.interactive import HttpWorkflowAdapter
from beltu.execution.capability_dispatcher import CapabilityDispatcher
from beltu.execution.models import ExecutionRequest
from beltu.execution.process_manager import ProcessResult
from beltu.execution.registry.capability_registry import CapabilityRegistry
from beltu.execution.registry.tool_registry import ToolRegistry
from beltu.execution.workers.common import redact_text, scope_url
from beltu.execution.workers.http_workflow import run_api, run_matrix, run_race, run_sequence
from beltu.policy.scope_guard import ScopeGuard
from beltu.storage.database import Database
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/workflow"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = b'{"id":"123","status":"ok","token":"supersecret123456789"}'
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/protected"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = b'{"allowed":true}'
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        body = b'{"id":"456","accepted":true}'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


@pytest.fixture
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


def test_scope_supports_exact_and_explicit_wildcard(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "targets:\n  - example.com\n  - '*.example.org'\n",
        encoding="utf-8",
    )
    scope = ScopeGuard(scope_file)
    assert scope.allowed("example.com")
    assert scope.allowed("api.example.org")
    assert not scope.allowed("evil-example.org")
    assert not scope.allowed("other.com")


def test_redaction_removes_auth_cookie_and_token_material():
    raw = "Authorization: Bearer SUPERSECRET123456789\nCookie: session=PRIVATESESSION123456789\ntoken=ANOTHERSECRET123456"
    safe = redact_text(raw)
    assert "SUPERSECRET" not in safe
    assert "PRIVATESESSION" not in safe
    assert "ANOTHERSECRET" not in safe
    assert "<REDACTED>" in safe


def test_http_workflow_is_bounded_and_redacts_url_and_body(http_server, tmp_path, capsys):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("targets:\n  - 127.0.0.1\n", encoding="utf-8")
    scope = ScopeGuard(scope_file)
    run_sequence(
        scope,
        {
            "target": "127.0.0.1",
            "requests": [
                {
                    "method": "GET",
                    "url": f"{http_server}/workflow?secret=secretvalue",
                    "assert": {"status": 200, "body_contains": "123"},
                    "extract": {"item_id": {"json_path": "id"}},
                }
            ],
        },
        kind="workflow.execution",
    )
    output = capsys.readouterr().out
    assert "secretvalue" not in output
    assert "SUPERSECRET" not in output
    assert "workflow.execution" in output
    assert scope_url(scope, http_server + "/workflow") == http_server + "/workflow"


def test_api_mutation_emits_each_controlled_mutation(http_server, tmp_path, capsys):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("targets:\n  - 127.0.0.1\n", encoding="utf-8")
    scope = ScopeGuard(scope_file)
    run_api(
        scope,
        {
            "target": "127.0.0.1",
            "request": {
                "method": "POST",
                "url": http_server + "/mutate",
                "json_body": {"quantity": 1},
            },
            "mutations": [
                {"location": "json", "name": "quantity", "value": 0},
                {"location": "json", "name": "quantity", "value": 2},
            ],
        },
    )
    output = capsys.readouterr().out
    assert output.count("api.manipulation_result") == 2
    assert '"mutation_index": 1' in output
    assert '"mutation_index": 2' in output


def test_authorization_matrix_compares_principals(http_server, tmp_path, capsys):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("targets:\n  - 127.0.0.1\n", encoding="utf-8")
    scope = ScopeGuard(scope_file)
    run_matrix(
        scope,
        {
            "target": "127.0.0.1",
            "principals": [
                {"name": "admin", "expected": "allow"},
                {"name": "guest", "expected": "deny"},
            ],
            "requests": [{"method": "GET", "url": http_server + "/protected"}],
        },
    )
    output = capsys.readouterr().out
    assert "authorization.response" in output
    assert "authorization.comparison" in output
    assert "same_response_fingerprint" in output


def test_race_worker_enforces_request_and_concurrency_bounds(http_server, tmp_path, capsys):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("targets:\n  - 127.0.0.1\n", encoding="utf-8")
    scope = ScopeGuard(scope_file)
    run_race(
        scope,
        {
            "target": "127.0.0.1",
            "request": {"method": "GET", "url": http_server + "/workflow"},
            "count": 4,
            "concurrency": 4,
        },
    )
    output = capsys.readouterr().out
    assert "race.summary" in output
    with pytest.raises(ValueError):
        run_race(
            scope,
            {
                "target": "127.0.0.1",
                "request": {"method": "GET", "url": http_server + "/workflow"},
                "count": 21,
                "concurrency": 8,
            },
        )


def test_job_adapter_cleans_private_job_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    adapter = HttpWorkflowAdapter()
    request = ExecutionRequest(
        scan_id=1,
        target="example.com",
        capability="http.workflow",
        options={"requests": [{"method": "GET", "url": "https://example.com/"}]},
    )
    argv = adapter.build_argv(request)
    job_path = Path(argv[-1])
    assert job_path.exists()
    payload = json.loads(job_path.read_text(encoding="utf-8"))
    assert payload["mode"] == "sequence"
    assert payload["target"] == "example.com"
    adapter.cleanup_argv(argv)
    assert not job_path.exists()


class ApprovalAdapter(ToolAdapter):
    name = "fixture-http"
    capability = "http.workflow"
    binary = "fixture"
    risk_level = "medium"
    requires_approval = True

    def build_argv(self, request):
        return ["fixture", request.target]

    def parse_output(self, request, stdout, stderr):
        return [{
            "kind": "http.response",
            "subject": request.target,
            "data": {"status": 200},
            "source": self.name,
            "confidence": 0.9,
        }]


class FakeGovernor:
    monitor = None

    def tool_runtime_limits(self, tool_name):
        return SimpleNamespace(thread_limit=1, max_parallel_processes=1, affinity_cpus=(), reason="fixture")

    async def acquire_process(self):
        return None

    def release_process(self):
        return None


class FakeProcessManager:
    async def run(self, argv, timeout_seconds, **_kwargs):
        return ProcessResult(tuple(argv), 0, "", "", 0.01, False, None, None)


def test_dispatcher_accepts_verified_approval_and_rejects_unverified(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    target = TargetRepository(db).add("example.com")
    scan = ScanRepository(db).create(target.id)

    tools = ToolRegistry()
    tools.register(ApprovalAdapter())
    registry = CapabilityRegistry(tools)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("targets:\n  - example.com\n", encoding="utf-8")

    dispatcher = CapabilityDispatcher(
        ScopeGuard(scope_file),
        registry,
        FakeProcessManager(),
        FakeGovernor(),
        ObservationRepository(db),
        ScanRepository(db),
        TargetRepository(db),
    )
    request = ExecutionRequest(scan.id, "example.com", "http.workflow")
    with pytest.raises(PermissionError):
        asyncio.run(dispatcher.execute(request))

    approved = ExecutionRequest(scan.id, "example.com", "http.workflow", approval_verified=True)
    result = asyncio.run(dispatcher.execute(approved))
    assert result.succeeded
    assert result.tool == "fixture-http"
    assert result.observations[0]["kind"] == "http.response"
