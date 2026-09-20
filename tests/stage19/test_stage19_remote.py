from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from beltu.common.types import Event
from beltu.core.event_bus import EventBus
from beltu.remote.app import create_app
from beltu.remote.auth import RemoteAuth
from beltu.storage.database import Database
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "scope.yaml").write_text("targets:\n  - example.com\n", encoding="utf-8")
    db = Database(tmp_path / "data" / "beltu.db")
    db.initialize()
    target = TargetRepository(db).add("example.com")
    scan = ScanRepository(db).create(target.id)
    ws = tmp_path / "data" / "targets" / "example.com" / f"scan-{scan.id}"
    (ws / "agent").mkdir(parents=True)
    (ws / "reports").mkdir()
    (ws / "agent" / "activity.log").write_text("agent event\n", encoding="utf-8")
    (ws / "reports" / "technical_findings.md").write_text("# Findings\n", encoding="utf-8")
    return tmp_path


def auth() -> RemoteAuth:
    return RemoteAuth(username="beltu", password="pw", secret="s" * 40, ttl_seconds=3600)


def client(project: Path, event_bus: EventBus | None = None) -> TestClient:
    app = create_app(project, auth=auth(), event_bus=event_bus)
    return TestClient(app)


def token(c: TestClient) -> str:
    r = c.post("/v1/auth/login", json={"username": "beltu", "password": "pw"})
    assert r.status_code == 200
    return r.json()["access_token"]


def test_auth_and_lists(project: Path):
    with client(project) as c:
        assert c.get("/v1/scans").status_code == 401
        t = token(c)
        headers = {"Authorization": f"Bearer {t}"}
        assert c.get("/v1/scans", headers=headers).status_code == 200
        assert c.get("/v1/targets", headers=headers).json()["items"][0]["value"] == "example.com"


def test_workspace_path_is_contained(project: Path):
    with client(project) as c:
        t = token(c)
        h = {"Authorization": f"Bearer {t}"}
        scan_id = c.get("/v1/scans", headers=h).json()["items"][0]["id"]
        assert c.get(f"/v1/scans/{scan_id}/files", params={"path": "agent"}, headers=h).status_code == 200
        assert c.get(f"/v1/scans/{scan_id}/files", params={"path": "../../../../"}, headers=h).status_code == 403
        assert c.get(f"/v1/scans/{scan_id}/files/content", params={"path": "agent/activity.log"}, headers=h).text == "agent event\n"


def test_chat_is_persistent_and_emits_event(project: Path):
    events = EventBus()
    seen = []

    async def handler(event: Event):
        seen.append(event)

    events.subscribe_sync("remote.chat.message", handler)
    with client(project, events) as c:
        t = token(c)
        h = {"Authorization": f"Bearer {t}"}
        response = c.post("/v1/chat/messages", headers=h, json={"conversation_id": "c1", "body": "status"})
        assert response.status_code == 200
        assert response.json()["body"] == "status"
        history = c.get("/v1/chat/c1", headers=h).json()["items"]
        assert history[0]["body"] == "status"
    assert seen and seen[0].payload["conversation_id"] == "c1"


def test_live_websocket_receives_agent_event(project: Path):
    bus = EventBus()
    with client(project, bus) as c:
        t = token(c)
        with c.websocket_connect(f"/v1/ws/events?token={t}") as ws:
            connected = ws.receive_json()
            assert connected["type"] == "remote.connected"
            import asyncio
            asyncio.run(bus.publish("agent.event", {"scan_id": 1, "status": "running"}))
            message = ws.receive_json()
            assert message["type"] == "agent.event"
            assert message["payload"]["status"] == "running"


def test_mobile_approval_flow(project: Path):
    db = Database(project / "data" / "beltu.db")
    from beltu.storage.repositories.decision_repository import DecisionRepository
    from beltu.storage.repositories.approval_repository import ApprovalRepository, canonical_action_hash
    decisions = DecisionRepository(db)
    # Match the existing repository factory shape used by the project tests.
    decision = decisions.create(
        scan_id=1,
        hypothesis_id=None,
        action_kind="http.verify",
        action_payload={"target": "example.com"},
        rationale="verify a newly observed HTTP service",
        confidence=0.8,
        risk_level="medium",
        requires_approval=True,
    )
    ar = ApprovalRepository(db)
    approval = ar.create(decision.id, 1, decision.action_kind, canonical_action_hash(decision.id, decision.action_kind, decision.action_payload), decision.rationale, channel="mobile", ttl_seconds=600)
    with client(project) as c:
        t = token(c)
        h = {"Authorization": f"Bearer {t}"}
        pending = c.get("/v1/approvals", headers=h).json()["items"]
        assert pending[0]["id"] == approval.id
        result = c.post(f"/v1/approvals/{approval.id}/approve", params={"token": approval.token}, headers=h)
        assert result.status_code == 200
        assert result.json()["status"] == "approved"
        assert c.post(f"/v1/approvals/{approval.id}/approve", params={"token": approval.token}, headers=h).status_code == 409
