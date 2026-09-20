from pathlib import Path
from fastapi.testclient import TestClient

from beltu.remote.app import create_app
from beltu.remote.auth import RemoteAuth
from beltu.remote.repository import RemoteRepository
from beltu.core.event_bus import EventBus
from beltu.storage.database import Database
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.release.audit import ReleaseAudit
from beltu.version import __version__


def seed(tmp_path: Path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "scope.yaml").write_text("targets:\n  - example.com\n", encoding="utf-8")
    db = Database(tmp_path / "data" / "beltu.db")
    db.initialize()
    target = TargetRepository(db).add("example.com")
    scan = ScanRepository(db).create(target.id)
    return db, scan


def test_release_audit_passes_defaults(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "agent.yaml").write_text("brain:\n  llm_enabled: false\nexecution:\n  external_tools_enabled: false\n", encoding="utf-8")
    (tmp_path / "config" / "remote.yaml").write_text("remote:\n  host: 127.0.0.1\n  cors_origins: []\n", encoding="utf-8")
    (tmp_path / "config" / "notifications.yaml").write_text("whatsapp:\n  enabled: false\n", encoding="utf-8")
    (tmp_path / "config" / "scope.yaml").write_text("targets: []\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    assert all(c.ok for c in ReleaseAudit(tmp_path).run())


def test_remote_auth_has_control_scope_by_default():
    auth = RemoteAuth(username="u", password="p", secret="s" * 40)
    principal = auth.verify(auth.login("u", "p"))
    assert "control" in principal.scopes


def test_chat_bridge_answers_read_only_status(tmp_path: Path):
    db, scan = seed(tmp_path)
    events = EventBus()
    RemoteRepository(db).audit(actor="test", action="seed", resource=f"scan:{scan.id}")
    app = create_app(tmp_path, event_bus=events, auth=RemoteAuth(username="u", password="p", secret="s" * 40))
    with TestClient(app) as c:
        token = c.post("/v1/auth/login", json={"username":"u","password":"p"}).json()["access_token"]
        headers={"Authorization": f"Bearer {token}"}
        r = c.post("/v1/chat/messages", headers=headers, json={"conversation_id":"c1","body":"status"})
        assert r.status_code == 200
        history = c.get("/v1/chat/c1", headers=headers).json()["items"]
        assert any("resumable scans" in x["body"] for x in history)


def test_remote_api_version_matches_package(tmp_path: Path):
    _, _ = seed(tmp_path)
    app = create_app(tmp_path, auth=RemoteAuth(username="u", password="p", secret="s" * 40))
    assert app.version == __version__
