from __future__ import annotations

from pathlib import Path
from fastapi.testclient import TestClient

from beltu.remote.app import create_app
from beltu.remote.auth import RemoteAuth
from beltu.storage.database import Database
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository


def make_project(tmp_path: Path) -> tuple[Path, int]:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "scope.yaml").write_text("targets:\n  - example.com\n", encoding="utf-8")
    db = Database(tmp_path / "data" / "beltu.db"); db.initialize()
    target = TargetRepository(db).add("example.com")
    scan = ScanRepository(db).create(target.id)
    ws = tmp_path / "data" / "targets" / "example.com" / f"scan-{scan.id}"
    (ws / "reports").mkdir(parents=True)
    (ws / "reports" / "technical.md").write_text("# test\n", encoding="utf-8")
    return tmp_path, scan.id


def test_resource_endpoint_and_file_download(tmp_path: Path):
    project, scan_id = make_project(tmp_path)
    app = create_app(project, auth=RemoteAuth(username="u", password="p", secret="s"*40))
    with TestClient(app) as c:
        token = c.post("/v1/auth/login", json={"username":"u","password":"p"}).json()["access_token"]
        headers={"Authorization": f"Bearer {token}"}
        resources = c.get("/v1/system/resources", headers=headers)
        assert resources.status_code == 200
        assert "adaptive_process_capacity" in resources.json()
        file_response = c.get(f"/v1/scans/{scan_id}/files/download", params={"path":"reports/technical.md"}, headers=headers)
        assert file_response.status_code == 200
        assert file_response.text == "# test\n"
