from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any

from beltu.reporting.engine import safe_slug
from beltu.storage.database import Database


class WorkspaceService:
    def __init__(self, db: Database, project_root: str | Path) -> None:
        self.db = db
        self.project_root = Path(project_root).resolve()
        self.targets_root = (self.project_root / "data" / "targets").resolve()

    def workspace_root(self, scan_id: int) -> Path:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT s.id, t.value FROM scans s JOIN targets t ON t.id=s.target_id WHERE s.id=?",
                (scan_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown scan: {scan_id}")
        return (self.targets_root / safe_slug(row["value"]) / f"scan-{scan_id}").resolve()

    @staticmethod
    def _safe_child(root: Path, relative_path: str) -> Path:
        rel = relative_path.strip().lstrip("/")
        candidate = (root / rel).resolve()
        if candidate != root and root not in candidate.parents:
            raise PermissionError("Path escapes workspace")
        return candidate

    def list_path(self, scan_id: int, relative_path: str = "") -> list[dict[str, Any]]:
        root = self.workspace_root(scan_id)
        if not root.exists():
            return []
        path = self._safe_child(root, relative_path)
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(relative_path or "/")
        items = []
        for child in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            stat = child.stat()
            items.append({"name": child.name, "path": child.relative_to(root).as_posix(), "type": "directory" if child.is_dir() else "file", "size_bytes": stat.st_size if child.is_file() else 0, "mime_type": mimetypes.guess_type(child.name)[0] if child.is_file() else None})
        return items

    def read_file(self, scan_id: int, relative_path: str, max_bytes: int = 2_000_000) -> tuple[Path, bytes, str]:
        root = self.workspace_root(scan_id)
        path = self._safe_child(root, relative_path)
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(relative_path)
        stat = path.stat()
        if stat.st_size > max_bytes:
            raise ValueError("File exceeds remote preview limit")
        data = path.read_bytes()
        return path, data, mimetypes.guess_type(path.name)[0] or "application/octet-stream"
