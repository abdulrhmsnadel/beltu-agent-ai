from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database
from beltu.storage.models.evidence import Evidence


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _from_row(row) -> Evidence:
        return Evidence(
            row["id"], row["scan_id"], row["observation_id"], row["kind"], row["path"],
            row["sha256"], row["size_bytes"], row["mime_type"], json.loads(row["metadata_json"]), row["created_at"]
        )

    def add(self, scan_id: int, observation_id: int | None, kind: str, path: str | None, sha256: str, size_bytes: int, mime_type: str, metadata: dict[str, Any] | None = None) -> Evidence:
        if not kind.strip() or not sha256.strip():
            raise ValueError("Evidence kind and sha256 are required")
        if size_bytes < 0:
            raise ValueError("Evidence size cannot be negative")
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                """INSERT INTO evidence(scan_id, observation_id, kind, path, sha256, size_bytes, mime_type, metadata_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, observation_id, kind.strip(), path, sha256.lower(), int(size_bytes), mime_type.strip() or "application/octet-stream", json.dumps(metadata or {}, sort_keys=True), now)
            )
            row = conn.execute("SELECT * FROM evidence WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return self._from_row(row)

    def list_for_scan(self, scan_id: int) -> list[Evidence]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM evidence WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [self._from_row(r) for r in rows]

    def list_for_observation(self, observation_id: int) -> list[Evidence]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM evidence WHERE observation_id = ? ORDER BY id", (observation_id,)).fetchall()
        return [self._from_row(r) for r in rows]
