from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RemoteRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add_chat(self, *, conversation_id: str, sender: str, direction: str, body: str, metadata: dict[str, Any] | None = None) -> int:
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO remote_chat_messages(conversation_id,sender,direction,body,metadata_json,created_at) VALUES(?,?,?,?,?,?)",
                (conversation_id, sender, direction, body, json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True), now),
            )
            return int(cur.lastrowid)

    def list_chat(self, conversation_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT id,conversation_id,sender,direction,body,metadata_json,created_at FROM remote_chat_messages WHERE conversation_id=? ORDER BY id DESC LIMIT ?",
                (conversation_id, min(max(1, limit), 500)),
            ).fetchall()
        out = []
        for row in reversed(rows):
            item = dict(row)
            try:
                item["metadata"] = json.loads(item.pop("metadata_json"))
            except json.JSONDecodeError:
                item["metadata"] = {}
                item.pop("metadata_json", None)
            out.append(item)
        return out

    def audit(self, *, actor: str, action: str, resource: str, metadata: dict[str, Any] | None = None) -> int:
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO remote_audit_events(actor,action,resource,metadata_json,created_at) VALUES(?,?,?,?,?)",
                (actor, action, resource, json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True), now),
            )
            return int(cur.lastrowid)
