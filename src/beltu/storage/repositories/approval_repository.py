from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from beltu.storage.database import Database
from beltu.storage.models.approval import ApprovalRequest


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_action_hash(decision_id: int, action_kind: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"decision_id": decision_id, "action_kind": action_kind, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


class ApprovalRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _from_row(row) -> ApprovalRequest:
        return ApprovalRequest(
            row["id"], row["decision_id"], row["scan_id"], row["action_kind"],
            row["action_hash"], row["status"], row["channel"], row["recipient"],
            row["reason"], row["requested_at"], row["expires_at"],
            row["resolved_at"], row["resolved_by"], row["token"],
        )

    def create(
        self,
        decision_id: int,
        scan_id: int,
        action_kind: str,
        action_hash: str,
        reason: str,
        *,
        channel: str = "cli",
        recipient: str | None = None,
        ttl_seconds: int = 600,
    ) -> ApprovalRequest:
        if ttl_seconds < 30:
            raise ValueError("Approval TTL must be at least 30 seconds")
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        token = secrets.token_urlsafe(18)
        with self.db.connect() as conn:
            cur = conn.execute(
                """INSERT INTO approvals
                   (decision_id, scan_id, action_kind, action_hash, status, channel,
                    recipient, reason, requested_at, expires_at, token)
                   VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)""",
                (
                    decision_id, scan_id, action_kind, action_hash, channel,
                    recipient, reason, now.isoformat(), expires.isoformat(), token,
                ),
            )
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return self._from_row(row)

    def get(self, approval_id: int) -> ApprovalRequest | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return self._from_row(row) if row else None

    def list_for_decision(self, decision_id: int) -> list[ApprovalRequest]:
        self.expire_due()
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM approvals WHERE decision_id = ? ORDER BY id DESC", (decision_id,)).fetchall()
        return [self._from_row(row) for row in rows]

    def list_pending(self, *, channel: str | None = None, recipient: str | None = None) -> list[ApprovalRequest]:
        self.expire_due()
        clauses = ["status = 'pending'"]
        params: list[Any] = []
        if channel is not None:
            clauses.append("channel = ?")
            params.append(channel)
        if recipient is not None:
            clauses.append("recipient = ?")
            params.append(recipient)
        with self.db.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM approvals WHERE {' AND '.join(clauses)} ORDER BY id ASC",
                params,
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def expire_due(self) -> int:
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE approvals SET status = 'expired', resolved_at = ?, resolved_by = 'system' "
                "WHERE status = 'pending' AND expires_at <= ?",
                (now, now),
            )
        return cur.rowcount

    def resolve(self, approval_id: int, status: str, resolved_by: str, *, token: str | None = None) -> ApprovalRequest:
        if status not in {"approved", "rejected"}:
            raise ValueError("Approval resolution must be approved or rejected")
        now = utc_now()
        expired = False
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
            if row is None:
                raise KeyError(f"Approval #{approval_id} not found")
            if row["status"] != "pending":
                raise ValueError(f"Approval #{approval_id} is already {row['status']}")
            if row["expires_at"] <= now:
                conn.execute(
                    "UPDATE approvals SET status='expired', resolved_at=?, resolved_by='system' WHERE id=?",
                    (now, approval_id),
                )
                expired = True
            elif token is not None and not secrets.compare_digest(str(row["token"]), str(token)):
                raise PermissionError("Invalid approval token")
            else:
                conn.execute(
                    "UPDATE approvals SET status=?, resolved_at=?, resolved_by=? WHERE id=?",
                    (status, now, resolved_by, approval_id),
                )
            fresh = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if expired:
            raise ValueError(f"Approval #{approval_id} has expired")
        return self._from_row(fresh)
