from __future__ import annotations

from datetime import datetime, timezone

from beltu.storage.database import Database
from beltu.storage.models.llm import LLMRun


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LLMRunRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _from_row(row) -> LLMRun:
        return LLMRun(
            row["id"], row["scan_id"], row["cycle_id"], row["provider"], row["model"],
            row["status"], row["prompt_sha256"], row["response_sha256"], float(row["latency_ms"]),
            row["response_text"], row["error"], row["created_at"],
        )

    def create(
        self,
        scan_id: int,
        cycle_id: int,
        provider: str,
        model: str,
        status: str,
        prompt_sha256: str,
        response_sha256: str,
        latency_ms: float,
        response_text: str | None,
        error: str | None,
    ) -> LLMRun:
        now = utc_now()
        # Raw model output is audit data; cap it to keep one bad provider response
        # from becoming an unbounded local artifact.
        if response_text is not None:
            response_text = response_text[:20_000]
        with self.db.connect() as conn:
            cur = conn.execute(
                """INSERT INTO llm_runs
                   (scan_id, cycle_id, provider, model, status, prompt_sha256,
                    response_sha256, latency_ms, response_text, error, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, cycle_id, provider, model, status, prompt_sha256,
                    response_sha256, float(latency_ms), response_text, error, now,
                ),
            )
            row = conn.execute("SELECT * FROM llm_runs WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return self._from_row(row)

    def get(self, run_id: int) -> LLMRun | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM llm_runs WHERE id = ?", (run_id,)).fetchone()
        return self._from_row(row) if row else None

    def list_for_scan(self, scan_id: int) -> list[LLMRun]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM llm_runs WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
        return [self._from_row(row) for row in rows]
