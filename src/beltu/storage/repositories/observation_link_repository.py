from __future__ import annotations

from datetime import datetime, timezone

from beltu.storage.database import Database
from beltu.storage.models.evidence import ObservationLink


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ObservationLinkRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _from_row(row) -> ObservationLink:
        return ObservationLink(row["id"], row["scan_id"], row["observation_id"], row["related_observation_id"], row["relation"], float(row["score"]), row["created_at"])

    def upsert(self, scan_id: int, observation_id: int, related_observation_id: int, relation: str, score: float) -> ObservationLink:
        if observation_id == related_observation_id:
            raise ValueError("Observation cannot link to itself")
        if not 0.0 <= score <= 1.0:
            raise ValueError("Link score must be between 0 and 1")
        relation = relation.strip()
        if not relation:
            raise ValueError("Relation is required")
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO observation_links(scan_id, observation_id, related_observation_id, relation, score, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(observation_id, related_observation_id, relation)
                   DO UPDATE SET score=excluded.score""",
                (scan_id, observation_id, related_observation_id, relation, score, now)
            )
            row = conn.execute(
                "SELECT * FROM observation_links WHERE observation_id = ? AND related_observation_id = ? AND relation = ?",
                (observation_id, related_observation_id, relation)
            ).fetchone()
        return self._from_row(row)

    def list_for_observation(self, observation_id: int) -> list[ObservationLink]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM observation_links WHERE observation_id = ? ORDER BY score DESC, id",
                (observation_id,)
            ).fetchall()
        return [self._from_row(r) for r in rows]
