from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database
from beltu.storage.models.asset import Asset, AssetEndpoint, AssetRelation, AssetService, AssetTechnology


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


class AssetRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert_asset(
        self, scan_id: int, target_id: int, asset_type: str, value: str, normalized_value: str,
        source: str, confidence: float, metadata: dict[str, Any] | None = None, status: str = "discovered",
    ) -> Asset:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Asset confidence must be between 0 and 1")
        now = utc_now()
        metadata = metadata or {}
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO assets
                   (scan_id, target_id, asset_type, value, normalized_value, status, source, confidence, metadata_json, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scan_id, normalized_value, asset_type) DO UPDATE SET
                     value=excluded.value, status=excluded.status, source=excluded.source,
                     confidence=CASE WHEN excluded.confidence > assets.confidence THEN excluded.confidence ELSE assets.confidence END,
                     metadata_json=excluded.metadata_json, last_seen=excluded.last_seen""",
                (scan_id, target_id, asset_type, value, normalized_value, status, source, confidence, json.dumps(metadata, sort_keys=True), now, now),
            )
            row = conn.execute(
                "SELECT * FROM assets WHERE scan_id = ? AND asset_type = ? AND normalized_value = ?",
                (scan_id, asset_type, normalized_value),
            ).fetchone()
        return self._asset(row)

    def get(self, asset_id: int) -> Asset | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        return self._asset(row) if row else None

    def list_for_scan(self, scan_id: int) -> list[Asset]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM assets WHERE scan_id = ? ORDER BY asset_type, normalized_value", (scan_id,)).fetchall()
        return [self._asset(row) for row in rows]

    def find(self, scan_id: int, normalized_value: str, asset_type: str | None = None) -> Asset | None:
        with self.db.connect() as conn:
            if asset_type:
                row = conn.execute("SELECT * FROM assets WHERE scan_id = ? AND normalized_value = ? AND asset_type = ?", (scan_id, normalized_value, asset_type)).fetchone()
            else:
                row = conn.execute("SELECT * FROM assets WHERE scan_id = ? AND normalized_value = ? ORDER BY id LIMIT 1", (scan_id, normalized_value)).fetchone()
        return self._asset(row) if row else None

    def add_relation(self, scan_id: int, parent_asset_id: int, child_asset_id: int, relation: str, confidence: float = 1.0, metadata: dict[str, Any] | None = None) -> AssetRelation:
        if parent_asset_id == child_asset_id:
            raise ValueError("Asset relations cannot self-reference")
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO asset_relations(scan_id, parent_asset_id, child_asset_id, relation, confidence, metadata_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(parent_asset_id, child_asset_id, relation) DO UPDATE SET confidence=MAX(asset_relations.confidence, excluded.confidence), metadata_json=excluded.metadata_json""",
                (scan_id, parent_asset_id, child_asset_id, relation, confidence, json.dumps(metadata or {}, sort_keys=True), now),
            )
            row = conn.execute(
                "SELECT * FROM asset_relations WHERE parent_asset_id = ? AND child_asset_id = ? AND relation = ?",
                (parent_asset_id, child_asset_id, relation),
            ).fetchone()
        return self._relation(row)

    def relations_for_scan(self, scan_id: int) -> list[AssetRelation]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM asset_relations WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [self._relation(row) for row in rows]

    def upsert_service(self, scan_id: int, asset_id: int, transport: str, port: int, state: str, service: str | None, product: str | None, version: str | None, source: str, confidence: float, metadata: dict[str, Any] | None = None) -> AssetService:
        now = utc_now()
        with self.db.connect() as conn:
            row = conn.execute(
                """SELECT * FROM asset_services
                   WHERE asset_id = ? AND transport = ? AND port = ?
                     AND service IS ? AND product IS ? AND version IS ?""",
                (asset_id, transport, int(port), service, product, version),
            ).fetchone()
            metadata_json = json.dumps(metadata or {}, sort_keys=True)
            if row is None:
                cur = conn.execute(
                    """INSERT INTO asset_services(scan_id, asset_id, transport, port, state, service, product, version, source, confidence, metadata_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id, asset_id, transport, int(port), state, service, product, version, source, confidence, metadata_json, now),
                )
                row = conn.execute("SELECT * FROM asset_services WHERE id = ?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute(
                    "UPDATE asset_services SET state = ?, source = ?, confidence = MAX(confidence, ?), metadata_json = ? WHERE id = ?",
                    (state, source, confidence, metadata_json, row["id"]),
                )
                row = conn.execute("SELECT * FROM asset_services WHERE id = ?", (row["id"],)).fetchone()
        return self._service(row)

    def list_services(self, scan_id: int) -> list[AssetService]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM asset_services WHERE scan_id = ? ORDER BY asset_id, port", (scan_id,)).fetchall()
        return [self._service(row) for row in rows]

    def upsert_endpoint(self, scan_id: int, asset_id: int, url: str, method: str, path: str, endpoint_type: str, auth_hint: str | None, source: str, confidence: float, metadata: dict[str, Any] | None = None) -> AssetEndpoint:
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO asset_endpoints(scan_id, asset_id, url, method, path, endpoint_type, auth_hint, source, confidence, metadata_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(asset_id, url, method) DO UPDATE SET auth_hint=COALESCE(excluded.auth_hint, asset_endpoints.auth_hint), confidence=MAX(asset_endpoints.confidence, excluded.confidence), metadata_json=excluded.metadata_json""",
                (scan_id, asset_id, url, method.upper(), path, endpoint_type, auth_hint, source, confidence, json.dumps(metadata or {}, sort_keys=True), now),
            )
            row = conn.execute("SELECT * FROM asset_endpoints WHERE asset_id = ? AND url = ? AND method = ?", (asset_id, url, method.upper())).fetchone()
        return self._endpoint(row)

    def list_endpoints(self, scan_id: int) -> list[AssetEndpoint]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM asset_endpoints WHERE scan_id = ? ORDER BY asset_id, url, method", (scan_id,)).fetchall()
        return [self._endpoint(row) for row in rows]

    def upsert_technology(self, scan_id: int, asset_id: int, name: str, version: str | None, category: str | None, source: str, confidence: float, metadata: dict[str, Any] | None = None) -> AssetTechnology:
        now = utc_now()
        with self.db.connect() as conn:
            clean_name = name.strip()
            row = conn.execute(
                """SELECT * FROM asset_technologies
                   WHERE asset_id = ? AND name = ? AND version IS ? AND category IS ?""",
                (asset_id, clean_name, version, category),
            ).fetchone()
            metadata_json = json.dumps(metadata or {}, sort_keys=True)
            if row is None:
                cur = conn.execute(
                    """INSERT INTO asset_technologies(scan_id, asset_id, name, version, category, source, confidence, metadata_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id, asset_id, clean_name, version, category, source, confidence, metadata_json, now),
                )
                row = conn.execute("SELECT * FROM asset_technologies WHERE id = ?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute(
                    "UPDATE asset_technologies SET source = ?, confidence = MAX(confidence, ?), metadata_json = ? WHERE id = ?",
                    (source, confidence, metadata_json, row["id"]),
                )
                row = conn.execute("SELECT * FROM asset_technologies WHERE id = ?", (row["id"],)).fetchone()
        return self._technology(row)

    def list_technologies(self, scan_id: int) -> list[AssetTechnology]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM asset_technologies WHERE scan_id = ? ORDER BY asset_id, name", (scan_id,)).fetchall()
        return [self._technology(row) for row in rows]

    def summary(self, scan_id: int) -> dict[str, int]:
        with self.db.connect() as conn:
            assets = conn.execute("SELECT COUNT(*) FROM assets WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            services = conn.execute("SELECT COUNT(*) FROM asset_services WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            endpoints = conn.execute("SELECT COUNT(*) FROM asset_endpoints WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            technologies = conn.execute("SELECT COUNT(*) FROM asset_technologies WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            relations = conn.execute("SELECT COUNT(*) FROM asset_relations WHERE scan_id = ?", (scan_id,)).fetchone()[0]
        return {"assets": int(assets), "services": int(services), "endpoints": int(endpoints), "technologies": int(technologies), "relations": int(relations)}

    @staticmethod
    def _asset(row) -> Asset:
        return Asset(row["id"], row["scan_id"], row["target_id"], row["asset_type"], row["value"], row["normalized_value"], row["status"], row["source"], float(row["confidence"]), _json(row["metadata_json"]), row["first_seen"], row["last_seen"])

    @staticmethod
    def _relation(row) -> AssetRelation:
        return AssetRelation(row["id"], row["scan_id"], row["parent_asset_id"], row["child_asset_id"], row["relation"], float(row["confidence"]), _json(row["metadata_json"]), row["created_at"])

    @staticmethod
    def _service(row) -> AssetService:
        return AssetService(row["id"], row["scan_id"], row["asset_id"], row["transport"], int(row["port"]), row["state"], row["service"], row["product"], row["version"], row["source"], float(row["confidence"]), _json(row["metadata_json"]), row["created_at"])

    @staticmethod
    def _endpoint(row) -> AssetEndpoint:
        return AssetEndpoint(row["id"], row["scan_id"], row["asset_id"], row["url"], row["method"], row["path"], row["endpoint_type"], row["auth_hint"], row["source"], float(row["confidence"]), _json(row["metadata_json"]), row["created_at"])

    @staticmethod
    def _technology(row) -> AssetTechnology:
        return AssetTechnology(row["id"], row["scan_id"], row["asset_id"], row["name"], row["version"], row["category"], row["source"], float(row["confidence"]), _json(row["metadata_json"]), row["created_at"])
