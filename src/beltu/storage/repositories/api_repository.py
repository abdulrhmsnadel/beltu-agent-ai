
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database
from beltu.storage.models.api import ApiOperation, ApiParameter, ApiRelation


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_object(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _json_list(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return ()
    if not isinstance(parsed, list):
        return ()
    return tuple(str(x) for x in parsed if str(x).strip())


class ApiRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert_operation(
        self,
        scan_id: int,
        asset_id: int,
        endpoint_id: int | None,
        operation_key: str,
        method: str,
        path: str,
        operation_id: str | None,
        api_style: str,
        tags: tuple[str, ...],
        auth_required: bool,
        auth_schemes: tuple[str, ...],
        request_content_types: tuple[str, ...],
        response_content_types: tuple[str, ...],
        summary: str | None,
        description: str | None,
        source: str,
        confidence: float,
        metadata: dict[str, Any] | None = None,
    ) -> ApiOperation:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("API operation confidence must be between 0 and 1")
        now = utc_now()
        payload = (
            scan_id, asset_id, endpoint_id, operation_key, method.upper(), path,
            operation_id, api_style, json.dumps(list(tags), sort_keys=True), int(auth_required),
            json.dumps(list(auth_schemes), sort_keys=True), json.dumps(list(request_content_types), sort_keys=True),
            json.dumps(list(response_content_types), sort_keys=True), summary, description, source, confidence,
            json.dumps(metadata or {}, sort_keys=True), now, now,
        )
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM api_operations WHERE scan_id = ? AND operation_key = ?", (scan_id, operation_key)).fetchone()
            if row is None:
                cur = conn.execute(
                    """INSERT INTO api_operations(
                        scan_id, asset_id, endpoint_id, operation_key, method, path, operation_id, api_style,
                        tags_json, auth_required, auth_schemes_json, request_content_types_json,
                        response_content_types_json, summary, description, source, confidence, metadata_json,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    payload,
                )
                row = conn.execute("SELECT * FROM api_operations WHERE id = ?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute(
                    """UPDATE api_operations SET asset_id=?, endpoint_id=?, method=?, path=?, operation_id=?, api_style=?,
                       tags_json=?, auth_required=?, auth_schemes_json=?, request_content_types_json=?,
                       response_content_types_json=?, summary=?, description=?, source=?, confidence=MAX(confidence, ?),
                       metadata_json=?, updated_at=? WHERE id=?""",
                    (asset_id, endpoint_id, method.upper(), path, operation_id, api_style,
                     json.dumps(list(tags), sort_keys=True), int(auth_required), json.dumps(list(auth_schemes), sort_keys=True),
                     json.dumps(list(request_content_types), sort_keys=True), json.dumps(list(response_content_types), sort_keys=True),
                     summary, description, source, confidence, json.dumps(metadata or {}, sort_keys=True), now, row["id"]),
                )
                row = conn.execute("SELECT * FROM api_operations WHERE id = ?", (row["id"],)).fetchone()
        return self._operation(row)

    def upsert_parameter(
        self,
        scan_id: int,
        operation_id: int,
        name: str,
        location: str,
        required: bool,
        parameter_type: str | None,
        schema: dict[str, Any] | None,
        source: str,
        confidence: float,
        metadata: dict[str, Any] | None = None,
    ) -> ApiParameter:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("API parameter confidence must be between 0 and 1")
        now = utc_now()
        name = name.strip()
        location = location.strip().lower() or "unknown"
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM api_parameters WHERE operation_id = ? AND name = ? AND location = ?",
                (operation_id, name, location),
            ).fetchone()
            schema_json = json.dumps(schema or {}, sort_keys=True)
            metadata_json = json.dumps(metadata or {}, sort_keys=True)
            if row is None:
                cur = conn.execute(
                    """INSERT INTO api_parameters(scan_id, operation_id, name, location, required, parameter_type,
                       schema_json, source, confidence, metadata_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id, operation_id, name, location, int(required), parameter_type, schema_json, source, confidence, metadata_json, now),
                )
                row = conn.execute("SELECT * FROM api_parameters WHERE id = ?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute(
                    """UPDATE api_parameters SET required=?, parameter_type=?, schema_json=?, source=?,
                       confidence=MAX(confidence, ?), metadata_json=? WHERE id=?""",
                    (int(required), parameter_type, schema_json, source, confidence, metadata_json, row["id"]),
                )
                row = conn.execute("SELECT * FROM api_parameters WHERE id = ?", (row["id"],)).fetchone()
        return self._parameter(row)

    def add_relation(
        self, scan_id: int, from_operation_id: int, to_operation_id: int,
        relation: str, confidence: float = 1.0, basis: dict[str, Any] | None = None,
    ) -> ApiRelation:
        if from_operation_id == to_operation_id:
            raise ValueError("API operation relations cannot self-reference")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("API relation confidence must be between 0 and 1")
        now = utc_now()
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM api_relations WHERE from_operation_id = ? AND to_operation_id = ? AND relation = ?",
                (from_operation_id, to_operation_id, relation),
            ).fetchone()
            basis_json = json.dumps(basis or {}, sort_keys=True)
            if row is None:
                cur = conn.execute(
                    """INSERT INTO api_relations(scan_id, from_operation_id, to_operation_id, relation, confidence, basis_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id, from_operation_id, to_operation_id, relation, confidence, basis_json, now),
                )
                row = conn.execute("SELECT * FROM api_relations WHERE id = ?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute(
                    "UPDATE api_relations SET confidence=MAX(confidence, ?), basis_json=? WHERE id=?",
                    (confidence, basis_json, row["id"]),
                )
                row = conn.execute("SELECT * FROM api_relations WHERE id = ?", (row["id"],)).fetchone()
        return self._relation(row)

    def get_operation(self, operation_id: int) -> ApiOperation | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM api_operations WHERE id = ?", (operation_id,)).fetchone()
        return self._operation(row) if row else None

    def list_operations(self, scan_id: int) -> list[ApiOperation]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM api_operations WHERE scan_id = ? ORDER BY path, method, id", (scan_id,)).fetchall()
        return [self._operation(r) for r in rows]

    def list_parameters(self, scan_id: int) -> list[ApiParameter]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM api_parameters WHERE scan_id = ? ORDER BY operation_id, location, name, id", (scan_id,)).fetchall()
        return [self._parameter(r) for r in rows]

    def list_parameters_for_operation(self, operation_id: int) -> list[ApiParameter]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM api_parameters WHERE operation_id = ? ORDER BY location, name, id", (operation_id,)).fetchall()
        return [self._parameter(r) for r in rows]

    def list_relations(self, scan_id: int) -> list[ApiRelation]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM api_relations WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [self._relation(r) for r in rows]

    def summary(self, scan_id: int) -> dict[str, int]:
        with self.db.connect() as conn:
            operations = conn.execute("SELECT COUNT(*) FROM api_operations WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            parameters = conn.execute("SELECT COUNT(*) FROM api_parameters WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            relations = conn.execute("SELECT COUNT(*) FROM api_relations WHERE scan_id = ?", (scan_id,)).fetchone()[0]
            protected = conn.execute("SELECT COUNT(*) FROM api_operations WHERE scan_id = ? AND auth_required = 1", (scan_id,)).fetchone()[0]
            graphql = conn.execute("SELECT COUNT(*) FROM api_operations WHERE scan_id = ? AND api_style = 'graphql'", (scan_id,)).fetchone()[0]
        return {"operations": int(operations), "parameters": int(parameters), "relations": int(relations), "protected_operations": int(protected), "graphql_operations": int(graphql)}

    def context_payload(self, scan_id: int, limit: int = 200) -> dict[str, Any]:
        operations = self.list_operations(scan_id)
        parameters = self.list_parameters(scan_id)
        relations = self.list_relations(scan_id)
        by_operation: dict[int, list[dict[str, Any]]] = {}
        for item in parameters:
            by_operation.setdefault(item.operation_id, []).append({
                "id": item.id, "name": item.name, "location": item.location, "required": item.required,
                "type": item.parameter_type, "schema": item.schema, "confidence": item.confidence,
            })
        op_payload = []
        for op in operations[:limit]:
            op_payload.append({
                "id": op.id, "asset_id": op.asset_id, "endpoint_id": op.endpoint_id,
                "operation_key": op.operation_key, "method": op.method, "path": op.path,
                "operation_id": op.operation_id, "api_style": op.api_style, "tags": list(op.tags),
                "auth_required": op.auth_required, "auth_schemes": list(op.auth_schemes),
                "request_content_types": list(op.request_content_types),
                "response_content_types": list(op.response_content_types),
                "summary": op.summary, "description": op.description,
                "source": op.source, "confidence": op.confidence,
                "parameters": by_operation.get(op.id, []),
            })
        return {
            "summary": self.summary(scan_id),
            "operations": op_payload,
            "relations": [
                {"from_operation_id": r.from_operation_id, "to_operation_id": r.to_operation_id, "relation": r.relation, "confidence": r.confidence, "basis": r.basis}
                for r in relations
            ],
        }

    @staticmethod
    def _operation(row) -> ApiOperation:
        return ApiOperation(
            row["id"], row["scan_id"], row["asset_id"], row["endpoint_id"], row["operation_key"], row["method"], row["path"],
            row["operation_id"], row["api_style"], _json_list(row["tags_json"]), bool(row["auth_required"]), _json_list(row["auth_schemes_json"]),
            _json_list(row["request_content_types_json"]), _json_list(row["response_content_types_json"]), row["summary"], row["description"],
            row["source"], float(row["confidence"]), _json_object(row["metadata_json"]), row["created_at"], row["updated_at"],
        )

    @staticmethod
    def _parameter(row) -> ApiParameter:
        return ApiParameter(
            row["id"], row["scan_id"], row["operation_id"], row["name"], row["location"], bool(row["required"]), row["parameter_type"],
            _json_object(row["schema_json"]), row["source"], float(row["confidence"]), _json_object(row["metadata_json"]), row["created_at"],
        )

    @staticmethod
    def _relation(row) -> ApiRelation:
        return ApiRelation(
            row["id"], row["scan_id"], row["from_operation_id"], row["to_operation_id"], row["relation"], float(row["confidence"]),
            _json_object(row["basis_json"]), row["created_at"],
        )
