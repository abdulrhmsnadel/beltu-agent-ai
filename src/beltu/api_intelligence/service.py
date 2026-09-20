
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlparse

from beltu.intelligence.normalizer import host_from_url, normalize_host
from beltu.storage.database import Database
from beltu.storage.models.api import ApiOperation
from beltu.storage.repositories.api_repository import ApiRepository
from beltu.storage.repositories.asset_repository import AssetRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.intelligence.service import AssetIntelligenceService


_SENSITIVE_KEYS = re.compile(r"(?:authorization|cookie|set-cookie|token|secret|password|passwd|api[-_]?key|session|jwt|credential)", re.I)
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}


@dataclass(frozen=True, slots=True)
class ApiInventoryResult:
    operations: tuple[ApiOperation, ...]
    summary: dict[str, int]
    relations: tuple[dict[str, Any], ...]


def _clean_text(value: Any, limit: int = 600) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _string_tuple(value: Any, limit: int = 20) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return ()
    out: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return tuple(out)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if _SENSITIVE_KEYS.search(str(key)):
                result[str(key)] = "<redacted>"
            else:
                result[str(key)] = _redact(item)
        return result
    if isinstance(value, list):
        return [_redact(item) for item in value[:100]]
    if isinstance(value, tuple):
        return [_redact(item) for item in value[:100]]
    return value


def _schema_type(schema: Any) -> str | None:
    if not isinstance(schema, dict):
        return None
    value = schema.get("type")
    if isinstance(value, str):
        return value
    if "$ref" in schema:
        return "ref"
    if "oneOf" in schema:
        return "oneOf"
    if "anyOf" in schema:
        return "anyOf"
    return None


def _api_style(path: str, explicit: Any = None) -> str:
    candidate = str(explicit or "").strip().lower()
    if candidate in {"rest", "graphql", "grpc", "soap", "websocket"}:
        return candidate
    if "graphql" in path.lower():
        return "graphql"
    return "rest"


def _path_from_url(url: str, fallback: str = "/") -> tuple[str, str]:
    parsed = urlparse(url if "://" in url else "//" + url)
    host = (parsed.hostname or "").strip().lower()
    path = parsed.path or fallback
    if not path.startswith("/"):
        path = "/" + path
    return host, path


def _operation_from_item(item: dict[str, Any], *, default_host: str, source: str, confidence: float) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    url = str(item.get("url") or item.get("server_url") or "").strip()
    host, url_path = _path_from_url(url, str(item.get("path") or "/")) if url else ("", str(item.get("path") or "/"))
    host = normalize_host(host) or normalize_host(str(item.get("host") or default_host)) or default_host
    path = str(item.get("path") or url_path or "/").strip()
    if not path.startswith("/"):
        path = "/" + path
    method = str(item.get("method") or item.get("http_method") or "GET").upper()
    if method not in _METHODS:
        method = "UNKNOWN"
    params_raw = item.get("parameters", [])
    params: list[dict[str, Any]] = []
    if isinstance(params_raw, dict):
        params_raw = [
            {"name": name, "in": location, "required": bool(spec.get("required", False)), **spec}
            if isinstance(spec, dict) else {"name": name, "in": location, "required": False}
            for location, entries in params_raw.items()
            if isinstance(entries, dict)
            for name, spec in entries.items()
        ]
    if isinstance(params_raw, list):
        for param in params_raw[:200]:
            if not isinstance(param, dict):
                continue
            if "$ref" in param and not param.get("name"):
                params.append({"name": str(param.get("$ref")), "location": "ref", "required": False, "parameter_type": "ref", "schema": {"$ref": param.get("$ref")}})
                continue
            name = str(param.get("name") or "").strip()
            location = str(param.get("in") or param.get("location") or "unknown").strip().lower()
            if not name:
                continue
            schema = param.get("schema") if isinstance(param.get("schema"), dict) else {}
            params.append({
                "name": name, "location": location, "required": bool(param.get("required", False)),
                "parameter_type": _schema_type(schema) or str(param.get("type") or "") or None,
                "schema": _redact({k: v for k, v in schema.items() if k not in {"example", "examples", "default"}}),
                "metadata": {"description": _clean_text(param.get("description"), 300)},
            })
    request_body = item.get("requestBody") if isinstance(item.get("requestBody"), dict) else {}
    request_content = request_body.get("content") if isinstance(request_body.get("content"), dict) else item.get("request_content_types")
    response_content = item.get("response_content_types")
    if response_content is None and isinstance(item.get("responses"), dict):
        collected: list[str] = []
        for response in list(item["responses"].values())[:30]:
            if not isinstance(response, dict) or not isinstance(response.get("content"), dict):
                continue
            collected.extend(str(x) for x in response["content"].keys())
        response_content = collected
    security = item.get("security")
    auth_schemes = []
    if isinstance(security, list):
        for block in security[:20]:
            if isinstance(block, dict):
                auth_schemes.extend(str(k) for k in block.keys())
    auth_schemes.extend(_string_tuple(item.get("auth_schemes"), 20))
    auth_schemes = list(dict.fromkeys(x for x in auth_schemes if x))
    auth_hint = _clean_text(item.get("auth_hint") or item.get("auth"))
    auth_required = bool(item.get("auth_required", False)) or bool(security) or bool(auth_hint)
    if isinstance(item.get("headers"), dict):
        header_names = {str(k).lower() for k in item["headers"]}
        if "authorization" in header_names or "cookie" in header_names:
            auth_required = True
    workflow_hints: dict[str, Any] = {}
    for key in ("next_path", "next_endpoint", "precedes", "depends_on", "transitions"):
        if key in item:
            workflow_hints[key] = item.get(key)
    metadata = _redact({
        "servers": _string_tuple(item.get("servers"), 10),
        "deprecated": bool(item.get("deprecated", False)),
        "operation_source": item.get("source_type") or "observation",
        "workflow_hints": workflow_hints,
    })
    operation = {
        "host": host,
        "url": url or f"https://{host}{path}",
        "method": method,
        "path": path,
        "operation_id": _clean_text(item.get("operationId") or item.get("operation_id"), 200),
        "api_style": _api_style(path, item.get("api_style") or item.get("type") or item.get("endpoint_type")),
        "tags": _string_tuple(item.get("tags"), 30),
        "auth_required": auth_required,
        "auth_schemes": tuple(dict.fromkeys(auth_schemes)),
        "request_content_types": tuple(str(x) for x in (request_content.keys() if isinstance(request_content, dict) else _string_tuple(request_content, 20))),
        "response_content_types": tuple(str(x) for x in (response_content.keys() if isinstance(response_content, dict) else _string_tuple(response_content, 20))),
        "summary": _clean_text(item.get("summary"), 400),
        "description": _clean_text(item.get("description"), 800),
        "source": source,
        "confidence": confidence,
        "metadata": metadata,
    }
    # Query names are useful structure; never persist query values.
    if url and "?" in url:
        try:
            for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
                if name and not any(p["name"] == name and p["location"] == "query" for p in params):
                    params.append({"name": name, "location": "query", "required": False, "parameter_type": None, "schema": {}, "metadata": {"derived_from_url": True}})
        except Exception:
            pass
    return operation, params


class ApiIntelligenceService:
    """Build a persistent API/web structure from stored observations only.

    This stage never sends traffic and deliberately stores structure, not credential values.
    """

    def __init__(self, db: Database) -> None:
        self.db = db
        self.api = ApiRepository(db)
        self.assets = AssetRepository(db)
        self.observations = ObservationRepository(db)
        self.scans = ScanRepository(db)
        self.targets = TargetRepository(db)
        self.asset_intelligence = AssetIntelligenceService(db)

    def rebuild(self, scan_id: int) -> ApiInventoryResult:
        scan = self.scans.get(scan_id)
        if scan is None:
            raise ValueError(f"Scan #{scan_id} not found")
        target = self.targets.get(scan.target_id)
        if target is None:
            raise ValueError(f"Target #{scan.target_id} not found")
        target_host = normalize_host(target.value) or target.value.strip().lower().rstrip('.')
        # Ensure Stage 11 inventory exists; this is read/normalize/store only.
        self.asset_intelligence.rebuild(scan_id)
        operation_by_key: dict[str, ApiOperation] = {op.operation_key: op for op in self.api.list_operations(scan_id)}
        for observation in self.observations.list_for_scan(scan_id):
            data = dict(observation.data)
            structured = data.get("structured") if isinstance(data.get("structured"), dict) else {}
            generated: list[dict[str, Any]] = []
            openapi_doc = None
            for candidate in (structured.get("openapi"), structured.get("spec"), data.get("openapi"), data.get("spec"), structured if isinstance(structured.get("paths"), dict) else None):
                if isinstance(candidate, dict) and isinstance(candidate.get("paths"), dict):
                    openapi_doc = candidate
                    break
            if openapi_doc is not None:
                servers = openapi_doc.get("servers")
                server_url = None
                if isinstance(servers, list) and servers and isinstance(servers[0], dict):
                    server_url = servers[0].get("url")
                security_schemes = {}
                components = openapi_doc.get("components")
                if isinstance(components, dict) and isinstance(components.get("securitySchemes"), dict):
                    security_schemes = components["securitySchemes"]
                for path, path_item in list(openapi_doc["paths"].items())[:500]:
                    if not isinstance(path_item, dict):
                        continue
                    path_level = path_item.get("parameters", []) if isinstance(path_item.get("parameters"), list) else []
                    for method, op_spec in path_item.items():
                        if method.lower() not in {m.lower() for m in _METHODS} or not isinstance(op_spec, dict):
                            continue
                        merged = dict(op_spec)
                        own_params = list(merged.get("parameters", [])) if isinstance(merged.get("parameters"), list) else []
                        merged["parameters"] = path_level + own_params
                        if server_url:
                            merged["url"] = f"{str(server_url).rstrip('/')}{path}"
                        merged["path"] = path
                        merged["method"] = method.upper()
                        merged["security_schemes"] = security_schemes
                        if "security" not in merged and "security" in openapi_doc:
                            merged["security"] = openapi_doc.get("security")
                        generated.append({"item": merged, "source": observation.source + ":openapi", "confidence": min(1.0, observation.confidence + 0.03)})
            elif observation.kind in {"api_endpoint", "api.operation", "endpoint", "crawler.request", "openapi.operation", "web.http_probe"}:
                item = dict(structured or data)
                if observation.kind == "web.http_probe" and not any(k in item for k in ("url", "path", "method", "endpoint_type", "api_style")):
                    item = {"url": observation.subject}
                if not item.get("url") and observation.subject:
                    item["url"] = observation.subject
                generated.append({"item": item, "source": observation.source, "confidence": observation.confidence})
            elif observation.kind in {"auth", "session", "authentication"}:
                # Attach auth hints to an existing operation where possible.
                subject = observation.subject
                for op in list(operation_by_key.values()):
                    if op.path == subject or op.operation_key.endswith("|" + subject):
                        schemes = tuple(dict.fromkeys((*op.auth_schemes, *(_string_tuple(structured.get("schemes"), 10)))))
                        self.api.upsert_operation(scan_id, op.asset_id, op.endpoint_id, op.operation_key, op.method, op.path, op.operation_id, op.api_style, op.tags, True, schemes, op.request_content_types, op.response_content_types, op.summary, op.description, op.source, max(op.confidence, observation.confidence), {**op.metadata, "auth_observation": observation.id})
            if generated:
                for envelope in generated:
                    parsed = _operation_from_item(envelope["item"], default_host=target_host, source=envelope["source"], confidence=envelope["confidence"])
                    if parsed is None:
                        continue
                    item, params = parsed
                    host = normalize_host(item["host"]) or target_host
                    asset = self.assets.find(scan_id, host)
                    if asset is None:
                        asset = self.assets.find(scan_id, target_host)
                    if asset is None:
                        continue
                    operation_key = f"{host}|{item['method']}|{item['path']}"
                    endpoint_id = None
                    for endpoint in self.assets.list_endpoints(scan_id):
                        if endpoint.asset_id == asset.id and endpoint.method == item["method"] and (endpoint.url == item["url"] or endpoint.path == item["path"]):
                            endpoint_id = endpoint.id
                            break
                    op = self.api.upsert_operation(
                        scan_id, asset.id, endpoint_id, operation_key, item["method"], item["path"], item["operation_id"], item["api_style"], item["tags"],
                        item["auth_required"], item["auth_schemes"], item["request_content_types"], item["response_content_types"], item["summary"], item["description"],
                        item["source"], item["confidence"], item["metadata"],
                    )
                    operation_by_key[operation_key] = op
                    for param in params:
                        self.api.upsert_parameter(scan_id, op.id, param["name"], param["location"], param["required"], param["parameter_type"], param["schema"], item["source"], item["confidence"], param.get("metadata"))
                    self._infer_relations(scan_id, op, envelope["item"], operation_by_key)

        self._reconcile_relations(scan_id)
        operations = tuple(self.api.list_operations(scan_id))
        relations = tuple({
            "from_operation_id": r.from_operation_id,
            "to_operation_id": r.to_operation_id,
            "relation": r.relation,
            "confidence": r.confidence,
            "basis": r.basis,
        } for r in self.api.list_relations(scan_id))
        return ApiInventoryResult(operations, self.api.summary(scan_id), relations)

    def _reconcile_relations(self, scan_id: int) -> None:
        operations = {op.id: op for op in self.api.list_operations(scan_id)}
        by_path: dict[str, list[ApiOperation]] = {}
        for op in operations.values():
            by_path.setdefault(op.path, []).append(op)
        for op in operations.values():
            hints = op.metadata.get("workflow_hints", {}) if isinstance(op.metadata, dict) else {}
            if not isinstance(hints, dict):
                continue
            raw_candidates: list[tuple[str, float, str]] = []
            for key in ("next_path", "next_endpoint", "precedes", "depends_on"):
                value = hints.get(key)
                values = [value] if isinstance(value, str) else value if isinstance(value, list) else []
                for target in values:
                    if isinstance(target, str) and target.strip():
                        raw_candidates.append((target.strip(), 0.8, key))
            transitions = hints.get("transitions")
            if isinstance(transitions, list):
                for item in transitions[:100]:
                    if not isinstance(item, dict):
                        continue
                    from_path = str(item.get("from") or item.get("from_path") or "").strip()
                    to_path = str(item.get("to") or item.get("to_path") or "").strip()
                    if from_path and to_path and from_path == op.path:
                        raw_candidates.append((to_path, min(1.0, float(item.get("confidence", 0.8))), "transition"))
            for target, confidence, basis_key in raw_candidates:
                target_ops = by_path.get(target, [])
                if not target_ops:
                    target_ops = [candidate for candidate in operations.values() if candidate.operation_key.endswith("|" + target)]
                for target_op in target_ops[:5]:
                    if target_op.id == op.id:
                        continue
                    relation = "workflow_next" if basis_key in {"next_path", "next_endpoint", "transition"} else basis_key
                    self.api.add_relation(scan_id, op.id, target_op.id, relation, confidence, {"source_field": basis_key, "reconciled": True})


    def _infer_relations(self, scan_id: int, op: ApiOperation, raw: dict[str, Any], operations: dict[str, ApiOperation]) -> None:
        candidates: list[tuple[str, float, str]] = []
        for key in ("next_path", "next_endpoint", "precedes", "depends_on"):
            value = raw.get(key)
            for target in ([value] if isinstance(value, str) else value if isinstance(value, list) else []):
                if isinstance(target, str) and target.strip():
                    candidates.append((target.strip(), 0.8, key))
        transitions = raw.get("transitions")
        if isinstance(transitions, list):
            for item in transitions[:100]:
                if not isinstance(item, dict):
                    continue
                from_path = str(item.get("from") or item.get("from_path") or "").strip()
                to_path = str(item.get("to") or item.get("to_path") or "").strip()
                if from_path and to_path and from_path == op.path:
                    candidates.append((to_path, min(1.0, float(item.get("confidence", 0.8))), "transition"))
        for target, confidence, basis_key in candidates:
            target_op = None
            for candidate in operations.values():
                if candidate.path == target or candidate.operation_key.endswith("|" + target):
                    target_op = candidate
                    break
            if target_op and target_op.id != op.id:
                relation = "workflow_next" if basis_key in {"next_path", "next_endpoint", "transition"} else basis_key
                self.api.add_relation(scan_id, op.id, target_op.id, relation, confidence, {"source_field": basis_key})

    def context_payload(self, scan_id: int, limit: int = 200) -> dict[str, Any]:
        self.rebuild(scan_id)
        return self.api.context_payload(scan_id, limit=limit)
