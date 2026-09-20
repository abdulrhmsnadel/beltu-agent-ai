from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from beltu.storage.models.evidence import Evidence
from beltu.storage.repositories.evidence_repository import EvidenceRepository


class EvidenceCollector:
    """Persist bounded execution artifacts and content-address them by SHA-256."""

    def __init__(self, repository: EvidenceRepository, root: str | Path, max_bytes: int = 1_000_000) -> None:
        self.repository = repository
        self.root = Path(root)
        self.max_bytes = max(1024, int(max_bytes))

    def collect_text(self, scan_id: int, observation_id: int | None, kind: str, text: str, *, metadata: dict[str, Any] | None = None, suffix: str = ".txt") -> Evidence:
        data = text.encode("utf-8", errors="replace")[: self.max_bytes]
        return self.collect_bytes(scan_id, observation_id, kind, data, "text/plain; charset=utf-8", metadata=metadata, suffix=suffix)

    def collect_json(self, scan_id: int, observation_id: int | None, kind: str, payload: Any, *, metadata: dict[str, Any] | None = None) -> Evidence:
        data = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")[: self.max_bytes]
        return self.collect_bytes(scan_id, observation_id, kind, data, "application/json", metadata=metadata, suffix=".json")

    def collect_bytes(self, scan_id: int, observation_id: int | None, kind: str, data: bytes, mime_type: str, *, metadata: dict[str, Any] | None = None, suffix: str = ".bin") -> Evidence:
        bounded = data[: self.max_bytes]
        digest = hashlib.sha256(bounded).hexdigest()
        directory = self.root / f"scan-{scan_id}"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{digest}{suffix}"
        if not path.exists():
            path.write_bytes(bounded)
        return self.repository.add(scan_id, observation_id, kind, str(path), digest, len(bounded), mime_type, metadata)
