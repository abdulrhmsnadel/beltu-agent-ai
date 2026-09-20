from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class ReportPackage:
    id: int
    scan_id: int
    report_type: str
    relative_path: str
    sha256: str
    size_bytes: int
    generation_fingerprint: str
    created_at: str

@dataclass(frozen=True, slots=True)
class ReportFile:
    id: int
    package_id: int
    kind: str
    relative_path: str
    sha256: str
    size_bytes: int
    mime_type: str
    created_at: str
