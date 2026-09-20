from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from typing import Any
from beltu.storage.database import Database
from beltu.storage.models.report import ReportFile, ReportPackage

def now() -> str:
    return datetime.now(timezone.utc).isoformat()

def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

class ReportRepository:
    def __init__(self, db: Database):
        self.db = db
    def _package(self, row):
        return ReportPackage(row['id'], row['scan_id'], row['report_type'], row['relative_path'], row['sha256'], row['size_bytes'], row['generation_fingerprint'], row['created_at'])
    def _file(self, row):
        return ReportFile(row['id'], row['package_id'], row['kind'], row['relative_path'], row['sha256'], row['size_bytes'], row['mime_type'], row['created_at'])
    def upsert_package(self, *, scan_id: int, report_type: str, relative_path: str, generation_fingerprint: str, absolute_path: str) -> ReportPackage:
        digest = file_sha256(absolute_path)
        size = __import__('os').path.getsize(absolute_path)
        ts = now()
        with self.db.connect() as conn:
            row = conn.execute('SELECT * FROM report_packages WHERE scan_id=? AND report_type=?', (scan_id, report_type)).fetchone()
            if row:
                conn.execute('UPDATE report_packages SET relative_path=?, sha256=?, size_bytes=?, generation_fingerprint=?, created_at=? WHERE id=?', (relative_path, digest, size, generation_fingerprint, ts, row['id']))
                row = conn.execute('SELECT * FROM report_packages WHERE id=?', (row['id'],)).fetchone()
            else:
                cur = conn.execute('INSERT INTO report_packages(scan_id,report_type,relative_path,sha256,size_bytes,generation_fingerprint,created_at) VALUES(?,?,?,?,?,?,?)', (scan_id, report_type, relative_path, digest, size, generation_fingerprint, ts))
                row = conn.execute('SELECT * FROM report_packages WHERE id=?', (cur.lastrowid,)).fetchone()
        return self._package(row)
    def replace_files(self, package_id: int, files: list[dict[str, Any]]) -> list[ReportFile]:
        ts = now()
        with self.db.connect() as conn:
            conn.execute('DELETE FROM report_files WHERE package_id=?', (package_id,))
            for item in files:
                conn.execute('INSERT INTO report_files(package_id,kind,relative_path,sha256,size_bytes,mime_type,created_at) VALUES(?,?,?,?,?,?,?)', (package_id, item['kind'], item['relative_path'], item['sha256'], item['size_bytes'], item['mime_type'], ts))
            rows = conn.execute('SELECT * FROM report_files WHERE package_id=? ORDER BY relative_path', (package_id,)).fetchall()
        return [self._file(row) for row in rows]
    def list_packages(self, scan_id: int) -> list[ReportPackage]:
        with self.db.connect() as conn:
            rows = conn.execute('SELECT * FROM report_packages WHERE scan_id=? ORDER BY id', (scan_id,)).fetchall()
        return [self._package(row) for row in rows]
    def list_files(self, package_id: int) -> list[ReportFile]:
        with self.db.connect() as conn:
            rows = conn.execute('SELECT * FROM report_files WHERE package_id=? ORDER BY relative_path', (package_id,)).fetchall()
        return [self._file(row) for row in rows]
