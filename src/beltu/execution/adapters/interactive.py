from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

from beltu.execution.adapters.base import ToolAdapter
from beltu.execution.models import ExecutionRequest


class JobFileAdapter(ToolAdapter):
    """Builds a bounded worker job in a private runtime file and cleans it up."""

    worker_module: str
    job_mode: str

    def _job_payload(self, request: ExecutionRequest) -> dict[str, Any]:
        options = {k: v for k, v in request.options.items() if not str(k).startswith("_")}
        payload = {"target": request.target, **options}
        payload["mode"] = self.job_mode
        return payload

    def _write_job(self, request: ExecutionRequest) -> Path:
        root = Path.cwd() / "data" / "runtime" / "jobs"
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{self.name}-{os.getpid()}-{uuid.uuid4().hex}.json"
        payload = self._job_payload(request)
        with path.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\\n")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return path

    def build_argv(self, request: ExecutionRequest) -> list[str]:
        self.validate_request(request)
        job = self._write_job(request)
        return [sys.executable, "-m", self.worker_module, "--job-file", str(job)]

    def cleanup_argv(self, argv: tuple[str, ...] | list[str]) -> None:
        values = list(argv)
        try:
            index = values.index("--job-file")
            path = Path(values[index + 1])
        except (ValueError, IndexError):
            return
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    def parse_output(self, request: ExecutionRequest, stdout: str, stderr: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict) or not row.get("kind") or not row.get("subject"):
                continue
            data = row.get("data", {})
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    data = {"value": data}
            if not isinstance(data, dict):
                data = {"value": data}
            try:
                confidence = float(row.get("confidence", 0.8))
            except (TypeError, ValueError):
                confidence = 0.8
            rows.append({
                "kind": str(row["kind"]),
                "subject": str(row["subject"]),
                "data": data,
                "source": str(row.get("source", self.name)),
                "confidence": max(0.0, min(1.0, confidence)),
            })
        return rows


class BrowserAutomationAdapter(JobFileAdapter):
    name = "browser"
    capability = "browser.automation"
    binary = sys.executable
    worker_module = "beltu.execution.workers.browser_workflow"
    job_mode = "browser"
    risk_level = "medium"
    requires_approval = True
    timeout_seconds = 300.0


class HttpWorkflowAdapter(JobFileAdapter):
    name = "http-workflow"
    capability = "http.workflow"
    binary = sys.executable
    worker_module = "beltu.execution.workers.http_workflow"
    job_mode = "sequence"
    risk_level = "medium"
    requires_approval = True
    timeout_seconds = 300.0


class SessionReplayAdapter(JobFileAdapter):
    name = "session-replay"
    capability = "session.replay"
    binary = sys.executable
    worker_module = "beltu.execution.workers.http_workflow"
    job_mode = "session"
    risk_level = "high"
    requires_approval = True
    timeout_seconds = 300.0


class ApiManipulationAdapter(JobFileAdapter):
    name = "api-manipulation"
    capability = "api.manipulation"
    binary = sys.executable
    worker_module = "beltu.execution.workers.http_workflow"
    job_mode = "api"
    risk_level = "high"
    requires_approval = True
    timeout_seconds = 300.0


class AuthorizationTestingAdapter(JobFileAdapter):
    name = "authorization-matrix"
    capability = "authorization.interactive"
    binary = sys.executable
    worker_module = "beltu.execution.workers.http_workflow"
    job_mode = "matrix"
    risk_level = "high"
    requires_approval = True
    timeout_seconds = 360.0


class BusinessLogicWorkflowAdapter(JobFileAdapter):
    name = "business-logic"
    capability = "business_logic.workflow"
    binary = sys.executable
    worker_module = "beltu.execution.workers.http_workflow"
    job_mode = "sequence"
    risk_level = "high"
    requires_approval = True
    timeout_seconds = 360.0


class RaceConditionAdapter(JobFileAdapter):
    name = "race-condition"
    capability = "race_condition.test"
    binary = sys.executable
    worker_module = "beltu.execution.workers.http_workflow"
    job_mode = "race"
    risk_level = "high"
    requires_approval = True
    timeout_seconds = 180.0
