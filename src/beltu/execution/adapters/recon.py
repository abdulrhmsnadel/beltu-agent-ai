from __future__ import annotations

from beltu.execution.adapters.base import ToolAdapter
from beltu.execution.models import ExecutionRequest
from beltu.execution.normalizers import normalize_jsonl_or_lines


def _line_observations(kind: str, source: str, stdout: str, subject_filter=None):
    rows = []
    for raw in stdout.splitlines():
        value = raw.strip()
        if not value or value.startswith("["):
            continue
        if subject_filter and not subject_filter(value):
            continue
        rows.append({
            "kind": kind,
            "subject": value,
            "data": {"raw": value},
            "source": source,
            "confidence": 0.9,
        })
    return rows


class SubfinderAdapter(ToolAdapter):
    name = "subfinder"
    capability = "asset.discovery.subdomains"
    binary = "subfinder"
    risk_level = "low"

    def build_argv(self, request: ExecutionRequest) -> list[str]:
        self.validate_request(request)
        return [self.binary, "-d", request.target, "-silent", "-t", str(self.runtime_threads(request, 8))]

    def parse_output(self, request, stdout, stderr):
        return _line_observations("asset.subdomain", self.name, stdout)


class AssetfinderAdapter(ToolAdapter):
    name = "assetfinder"
    capability = "asset.discovery.subdomains"
    binary = "assetfinder"
    risk_level = "low"

    def build_argv(self, request):
        self.validate_request(request)
        return [self.binary, "--subs-only", request.target]

    def parse_output(self, request, stdout, stderr):
        return _line_observations("asset.subdomain", self.name, stdout)


class AmassPassiveAdapter(ToolAdapter):
    name = "amass-passive"
    capability = "asset.discovery.subdomains"
    binary = "amass"
    risk_level = "low"

    def build_argv(self, request):
        self.validate_request(request)
        return [self.binary, "enum", "-passive", "-d", request.target]

    def parse_output(self, request, stdout, stderr):
        return _line_observations("asset.subdomain", self.name, stdout)


class HttpxAdapter(ToolAdapter):
    name = "httpx"
    capability = "web.verify"
    binary = "httpx"
    risk_level = "medium"
    requires_approval = True

    def build_argv(self, request):
        self.validate_request(request)
        return [self.binary, "-silent", "-json", "-u", request.target, "-t", str(self.runtime_threads(request, 8))]

    def parse_output(self, request, stdout, stderr):
        return normalize_jsonl_or_lines("web.http_probe", self.name, stdout, confidence=0.85)


class NmapAdapter(ToolAdapter):
    name = "nmap"
    capability = "service.discovery"
    binary = "nmap"
    risk_level = "medium"
    requires_approval = True
    timeout_seconds = 300.0

    def build_argv(self, request):
        self.validate_request(request)
        top_ports = str(request.options.get("top_ports", 1000))
        if not top_ports.isdigit() or int(top_ports) < 1 or int(top_ports) > 10000:
            raise ValueError("top_ports must be an integer between 1 and 10000")
        threads = self.runtime_threads(request, 4)
        return [self.binary, "-Pn", "-sT", "--max-parallelism", str(max(1, min(threads, 20))), "--top-ports", top_ports, request.target]

    def parse_output(self, request, stdout, stderr):
        return _line_observations("service.scan_output", self.name, stdout)


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    capability = "web.vulnerability_detection"
    binary = "nuclei"
    risk_level = "high"
    requires_approval = True
    timeout_seconds = 600.0

    def build_argv(self, request):
        self.validate_request(request)
        return [self.binary, "-u", request.target, "-jsonl", "-silent", "-c", str(self.runtime_threads(request, 8))]

    def parse_output(self, request, stdout, stderr):
        return normalize_jsonl_or_lines("finding.candidate", self.name, stdout, confidence=0.8)
