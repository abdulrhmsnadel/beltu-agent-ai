from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
import yaml

@dataclass(frozen=True, slots=True)
class AuditCheck:
    name: str
    ok: bool
    detail: str

class ReleaseAudit:
    """Static/configuration release audit. It never contacts targets."""
    def __init__(self, project_root: str | Path):
        self.root = Path(project_root).resolve()

    def _config(self, relative: str) -> dict:
        path = self.root / relative
        if not path.exists():
            return {}
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}

    def _python_files(self) -> Iterable[Path]:
        yield from (self.root / "src").rglob("*.py")

    def run(self) -> list[AuditCheck]:
        checks: list[AuditCheck] = []
        agent = self._config("config/agent.yaml")
        remote = self._config("config/remote.yaml")
        notifications = self._config("config/notifications.yaml")
        scope = self._config("config/scope.yaml")

        external = bool((agent.get("execution") or {}).get("external_tools_enabled", False))
        brain = agent.get("brain") or {}
        llm = bool(brain.get("llm_enabled", False))
        llm_cfg = brain.get("llm") or {}
        llm_provider = str(llm_cfg.get("provider", ""))
        llm_url = str(llm_cfg.get("base_url", ""))
        gemini_cfg = llm_cfg.get("gemini") or {}
        llm_local_only = bool(llm_cfg.get("local_only", False))
        llm_key_required = bool(llm_cfg.get("api_key_required", False))
        wa = bool((notifications.get("whatsapp") or {}).get("enabled", False))
        host = (remote.get("remote") or {}).get("host", "127.0.0.1")
        cors = (remote.get("remote") or {}).get("cors_origins", [])
        targets = scope.get("targets", [])

        high_risk_approval = bool((agent.get("policy") or {}).get("high_risk_requires_approval", False))
        checks.append(AuditCheck(
            "external_tools_policy_safe",
            (not external) or (isinstance(targets, list) and high_risk_approval),
            f"external_tools_enabled={external}; explicit_scope_entries={len(targets) if isinstance(targets, list) else 'invalid'}; high_risk_requires_approval={high_risk_approval}",
        ))
        loopback_host = (urlparse(llm_url).hostname or "").lower()
        local_llm_safe = (not llm) or (llm_provider == "freetoken_local" and llm_local_only and loopback_host in {"127.0.0.1", "localhost", "::1"} and not llm_key_required)
        checks.append(AuditCheck("llm_local_only", local_llm_safe, f"provider={llm_provider!r} base_url={llm_url!r}"))
        gemini_enabled = bool(gemini_cfg.get("enabled", False))
        gemini_scrub = bool(gemini_cfg.get("scrub_before_send", False))
        gemini_key_env = str(gemini_cfg.get("api_key_env", ""))
        gemini_model = str(gemini_cfg.get("model", ""))
        gemini_forbidden = any(bool(gemini_cfg.get(name, True)) for name in (
            "allow_final_reports", "allow_exploit_payloads", "allow_poc_code",
            "allow_session_data", "allow_credentials",
        ))
        gemini_cfg_safe = (
            (not gemini_enabled)
            or (
                gemini_scrub
                and gemini_key_env == "GEMINI_API_KEY"
                and bool(gemini_model)
                and not gemini_forbidden
                and "api_key" not in gemini_cfg
            )
        )
        checks.append(AuditCheck(
            "gemini_privacy_boundary",
            gemini_cfg_safe,
            f"enabled={gemini_enabled}; scrub_before_send={gemini_scrub}; model={gemini_model!r}; "
            f"forbidden_flags_enabled={gemini_forbidden}",
        ))
        checks.append(AuditCheck(
            "gemini_key_env_only",
            (not gemini_enabled) or gemini_key_env == "GEMINI_API_KEY",
            f"api_key_env={gemini_key_env!r}; key material must remain outside repository config",
        ))
        checks.append(AuditCheck("whatsapp_default_off", not wa, f"whatsapp.enabled={wa}"))
        checks.append(AuditCheck("remote_defaults_to_loopback", host in {"127.0.0.1", "localhost", "::1"}, f"remote.host={host!r}"))
        checks.append(AuditCheck("cors_not_wildcard", "*" not in cors, f"cors_origins={cors!r}"))
        checks.append(AuditCheck("scope_default_deny", isinstance(targets, list), f"scope targets count={len(targets) if isinstance(targets,list) else 'invalid'}"))

        unsafe=[]
        for path in self._python_files():
            source=path.read_text(encoding="utf-8")
            if re.search(r"shell\s*=\s*True|os\.system\s*\(|\beval\s*\(|\bexec\s*\(|pickle\.",source):
                unsafe.append(str(path.relative_to(self.root)))
            if "yaml.load(" in source and "yaml.safe_load(" not in source:
                unsafe.append(f"{path.relative_to(self.root)}:yaml.load")
        checks.append(AuditCheck("unsafe_dynamic_execution_scan", not unsafe, "; ".join(unsafe) if unsafe else "no blocked patterns found"))
        ignore = (self.root/".gitignore").read_text(encoding="utf-8") if (self.root/".gitignore").exists() else ""
        checks.append(AuditCheck("env_is_gitignored", ".env" in ignore, "`.env` is ignored" if ".env" in ignore else "`.env` is not ignored"))
        checks.append(AuditCheck("gitignore_present", (self.root/".gitignore").exists(), "present" if (self.root/".gitignore").exists() else "missing"))
        return checks

def run_audit(project_root: str | Path = ".") -> list[AuditCheck]:
    return ReleaseAudit(project_root).run()
