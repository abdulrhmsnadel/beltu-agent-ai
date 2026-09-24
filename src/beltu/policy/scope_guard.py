from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse

import yaml

from beltu.common.exceptions import ConfigurationError, ScopeViolation


class ScopeGuard:
    """Default-deny scope checker for authorized testing targets.

    Scope entries support exact hosts and explicit wildcard subdomain patterns.
    No implicit parent-domain expansion is performed.
    """

    def __init__(self, scope_file: str | Path) -> None:
        self.scope_file = Path(scope_file)

    def _load(self) -> list[str]:
        if not self.scope_file.exists():
            raise ConfigurationError(f"Scope file not found: {self.scope_file}")
        try:
            data = yaml.safe_load(self.scope_file.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Invalid YAML in scope file: {exc}") from exc
        targets = data.get("targets", [])
        if not isinstance(targets, list) or not all(isinstance(x, str) for x in targets):
            raise ConfigurationError("scope.yaml: 'targets' must be a list of strings")
        return [x.strip().lower() for x in targets if x.strip()]

    def allowed(self, target: str) -> bool:
        value = target.strip().lower().rstrip(".")
        return any(fnmatch(value, pattern.rstrip(".")) for pattern in self._load())

    def allowed_url(self, url: str) -> bool:
        host = (urlparse(str(url).strip()).hostname or "").rstrip(".").lower()
        return bool(host) and self.allowed(host)

    def require_allowed(self, target: str) -> None:
        if not self.allowed(target):
            raise ScopeViolation(
                f"Target is not in explicit scope: {target!r}. "
                "Add it to config/scope.yaml before starting authorized testing."
            )
