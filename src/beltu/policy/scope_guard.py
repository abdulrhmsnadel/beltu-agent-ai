from __future__ import annotations

from pathlib import Path

import yaml

from beltu.common.exceptions import ConfigurationError, ScopeViolation


class ScopeGuard:
    """Default-deny scope checker for authorized testing targets."""

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
        return targets

    def allowed(self, target: str) -> bool:
        return target.strip().lower() in {x.strip().lower() for x in self._load()}

    def require_allowed(self, target: str) -> None:
        if not self.allowed(target):
            raise ScopeViolation(
                f"Target is not in explicit scope: {target!r}. "
                "Add it to config/scope.yaml before starting authorized testing."
            )
