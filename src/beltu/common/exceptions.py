class BeltuError(Exception):
    """Base exception for BELTU."""


class ScopeViolation(BeltuError):
    """Raised when an operation targets something outside configured scope."""


class ConfigurationError(BeltuError):
    """Raised for invalid BELTU configuration."""
