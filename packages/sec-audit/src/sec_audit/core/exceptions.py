class AuditConfigurationError(ValueError):
    """Raised when audit runtime configuration is invalid.

    Bases on ``ValueError`` (the idiomatic parent for an invalid value), not
    ``RuntimeError`` — a broad ``except RuntimeError`` in middleware or a test
    runner must not silently swallow a configuration error.
    """


class AuditImportError(AuditConfigurationError):
    """Raised when an import-string target cannot be loaded."""
