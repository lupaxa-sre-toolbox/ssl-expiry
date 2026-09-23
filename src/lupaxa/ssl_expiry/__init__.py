"""lupaxa.ssl_expiry — TLS certificate expiration checks."""

from __future__ import annotations

from .lookup import (
    DEFAULT_TIMEOUT,
    DEFAULT_WARN_DAYS,
    ExpiryResult,
    LeafCert,
    lookup,
    probe_certificate,
)
from .version import __version__, get_version

__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_WARN_DAYS",
    "ExpiryResult",
    "LeafCert",
    "__version__",
    "get_version",
    "lookup",
    "probe_certificate",
]
