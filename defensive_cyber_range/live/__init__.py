"""Live Folder Mode — safe local source scanning and remediation.

The package is intentionally dependency-free so the platform can run in an
air-gapped environment with the Python standard library alone.
"""

from .scanner import LiveScanner
from .service import LiveService, ServiceError

__all__ = ["LiveScanner", "LiveService", "ServiceError"]
