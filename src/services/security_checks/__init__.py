# src/app/services/security_checks/__init__.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List
@dataclass
class CheckResult:
    """
    Normalized result for a single security check.
    """
    check_type: str          # e.g. "headers", "tls", "cookies"
    name: str                # e.g. "Strict-Transport-Security"
    severity: str            # "low" | "medium" | "high" | "critical"
    description: str
    recommendation: str
    raw_data: Dict[str, Any] | None = None
from . import cookies, headers, tls  # import your individual check modules





def run_all_checks(url: str) -> List[CheckResult]:
    """
    Orchestrator that runs all enabled security checks against the given URL
    and returns a flat list of CheckResult objects.

    Adapt the called functions/signatures to match your ported GitHub logic.
    """
    results: List[CheckResult] = []

    # Each module should expose a function like:
    #   run(url: str) -> List[CheckResult]
    # or you can adapt them here as necessary.

    # HTTP security headers checks
    results.extend(headers.run(url))

    # TLS/SSL configuration checks
    results.extend(tls.run(url))

    # Cookie security flags checks
    results.extend(cookies.run(url))

    # Add more checks as you port them over:
    # from . import xss, csrf, ...
    # results.extend(xss.run(url))
    # results.extend(csrf.run(url))

    return results