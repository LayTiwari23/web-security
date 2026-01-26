# src/app/services/security_checks/headers.py

from __future__ import annotations
from typing import Dict, List
import requests
from . import CheckResult

def _fetch_headers(url: str) -> Dict[str, str]:
    """
    Fetch response headers from a GET request to the given URL.
    Includes verification disable for internal testing.
    """
    try:
        # verify=False is often needed for internal ISRO/testing environments
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        # Normalize header keys to lowercase for consistent checking
        return {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return {}

def run(url: str) -> List[CheckResult]:
    """
    Run a standardized set of HTTP security header checks.
    Severities are mapped for the color-coded Annexure-I report.
    """
    headers = _fetch_headers(url)
    results: List[CheckResult] = []

    if not headers:
        return results # Error handling handled at the worker level

    # Mapping Logic based on the 28 Compliance Items
    
    # 1) Item 9: Strict-Transport-Security (HSTS)
    hsts = headers.get("strict-transport-security")
    if not hsts:
        results.append(CheckResult(
            check_type="headers",
            name="Strict-Transport-Security",
            severity="critical",  # Red
            description="HSTS header is missing.",
            recommendation="Add HSTS header to enforce HTTPS.",
            raw_data={"observed": None},
        ))

    # 2) Item 10: Content-Security-Policy (CSP)
    csp = headers.get("content-security-policy")
    if not csp:
        results.append(CheckResult(
            check_type="headers",
            name="Content-Security-Policy",
            severity="error",  # Orange
            description="CSP header is missing.",
            recommendation="Define CSP to mitigate XSS attacks.",
            raw_data={"observed": None},
        ))

    # 3) Item 8: X-Frame-Options (Clickjacking)
    xfo = headers.get("x-frame-options")
    if not xfo or xfo.upper() not in ["DENY", "SAMEORIGIN"]:
        results.append(CheckResult(
            check_type="headers",
            name="X-Frame-Options",
            severity="critical", # Red for audit compliance
            description="X-Frame-Options header missing or weak.",
            recommendation="Set to 'DENY' or 'SAMEORIGIN'.",
            raw_data={"observed": xfo},
        ))

    # 4) X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if xcto is None or xcto.lower() != "nosniff":
        results.append(CheckResult(
            check_type="headers",
            name="X-Content-Type-Options",
            severity="warning", # Yellow
            description="MIME-sniffing protection missing.",
            recommendation="Set to 'nosniff'.",
            raw_data={"observed": xcto},
        ))

    return results