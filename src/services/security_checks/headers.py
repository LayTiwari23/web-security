# src/app/services/security_checks/headers.py

from __future__ import annotations

from typing import Dict, List

import requests

from . import CheckResult


def _fetch_headers(url: str) -> Dict[str, str]:
    """
    Fetch response headers from a GET request to the given URL.
    You can improve this (timeouts, redirects, error handling) as needed.
    """
    resp = requests.get(url, timeout=10, allow_redirects=True)
    resp.raise_for_status()
    # Normalize header keys to lowercase
    return {k.lower(): v for k, v in resp.headers.items()}


def run(url: str) -> List[CheckResult]:
    """
    Run a simple set of HTTP security header checks against `url`.
    Returns a list of CheckResult.
    """
    headers = _fetch_headers(url)
    results: List[CheckResult] = []

    # 1) Strict-Transport-Security
    if "strict-transport-security" not in headers:
        results.append(
            CheckResult(
                check_type="headers",
                name="Strict-Transport-Security",
                severity="high",
                description="HSTS header is missing.",
                recommendation=(
                    "Add 'Strict-Transport-Security' header to enforce HTTPS. "
                    "Example: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
                ),
                raw_data={"observed": None},
            )
        )

    # 2) Content-Security-Policy
    if "content-security-policy" not in headers:
        results.append(
            CheckResult(
                check_type="headers",
                name="Content-Security-Policy",
                severity="high",
                description="CSP header is missing.",
                recommendation=(
                    "Define a Content-Security-Policy header to restrict sources of scripts, "
                    "styles, images, etc., and mitigate XSS attacks."
                ),
                raw_data={"observed": None},
            )
        )

    # 3) X-Frame-Options
    xfo = headers.get("x-frame-options")
    if not xfo:
        results.append(
            CheckResult(
                check_type="headers",
                name="X-Frame-Options",
                severity="medium",
                description="X-Frame-Options header is missing.",
                recommendation=(
                    "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to protect against clickjacking."
                ),
                raw_data={"observed": xfo},
            )
        )

    # 4) X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if xcto is None or xcto.lower() != "nosniff":
        results.append(
            CheckResult(
                check_type="headers",
                name="X-Content-Type-Options",
                severity="medium",
                description="X-Content-Type-Options header is missing or not set to 'nosniff'.",
                recommendation=(
                    "Set X-Content-Type-Options to 'nosniff' to prevent MIME-sniffing."
                ),
                raw_data={"observed": xcto},
            )
        )

    # 5) Referrer-Policy
    rp = headers.get("referrer-policy")
    if not rp:
        results.append(
            CheckResult(
                check_type="headers",
                name="Referrer-Policy",
                severity="low",
                description="Referrer-Policy header is missing.",
                recommendation=(
                    "Set a Referrer-Policy header (e.g. 'no-referrer', 'strict-origin-when-cross-origin') "
                    "to control how much referrer information is sent."
                ),
                raw_data={"observed": rp},
            )
        )

    # 6) Permissions-Policy (formerly Feature-Policy)
    pp = headers.get("permissions-policy") or headers.get("feature-policy")
    if not pp:
        results.append(
            CheckResult(
                check_type="headers",
                name="Permissions-Policy",
                severity="low",
                description="Permissions-Policy (or legacy Feature-Policy) header is missing.",
                recommendation=(
                    "Add a Permissions-Policy header to limit access to powerful browser features "
                    "(camera, microphone, geolocation, etc.)."
                ),
                raw_data={"observed": pp},
            )
        )

    # 7) Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy (optional)
    coop = headers.get("cross-origin-opener-policy")
    if not coop:
        results.append(
            CheckResult(
                check_type="headers",
                name="Cross-Origin-Opener-Policy",
                severity="low",
                description="Cross-Origin-Opener-Policy header is missing.",
                recommendation=(
                    "Set Cross-Origin-Opener-Policy to 'same-origin' where appropriate to "
                    "isolate the browsing context and improve security."
                ),
                raw_data={"observed": coop},
            )
        )

    coep = headers.get("cross-origin-embedder-policy")
    if not coep:
        results.append(
            CheckResult(
                check_type="headers",
                name="Cross-Origin-Embedder-Policy",
                severity="low",
                description="Cross-Origin-Embedder-Policy header is missing.",
                recommendation=(
                    "Set Cross-Origin-Embedder-Policy to 'require-corp' or similar where appropriate "
                    "to opt into cross-origin isolation."
                ),
                raw_data={"observed": coep},
            )
        )

    return results