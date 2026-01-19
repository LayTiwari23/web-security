# src/app/services/security_checks/cookies.py

from __future__ import annotations

from typing import Dict, List, Tuple

import requests

from . import CheckResult


def _fetch_cookies_and_headers(url: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Perform a GET request and return (cookies, headers).

    - cookies: dict of cookie_name -> cookie_value (from requests' cookie jar)
    - headers: response headers (normalized to lowercase keys)
    """
    resp = requests.get(url, timeout=10, allow_redirects=True)
    resp.raise_for_status()

    cookies = {c.name: c.value for c in resp.cookies}
    headers = {k.lower(): v for k, v in resp.headers.items()}
    return cookies, headers


def _parse_set_cookie_headers(headers: Dict[str, str]) -> List[str]:
    """
    Extract Set-Cookie headers. If multiple Set-Cookie headers exist,
    some servers combine them into a single header; others send multiple.
    requests will typically join multiple headers with commas, but that can
    break parsing of attributes that also contain commas.

    For a simple implementation, we just split on ', ' for now. For
    production-grade parsing, consider using 'cookies.SimpleCookie' or
    'http.cookies' from the stdlib.
    """
    set_cookie_raw = headers.get("set-cookie")
    if not set_cookie_raw:
        return []

    # Naive splitting; good enough for basic checks
    if ", " in set_cookie_raw:
        parts = set_cookie_raw.split(", ")
    else:
        parts = [set_cookie_raw]

    return parts


def _analyze_cookie_attributes(set_cookie_headers: List[str]) -> List[Dict[str, str]]:
    """
    Very simple parser for 'Set-Cookie' header lines to check attributes
    like Secure, HttpOnly, SameSite.
    Returns list of dicts: {"name": ..., "attributes": {attr_name: attr_value or True}}
    """
    cookies_info: List[Dict[str, str]] = []

    for header in set_cookie_headers:
        # Example: "sessionid=abc123; HttpOnly; Secure; SameSite=Lax"
        parts = [p.strip() for p in header.split(";")]
        if not parts:
            continue

        name_value = parts[0]
        if "=" in name_value:
            name, _ = name_value.split("=", 1)
        else:
            name = name_value

        attrs: Dict[str, str] = {}
        for attr in parts[1:]:
            if "=" in attr:
                k, v = attr.split("=", 1)
                attrs[k.lower()] = v.strip()
            else:
                attrs[attr.lower()] = "true"

        cookies_info.append(
            {
                "name": name,
                "attributes": attrs,
            }
        )

    return cookies_info


def run(url: str) -> List[CheckResult]:
    """
    Check cookie security attributes:
      - Secure
      - HttpOnly
      - SameSite
    """
    _, headers = _fetch_cookies_and_headers(url)
    set_cookie_headers = _parse_set_cookie_headers(headers)
    cookies_info = _analyze_cookie_attributes(set_cookie_headers)

    results: List[CheckResult] = []

    if not cookies_info:
        # Not necessarily a problem; some endpoints may not set cookies.
        # Return an informational finding.
        results.append(
            CheckResult(
                check_type="cookies",
                name="No Cookies Set",
                severity="low",
                description="No cookies were set by the application on the scanned URL.",
                recommendation=(
                    "If the application uses sessions or authentication, ensure that cookies are "
                    "configured securely (Secure, HttpOnly, SameSite)."
                ),
                raw_data={"set_cookie_headers": set_cookie_headers},
            )
        )
        return results

    for cookie in cookies_info:
        name = cookie["name"]
        attrs = cookie["attributes"]

        # 1) Secure flag
        if "secure" not in attrs:
            results.append(
                CheckResult(
                    check_type="cookies",
                    name=f"Cookie '{name}' Secure flag",
                    severity="high",
                    description=f"Cookie '{name}' is missing the Secure attribute.",
                    recommendation=(
                        "Set the Secure flag on cookies that contain sensitive data or session "
                        "information to ensure they are only sent over HTTPS."
                    ),
                    raw_data={"cookie": name, "attributes": attrs},
                )
            )

        # 2) HttpOnly flag
        if "httponly" not in attrs:
            results.append(
                CheckResult(
                    check_type="cookies",
                    name=f"Cookie '{name}' HttpOnly flag",
                    severity="high",
                    description=f"Cookie '{name}' is missing the HttpOnly attribute.",
                    recommendation=(
                        "Set the HttpOnly flag on session and authentication cookies to mitigate "
                        "the risk of client-side script access (e.g., XSS exfiltration)."
                    ),
                    raw_data={"cookie": name, "attributes": attrs},
                )
            )

        # 3) SameSite attribute
        samesite = attrs.get("samesite")
        if not samesite:
            results.append(
                CheckResult(
                    check_type="cookies",
                    name=f"Cookie '{name}' SameSite attribute",
                    severity="medium",
                    description=f"Cookie '{name}' is missing the SameSite attribute.",
                    recommendation=(
                        "Set the SameSite attribute to 'Lax' or 'Strict' where possible to help "
                        "mitigate CSRF attacks. If cross-site usage is required, use 'None; Secure'."
                    ),
                    raw_data={"cookie": name, "attributes": attrs},
                )
            )
        else:
            if samesite.lower() not in {"lax", "strict", "none"}:
                results.append(
                    CheckResult(
                        check_type="cookies",
                        name=f"Cookie '{name}' SameSite attribute",
                        severity="medium",
                        description=f"Cookie '{name}' SameSite attribute has a non-standard value: {samesite!r}.",
                        recommendation=(
                            "Use a valid SameSite value: 'Lax', 'Strict', or 'None'. When using 'None', "
                            "the cookie must also have the Secure attribute."
                        ),
                        raw_data={"cookie": name, "attributes": attrs},
                    )
                )
            elif samesite.lower() == "none" and "secure" not in attrs:
                results.append(
                    CheckResult(
                        check_type="cookies",
                        name=f"Cookie '{name}' SameSite=None without Secure",
                        severity="medium",
                        description=(
                            f"Cookie '{name}' has SameSite=None but is missing the Secure attribute."
                        ),
                        recommendation=(
                            "When using SameSite=None, the cookie must be marked Secure to comply "
                            "with modern browser requirements and avoid being rejected."
                        ),
                        raw_data={"cookie": name, "attributes": attrs},
                    )
                )

    return results