# src/app/services/security_checks/cookies.py

from __future__ import annotations
from typing import Dict, List, Tuple
import requests
from . import CheckResult

def _fetch_cookies_and_headers(url: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Perform a GET request and return (cookies, headers).
    Includes verify=False for internal development environments.
    """
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        cookies = {c.name: c.value for c in resp.cookies}
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return cookies, headers
    except Exception:
        return {}, {}

def _parse_set_cookie_headers(headers: Dict[str, str]) -> List[str]:
    """
    Extract Set-Cookie headers from normalized response headers.
    """
    set_cookie_raw = headers.get("set-cookie")
    if not set_cookie_raw:
        return []
    # requests may join multiple cookies with a comma
    return set_cookie_raw.split(", ") if ", " in set_cookie_raw else [set_cookie_raw]

def _analyze_cookie_attributes(set_cookie_headers: List[str]) -> List[Dict]:
    """
    Parses 'Set-Cookie' header lines to check for mandatory security attributes.
    """
    cookies_info = []
    for header in set_cookie_headers:
        parts = [p.strip() for p in header.split(";")]
        if not parts: continue

        name_value = parts[0]
        name = name_value.split("=", 1)[0] if "=" in name_value else name_value

        attrs: Dict[str, str] = {}
        for attr in parts[1:]:
            if "=" in attr:
                k, v = attr.split("=", 1)
                attrs[k.lower()] = v.strip()
            else:
                attrs[attr.lower()] = "true"

        cookies_info.append({"name": name, "attributes": attrs})
    return cookies_info

def run(url: str) -> List[CheckResult]:
    """
    Check cookie security attributes against the 28-item compliance list.
    Maps to Item 11 (HttpOnly/Secure) and Item 12 (SameSite).
    """
    _, headers = _fetch_cookies_and_headers(url)
    set_cookie_headers = _parse_set_cookie_headers(headers)
    cookies_info = _analyze_cookie_attributes(set_cookie_headers)

    results: List[CheckResult] = []

    if not cookies_info:
        results.append(CheckResult(
            check_type="cookies",
            name="No Cookies Set",
            severity="info",
            description="No cookies detected on this URL.",
            recommendation="Standard for static pages; ensure Secure/HttpOnly if sessions are added.",
            raw_data={"set_cookie_headers": []},
        ))
        return results

    for cookie in cookies_info:
        name = cookie["name"]
        attrs = cookie["attributes"]

        # 1) Item 11: Secure & HttpOnly flag check
        if "secure" not in attrs:
            results.append(CheckResult(
                check_type="cookies",
                name=f"Cookie '{name}' Secure flag",
                severity="critical", # Red
                description=f"Cookie '{name}' is missing the Secure attribute.",
                recommendation="Set the Secure flag to ensure cookies are only sent over HTTPS.",
                raw_data={"cookie": name},
            ))

        if "httponly" not in attrs:
            results.append(CheckResult(
                check_type="cookies",
                name=f"Cookie '{name}' HttpOnly flag",
                severity="critical", # Red
                description=f"Cookie '{name}' is missing the HttpOnly attribute.",
                recommendation="Set the HttpOnly flag to mitigate XSS script access.",
                raw_data={"cookie": name},
            ))

        # 2) Item 12: SameSite attribute check
        samesite = attrs.get("samesite")
        if not samesite or samesite.lower() not in {"lax", "strict"}:
            results.append(CheckResult(
                check_type="cookies",
                name=f"Cookie '{name}' SameSite attribute",
                severity="warning", # Yellow/Orange
                description=f"Cookie '{name}' has missing or weak SameSite attribute.",
                recommendation="Set SameSite to 'Lax' or 'Strict' to mitigate CSRF.",
                raw_data={"cookie": name, "observed": samesite},
            ))

    return results