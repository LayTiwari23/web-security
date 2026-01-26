# src/app/services/security_checks/tls.py

from __future__ import annotations
import socket
import ssl
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse
from . import CheckResult

@dataclass
class TLSConfig:
    protocol_version: str
    cipher_suite: Optional[str]
    certificate_issuer: str
    not_before: str
    not_after: str

def _parse_host_port(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    host = parsed.hostname or url
    port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)
    return host, port

def _check_protocol_support(host: str, port: int, version: ssl.TLSVersion) -> bool:
    """Tests if the server supports a specific legacy protocol version."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = version
    context.maximum_version = version
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False

def _get_tls_info(host: str, port: int = 443, timeout: int = 5) -> Optional[TLSConfig]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                version = ssock.version() or "unknown"
                cert = ssock.getpeercert() or {}
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return TLSConfig(
                    protocol_version=version,
                    cipher_suite=cipher[0] if cipher else None,
                    certificate_issuer=issuer.get("commonName", "Unknown"),
                    not_before=cert.get("notBefore", "unknown"),
                    not_after=cert.get("notAfter", "unknown"),
                )
    except Exception:
        return None

def run(url: str) -> List[CheckResult]:
    host, port = _parse_host_port(url)
    results: List[CheckResult] = []
    tls_info = _get_tls_info(host, port)

    if not tls_info:
        results.append(CheckResult(check_type="tls", name="TLS Connectivity", severity="high", 
                                   description="Failed to establish TLS connection.", 
                                   recommendation="Enable TLS 1.2 or 1.3.", raw_data={}))
        return results

    # 1) Item 16: Outdated Protocol Check
    legacy_found = []
    # Test for SSLv3 (Item 18 POODLE) and TLS 1.0/1.1
    if _check_protocol_support(host, port, ssl.TLSVersion.TLSv1): legacy_found.append("TLSv1.0")
    if _check_protocol_support(host, port, ssl.TLSVersion.TLSv1_1): legacy_found.append("TLSv1.1")

    if legacy_found:
        results.append(CheckResult(
            check_type="tls", name="Legacy TLS Protocols", severity="critical",
            description=f"Outdated protocols enabled: {', '.join(legacy_found)}.",
            recommendation="Disable TLS 1.0/1.1 and SSLv3. Use only TLS 1.2 or 1.3.",
            raw_data={"found": legacy_found}
        ))

    # 2) Item 17 & 23: Cipher Check
    weak_ciphers = ["NULL", "EXPORT", "RC4", "DES", "MD5", "ADH"]
    if any(weak in (tls_info.cipher_suite or "").upper() for weak in weak_ciphers):
        results.append(CheckResult(
            check_type="tls", name="Weak Cipher Suites", severity="critical",
            description=f"Insecure cipher in use: {tls_info.cipher_suite}.",
            recommendation="Disable weak ciphers (RC4, DES, MD5).",
            raw_data={"cipher": tls_info.cipher_suite}
        ))

    # 3) Item 26: Forward Secrecy
    if not any(x in (tls_info.cipher_suite or "").upper() for x in ["ECDHE", "DHE"]):
        results.append(CheckResult(
            check_type="tls", name="Forward Secrecy", severity="error",
            description="Cipher suite does not support Forward Secrecy.",
            recommendation="Enable ECDHE or DHE based cipher suites.",
            raw_data={}
        ))

    return results