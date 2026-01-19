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
    certificate_subject: str
    certificate_issuer: str
    not_before: str
    not_after: str


def _parse_host_port(url: str) -> tuple[str, int]:
    """
    Extract host and port from a URL.
    Defaults to 443 for HTTPS and 80 for HTTP (but we mostly care about HTTPS).
    """
    parsed = urlparse(url)
    host = parsed.hostname or url
    if parsed.port:
        port = parsed.port
    else:
        port = 443 if parsed.scheme == "https" else 80
    return host, port


def _get_tls_info(host: str, port: int = 443, timeout: int = 5) -> Optional[TLSConfig]:
    """
    Open an SSL/TLS connection and extract some basic information:
      - Protocol version
      - Cipher suite
      - Certificate subject/issuer
      - Validity period
    Returns None on failure (e.g., cannot connect).
    """
    context = ssl.create_default_context()
    # You can tweak this to be more strict/lenient as needed
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cipher = ssock.cipher()
            version = ssock.version() or "unknown"

            cert = ssock.getpeercert()
            if not cert:
                return None

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            not_before = cert.get("notBefore", "unknown")
            not_after = cert.get("notAfter", "unknown")

            return TLSConfig(
                protocol_version=version,
                cipher_suite=cipher[0] if cipher else None,
                certificate_subject=subject.get("commonName", ""),
                certificate_issuer=issuer.get("commonName", ""),
                not_before=not_before,
                not_after=not_after,
            )


def run(url: str) -> List[CheckResult]:
    """
    Basic TLS/SSL configuration checks.
    These are intentionally simple and not a full TLS scanner
    (like testssl.sh or SSL Labs), but still useful for a quick look.
    """
    host, port = _parse_host_port(url)
    results: List[CheckResult] = []

    try:
        tls_info = _get_tls_info(host, port)
    except (OSError, ssl.SSLError) as e:
        results.append(
            CheckResult(
                check_type="tls",
                name="TLS Connection",
                severity="high",
                description=f"Failed to establish TLS connection to {host}:{port}.",
                recommendation=(
                    "Ensure the host is reachable over HTTPS and has a valid TLS configuration. "
                    "Check firewall, certificate configuration, and supported protocols."
                ),
                raw_data={"error": str(e)},
            )
        )
        return results

    if not tls_info:
        results.append(
            CheckResult(
                check_type="tls",
                name="TLS Certificate",
                severity="high",
                description="Could not retrieve TLS certificate from server.",
                recommendation=(
                    "Ensure the server presents a valid TLS certificate and supports modern "
                    "protocols like TLS 1.2+."
                ),
                raw_data={},
            )
        )
        return results

    # 1) Protocol version check
    weak_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    if tls_info.protocol_version in weak_protocols:
        results.append(
            CheckResult(
                check_type="tls",
                name="TLS Protocol Version",
                severity="high",
                description=f"Server uses weak or outdated protocol version: {tls_info.protocol_version}.",
                recommendation=(
                    "Disable old protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) and only allow "
                    "TLS 1.2 or TLS 1.3 on the server."
                ),
                raw_data={"protocol_version": tls_info.protocol_version},
            )
        )

    # 2) Cipher suite presence (very minimal check)
    if not tls_info.cipher_suite:
        results.append(
            CheckResult(
                check_type="tls",
                name="Cipher Suite",
                severity="medium",
                description="Could not determine the cipher suite used.",
                recommendation=(
                    "Ensure the server is configured with modern and secure cipher suites "
                    "that prefer forward secrecy (e.g., ECDHE-based ciphers)."
                ),
                raw_data={},
            )
        )

    # 3) Certificate issuer & subject sanity (no full validation here)
    if not tls_info.certificate_subject:
        results.append(
            CheckResult(
                check_type="tls",
                name="Certificate Subject",
                severity="medium",
                description="TLS certificate subject (CN) appears to be empty.",
                recommendation=(
                    "Use a properly issued certificate with a subject or SAN that matches "
                    "the public hostname."
                ),
                raw_data={},
            )
        )

    if "let's encrypt" in tls_info.certificate_issuer.lower():
        # Example: informational note only
        results.append(
            CheckResult(
                check_type="tls",
                name="Certificate Issuer",
                severity="low",
                description="Certificate issued by Let's Encrypt.",
                recommendation=(
                    "Ensure automatic renewal is configured and monitored so certificates "
                    "do not expire unexpectedly."
                ),
                raw_data={"issuer": tls_info.certificate_issuer},
            )
        )

    # 4) Certificate validity dates (string-only check here)
    # For a more robust check, parse these strings to datetime.
    # We'll at least return them as informational.
    results.append(
        CheckResult(
            check_type="tls",
            name="Certificate Validity",
            severity="low",
            description="TLS certificate validity period information.",
            recommendation=(
                "Ensure the certificate is not expired and plan renewals before the 'notAfter' date."
            ),
            raw_data={
                "not_before": tls_info.not_before,
                "not_after": tls_info.not_after,
            },
        )
    )

    return results