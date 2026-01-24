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
    Defaults to 443 for HTTPS.
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
    Open an SSL/TLS connection and extract basic information.
    Enforces TLS 1.2+ to avoid 'protocol version' alerts.
    """
    # Fix: Use the modern default context which supports TLS 1.2/1.3
    context = ssl.create_default_context()
    
    # Force the minimum version to TLS 1.2 to prevent handshake failures with modern servers
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # For a security scanner, we often want to inspect the cert even if hostname doesn't match
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                version = ssock.version() or "unknown"

                # getpeercert() returns a dict if the cert was validated, 
                # or an empty dict if verify_mode is CERT_NONE.
                # To get info without validation, we use the binary form.
                cert_bin = ssock.getpeercert(binary_form=True)
                if not cert_bin:
                    return None
                
                # Re-wrapping to get the dictionary with binary_form=False usually requires CERT_REQUIRED,
                # but many servers will return basic info if we call it again properly.
                cert = ssock.getpeercert() or {}

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
    except (OSError, ssl.SSLError):
        return None


def run(url: str) -> List[CheckResult]:
    """
    Main entry point for TLS configuration checks.
    """
    host, port = _parse_host_port(url)
    results: List[CheckResult] = []

    try:
        tls_info = _get_tls_info(host, port)
    except Exception as e:
        results.append(
            CheckResult(
                check_type="tls",
                name="TLS Connection",
                severity="high",
                description=f"Failed to establish TLS connection to {host}:{port}.",
                recommendation="Ensure the host supports TLS 1.2 or 1.3.",
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
                description="Could not retrieve TLS certificate. The server may be rejecting old protocols.",
                recommendation="Update server to support modern TLS versions.",
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
                description=f"Server uses outdated version: {tls_info.protocol_version}.",
                recommendation="Only allow TLS 1.2 or TLS 1.3.",
                raw_data={"protocol_version": tls_info.protocol_version},
            )
        )

    # 2) Cipher suite check
    if not tls_info.cipher_suite:
        results.append(
            CheckResult(
                check_type="tls",
                name="Cipher Suite",
                severity="medium",
                description="Could not determine the cipher suite.",
                recommendation="Configure modern suites like ECDHE.",
                raw_data={},
            )
        )

    # 3) Validity Period
    results.append(
        CheckResult(
            check_type="tls",
            name="Certificate Validity",
            severity="low",
            description=f"Certificate valid from {tls_info.not_before} to {tls_info.not_after}.",
            recommendation="Monitor expiration dates for timely renewal.",
            raw_data={
                "not_before": tls_info.not_before,
                "not_after": tls_info.not_after,
                "issuer": tls_info.certificate_issuer
            },
        )
    )

    return results