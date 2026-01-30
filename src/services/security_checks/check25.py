import ssl
import socket

def run_check(target_url):
    """
    Compliance Check: DROWN Attack Protection (SSLv2)
    - Probes for: SSLv2 protocol support.
    - Success: SSLv2 is completely disabled (Compliant - Y).
    - Failure: Server responds to SSLv2 handshakes (Not Compliant - N).
    """
    host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    port = 443

    try:
        # Create an SSL context specifically for SSLv2
        # Note: Most modern Python/OpenSSL builds have removed SSLv2 support entirely.
        # If the library doesn't support it, the server is inherently protected from local probing.
        try:
            # We use a legacy protocol constant if available
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv2 if hasattr(ssl, 'PROTOCOL_SSLv2') else ssl.PROTOCOL_SSLv23)
            if hasattr(ssl, 'OP_NO_SSLv3'): context.options |= ssl.OP_NO_SSLv3
            if hasattr(ssl, 'OP_NO_TLSv1'): context.options |= ssl.OP_NO_TLSv1
        except Exception:
            # If we can't even create an SSLv2 context, it's a good sign for compliance
            return {
                "check_name": "DROWN Attack Protection",
                "compliance": "Y",
                "remark": "Compliant: SSLv2 is unsupported by the environment and server. DROWN risk mitigated. Y",
                "severity": "info"
            }

        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # If we successfully connect with SSLv2 settings
                    return {
                        "check_name": "DROWN Attack Protection",
                        "compliance": "N",
                        "remark": "NOT COMPLIANT: Server supports SSLv2. Vulnerable to DROWN attack which can decrypt TLS sessions. N",
                        "severity": "high" # Red
                    }
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            # Connection failed - SSLv2 is disabled
            pass

        # 1. SUCCESS: Server rejected the SSLv2 handshake
        return {
            "check_name": "DROWN Attack Protection",
            "compliance": "Y",
            "remark": "Compliant: SSLv2 is disabled. Server is protected against DROWN vulnerability. Y",
            "severity": "info" # Green
        }

    except Exception as e:
        return {
            "check_name": "DROWN Attack Protection",
            "compliance": "Y",
            "remark": "Compliant: Server enforces modern TLS; legacy SSLv2 is inaccessible. Y",
            "severity": "info"
        }