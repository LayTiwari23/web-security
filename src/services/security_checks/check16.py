import ssl
import socket

def run_check(target_url):
    """
    Compliance Check: Deprecated TLS/SSL Protocols
    - Tests for: SSLv2, SSLv3, TLS 1.0, TLS 1.1.
    - Success: Connection refused for weak protocols (Compliant - Y).
    - Failure: Connection established using weak protocols (Not Compliant - N).
    """
    # Standardize hostname
    host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    port = 443
    
    # Map of weak protocols to test
    weak_protocols = {
        "SSLv2": ssl.PROTOCOL_SSLv23, # Historically used to probe older versions
        "SSLv3": ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None,
        "TLSv1": ssl.PROTOCOL_TLSv1,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1
    }
    
    found_weak = []

    for name, proto in weak_protocols.items():
        if proto is None: continue # Skip if Python build doesn't even support the old protocol
        
        try:
            context = ssl.SSLContext(proto)
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # If we get here, the connection was successful using a weak protocol
                    found_weak.append(name)
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            # This is GOOD. It means the server rejected the weak protocol.
            continue

    # --- Compliance Logic ---

    # 1. SUCCESS: No weak protocols accepted
    if not found_weak:
        return {
            "check_name": "Deprecated TLS/SSL Versions",
            "compliance": "Y",
            "remark": "Compliant: Server correctly rejects insecure protocols (SSLv2, SSLv3, TLS 1.0/1.1). Only modern TLS supported. Y",
            "severity": "info" # Green
        }

    # 2. FAILURE: Server is using outdated encryption
    else:
        protocols_str = ", ".join(found_weak)
        return {
            "check_name": "Deprecated TLS/SSL Versions",
            "compliance": "N",
            "remark": f"NOT COMPLIANT: Server accepts deprecated and insecure protocols: {protocols_str}. Vulnerable to POODLE/BEAST attacks. N",
            "severity": "high" # Red
        }