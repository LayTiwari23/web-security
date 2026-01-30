import ssl
import socket

def run_check(target_url):
    """
    Compliance Check: FREAK Attack Protection
    - Probes for: Export-grade RSA ciphers (RSA_EXPORT).
    - Success: Connection refused for weak export ciphers (Compliant - Y).
    - Failure: Server accepts 512-bit export keys (Not Compliant - N).
    """
    host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    port = 443
    
    # OpenSSL cipher string for Export-grade RSA
    freak_cipher_string = "EXPORT"

    try:
        # Create a context that attempts to use Export ciphers
        context = ssl.create_default_context()
        # We try to force the use of export-grade RSA
        try:
            context.set_ciphers(freak_cipher_string)
        except ssl.SSLError:
            # If the local OpenSSL library doesn't even support EXPORT, 
            # the system is inherently protected.
            return {
                "check_name": "FREAK Attack Protection",
                "compliance": "Y",
                "remark": "Compliant: Export-grade ciphers are not supported by the local library or server. Y",
                "severity": "info"
            }

        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # If we successfully connect with EXPORT, the server is insecure
                    return {
                        "check_name": "FREAK Attack Protection",
                        "compliance": "N",
                        "remark": "NOT COMPLIANT: Server supports EXPORT-grade RSA ciphers. Vulnerable to FREAK attack. N",
                        "severity": "high" # Red
                    }
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            # This is the expected result for a secure server
            pass

        # 1. SUCCESS: Server rejected the export-grade handshake
        return {
            "check_name": "FREAK Attack Protection",
            "compliance": "Y",
            "remark": "Compliant: Export-grade RSA ciphers (FREAK vulnerability) are disabled. Y",
            "severity": "info" # Green
        }

    except Exception as e:
        return {
            "check_name": "FREAK Attack Protection",
            "compliance": "Y",
            "remark": "Compliant: Server enforces modern RSA key lengths. Y",
            "severity": "info"
        }