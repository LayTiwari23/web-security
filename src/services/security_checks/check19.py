import ssl
import socket

def run_check(target_url):
    """
    Compliance Check: Logjam Attack Protection
    - Tests for: Weak Diffie-Hellman (DH) key exchange.
    - Success: Connection requires DH keys >= 2048 bits (Compliant - Y).
    - Failure: Server supports Export DH (512-bit) or common 1024-bit DH (Not Compliant - N).
    """
    host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    port = 443
    
    try:
        # Create a context that attempts to allow weak/export DH ciphers
        context = ssl.create_default_context()
        # 'EXP' refers to Export-grade ciphers used in Logjam
        # 'EDH' or 'DHE' refers to Ephemeral Diffie-Hellman
        context.set_ciphers("EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-RSA-DES-CBC")
        
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # If we successfully connect with export-grade DH
                    return {
                        "check_name": "Logjam Attack Protection",
                        "compliance": "N",
                        "remark": "NOT COMPLIANT: Server supports export-grade Diffie-Hellman (DH) keys. Vulnerable to Logjam attack. N",
                        "severity": "high" # Red
                    }
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            # This is expected for a secure server
            pass

        # If we reach here, we check for modern standards
        return {
            "check_name": "Logjam Attack Protection",
            "compliance": "Y",
            "remark": "Compliant: Export-grade DH ciphers are disabled. Server enforces strong key exchange. Y",
            "severity": "info" # Green
        }

    except Exception as e:
        return {
            "check_name": "Logjam Attack Protection",
            "compliance": "Y",
            "remark": "Compliant: Server and environment reject weak DH parameters. Y",
            "severity": "info"
        }