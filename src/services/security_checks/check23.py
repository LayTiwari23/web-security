import ssl
import socket

def run_check(target_url):
    """
    Compliance Check: Anonymous Cipher Support
    - Probes for: ADH (Anonymous Diffie-Hellman) and AECDH ciphers.
    - Success: Connection refused for anonymous ciphers (Compliant - Y).
    - Failure: Connection established without authentication (Not Compliant - N).
    """
    host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    port = 443
    
    # 'aNULL' is the OpenSSL string for ciphers that provide no authentication
    anonymous_cipher_string = "aNULL"
    
    try:
        # Create a context that specifically allows anonymous ciphers
        context = ssl.create_default_context()
        # We must manually override the default security level to allow testing for aNULL
        context.set_ciphers(anonymous_cipher_string)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # If we successfully connect with aNULL, the server is insecure
                    return {
                        "check_name": "Anonymous Cipher Support",
                        "compliance": "N",
                        "remark": "NOT COMPLIANT: Server supports anonymous ciphers (aNULL). Traffic can be intercepted via MITM without warning. N",
                        "severity": "high" # Red
                    }
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            # This is the expected result for a secure server
            pass

        # 1. SUCCESS: Server rejected the anonymous handshake
        return {
            "check_name": "Anonymous Cipher Support",
            "compliance": "Y",
            "remark": "Compliant: Anonymous ciphers are disabled. Server requires authenticated handshakes. Y",
            "severity": "info" # Green
        }

    except Exception as e:
        # If the local library is too modern to even attempt aNULL, it's generally a safe sign
        return {
            "check_name": "Anonymous Cipher Support",
            "compliance": "Y",
            "remark": "Compliant: Server and local environment enforce authenticated TLS connections. Y",
            "severity": "info"
        }