import ssl
import socket

def run_check(target_url):
    """
    Compliance Check: Forward Secrecy (PFS) Support
    - Success: Server negotiates Ephemeral Diffie-Hellman ciphers (Compliant - Y).
    - Failure: Server uses static RSA ciphers without PFS (Not Compliant - N).
    """
    host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    port = 443
    
    try:
        # Create a default context which prioritizes PFS ciphers
        context = ssl.create_default_context()
        
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get the cipher used for the connection
                cipher_name, proto, bits = ssock.cipher()
                
                # Check for Ephemeral (E) indicators: ECDHE or DHE
                has_pfs = "ECDHE" in cipher_name or "DHE" in cipher_name

                # --- Compliance Logic ---

                # 1. SUCCESS: Connection used an Ephemeral Key Exchange
                if has_pfs:
                    return {
                        "check_name": "Forward Secrecy Support",
                        "compliance": "Y",
                        "remark": f"Compliant: Server supports Forward Secrecy using {cipher_name}. Past traffic is protected. Y",
                        "severity": "info" # Green
                    }

                # 2. FAILURE: Connection used static RSA (No PFS)
                else:
                    return {
                        "check_name": "Forward Secrecy Support",
                        "compliance": "N",
                        "remark": f"NOT COMPLIANT: Server uses {cipher_name} without Forward Secrecy. Compromise of private key leaks all past traffic. N",
                        "severity": "high" # Red
                    }

    except Exception as e:
        return {
            "check_name": "Forward Secrecy Support",
            "compliance": "N",
            "remark": f"Error: Could not verify PFS support ({str(e)}).",
            "severity": "high"
        }