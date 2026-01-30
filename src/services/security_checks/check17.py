import ssl
import socket

def run_check(target_url):
    """
    Compliance Check: Weak Cipher Suites
    - Probes for known weak ciphers (RC4, DES, 3DES, NULL, EXPORT).
    - Success: Connection refused for weak ciphers (Compliant - Y).
    - Failure: Weak ciphers are accepted (Not Compliant - N).
    """
    host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    port = 443
    
    # List of OpenSSL cipher strings that are considered weak/insecure
    # NULL: No encryption, EXPORT: Old 40/56-bit encryption, DES/RC4: Broken
    weak_cipher_groups = [
        "NULL", "EXPORT", "DES", "RC4", "3DES", "MD5"
    ]
    
    found_weak = []

    for cipher in weak_cipher_groups:
        try:
            # Create a context that specifically tries to use the weak cipher
            context = ssl.create_default_context()
            context.set_ciphers(cipher)
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # If connection succeeds, the server supports this weak cipher
                    actual_cipher = ssock.cipher()
                    found_weak.append(f"{cipher} ({actual_cipher[0]})")
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            # This is GOOD - server rejected the weak cipher
            continue

    # --- Compliance Logic ---

    # 1. SUCCESS: No weak ciphers detected
    if not found_weak:
        return {
            "check_name": "Weak Cipher Support",
            "compliance": "Y",
            "remark": "Compliant: Server rejects weak/legacy ciphers (RC4, DES, 3DES, Export). Y",
            "severity": "info" # Green
        }

    # 2. FAILURE: Server supports broken encryption
    else:
        weak_str = ", ".join(found_weak)
        return {
            "check_name": "Weak Cipher Support",
            "compliance": "N",
            "remark": f"NOT COMPLIANT: Server supports insecure ciphers: {weak_str}. Vulnerable to decryption attacks. N",
            "severity": "high" # Red
        }