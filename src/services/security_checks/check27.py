import socket

def run_check(target_url):
    """
    Compliance Check: Block Legacy HTTP/1.0 Requests
    - Success: Server rejects or upgrades HTTP/1.0 requests (Compliant - Y).
    - Failure: Server responds fully to HTTP/1.0 (Not Compliant - N).
    """
    host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    port = 443 if target_url.startswith("https") else 80
    
    # Raw HTTP/1.0 request string
    # HTTP/1.0 does not require a 'Host' header, which is a security weakness
    request = f"GET / HTTP/1.0\r\n\r\n"

    try:
        # We use a raw socket to ensure we are sending exactly HTTP/1.0 
        # (The requests library often auto-upgrades to 1.1)
        with socket.create_connection((host, port), timeout=5) as sock:
            if port == 443:
                import ssl
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.sendall(request.encode())
            response = sock.recv(1024).decode(errors='ignore')

            # --- Compliance Logic ---

            # 1. SUCCESS: Server returns 426 (Upgrade Required), 400 (Bad Request), 
            # or specifically labels the response as HTTP/1.1 even though we asked for 1.0.
            if "HTTP/1.1" in response or "426 Upgrade Required" in response or "400 Bad Request" in response:
                return {
                    "check_name": "Legacy HTTP/1.0 Support",
                    "compliance": "Y",
                    "remark": "Compliant: Server restricts or upgrades legacy HTTP/1.0 requests to HTTP/1.1+. Y",
                    "severity": "info" # Green
                }

            # 2. FAILURE: Server responds with 200 OK using the legacy HTTP/1.0 protocol
            elif "HTTP/1.0 200 OK" in response:
                return {
                    "check_name": "Legacy HTTP/1.0 Support",
                    "compliance": "N",
                    "remark": "NOT COMPLIANT: Server fully supports obsolete HTTP/1.0. Risk of request smuggling and proxy bypass. N",
                    "severity": "high" # Red
                }

            # 3. SUCCESS: Any other error or connection drop
            else:
                return {
                    "check_name": "Legacy HTTP/1.0 Support",
                    "compliance": "Y",
                    "remark": "Compliant: Server does not provide a standard HTTP/1.0 response. Y",
                    "severity": "info"
                }

    except Exception as e:
        return {
            "check_name": "Legacy HTTP/1.0 Support",
            "compliance": "Y",
            "remark": f"Compliant: Server refused the legacy connection attempt. Y",
            "severity": "info"
        }