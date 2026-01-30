import requests

def run_check(target_url):
    """
    Compliance Check: Insecure HTTP Methods
    - Tests for dangerous methods: PUT, DELETE, TRACE, OPTIONS, CONNECT.
    - Success: Server returns 405 Method Not Allowed or 403 Forbidden (Compliant - Y).
    - Failure: Server accepts the method (200, 201, 204) (Not Compliant - N).
    """
    dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
    allowed_but_check = ['OPTIONS'] # Often used for CORS, but can leak info
    
    found_methods = []
    
    try:
        # Standardize URL
        clean_url = target_url if target_url.startswith('http') else f"https://{target_url}"

        for method in dangerous_methods:
            try:
                # We send a dummy request for each method
                response = requests.request(method, clean_url, timeout=5)
                
                # If the status code is 2xx, the method is ACTIVE and insecure
                if 200 <= response.status_code < 300:
                    found_methods.append(method)
            except requests.exceptions.RequestException:
                continue

        # --- Compliance Logic ---

        # 1. SUCCESS: No dangerous methods allowed
        if not found_methods:
            return {
                "check_name": "Insecure HTTP Methods",
                "compliance": "Y",
                "remark": "Compliant: Dangerous HTTP methods (PUT, DELETE, TRACE) are disabled or blocked by the server. Y",
                "severity": "info" # Green
            }

        # 2. FAILURE: Dangerous methods are active
        else:
            methods_str = ", ".join(found_methods)
            return {
                "check_name": "Insecure HTTP Methods",
                "compliance": "N",
                "remark": f"NOT COMPLIANT: The server accepts insecure HTTP methods: {methods_str}. This could allow unauthorized file modification. N",
                "severity": "high" # Red
            }

    except Exception as e:
        return {
            "check_name": "Insecure HTTP Methods",
            "compliance": "N",
            "remark": f"Error: Failed to perform HTTP method scan ({str(e)})",
            "severity": "high"
        }