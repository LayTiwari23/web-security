import requests

def run_check(target_url):
    """
    Compliance Check: X-XSS-Protection Header
    - Success: Header set to '1; mode=block' (Compliant - Y)
    - Warning: Header exists but in 'sanitize' mode or '0' (Warning - Y)
    - Failure: Header is missing (Not Compliant - N)
    """
    try:
        response = requests.get(target_url, timeout=10)
        xss_header = response.headers.get('X-XSS-Protection', '').lower()

        # --- Compliance Logic ---

        # 1. SUCCESS: The gold standard for this header
        if xss_header == "1; mode=block":
            return {
                "check_name": "X-XSS-Protection",
                "compliance": "Y",
                "remark": "Compliant: Header is enabled in 'block' mode (1; mode=block).",
                "severity": "info" # Green
            }

        # 2. WARNING: Enabled but not in block mode
        elif "1" in xss_header:
            return {
                "check_name": "X-XSS-Protection",
                "compliance": "Y",
                "remark": f"Warning: Header is enabled ('{xss_header}') but not in 'block' mode. Sanitization can sometimes be bypassed.",
                "severity": "warning" # Orange/Yellow
            }

        # 3. FAILURE: Header is disabled (0)
        elif xss_header == "0":
            return {
                "check_name": "X-XSS-Protection",
                "compliance": "N",
                "remark": "NOT COMPLIANT: XSS filter is explicitly disabled (X-XSS-Protection: 0).",
                "severity": "high" # Red
            }

        # 4. FAILURE: Header is missing
        else:
            return {
                "check_name": "X-XSS-Protection",
                "compliance": "N",
                "remark": "NOT COMPLIANT: X-XSS-Protection header is missing. Legacy browsers remain vulnerable to reflected XSS.",
                "severity": "high" # Red
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "X-XSS-Protection",
            "compliance": "N",
            "remark": f"Error: Could not retrieve headers for XSS analysis ({str(e)}).",
            "severity": "high"
        }