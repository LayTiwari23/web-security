import requests

def run_check(target_url):
    """
    Compliance Check: X-Frame-Options (Clickjacking Protection)
    - Success: Header set to 'DENY' or 'SAMEORIGIN' (Compliant - Y)
    - Failure: Header is missing or set incorrectly (Not Compliant - N)
    """
    try:
        response = requests.get(target_url, timeout=10)
        # Headers are case-insensitive, but we normalize to uppercase for comparison
        xfo_header = response.headers.get('X-Frame-Options', '').upper()

        # --- Compliance Logic ---

        # 1. SUCCESS: The most restrictive and secure setting
        if xfo_header == "DENY":
            return {
                "check_name": "X-Frame-Options",
                "compliance": "Y",
                "remark": "Compliant: Clickjacking protection is fully enabled (X-Frame-Options: DENY).",
                "severity": "info" # Green
            }

        # 2. SUCCESS: Safe for internal framing
        elif xfo_header == "SAMEORIGIN":
            return {
                "check_name": "X-Frame-Options",
                "compliance": "Y",
                "remark": "Compliant: Framing is restricted to the same origin (X-Frame-Options: SAMEORIGIN).",
                "severity": "info" # Green
            }

        # 3. FAILURE: Explicitly insecure or deprecated value
        elif "ALLOW-FROM" in xfo_header:
            return {
                "check_name": "X-Frame-Options",
                "compliance": "N",
                "remark": f"NOT COMPLIANT: Uses deprecated 'ALLOW-FROM' directive. This is not supported by modern browsers.",
                "severity": "high" # Red
            }

        # 4. FAILURE: Header is completely missing
        else:
            return {
                "check_name": "X-Frame-Options",
                "compliance": "N",
                "remark": "NOT COMPLIANT: X-Frame-Options header is missing. The site is vulnerable to Clickjacking attacks.",
                "severity": "high" # Red
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "X-Frame-Options",
            "compliance": "N",
            "remark": f"Error: Failed to perform Clickjacking analysis ({str(e)}).",
            "severity": "high"
        }