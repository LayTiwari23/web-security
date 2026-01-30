import requests

def run_check(target_url):
    """
    Compliance Check: Content-Security-Policy (CSP)
    - Success: Strong CSP defined (Compliant - Y)
    - Warning: CSP exists but is weak (unsafe-inline/wildcards) (Warning - Y)
    - Failure: CSP missing (Not Compliant - N)
    """
    try:
        response = requests.get(target_url, timeout=10)
        # Headers are case-insensitive
        csp = response.headers.get('Content-Security-Policy', '')

        # --- Compliance Logic ---

        # 1. FAILURE: Header is completely missing
        if not csp:
            return {
                "check_name": "Content-Security-Policy",
                "compliance": "N",
                "remark": "NOT COMPLIANT: No CSP header detected. The site is highly vulnerable to XSS and injection attacks.",
                "severity": "high" # Red
            }

        # 2. WARNING: CSP exists but contains dangerous keywords
        # 'unsafe-inline' allows execution of inline scripts (huge XSS risk)
        # 'unsafe-eval' allows string-to-code execution
        # '*' allows loading data from any domain in the world
        weak_keywords = ["unsafe-inline", "unsafe-eval", "*"]
        found_weakness = [word for word in weak_keywords if word in csp.lower()]

        if found_weakness:
            return {
                "check_name": "Content-Security-Policy",
                "compliance": "Y",
                "remark": f"Warning: CSP is enabled but contains weak directives ({', '.join(found_weakness)}). This reduces XSS protection. Y.",
                "severity": "warning" # Orange/Yellow
            }

        # 3. SUCCESS: CSP exists and doesn't contain obvious weaknesses
        else:
            return {
                "check_name": "Content-Security-Policy",
                "compliance": "Y",
                "remark": "Compliant: Strong Content-Security-Policy detected. Y.",
                "severity": "info" # Green
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "Content-Security-Policy",
            "compliance": "N",
            "remark": f"Error: Failed to analyze CSP header ({str(e)}).",
            "severity": "high"
        }