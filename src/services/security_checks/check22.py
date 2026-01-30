import requests

def run_check(target_url):
    """
    Compliance Check: CSS Injection Protection
    - Success: CSP style-src is restricted and nosniff is enabled (Compliant - Y).
    - Warning: Only one of the protections is present (Warning - Y).
    - Failure: No protections against CSS injection (Not Compliant - N).
    """
    try:
        response = requests.get(target_url, timeout=10)
        csp = response.headers.get('Content-Security-Policy', '').lower()
        nosniff = response.headers.get('X-Content-Type-Options', '').lower()

        # Check for CSP style-src restriction
        has_csp_style = "style-src" in csp and "'unsafe-inline'" not in csp
        # Check for MIME-sniffing protection
        has_nosniff = "nosniff" in nosniff

        # --- Compliance Logic ---

        # 1. SUCCESS: Both primary defenses are active
        if has_csp_style and has_nosniff:
            return {
                "check_name": "CSS Injection Protection",
                "compliance": "Y",
                "remark": "Compliant: Strong style-src CSP and MIME-sniffing protection enabled. Y",
                "severity": "info" # Green
            }

        # 2. WARNING: Partial protection
        elif has_csp_style or has_nosniff:
            status = "CSP present but nosniff missing" if has_csp_style else "nosniff present but CSP weak/missing"
            return {
                "check_name": "CSS Injection Protection",
                "compliance": "Y",
                "remark": f"Warning: Partial protection detected ({status}). Y",
                "severity": "warning" # Orange/Yellow
            }

        # 3. FAILURE: No protection
        else:
            return {
                "check_name": "CSS Injection Protection",
                "compliance": "N",
                "remark": "NOT COMPLIANT: Site is vulnerable to CSS injection. Missing CSP style-src and nosniff headers. N",
                "severity": "high" # Red
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "CSS Injection Protection",
            "compliance": "N",
            "remark": f"Error: Failed to analyze headers ({str(e)})",
            "severity": "high"
        }