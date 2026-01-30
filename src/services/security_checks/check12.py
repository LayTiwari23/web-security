import requests

def run_check(target_url):
    """
    Compliance Check: SameSite Cookie Attribute
    - Dynamic Sites: Must be 'Strict' or 'Lax' (Green Y). If 'None' or missing = Red N.
    - Static Sites: If 'None' or missing = Yellow Y.
    - Standards: OWASP CSRF Prevention Cheat Sheet.
    """
    try:
        response = requests.get(target_url, timeout=10)
        cookies = response.headers.get('Set-Cookie', '')
        
        # Heuristic to identify dynamic sites (looking for session identifiers)
        is_dynamic = any(x in cookies.lower() for x in ['session', 'id', 'token', 'user', 'sid', 'auth'])

        # If no cookies are set at all
        if not cookies:
            return {
                "check_name": "Cookie SameSite Attribute",
                "compliance": "Y",
                "remark": "Compliant: No cookies detected. No CSRF risk via cookie injection. Y",
                "severity": "info" # Green
            }

        # Check for SameSite values
        cookie_lower = cookies.lower()
        is_strict = "samesite=strict" in cookie_lower
        is_lax = "samesite=lax" in cookie_lower
        is_none = "samesite=none" in cookie_lower
        has_samesite = "samesite" in cookie_lower

        # --- Compliance Logic ---

        # 1. SUCCESS: Best Practice (Strict or Lax)
        if is_strict or is_lax:
            return {
                "check_name": "Cookie SameSite Attribute",
                "compliance": "Y",
                "remark": f"Compliant: SameSite is set to {'Strict' if is_strict else 'Lax'}. Strong CSRF protection. Y",
                "severity": "info" # Green
            }

        # 2. DYNAMIC SITE CASE: If missing or set to 'None', it's a failure (Red N)
        if is_dynamic:
            reason = "set to 'None'" if is_none else "missing"
            return {
                "check_name": "Cookie SameSite Attribute",
                "compliance": "N",
                "remark": f"NOT COMPLIANT: Dynamic site detected with SameSite attribute {reason}. Vulnerable to CSRF. N",
                "severity": "high" # Red
            }

        # 3. STATIC SITE CASE: If missing or 'None', it's a warning (Yellow Y)
        else:
            return {
                "check_name": "Cookie SameSite Attribute",
                "compliance": "Y",
                "remark": "Warning: SameSite attribute is missing or None on a static site. Low risk, but 'Lax' is recommended. Y",
                "severity": "warning" # Orange/Yellow
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "Cookie SameSite Attribute",
            "compliance": "N",
            "remark": f"Error: Failed to analyze SameSite attribute ({str(e)})",
            "severity": "high"
        }