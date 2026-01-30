import requests

def run_check(target_url):
    """
    Compliance Check: Cookie Security (HttpOnly and Secure)
    - Dynamic Sites: Both MUST be true. If ANY are false = Red N.
    - Static Sites: If any are false = Yellow Y.
    """
    try:
        response = requests.get(target_url, timeout=10)
        # Get all Set-Cookie headers
        cookies = response.headers.get('Set-Cookie', '')
        content_type = response.headers.get('Content-Type', '').lower()

        # Simple heuristic to identify dynamic sites (Cookies like 'session', 'id', 'token')
        is_dynamic = any(x in cookies.lower() for x in ['session', 'id', 'token', 'user', 'sid'])

        if not cookies:
            return {
                "check_name": "Cookie Security Flags",
                "compliance": "Y",
                "remark": "Compliant: No cookies are set. No session security risk. Y",
                "severity": "info" # Green
            }

        has_http_only = "httponly" in cookies.lower()
        has_secure = "secure" in cookies.lower()

        # --- Compliance Logic ---

        # 1. BOTH FLAGS PRESENT: Perfect (Green Y)
        if has_http_only and has_secure:
            return {
                "check_name": "Cookie Security Flags",
                "compliance": "Y",
                "remark": "Compliant: Both HttpOnly and Secure flags are correctly set. Y",
                "severity": "info"
            }

        # 2. DYNAMIC SITE CASE: If either is missing, it's a failure (Red N)
        if is_dynamic:
            missing = []
            if not has_http_only: missing.append("HttpOnly")
            if not has_secure: missing.append("Secure")
            
            return {
                "check_name": "Cookie Security Flags",
                "compliance": "N",
                "remark": f"NOT COMPLIANT: Dynamic site detected. Missing {', '.join(missing)} flag(s). Session hijacking risk. N",
                "severity": "high"
            }

        # 3. STATIC SITE CASE: If either is missing, it's a warning (Yellow Y)
        else:
            return {
                "check_name": "Cookie Security Flags",
                "compliance": "Y",
                "remark": "Warning: Site appears static but uses cookies without full security flags. Y",
                "severity": "warning"
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "Cookie Security Flags",
            "compliance": "N",
            "remark": f"Error: Could not analyze cookies ({str(e)})",
            "severity": "high"
        }