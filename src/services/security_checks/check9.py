import requests

def run_check(target_url):
    """
    Compliance Check: HSTS (HTTP Strict-Transport-Security)
    - Success: Header present with max-age >= 15768000 (6 months) (Compliant - Y)
    - Warning: Header present but max-age is low or includeSubDomains is missing (Warning - Y)
    - Failure: Header missing or set to 0 (Not Compliant - N)
    """
    try:
        # HSTS only works over HTTPS, so we force an HTTPS check
        clean_host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
        https_url = f"https://{clean_host}"
        
        response = requests.get(https_url, timeout=10)
        hsts = response.headers.get('Strict-Transport-Security', '')

        # --- Compliance Logic ---

        # 1. FAILURE: Header is completely missing
        if not hsts:
            return {
                "check_name": "HSTS Enabled",
                "compliance": "N",
                "remark": "NOT COMPLIANT: HSTS header is missing. Site is vulnerable to SSL stripping attacks.",
                "severity": "high" # Red
            }

        # Parse directives
        directives = {d.strip().split('=')[0].lower(): d.strip().split('=')[1] if '=' in d else True 
                      for d in hsts.split(';')}
        
        max_age = int(directives.get('max-age', 0))
        has_subdomains = 'includesubdomains' in directives

        # 2. SUCCESS: The "Gold Standard" (>= 1 year, includes subdomains)
        if max_age >= 31536000 and has_subdomains:
            return {
                "check_name": "HSTS Enabled",
                "compliance": "Y",
                "remark": f"Compliant: Strong HSTS policy detected (max-age={max_age}, includeSubDomains). Y",
                "severity": "info" # Green
            }

        # 3. WARNING: Enabled but weak (Short duration or missing subdomains)
        elif max_age > 0:
            msg = "Y"
            if max_age < 15768000:
                msg += " (Warning: max-age is less than 6 months)"
            if not has_subdomains:
                msg += " (Warning: subdomains not protected)"
            
            return {
                "check_name": "HSTS Enabled",
                "compliance": "Y",
                "remark": f"Compliant with warnings: {msg}.",
                "severity": "warning" # Orange/Yellow
            }

        # 4. FAILURE: max-age=0 (Explicitly disabled)
        else:
            return {
                "check_name": "HSTS Enabled",
                "compliance": "N",
                "remark": "NOT COMPLIANT: HSTS is explicitly disabled (max-age=0).",
                "severity": "high" # Red
            }

    except Exception as e:
        return {
            "check_name": "HSTS Enabled",
            "compliance": "N",
            "remark": f"Error: Could not analyze HSTS header ({str(e)}).",
            "severity": "high"
        }