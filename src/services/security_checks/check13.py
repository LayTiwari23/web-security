import requests

def run_check(target_url):
    """
    Compliance Check: Cache-Control Headers
    - Success: Header present and restricts sensitive caching (Compliant - Y)
    - Warning: Header present but allows caching (Warning - Y)
    - Failure: Header missing (Not Compliant - N)
    """
    try:
        response = requests.get(target_url, timeout=10)
        cache_header = response.headers.get('Cache-Control', '').lower()
        pragma_header = response.headers.get('Pragma', '').lower()

        # --- Compliance Logic ---

        # 1. SUCCESS: The "Gold Standard" for security (prevents all caching)
        if all(x in cache_header for x in ["no-store", "no-cache"]):
            return {
                "check_name": "Cache-Control Security",
                "compliance": "Y",
                "remark": "Compliant: Strong anti-caching headers detected (no-store, no-cache). Y",
                "severity": "info" # Green
            }

        # 2. WARNING: Header exists but allows some caching
        elif cache_header:
            return {
                "check_name": "Cache-Control Security",
                "compliance": "Y",
                "remark": f"Warning: Cache-Control is set to '{cache_header}'. While present, it may allow browsers to store sensitive content. Y",
                "severity": "warning" # Orange/Yellow
            }

        # 3. FAILURE: Header is completely missing
        else:
            return {
                "check_name": "Cache-Control Security",
                "compliance": "N",
                "remark": "NOT COMPLIANT: Cache-Control header is missing. Sensitive data may be stored in local or public caches. N",
                "severity": "high" # Red
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "Cache-Control Security",
            "compliance": "N",
            "remark": f"Error: Failed to analyze cache headers ({str(e)})",
            "severity": "high"
        }