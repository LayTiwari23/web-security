import requests

def run_check(target_url):
    """
    Compliance Check: Enforce HTTPS Redirection
    - Tests if http:// version redirects to https://
    - Success: 301 Redirect to HTTPS (Compliant - Y)
    - Failure: No redirect or stays on HTTP (Not Compliant - N)
    """
    # Create the insecure version of the target URL
    # We strip any existing protocol and force http://
    clean_host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    http_url = f"http://{clean_host}"
    
    try:
        # We set allow_redirects=False so we can catch the 301 status code itself
        response = requests.head(http_url, timeout=10, allow_redirects=False)
        
        status_code = response.status_code
        location = response.headers.get('Location', '')

        # --- Compliance Logic ---

        # 1. Success Case: 301 Redirect to HTTPS
        if status_code == 301 and location.startswith("https://"):
            return {
                "check_name": "HTTP to HTTPS Redirection",
                "compliance": "Y",
                "remark": f"Compliant: Website enforces HTTPS. HTTP request redirected with code {status_code} to {location}.",
                "severity": "info" # Green
            }
        
        # 2. Success Case: Other Redirects to HTTPS (302, 307, 308)
        elif status_code in [302, 307, 308] and location.startswith("https://"):
            return {
                "check_name": "HTTP to HTTPS Redirection",
                "compliance": "Y",
                "remark": f"Compliant: Redirection to HTTPS detected (Code {status_code}). Note: 301 is preferred for SEO/Standards.",
                "severity": "info" # Green
            }

        # 3. Failure Case: No Redirection or Not Safe
        else:
            return {
                "check_name": "HTTP to HTTPS Redirection",
                "compliance": "N",
                "remark": "NOT COMPLIANT: Website is accessible over insecure HTTP. No automatic redirection to HTTPS detected.",
                "severity": "high" # Red
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "HTTP to HTTPS Redirection",
            "compliance": "N",
            "remark": f"Error: Could not reach the HTTP version of the site for testing ({str(e)}).",
            "severity": "high"
        }