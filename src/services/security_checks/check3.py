import requests

def run_check(target_url):
    """
    Compliance Check: HTTPS Operational State
    - Verifies the site is fully operational over HTTPS.
    - Success: Status 200 OK via HTTPS (Compliant - Y)
    - Failure: SSL Errors, Connection Failures, or Certificate issues (Not Compliant - N)
    """
    # Ensure we are testing the HTTPS version
    clean_host = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    https_url = f"https://{clean_host}"
    
    try:
        # We allow redirects here because we want to see the final destination
        # verify=True ensures we check the SSL certificate validity
        response = requests.get(https_url, timeout=10, allow_redirects=True)
        
        # --- Compliance Logic ---

        # 1. Success Case: Operational 200 OK over HTTPS
        if response.status_code == 200 and response.url.startswith("https://"):
            return {
                "check_name": "HTTPS Operationality",
                "compliance": "Y",
                "remark": "Compliant: Website is fully operational over HTTPS (Status 200). Secure connection established.",
                "severity": "info" # Green
            }
        
        # 2. Warning Case: Accessible but weird status (e.g., 403 Forbidden or 401 Unauthorized)
        elif response.url.startswith("https://"):
            return {
                "check_name": "HTTPS Operationality",
                "compliance": "Y",
                "remark": f"Operational over HTTPS, but returned status code {response.status_code}. The connection is secure, but content access is restricted.",
                "severity": "warning" # Orange/Yellow
            }

        # 3. Failure Case: Somehow landed back on HTTP
        else:
            return {
                "check_name": "HTTPS Operationality",
                "compliance": "N",
                "remark": "NOT COMPLIANT: The final destination after processing is not secure (HTTP).",
                "severity": "high" # Red
            }

    except requests.exceptions.SSLError:
        return {
            "check_name": "HTTPS Operationality",
            "compliance": "N",
            "remark": "NOT COMPLIANT: SSL/TLS Certificate validation failed. The site may be using an expired or self-signed certificate.",
            "severity": "high" # Red
        }
    except requests.exceptions.RequestException as e:
        return {
            "check_name": "HTTPS Operationality",
            "compliance": "N",
            "remark": f"NOT COMPLIANT: Website is not reachable over HTTPS. Error: {str(e)}",
            "severity": "high" # Red
        }