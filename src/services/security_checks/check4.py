import requests
import re

def run_check(target_url):
    """
    Compliance Check: Webserver Version Disclosure
    - Inspects the 'Server' header for version information.
    - Success: Header missing, obfuscated, or generic (Compliant - Y)
    - Failure: Detailed version info disclosed (Not Compliant - N)
    """
    try:
        # Use a generic User-Agent to see how the server responds normally
        headers = {'User-Agent': 'Mozilla/5.0 (Security-Scanner-ISRO)'}
        response = requests.get(target_url, timeout=10, headers=headers)
        
        server_header = response.headers.get('Server', '')

        # Regex to detect common version patterns like /1.2.3 or (Ubuntu)
        version_pattern = r'\d+\.\d+' # Matches numbers like 1.2 or 2.4.5
        
        # --- Compliance Logic ---

        # 1. SUCCESS: Header is completely missing
        if not server_header:
            return {
                "check_name": "Server Version Disclosure",
                "compliance": "Y",
                "remark": "Compliant: 'Server' header is completely disabled/removed. No information leaked.",
                "severity": "info" # Green
            }

        # 2. SUCCESS: Generic name only (e.g., 'Apache', 'nginx', 'cloudflare')
        # We check if it DOES NOT contain numbers or specific OS details
        elif not re.search(version_pattern, server_header) and "(" not in server_header:
            return {
                "check_name": "Server Version Disclosure",
                "compliance": "Y",
                "remark": f"Compliant: Server header is generic ('{server_header}'). Exact version is hidden.",
                "severity": "info" # Green
            }

        # 3. FAILURE: Detailed version disclosure detected
        else:
            return {
                "check_name": "Server Version Disclosure",
                "compliance": "N",
                "remark": f"NOT COMPLIANT: Sensitive information leaked in 'Server' header: '{server_header}'. Standards require hiding version numbers.",
                "severity": "high" # Red
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "Server Version Disclosure",
            "compliance": "N",
            "remark": f"Error: Could not retrieve headers for analysis ({str(e)}).",
            "severity": "high"
        }