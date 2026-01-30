import requests
import re

def run_check(target_url):
    """
    Compliance Check: Software Fingerprinting Disclosure
    - Inspects headers like X-Powered-By, X-Generator, and X-AspNet-Version.
    - Success: These headers are missing or generic (Compliant - Y).
    - Failure: Software versions are exposed (Not Compliant - N).
    """
    # List of common headers that leak software/CMS information
    leak_headers = [
        "X-Powered-By", 
        "X-Generator", 
        "X-AspNet-Version", 
        "X-AspNetMvc-Version",
        "X-Powered-CMS"
    ]
    
    # Regex to detect version numbers (e.g., 7.4.3, 5.0)
    version_pattern = r'\d+\.\d+'

    try:
        response = requests.get(target_url, timeout=10)
        found_leaks = []

        for header in leak_headers:
            value = response.headers.get(header)
            if value:
                # Check if the value contains a version number
                if re.search(version_pattern, value):
                    found_leaks.append(f"{header}: {value}")
                # Even if no version, X-Powered-By is better removed entirely
                elif header == "X-Powered-By":
                    found_leaks.append(f"{header}: {value}")

        # --- Compliance Logic ---

        # 1. SUCCESS: No leaking headers found
        if not found_leaks:
            return {
                "check_name": "Software Version Disclosure",
                "compliance": "Y",
                "remark": "Compliant: No software or CMS version information detected in HTTP headers.",
                "severity": "info" # Green
            }

        # 2. FAILURE: One or more headers are leaking info
        else:
            leaks_str = ", ".join(found_leaks)
            return {
                "check_name": "Software Version Disclosure",
                "compliance": "N",
                "remark": f"NOT COMPLIANT: Sensitive technology stack info leaked: {leaks_str}. Versions should be disabled.",
                "severity": "high" # Red
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "Software Version Disclosure",
            "compliance": "N",
            "remark": f"Error: Failed to analyze software headers ({str(e)}).",
            "severity": "high"
        }