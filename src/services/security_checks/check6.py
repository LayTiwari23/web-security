import requests
import re

def run_check(target_url):
    """
    Compliance Check: E-Tag Information Leakage
    - Inspects the 'ETag' header for potential Inode leakage.
    - Success: Header missing, or uses a secure hash (Compliant - Y).
    - Failure: Header reveals filesystem Inodes (Not Compliant - N).
    """
    try:
        response = requests.get(target_url, timeout=10)
        etag = response.headers.get('ETag', '')

        # --- Compliance Logic ---

        # 1. SUCCESS: Header is not present (Standard recommendation for high security)
        if not etag:
            return {
                "check_name": "E-Tag Info Leakage",
                "compliance": "Y",
                "remark": "Compliant: E-Tag header is disabled. No filesystem or version info leaked.",
                "severity": "info" # Green
            }

        # 2. FAILURE: Detects the 'Inode' pattern (typically 3 parts separated by dashes/quotes)
        # Apache Inode-style ETags often look like: "inode-size-timestamp"
        # Example: "680c1-45-42a7c8D8"
        inode_pattern = r'^[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+$'
        
        # Clean the E-Tag for testing (remove quotes and 'W/' prefix for weak ETags)
        clean_etag = etag.replace('W/', '').replace('"', '')

        if re.match(inode_pattern, clean_etag):
            return {
                "check_name": "E-Tag Info Leakage",
                "compliance": "N",
                "remark": f"NOT COMPLIANT: E-Tag '{etag}' appears to leak Inode/filesystem info. Risk of internal server mapping.",
                "severity": "high" # Red
            }

        # 3. SUCCESS: E-Tag is present but appears to be a secure hash (like a single long string)
        else:
            return {
                "check_name": "E-Tag Info Leakage",
                "compliance": "Y",
                "remark": "Compliant: E-Tag is present but uses a secure hash format without leaking Inode data.",
                "severity": "info" # Green
            }

    except requests.exceptions.RequestException as e:
        return {
            "check_name": "E-Tag Info Leakage",
            "compliance": "N",
            "remark": f"Error: Failed to analyze E-Tag header ({str(e)}).",
            "severity": "high"
        }