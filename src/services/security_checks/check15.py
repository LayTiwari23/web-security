import requests

def run_check(target_url):
    """
    Compliance Check: Management/CMS Interface Exposure
    - Scans for common admin paths (wp-admin, phpmyadmin, admin, etc.)
    - Success: 404 Not Found or 403 Forbidden (Compliant - Y)
    - Failure: 200 OK (Not Compliant - N)
    """
    # Common administrative paths to check
    admin_paths = [
        '/admin', '/wp-admin', '/phpmyadmin', '/controlpanel', 
        '/cp', '/administrator', '/console', '/login.php', 
        '/admin.php', '/magento/admin'
    ]
    
    exposed_paths = []
    clean_url = target_url.rstrip('/')

    try:
        for path in admin_paths:
            try:
                # We use a 5-second timeout to avoid hanging the scan
                response = requests.head(f"{clean_url}{path}", timeout=5, allow_redirects=True)
                
                # If the page exists (200 OK) or requires login (401), it is "Exposed"
                if response.status_code == 200:
                    exposed_paths.append(path)
            except requests.exceptions.RequestException:
                continue

        # --- Compliance Logic ---

        # 1. SUCCESS: No common admin paths are public
        if not exposed_paths:
            return {
                "check_name": "Management Interface Exposure",
                "compliance": "Y",
                "remark": "Compliant: No common administration or CMS login portals were found to be publicly accessible. Y",
                "severity": "info" # Green
            }

        # 2. FAILURE: Admin portal is live on the internet
        else:
            paths_str = ", ".join(exposed_paths)
            return {
                "check_name": "Management Interface Exposure",
                "compliance": "N",
                "remark": f"NOT COMPLIANT: Sensitive management interface(s) detected: {paths_str}. These should be restricted to internal IP addresses or VPN. N",
                "severity": "high" # Red
            }

    except Exception as e:
        return {
            "check_name": "Management Interface Exposure",
            "compliance": "N",
            "remark": f"Error: Failed to perform directory brute-force scan ({str(e)})",
            "severity": "high"
        }