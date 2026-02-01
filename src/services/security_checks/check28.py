import dns.resolver
from typing import Dict, Any

def run_check(target_url: str) -> Dict[str, Any]:
    """
    Check 28: DNS CAA (Certification Authority Authorization)
    - Success: CAA record exists, restricting certificate issuance (Compliant - Y).
    - Failure: No CAA record found; any CA can issue a cert (Not Compliant - N).
    - Standards: RFC 8659, CA/Browser Forum requirements.
    """
    check_name = "DNS CAA Record Status"
    # Extract domain from URL (e.g., https://example.com/page -> example.com)
    domain = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    
    try:
        # Query for CAA records
        answers = dns.resolver.resolve(domain, 'CAA')
        
        caa_records = []
        for rdata in answers:
            # CAA format: <flags> <tag> <value> (e.g., 0 issue "letsencrypt.org")
            caa_records.append(str(rdata))

        # --- Compliance Logic: SUCCESS ---
        if caa_records:
            records_str = " | ".join(caa_records)
            return {
                "check_type": "dns_caa",
                "name": check_name,
                "compliance": "Y",
                "severity": "info", # Maps to Green in UI
                "description": f"Compliant: CAA record(s) found: {records_str}.",
                "recommendation": "CAA records are correctly configured to restrict certificate issuance.",
                "raw_data": {"records": caa_records, "domain": domain}
            }

        # --- Compliance Logic: FAILURE (No records) ---
        return {
            "check_type": "dns_caa",
            "name": check_name,
            "compliance": "N",
            "severity": "high", # Maps to Red in UI
            "description": "NOT COMPLIANT: No CAA record detected. Any Certificate Authority can issue a certificate for this domain.",
            "recommendation": "Configure DNS CAA records (RFC 8659) to specify authorized Certificate Authorities.",
            "raw_data": {"domain": domain}
        }

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return {
            "check_type": "dns_caa",
            "name": check_name,
            "compliance": "N",
            "severity": "high",
            "description": "NOT COMPLIANT: CAA record is missing from DNS configuration.",
            "recommendation": "Add a CAA record to your DNS zone to prevent unauthorized certificate issuance.",
            "raw_data": {"domain": domain}
        }
    except Exception as e:
        return {
            "check_type": "dns_caa",
            "name": check_name,
            "compliance": "N",
            "severity": "high",
            "description": f"Error: DNS query failed ({str(e)}).",
            "recommendation": "Ensure the domain is valid and the DNS server is reachable.",
            "raw_data": {"error": str(e)}
        }