import dns.resolver

def run_check(target_url):
    """
    Compliance Check: DNS CAA Record
    - Success: CAA record exists, restricting certificate issuance (Compliant - Y).
    - Failure: No CAA record found; any CA can issue a cert (Not Compliant - N).
    - Standards: RFC 8659, CA/Browser Forum requirements.
    """
    # Extract domain from URL
    domain = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    
    try:
        # Query for CAA records
        answers = dns.resolver.resolve(domain, 'CAA')
        
        caa_records = []
        for rdata in answers:
            # CAA format: <flags> <tag> <value> (e.g., 0 issue "letsencrypt.org")
            caa_records.append(str(rdata))

        # --- Compliance Logic ---

        # 1. SUCCESS: One or more CAA records found
        if caa_records:
            records_str = " | ".join(caa_records)
            return {
                "check_name": "DNS CAA Record Status",
                "compliance": "Y",
                "remark": f"Compliant: CAA record(s) found: {records_str}. Certificate issuance is restricted. Y",
                "severity": "info" # Green
            }

        # 2. FAILURE: No records (this technically happens in the 'except' block for NXDOMAIN/NoAnswer)
        else:
            return {
                "check_name": "DNS CAA Record Status",
                "compliance": "N",
                "remark": "NOT COMPLIANT: No CAA record detected. Any Certificate Authority can issue a certificate for this domain. N",
                "severity": "high" # Red
            }

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return {
            "check_name": "DNS CAA Record Status",
            "compliance": "N",
            "remark": "NOT COMPLIANT: CAA record is missing from DNS configuration. N",
            "severity": "high" # Red
        }
    except Exception as e:
        return {
            "check_name": "DNS CAA Record Status",
            "compliance": "N",
            "remark": f"Error: DNS query failed ({str(e)}).",
            "severity": "high"
        }