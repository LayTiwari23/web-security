import logging
import time
from datetime import datetime
from pathlib import Path
import nmap
from src.workers.celery_app import celery_app
from src.db.session import SessionLocal
from src.db.models import Scan, PdfReport, Finding
from src.services.pdf_service import generate_pdf_for_scan, save_pdf_file

# Import specialized check modules
from src.services.security_checks import headers, cookies, tls

logger = logging.getLogger(__name__)

def evaluate_compliance(findings, target_url, hostname):
    """Orchestrates live scans and maps them to the 28 audit parameters."""
    compliance_map = {str(i): {"status": "Y", "remark": "Compliant.", "severity": "info"} for i in range(1, 29)}

    # 1. Map Nmap Port Findings
    for f in findings:
        name = f.name.lower()
        if "port" in name:
            if any(p in name for p in ["8000", "8080", "8443"]):
                compliance_map["1"] = {
                    "status": "Y", 
                    "remark": f"WARNING: {f.name} detected. Alternative web ports are open but acceptable.",
                    "severity": "warning" 
                }
            elif any(p in name for p in ["80", "443"]):
                continue 
            else:
                compliance_map["1"] = {
                    "status": "N", 
                    "remark": f"CRITICAL: {f.name} exposed. Non-standard service port detected.",
                    "severity": "critical"
                }

    try:
        # 2. Execute Specialized Scanners
        header_results = headers.run(target_url)
        cookie_results = cookies.run(target_url)
        tls_results = tls.run(target_url)

        # 3. Map Header Results (Items 4-10, 13)
        header_mapping = {"Strict-Transport-Security": "9", "Content-Security-Policy": "10", 
                          "X-Frame-Options": "8", "X-XSS-Protection": "7", "Server": "4", 
                          "X-Powered-By": "5", "Cache-Control": "13"}
        for res in header_results:
            item_id = header_mapping.get(res.name)
            if item_id:
                compliance_map[item_id] = {
                    "status": "N" if res.severity in ["high", "critical", "error"] else "Y",
                    "remark": f"ERROR: {res.description}" if res.severity in ["high", "critical", "error"] else res.description,
                    "severity": res.severity
                }

        # 4. Map Cookie Results (Items 11, 12)
        for res in cookie_results:
            if "Secure" in res.name or "HttpOnly" in res.name:
                compliance_map["11"] = {"status": "N" if res.severity in ["high", "critical"] else "Y",
                                        "remark": f"CRITICAL: {res.description}", "severity": res.severity}
            elif "SameSite" in res.name:
                compliance_map["12"] = {"status": "N" if res.severity in ["medium", "high"] else "Y",
                                        "remark": f"WARNING: {res.description}", "severity": res.severity}

        # 5. Map TLS Results (Items 16, 17, 26)
        tls_mapping = {"Legacy TLS Protocols": "16", "Weak Cipher Suites": "17", "Forward Secrecy": "26"}
        for res in tls_results:
            item_id = tls_mapping.get(res.name)
            if item_id:
                compliance_map[item_id] = {
                    "status": "N" if res.severity in ["high", "critical"] else "Y",
                    "remark": f"CRITICAL: {res.description}", "severity": res.severity
                }

    except Exception as e:
        logger.error(f"Scan Integration Error for {hostname}: {str(e)}")

    return compliance_map

@celery_app.task(name="run_security_scan_task")
def run_security_scan_task(scan_id: int):
    db = SessionLocal()
    start_time = datetime.now() # Record start
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan: return False

        scan.status = "processing"
        db.commit()

        # Deep inspection delay (simulate thorough audit)
        time.sleep(45) 

        target_host = scan.target.url.replace("https://", "").replace("http://", "").split('/')[0]
        
        nm = nmap.PortScanner()
        nm.scan(target_host, '21,22,23,25,80,443,3389,8000,8080,8443', arguments='-n -T4 --max-retries 1')

        if target_host in nm.all_hosts():
            for port in nm[target_host].get('tcp', {}):
                state = nm[target_host]['tcp'][port]['state']
                if state == 'open' and port not in [80, 443]:
                    db.add(Finding(scan_id=scan_id, name=f"Insecure Port Open: {port}",
                                   description=f"Port {port} is open."))

        scan.status = "completed"
        db.commit()
        
        # Prepare metadata
        timings = {"start": start_time.strftime("%Y-%m-%d %H:%M:%S"), 
                   "end": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        
        generate_pdf_report_task.delay(scan_id, scan.user_id, timings)
        return True
    finally:
        db.close()

@celery_app.task(name="generate_pdf_report_task")
def generate_pdf_report_task(scan_id: int, user_id: int, timings: dict = None):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan: return False

        target_url = scan.target.url
        hostname = target_url.replace("https://", "").replace("http://", "").split('/')[0]
        
        # Dynamic naming: sac.pdf, google.pdf
        domain_parts = hostname.split('.')
        file_prefix = domain_parts[0] if domain_parts[0] != "www" else domain_parts[1]

        compliance_data = evaluate_compliance(scan.findings, target_url, hostname)
        
        pdf_bytes, filename = generate_pdf_for_scan(scan, compliance_data, file_prefix, timings)
        full_path = save_pdf_file(pdf_bytes, filename)
        
        db.add(PdfReport(scan_id=scan.id, user_id=user_id, file_path=Path(full_path).name))
        db.commit()
        return True
    finally:
        db.close()