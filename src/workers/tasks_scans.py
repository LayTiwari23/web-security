import logging
import time
from datetime import datetime
from pathlib import Path
import nmap

from src.workers.celery_app import celery_app
from src.db.session import SessionLocal
from src.db.models import Scan, PdfReport, Finding
from src.services.pdf_service import generate_pdf_for_scan, save_pdf_file

# Import the new Master Runner that orchestrates check1.py through check28.py
from src.services.security_checks import master_runner

logger = logging.getLogger(__name__)

def evaluate_compliance(findings, target_url, hostname):
    """
    Orchestrates live scans and maps them to the 28 audit parameters.
    Check 1 is processed here based on Nmap results.
    """
    # Initialize compliance map
    compliance_map = {str(i): {"status": "Y", "remark": "Compliant.", "severity": "info"} for i in range(1, 29)}

    # --- Check 1: Insecure HTTP/Network Ports Logic ---
    # Standards: CIS Benchmark 1.1, NIST SP 800-123 (Server Hardening)
    
    open_ports = []
    for f in findings:
        if "port" in f.name.lower():
            # Extract port number from name (e.g., "Insecure Port Open: 21")
            port_num = ''.join(filter(str.isdigit, f.name))
            if port_num:
                open_ports.append(port_num)

    if not open_ports:
        compliance_map["1"] = {
            "status": "Y",
            "remark": "Compliant: Only authorized ports (80/443) are exposed. Attack surface is minimized.",
            "severity": "info"
        }
    else:
        # Check for highly dangerous ports (Telnet, FTP, RDP, SMB)
        critical_ports = {"21", "23", "3389", "445", "139"}
        found_critical = [p for p in open_ports if p in critical_ports]
        
        if found_critical:
            compliance_map["1"] = {
                "status": "N",
                "remark": f"NOT COMPLIANT: Critical legacy/management ports exposed: {', '.join(found_critical)}. High risk of brute-force and sniffing.",
                "severity": "high"
            }
        else:
            # For non-standard but active ports like 8080, 8443
            compliance_map["1"] = {
                "status": "Y",
                "remark": f"Warning: Non-standard web ports detected ({', '.join(open_ports)}). Ensure these are restricted to authorized users. Y",
                "severity": "warning"
            }

    # --- Rest of the checks (2-28) ---
    try:
        from src.services.security_checks import master_runner
        check_results = master_runner.run_all(target_url)

        for check_id, res in check_results.items():
            compliance_map[check_id] = {
                "status": res.get("compliance", "N"),
                "remark": res.get("remark", "No data returned."),
                "severity": res.get("severity", "info")
            }
    except Exception as e:
        logger.error(f"Scan Integration Error for {hostname}: {str(e)}")

    return compliance_map
@celery_app.task(name="run_security_scan_task")
def run_security_scan_task(scan_id: int):
    db = SessionLocal()
    start_time = datetime.now()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan: return False

        scan.status = "processing"
        db.commit()

        # Extract target host for Nmap
        target_host = scan.target.url.replace("https://", "").replace("http://", "").split('/')[0]

        # Standard Nmap Port Scan (Check 1)
        nm = nmap.PortScanner()
        nm.scan(target_host, '21,22,23,25,80,443,3389,8000,8080,8443', arguments='-n -T4 --max-retries 2')

        if target_host in nm.all_hosts():
            for port in nm[target_host].get('tcp', {}):
                state = nm[target_host]['tcp'][port]['state']
                if state == 'open':
                    db.add(Finding(
                        scan_id=scan_id, 
                        name=f"Insecure Port Open: {port}",
                        description=f"Port {port} ({nm[target_host]['tcp'][port]['name']}) is open."
                    ))
        
        db.commit() # Save nmap findings before passing to evaluation

        # Transition to Report Generation
        timings = {
            "start": start_time.strftime("%Y-%m-%d %H:%M:%S"), 
            "end": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        generate_pdf_report_task.delay(scan_id, scan.user_id, timings)
        
        scan.status = "completed"
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Task Failed for Scan {scan_id}: {str(e)}")
        if scan: 
            scan.status = "failed"
            db.commit()
        return False
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
        
        # Clean naming for the file
        domain_parts = hostname.split('.')
        file_prefix = domain_parts[0] if domain_parts[0] != "www" else domain_parts[1]

        # Call the orchestrator
        compliance_data = evaluate_compliance(scan.findings, target_url, hostname)
        
        # Generate and save PDF
        pdf_bytes, filename = generate_pdf_for_scan(scan, compliance_data, file_prefix, timings)
        full_path = save_pdf_file(pdf_bytes, filename)
        
        db.add(PdfReport(scan_id=scan.id, user_id=user_id, file_path=Path(full_path).name))
        db.commit()
        return True
    finally:
        db.close()