# src/services/pdf_service.py
import os
import logging
from pathlib import Path
from datetime import datetime
from fpdf import FPDF  # ✅ Use a real library to fix the 65b error

logger = logging.getLogger(__name__)

def generate_pdf_for_scan(scan):
    """Generates a valid PDF using the FPDF library."""
    logger.info(f"Generating real PDF for Scan ID: {scan.id}")
    
    pdf = FPDF()
    pdf.add_page()
    
    # Header
    pdf.set_font("Arial", "B", 16)
    pdf.cell(190, 10, "Web Security Compliance Report", ln=True, align="C")
    pdf.ln(10)
    
    # Scan Details
    pdf.set_font("Arial", "", 12)
    pdf.cell(100, 10, f"Scan ID: {scan.id}", ln=True)
    pdf.cell(100, 10, f"Target ID: {scan.target_id}", ln=True)
    pdf.cell(100, 10, f"Status: {scan.status}", ln=True)
    pdf.cell(100, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.ln(5)
    
    # Placeholder for findings
    pdf.set_font("Arial", "B", 12)
    pdf.cell(100, 10, "Summary of Findings:", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(0, 10, "This is a placeholder for your web security compliance scan results.")

    # Output as bytes
    pdf_bytes = pdf.output()
    
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    filename = f"scan-{scan.id}-target-{scan.target_id}-{timestamp}.pdf"
    
    return pdf_bytes, filename

def save_pdf_file(pdf_bytes: bytes, filename: str) -> str:
    """Saves PDF to the named volume."""
    output_dir = Path("/app/pdf_reports")
    
    if not output_dir.exists():
        os.makedirs(output_dir, mode=0o777, exist_ok=True)
    
    file_path = output_dir / filename
    
    with file_path.open("wb") as f:
        f.write(pdf_bytes)
    
    os.chmod(file_path, 0o666)
    logger.info(f"Successfully saved real PDF to {file_path}")
        
    return str(file_path)