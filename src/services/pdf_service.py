# src/app/services/pdf_service.py

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML  # or reportlab / xhtml2pdf, etc.

from sqlalchemy.orm import Session

from src.core.settings import get_settings
from src.db.models.pdf_report import PdfReport
from src.db.models.scan import Finding, Scan
from src.db.models.user import User
from src.services.report_service import create_report_record

settings = get_settings()


# src/app/services/pdf_service.py

def _get_jinja_env() -> Environment:
    # Option A: Absolute path inside Docker (Safest)
    templates_dir = Path("/app/src/app/templates")
    
    # Check if path exists for debugging
    if not templates_dir.exists():
        # Fallback to relative path if running locally outside Docker
        templates_dir = Path(__file__).resolve().parents[1] / "templates"

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    return env


def render_scan_report_html(
    *,
    user: User,
    scan: Scan,
    findings: List[Finding],
) -> str:
    """
    Render HTML for a scan PDF report using Jinja2 template.
    Expects a template at templates/reports/pdf_report.html
    """
    env = _get_jinja_env()
    template = env.get_template("reports/pdf_report.html")

    # Simple severity stats
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        sev = (f.severity or "").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    html = template.render(
        user=user,
        scan=scan,
        findings=findings,
        generated_at=datetime.utcnow(),
        severity_counts=severity_counts,
    )
    return html


def html_to_pdf_bytes(html_content: str) -> bytes:
    """
    Convert rendered HTML to PDF bytes using WeasyPrint.
    """
    pdf = HTML(string=html_content).write_pdf()
    return pdf


def save_pdf_file(pdf_bytes: bytes, filename: str) -> str:
    """
    Save PDF bytes to disk under settings.PDF_OUTPUT_DIR.
    Returns relative file path (filename only) or full path –
    here we store relative path and let service resolve.
    """
    output_dir = Path(settings.PDF_OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    file_path = output_dir / filename
    with file_path.open("wb") as f:
        f.write(pdf_bytes)

    # Store relative path (filename) in DB; you may choose full path instead
    return str(file_path)


def generate_pdf_for_scan(
    db: Session,
    *,
    user: User,
    scan: Scan,
    findings: List[Finding],
) -> PdfReport:
    """
    High-level helper:
      1. Render HTML
      2. Convert to PDF
      3. Save PDF file
      4. Create PdfReport DB record
    """
    html = render_scan_report_html(user=user, scan=scan, findings=findings)
    pdf_bytes = html_to_pdf_bytes(html)

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    safe_target = f"{scan.target_id}"
    filename = f"scan-{scan.id}-target-{safe_target}-{timestamp}.pdf"

    file_path = save_pdf_file(pdf_bytes, filename)

    report = create_report_record(
        db,
        user_id=user.id,
        scan_id=scan.id,
        file_path=file_path,
    )
    return report