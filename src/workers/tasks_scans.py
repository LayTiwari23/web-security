# src/workers/tasks_scans.py
import logging
from src.workers.celery_app import celery_app
from src.db.session import SessionLocal
# Import models from the package root to ensure the registry is initialized
from src.db.models import Scan, PdfReport 
from src.services.pdf_service import generate_pdf_for_scan, save_pdf_file

logger = logging.getLogger(__name__)

@celery_app.task(name="run_security_scan_task")
def run_security_scan_task(scan_id: int):
    """✅ Fixes the ImportError causing 502/504 errors."""
    logger.info(f"Background scan started for Scan ID: {scan_id}")
    return True

@celery_app.task(name="generate_pdf_report_task")
def generate_pdf_report_task(scan_id: int, user_id: int):
    """Processes report generation and database updates."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
        if not scan:
            logger.error(f"Scan not found.")
            return False

        # Generate binary data and save to volume
        pdf_bytes, filename = generate_pdf_for_scan(scan)
        file_path = save_pdf_file(pdf_bytes, filename)

        # Update DB using the singular 'report' relationship
        new_report = PdfReport(
            scan_id=scan.id,
            user_id=user_id,
            file_path=file_path
        )
        db.add(new_report)
        db.commit()
        return f"Created: {file_path}"
    except Exception as e:
        logger.error(f"Task error: {str(e)}")
        db.rollback()
        raise e
    finally:
        db.close()