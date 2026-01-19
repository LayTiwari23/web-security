# src/app/services/report_service.py

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from sqlalchemy.orm import Session

from src.core.settings import get_settings
from src.db.models.pdf_report import PdfReport
from src.db.models.scan import Scan

settings = get_settings()


def list_reports_for_user(db: Session, user_id: int) -> List[PdfReport]:
    """
    Return all PDF reports for a given user, newest first.
    """
    return (
        db.query(PdfReport)
        .filter(PdfReport.user_id == user_id)
        .order_by(PdfReport.created_at.desc())
        .all()
    )


def get_report_for_user(
    db: Session,
    report_id: int,
    user_id: int,
) -> Optional[PdfReport]:
    """
    Fetch a specific report ensuring it belongs to the user.
    """
    return (
        db.query(PdfReport)
        .filter(PdfReport.id == report_id, PdfReport.user_id == user_id)
        .first()
    )


def create_report_record(
    db: Session,
    *,
    user_id: int,
    scan_id: int,
    file_path: str,
) -> PdfReport:
    """
    Create a PdfReport DB record. Assumes file already generated.
    """
    report = PdfReport(
        user_id=user_id,
        scan_id=scan_id,
        file_path=file_path,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def delete_report_for_user(
    db: Session,
    report_id: int,
    user_id: int,
) -> bool:
    """
    Delete report record and file if it belongs to the user.
    Returns True if deleted, False if not found / not owned.
    """
    report = get_report_for_user(db, report_id=report_id, user_id=user_id)
    if not report:
        return False

    # Remove file if exists
    file_path = Path(report.file_path)
    if not file_path.is_absolute():
        file_path = Path(settings.PDF_OUTPUT_DIR) / file_path
    if file_path.exists():
        try:
            file_path.unlink()
        except OSError:
            # Log error in production; here we silently ignore
            pass

    db.delete(report)
    db.commit()
    return True


def get_scan_owned_by_user(
    db: Session,
    *,
    scan_id: int,
    user_id: int,
) -> Optional[Scan]:
    """
    Helper: find scan by id ensuring it belongs to given user.
    Useful for pre-validating before generating a report.
    """
    return (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == user_id)
        .first()
    )