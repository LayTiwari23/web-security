# src/app/workers/tasks_scans.py

from __future__ import annotations

from datetime import datetime

from celery import shared_task
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.settings import get_settings
from src.db.models.scan import Scan, Finding
from src.db.models.user import User
from src.services.scan_service import (
    add_finding,
    mark_scan_completed,
    mark_scan_failed,
    mark_scan_started,
)
from src.services.security_checks import run_all_checks
from src.services.pdf_service import generate_pdf_for_scan

settings = get_settings()

# Celery doesn't automatically reuse FastAPI's session dependency,
# so we create our own simple session factory here.

# ✅ FIX: Add str() around the URL
engine = create_engine(str(settings.DATABASE_URL), pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _get_db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@shared_task(name="run_security_scan")
def run_security_scan_task(scan_id: int) -> None:
    """
    Celery task: run all security checks for a given scan.
    """
    for db in _get_db_session():
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            # Nothing to do
            return

        try:
            scan = mark_scan_started(db, scan)

            # Build the URL from the target. Assumes Target has a `url` field.
            target = scan.target
            url = target.url

            # Run all checks
            check_results = run_all_checks(url)

            # Store findings
            for result in check_results:
                add_finding(
                    db,
                    scan=scan,
                    check_type=result.check_type,
                    name=result.name,
                    severity=result.severity,
                    description=result.description,
                    recommendation=result.recommendation,
                    raw_data=result.raw_data or {},
                )

            # Optionally, create a high-level summary
            summary = f"Scan completed with {len(check_results)} findings."
            mark_scan_completed(
                db,
                scan,
                summary=summary,
                extra_data={
                    "findings_count": len(check_results),
                    "completed_at": datetime.utcnow().isoformat(),
                },
            )

        except Exception as e:  # pragma: no cover - error path
            mark_scan_failed(
                db,
                scan,
                error_message=f"Scan failed: {e}",
                extra_data={"error": str(e)},
            )
        finally:
            db.close()


@shared_task(name="generate_pdf_report")
def generate_pdf_report_task(scan_id: int, user_id: int) -> None:
    """
    Celery task: generate a PDF report for a given scan and user.
    """
    for db in _get_db_session():
        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id, Scan.user_id == user_id)
            .first()
        )
        if not scan:
            return

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return

        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == scan.id)
            .order_by(Finding.severity.desc())
            .all()
        )

        # If no findings, you may still want a PDF summarizing "no issues found"
        try:
            generate_pdf_for_scan(db, user=user, scan=scan, findings=findings)
        finally:
            db.close()