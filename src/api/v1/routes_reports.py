from __future__ import annotations
import os
import time
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db_session
from src.app.config import get_settings
from src.db.models.pdf_report import PdfReport
from src.db.models.user import User
from src.services.report_service import (
    delete_report_for_user,
    list_reports_for_user,
)
from src.workers.tasks_scans import generate_pdf_report_task

router = APIRouter()
settings = get_settings()

# ✅ Constant Configuration
PDF_STORAGE_DIR = "/app/pdf_reports"
APP_NAME = "WebSec Audit"

# -------------------------------------------------
# Pydantic schemas
# -------------------------------------------------

class ReportRead(BaseModel):
    id: int
    scan_id: int
    file_path: str

    class Config:
        from_attributes = True

# -------------------------------------------------
# Core Logic: Download & Generate
# -------------------------------------------------

@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Serves the PDF file. 
    Handles Docker volume pathing and syncs with the database 'file_path'.
    """
    # 1. Primary lookup by report_id
    report = db.query(PdfReport).filter(
        PdfReport.id == report_id, 
        PdfReport.user_id == current_user.id
    ).first()

    # 2. Fallback lookup by scan_id (in case frontend passes scan_id)
    if not report:
        report = db.query(PdfReport).filter(
            PdfReport.scan_id == report_id,
            PdfReport.user_id == current_user.id
        ).first()

    if not report:
        raise HTTPException(status_code=404, detail="Report record not found in database.")

    # 3. Resolve the path (e.g., mapping 'github.pdf' from DB to /app/pdf_reports/)
    filename = os.path.basename(report.file_path)
    file_path = Path(PDF_STORAGE_DIR) / filename

    # ⏳ Race Condition Handling:
    # If the user clicks 'Download' before the ~40s generation finishes, 
    # we retry for 3 seconds before throwing the final 404.
    retries = 3
    while not file_path.exists() and retries > 0:
        time.sleep(1) 
        retries -= 1

    if not file_path.exists():
        # Final fallback check for local/relative paths
        local_path = Path("pdf_reports") / filename
        if local_path.exists():
            file_path = local_path
        else:
            print(f"DEBUG: File not found for Scan {report.scan_id} at {file_path}")
            raise HTTPException(
                status_code=404, 
                detail=f"Physical file '{filename}' missing from storage. Please wait 60s after generation."
            )

    return FileResponse(
        path=str(file_path),
        media_type="application/pdf",
        filename=f"WebSec_Audit_Report_{filename}"
    )

# -------------------------------------------------
# HTML Interface Routes
# -------------------------------------------------

@router.get("/html", response_class=HTMLResponse)
async def list_reports_page(
    request: Request,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """Renders the central report repository page."""
    templates = request.app.state.templates
    reports = list_reports_for_user(db, user_id=current_user.id)
    return templates.TemplateResponse(
        "reports/list.html",
        {
            "request": request,
            "reports": reports,
            "user": current_user,
            "APP_NAME": APP_NAME 
        },
    )

@router.post("/{scan_id}/generate/html")
async def generate_report_html(
    scan_id: int,
    current_user: User = Depends(get_current_user),
):
    """Triggers the background worker to compile the PDF."""
    generate_pdf_report_task.delay(scan_id=scan_id, user_id=current_user.id)
    return RedirectResponse(
        url="/api/v1/reports/html", 
        status_code=status.HTTP_302_FOUND
    )

@router.post("/{report_id}/delete/html")
async def delete_report_html(
    report_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """Deletes report record and redirects back to list."""
    success = delete_report_for_user(db, report_id=report_id, user_id=current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="Report deletion failed")

    return RedirectResponse(
        url="/api/v1/reports/html", 
        status_code=status.HTTP_302_FOUND
    )

@router.post("/delete-all/html")
async def delete_all_reports_html(
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """Purges all reports for the authenticated user."""
    reports = db.query(PdfReport).filter(PdfReport.user_id == current_user.id).all()
    for report in reports:
        delete_report_for_user(db, report_id=report.id, user_id=current_user.id)
    
    db.commit()
    return RedirectResponse(
        url="/api/v1/reports/html", 
        status_code=status.HTTP_302_FOUND
    )