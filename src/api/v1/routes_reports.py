from __future__ import annotations

import os
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db_session
from src.core.settings import get_settings
from src.db.models.pdf_report import PdfReport
from src.db.models.user import User
from src.services.report_service import (
    delete_report_for_user,
    list_reports_for_user,
)
from src.workers.tasks_scans import generate_pdf_report_task

router = APIRouter()
settings = get_settings()

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
def download_report(
    report_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Serves the PDF file from the Docker volume /app/pdf_reports.
    """
    report = db.query(PdfReport).filter(
        PdfReport.id == report_id, 
        PdfReport.user_id == current_user.id
    ).first()

    if not report:
        raise HTTPException(status_code=404, detail="Report record not found")

    storage_base = Path("/app/pdf_reports")
    filename = Path(report.file_path).name 
    file_path = storage_base / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404, 
            detail=f"PDF file not found. Ensure worker and API share the same volume."
        )

    return FileResponse(
        path=str(file_path),
        media_type="application/pdf",
        filename=file_path.name
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
    templates = request.app.state.templates
    reports = list_reports_for_user(db, user_id=current_user.id)
    return templates.TemplateResponse(
        "reports/list.html",
        {
            "request": request,
            "reports": reports,
            "user": current_user,
        },
    )

@router.post("/{scan_id}/generate/html")
async def generate_report_html(
    scan_id: int,
    current_user: User = Depends(get_current_user),
):
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
    success = delete_report_for_user(db, report_id=report_id, user_id=current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="Report deletion failed")

    return RedirectResponse(
        url="/api/v1/reports/html", 
        status_code=status.HTTP_302_FOUND
    )

# -------------------------------------------------
# New Logic: Bulk Cleanup
# -------------------------------------------------

@router.post("/delete-all/html")
async def delete_all_reports_html(
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Purges all reports and associated physical files for the current user.
    Uses ORM-enabled deletion to ensure cleanup logic is triggered.
    """
    reports = db.query(PdfReport).filter(PdfReport.user_id == current_user.id).all()
    
    for report in reports:
        # Service handles both DB record and physical file cleanup
        delete_report_for_user(db, report_id=report.id, user_id=current_user.id)
    
    db.commit()
    
    return RedirectResponse(
        url="/api/v1/reports/html", 
        status_code=status.HTTP_302_FOUND
    )