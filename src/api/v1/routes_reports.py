# src/app/api/v1/routes_reports.py

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
# Pydantic schemas (Updated for V2)
# -------------------------------------------------

class ReportRead(BaseModel):
    id: int
    scan_id: int
    file_path: str

    class Config:
        # Fixed the V2 warning from your logs
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

    file_path = Path(report.file_path)
    
    # Ensure absolute path matching the volume mount
    if not file_path.is_absolute():
        file_path = Path("/app/pdf_reports") / file_path

    if not file_path.exists():
        raise HTTPException(
            status_code=404, 
            detail=f"PDF file not found at {file_path}. Is the worker running?"
        )

    return FileResponse(
        path=str(file_path),
        media_type="application/pdf",
        filename=file_path.name
    )

# -------------------------------------------------
# HTML Interface Routes (Fixes the 404)
# -------------------------------------------------

@router.get("/html", response_class=HTMLResponse)
async def list_reports_page(
    request: Request,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    This is the page your API tried to redirect to.
    """
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
    """
    Trigger generation and redirect to the reports list.
    """
    # Enqueue the background task
    generate_pdf_report_task.delay(scan_id=scan_id, user_id=current_user.id)
    
    # Redirect to the route we just defined above
    return RedirectResponse(
        url="/api/v1/reports/html", 
        status_code=status.HTTP_302_FOUND
    )