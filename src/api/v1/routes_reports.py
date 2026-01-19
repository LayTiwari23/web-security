# src/app/api/v1/routes_reports.py

from __future__ import annotations

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
        orm_mode = True


# -------------------------------------------------
# JSON API endpoints
# -------------------------------------------------


@router.get("/", response_model=List[ReportRead])
def list_reports(
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    List all PDF reports for the current user.
    """
    reports = list_reports_for_user(db, user_id=current_user.id)
    return reports


@router.post(
    "/generate/{scan_id}",
    status_code=status.HTTP_202_ACCEPTED,
)
def generate_report(
    scan_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Enqueue task to generate a PDF report for a scan.
    """
    # Ownership checks will be inside the task/service layer as well,
    # but we can do a quick pre-check here if desired.
    # For now we just enqueue; task will validate.
    generate_pdf_report_task.delay(scan_id=scan_id, user_id=current_user.id)
    return {"detail": "Report generation requested"}


@router.get("/{report_id}/download")
def download_report(
    report_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Download a PDF report if it belongs to the current user.
    """
    report = (
        db.query(PdfReport)
        .filter(
            PdfReport.id == report_id,
            PdfReport.user_id == current_user.id,
        )
        .first()
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )

    file_path = Path(report.file_path)
    if not file_path.is_absolute():
        file_path = Path(settings.PDF_OUTPUT_DIR) / file_path

    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file missing on server",
        )

    return FileResponse(
        path=str(file_path),
        media_type="application/pdf",
        filename=file_path.name,
    )


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    report_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Delete a PDF report and its file if it belongs to the current user.
    """
    success = delete_report_for_user(db, report_id=report_id, user_id=current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    return None


# -------------------------------------------------
# Server-rendered HTML endpoints
# -------------------------------------------------


@router.get("/html", response_class=HTMLResponse)
async def list_reports_page(
    request: Request,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Render a page listing all reports for the current user.
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


@router.post("/{scan_id}/generate/html", response_class=HTMLResponse)
async def generate_report_html(
    scan_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """
    Enqueue report generation from HTML UI, then redirect to reports list.
    """
    generate_pdf_report_task.delay(scan_id=scan_id, user_id=current_user.id)
    return RedirectResponse(
        url="/api/v1/reports/html",
        status_code=status.HTTP_302_FOUND,
    )


@router.get("/{report_id}/download/html")
async def download_report_html(
    report_id: int,
    request: Request,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    For HTML flow, reuse the same file download behavior.
    """
    return download_report(report_id=report_id, db=db, current_user=current_user)
