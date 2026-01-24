from __future__ import annotations
from datetime import datetime
import os
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse # ✅ Added FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db_session
from src.db.models.scan import Scan, Finding
from src.db.models.pdf_report import PdfReport # ✅ Added PdfReport model
from src.db.models.target import Target
from src.db.models.user import User
from src.services.scan_service import (
    create_scan_for_target,
    get_scan_with_findings,
    list_user_scans,
)
from src.workers.tasks_scans import run_security_scan_task

router = APIRouter()

# -------------------------------------------------
# Pydantic schemas
# -------------------------------------------------

class FindingRead(BaseModel):
    id: int
    check_type: str
    name: str
    severity: str
    description: Optional[str] = None
    recommendation: Optional[str] = None
    raw_data: Optional[dict] = None

    class Config:
        from_attributes = True

class ScanRead(BaseModel):
    id: int
    status: str
    target_id: int
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    summary: Optional[str] = None

    class Config:
        from_attributes = True

class ScanDetail(ScanRead):
    findings: List[FindingRead] = []

# -------------------------------------------------
# Server-rendered HTML endpoints
# -------------------------------------------------

@router.get("/html", response_class=HTMLResponse)
async def list_scans_page(
    request: Request,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    templates = request.app.state.templates
    scans = list_user_scans(db, user_id=current_user.id)
    return templates.TemplateResponse(
        "scans/list.html",
        {"request": request, "scans": scans, "user": current_user},
    )

@router.post("/start/html", response_class=HTMLResponse)
async def start_scan_html(
    request: Request,
    target_id: int = Form(...),
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = create_scan_for_target(db, user=current_user, target=target)
    run_security_scan_task.delay(scan_id=scan.id)

    return RedirectResponse(
        url="/api/v1/scans/html",
        status_code=status.HTTP_302_FOUND,
    )

@router.get("/{scan_id}/html", response_class=HTMLResponse)
async def scan_detail_page(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    templates = request.app.state.templates
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).order_by(Finding.severity.desc()).all()
    
    # ✅ FIX: Using singular 'report' relationship from our stabilized model
    report = scan.report if hasattr(scan, "report") else None

    return templates.TemplateResponse(
        "scans/detail.html",
        {"request": request, "scan": scan, "findings": findings, "report": report, "user": current_user},
    )

# -------------------------------------------------
# PDF Download Endpoint
# -------------------------------------------------

@router.get("/{scan_id}/report/download", response_class=FileResponse)
async def download_report(
    scan_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """
    Streams the PDF from the named volume to the browser.
    """
    report = db.query(PdfReport).filter(
        PdfReport.scan_id == scan_id, 
        PdfReport.user_id == current_user.id
    ).first()

    if not report:
        raise HTTPException(status_code=404, detail="No PDF report generated for this scan.")

    file_path = Path(report.file_path)

    # ✅ Verification: Ensure file is still in the websec_pdf_reports volume
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="The report file was not found in storage.")

    return FileResponse(
    path=file_path,
    media_type='application/pdf',
    filename=f"Report_Scan_{scan_id}.pdf" # Forces the browser to treat it as a download
)

# -------------------------------------------------
# JSON API endpoints
# -------------------------------------------------

@router.get("/", response_model=List[ScanRead])
def list_scans(
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    return list_user_scans(db, user_id=current_user.id)

@router.post("/", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def start_scan(
    target_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(Target.id == target_id, Target.user_id == current_user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = create_scan_for_target(db, user=current_user, target=target)
    run_security_scan_task.delay(scan_id=scan.id)
    return scan

@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan_detail(
    scan_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    scan = get_scan_with_findings(db, scan_id=scan_id, user_id=current_user.id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan