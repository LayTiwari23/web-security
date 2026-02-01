from __future__ import annotations
from datetime import datetime
import os
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db_session
from src.db.models.scan import Scan, Finding
from src.db.models.pdf_report import PdfReport
from src.db.models.target import Target
from src.db.models.user import User
from src.services.scan_service import (
    create_scan_for_target,
    get_scan_with_findings,
    list_user_scans,
)
from src.workers.tasks_scans import run_security_scan_task

router = APIRouter()

# ✅ Constant for the Docker Volume path
PDF_STORAGE_DIR = "/app/pdf_reports"

# -------------------------------------------------
# Pydantic schemas (JSON API)
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

class ScanDetailSchema(ScanRead):
    findings: List[FindingRead] = []

# -------------------------------------------------
# ✅ HTMX LIVE FEED WITH LOADING BAR
# -------------------------------------------------

@router.get("/recent-feed", response_class=HTMLResponse)
async def get_recent_feed(
    request: Request,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """Returns a partial HTML snippet for the dashboard's live monitor."""
    recent_scans = db.query(Scan).filter(
        Scan.user_id == current_user.id
    ).order_by(Scan.created_at.desc()).limit(5).all()

    if not recent_scans:
        return '<p class="text-slate-500 font-mono text-[9px] uppercase italic">SYSTEM_IDLE: No logs found.</p>'

    html_content = ""
    for scan in recent_scans:
        if scan.status in ["running", "pending"]:
            findings_count = db.query(Finding).filter(Finding.scan_id == scan.id).count()
            progress = min(int((findings_count / 28) * 100), 99) if findings_count > 0 else 12
            
            status_html = f"""
            <div class="flex flex-col w-32 gap-1.5">
                <div class="flex justify-between items-center text-[8px] font-black tracking-tighter">
                    <span class="text-blue-400 animate-pulse uppercase">PROBING_ASSET...</span>
                    <span class="text-blue-300">{progress}%</span>
                </div>
                <div class="h-1 w-full bg-blue-500/10 rounded-full overflow-hidden relative border border-blue-500/20">
                    <div class="h-full bg-blue-400 shadow-[0_0_10px_#60a5fa] transition-all duration-1000 animate-loading-bar" 
                         style="width: {progress}%;"></div>
                </div>
            </div>
            """
        elif scan.status == "completed":
            status_html = """
            <div class="flex flex-col w-32 gap-1.5">
                <div class="flex justify-between items-center text-[8px] font-black tracking-tighter">
                    <span class="text-cyber-green uppercase">DECRYPTED</span>
                    <span class="text-cyber-green">100%</span>
                </div>
                <div class="h-1 w-full bg-cyber-green/20 rounded-full overflow-hidden border border-cyber-green/30">
                    <div class="h-full bg-cyber-green shadow-[0_0_8px_#00ff41]" style="width: 100%;"></div>
                </div>
            </div>
            """
        else:
            status_html = f'<span class="text-slate-500 font-black text-[9px]">{scan.status.upper()}</span>'

        html_content += f"""
        <div class="border-l-2 border-white/10 pl-3 py-3 bg-white/[0.02] rounded-r-lg mb-3 group hover:bg-white/5 transition-all">
            <div class="flex justify-between items-start">
                <div class="flex flex-col">
                    <span class="font-bold text-slate-300 text-[10px]">#SESSION_{scan.id:04d}</span>
                    <span class="text-slate-500 text-[8px] truncate mt-1 w-32 italic">
                        {scan.target.url if scan.target else 'EXTERNAL_HOST'}
                    </span>
                </div>
                {status_html}
            </div>
        </div>
        """
    return html_content

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
        {
            "request": request, 
            "scans": scans, 
            "user": current_user,
            "APP_NAME": "WEBSEC AUDIT" # ✅ Updated here
        },
    )

@router.post("/start/html")
async def start_scan_html(
    target_id: int = Form(...),
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(
        Target.id == target_id, 
        Target.user_id == current_user.id
    ).first()
    
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
    scan = db.query(Scan).filter(
        Scan.id == scan_id, 
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(
        Finding.scan_id == scan.id
    ).order_by(Finding.id.asc()).all()
    
    report = db.query(PdfReport).filter(PdfReport.scan_id == scan.id).first()

    return templates.TemplateResponse(
        "scans/detail.html",
        {
            "request": request, 
            "scan": scan, 
            "results": findings,
            "report": report, 
            "user": current_user,
            "APP_NAME": "WebSec Audit" # ✅ Updated here
        },
    )

# -------------------------------------------------
# ✅ UPDATED: PDF Download Endpoint with Absolute Pathing
# -------------------------------------------------

@router.get("/{scan_id}/report/download")
async def download_report(
    scan_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    report = db.query(PdfReport).filter(
        PdfReport.scan_id == scan_id, 
        PdfReport.user_id == current_user.id
    ).first()

    if not report or not report.file_path:
        raise HTTPException(status_code=404, detail="Report record not found in database.")

    # ✅ Join the storage directory with the filename from the DB
    # This converts 'github.pdf' into '/app/pdf_reports/github.pdf'
    full_path = Path(PDF_STORAGE_DIR) / os.path.basename(report.file_path)

    if not full_path.exists():
        # Debugging aid: prints where it's looking in the docker logs
        print(f"DEBUG: Looking for file at {full_path}")
        raise HTTPException(
            status_code=404, 
            detail=f"Physical file missing. System expected it at: {full_path}"
        )

    return FileResponse(
        path=full_path,
        media_type='application/pdf',
        filename=f"Audit_Report_{scan_id}.pdf"
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

@router.get("/{scan_id}", response_model=ScanDetailSchema)
def get_scan_detail(
    scan_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    scan = get_scan_with_findings(db, scan_id=scan_id, user_id=current_user.id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan