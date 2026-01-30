from __future__ import annotations
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db_session
from src.db.models.target import Target
from src.db.models.user import User

router = APIRouter()

# -------------------------------------------------
# Pydantic schemas (JSON API compatibility)
# -------------------------------------------------

class TargetBase(BaseModel):
    url: str  # String allows for flexible entry; logic handles validation
    name: Optional[str] = None

class TargetCreate(TargetBase):
    pass

class TargetRead(TargetBase):
    id: int

    class Config:
        from_attributes = True

# -------------------------------------------------
# Server-rendered HTML endpoints (The UI)
# -------------------------------------------------

@router.get("/html", response_class=HTMLResponse)
async def list_targets_page(
    request: Request,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """Render the main targets gallery/list."""
    templates = request.app.state.templates
    targets = db.query(Target).filter(Target.user_id == current_user.id).all()
    
    return templates.TemplateResponse(
        "targets/list.html",
        {
            "request": request,
            "targets": targets,
            "user": current_user,
            "APP_NAME": "AUDIT_PRO"
        },
    )

@router.get("/new", response_class=HTMLResponse)
async def new_target_page(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Explicit page for adding a new target (linked from Dashboard)."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "targets/new.html",
        {
            "request": request,
            "user": current_user,
            "APP_NAME": "AUDIT_PRO"
        },
    )

@router.post("/html", response_class=HTMLResponse)
async def create_target_html(
    request: Request,
    url: str = Form(...),
    name: Optional[str] = Form(None),
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """Process target creation and redirect to list."""
    # Logic: ensure URL starts with http if user forgets
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'

    target = Target(
        user_id=current_user.id, 
        url=url, 
        name=name or url.replace('https://', '').replace('http://', '').split('/')[0]
    )
    db.add(target)
    db.commit()
    
    return RedirectResponse(
        url="/api/v1/targets/html",
        status_code=status.HTTP_302_FOUND,
    )

@router.post("/{target_id}/delete/html", response_class=HTMLResponse)
async def delete_target_html(
    target_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """Securely delete a target."""
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if target:
        db.delete(target)
        db.commit()

    return RedirectResponse(
        url="/api/v1/targets/html",
        status_code=status.HTTP_302_FOUND,
    )

# -------------------------------------------------
# JSON API (Standard endpoints)
# -------------------------------------------------

@router.get("/", response_model=List[TargetRead])
def list_targets(
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    return db.query(Target).filter(Target.user_id == current_user.id).all()

@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(Target.id == target_id, Target.user_id == current_user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
    return None