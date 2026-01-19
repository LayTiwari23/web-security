# src/app/api/v1/routes_targets.py

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status, Form  # Added Form
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from src.api.deps import get_current_user, get_db_session
from src.db.models.target import Target
from src.db.models.user import User

router = APIRouter()


# -------------------------------------------------
# Pydantic schemas (For JSON API)
# -------------------------------------------------


class TargetBase(BaseModel):
    url: HttpUrl
    name: str | None = None


class TargetCreate(TargetBase):
    pass


class TargetRead(TargetBase):
    id: int

    class Config:
        from_attributes = True  # Updated from orm_mode for Pydantic V2 compatibility


# -------------------------------------------------
# JSON API endpoints
# -------------------------------------------------


@router.get("/", response_model=List[TargetRead])
def list_targets(
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    List all targets for the current user via JSON API.
    """
    targets = db.query(Target).filter(Target.user_id == current_user.id).all()
    return targets


@router.post(
    "/",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
)
def create_target(
    target_in: TargetCreate,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Create a new target for the current user via JSON API.
    """
    target = Target(
        user_id=current_user.id,
        url=str(target_in.url),
        name=target_in.name,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: int,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Delete a target owned by the current user.
    """
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    db.delete(target)
    db.commit()
    return None


# -------------------------------------------------
# Server-rendered HTML endpoints
# -------------------------------------------------


@router.get("/html", response_class=HTMLResponse)
async def list_targets_page(
    request: Request,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Render a page with the user's targets and a simple 'add target' form.
    """
    templates = request.app.state.templates
    targets = db.query(Target).filter(Target.user_id == current_user.id).all()
    return templates.TemplateResponse(
        "targets/list.html",
        {
            "request": request,
            "targets": targets,
            "user": current_user,
        },
    )


@router.post("/html", response_class=HTMLResponse)
async def create_target_html(
    request: Request,
    url: str = Form(...),           # Fixed: Now reads from Form body
    name: str | None = Form(None),   # Fixed: Now reads from Form body
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Handle 'add target' form submission from HTML and redirect back to list.
    """
    # Create the database record
    target = Target(
        user_id=current_user.id, 
        url=url, 
        name=name
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
    request: Request,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Delete a target via HTML form and redirect back to list.
    """
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