from __future__ import annotations
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from src.api.deps import get_db_session
from src.core.security import create_access_token
from src.services.auth_service import (
    authenticate_user,
    create_user,
    get_user_by_email,
)

router = APIRouter()

# -------------------------------------------------
# Server-rendered HTML endpoints (UI)
# -------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render the themed login gateway."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "auth/login.html", 
        {"request": request, "APP_NAME": "AUDIT_PRO"}
    )

@router.post("/login/html", response_class=HTMLResponse)
async def login_submit_html(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db_session),
):
    """Handle login form with secure cookie injection."""
    user = authenticate_user(db, email, password)
    templates = request.app.state.templates

    if not user:
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": "ACCESS_DENIED: Invalid Credentials",
                "APP_NAME": "AUDIT_PRO"
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Token expires in 30 minutes for security
    token = create_access_token(subject=user.id)
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        secure=False,  # Set to True only when using HTTPS/Ngrok
        samesite="lax",
        max_age=1800   # 30 minutes
    )
    
    return response

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Render the user enrollment page."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "auth/register.html", 
        {"request": request, "APP_NAME": "AUDIT_PRO"}
    )

@router.post("/register/html", response_class=HTMLResponse)
async def register_submit_html(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db_session),
):
    """Handle registration and auto-login."""
    templates = request.app.state.templates
    existing = get_user_by_email(db, email=email)

    if existing:
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "error": "IDENTITY_EXISTS: Email already registered",
                "APP_NAME": "AUDIT_PRO"
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    user = create_user(db, email=email, password=password)
    token = create_access_token(subject=user.id)
    
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=1800
    )

    return response

@router.get("/logout")
@router.post("/logout")
async def logout(request: Request):
    """Clear authorization cookie and return to login."""
    response = RedirectResponse(url="/api/v1/auth/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

# -------------------------------------------------
# API JSON endpoints (For Tooling/Mobile)
# -------------------------------------------------

@router.post("/api/login")
def api_login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db_session),
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    access_token = create_access_token(subject=user.id)
    return {"access_token": access_token, "token_type": "bearer"}