# src/app/api/v1/routes_auth.py

from __future__ import annotations

from datetime import timedelta

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
# API JSON endpoints
# -------------------------------------------------


@router.post("/register", status_code=status.HTTP_201_CREATED)
def api_register(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db_session),
):
    """
    Register a new user via JSON/form API.
    """
    existing = get_user_by_email(db, email=email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    user = create_user(db, email=email, password=password)
    return {"id": user.id, "email": user.email}


@router.post("/login")
def api_login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db_session),
):
    """
    Login endpoint that returns an access token (OAuth2 password flow).
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password",
        )

    # OAuth2PasswordRequestForm uses `username` field; we're using email.
    access_token_expires = timedelta(minutes=60 * 24)
    access_token = create_access_token(subject=user.id, expires_delta=access_token_expires)

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


# -------------------------------------------------
# Server-rendered HTML endpoints
# -------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """
    Render login page.
    """
    templates = request.app.state.templates
    return templates.TemplateResponse("auth/login.html", {"request": request})


@router.post("/login/html", response_class=HTMLResponse)
async def login_submit_html(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db_session),
):
    """
    Handle login form submission for HTML UI.
    Sets token in a cookie and redirects to dashboard.
    """
    user = authenticate_user(db, email, password)
    templates = request.app.state.templates

    if not user:
        # Re-render login with error
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": "Invalid email or password",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    token = create_access_token(subject=user.id)
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    
    # --- FIX APPLIED HERE ---
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        secure=False,    # MUST be False for localhost
        samesite="lax",  # Keeps cookie during redirect
        max_age=1800     # 30 minutes
    )
    # ------------------------
    
    return response


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """
    Render registration page.
    """
    templates = request.app.state.templates
    return templates.TemplateResponse("auth/register.html", {"request": request})


@router.post("/register/html", response_class=HTMLResponse)
async def register_submit_html(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db_session),
):
    """
    Handle registration form for HTML UI.
    """
    templates = request.app.state.templates
    existing = get_user_by_email(db, email=email)

    if existing:
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "error": "Email already registered",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    user = create_user(db, email=email, password=password)

    # Auto-login after registration (optional)
    token = create_access_token(subject=user.id)
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    
    # --- FIX APPLIED HERE ---
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        secure=False,    # MUST be False for localhost
        samesite="lax",  # Keeps cookie during redirect
        max_age=1800     # 30 minutes
    )
    # ------------------------

    return response


@router.post("/logout", response_class=HTMLResponse)
async def logout(request: Request):
    """
    Simple logout for HTML UI: clear token cookie and redirect to login.
    """
    response = RedirectResponse(url="/api/v1/auth/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response