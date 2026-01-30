from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from src.app.config import get_settings
from src.core.logging_config import setup_logging
from src.core.exceptions import register_exception_handlers
from src.db.session import get_db

from src.api.v1 import (
    routes_auth,
    routes_targets,
    routes_scans,
    routes_reports,
)

def create_app() -> FastAPI:
    settings = get_settings()
    setup_logging()

    app = FastAPI(
        title="Web Security Compliance Checker",
        description="Scan web targets for common security misconfigurations.",
        version="1.0.0",
        debug=settings.DEBUG,
    )

    # -------------------------------------------------------------------
    # ✅ PROTOCOL MIDDLEWARE (Fixes Mixed Content for ngrok)
    # -------------------------------------------------------------------
    @app.middleware("http")
    async def force_https_behind_proxy(request: Request, call_next):
        if request.headers.get("x-forwarded-proto") == "https":
            request.scope["scheme"] = "https"
        return await call_next(request)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -------------------------------------------------------------------
    # ✅ ROBUST PATH CONFIGURATION (Absolute Paths)
    # -------------------------------------------------------------------
    current_file_path = os.path.abspath(__file__)
    # Go up two levels from src/app/main.py to get to project root
    src_dir = os.path.dirname(os.path.dirname(current_file_path)) 
    
    templates_dir = os.path.join(src_dir, "app", "templates")
    static_path = os.path.join(src_dir, "static")

    # Mount static files
    if os.path.exists(static_path):
        app.mount("/static", StaticFiles(directory=static_path), name="static")

    # Use absolute path for templates
    templates = Jinja2Templates(directory=templates_dir)
    app.state.templates = templates

    # -------------------------------------------------------------------
    # ✅ REGISTER ROUTERS
    # -------------------------------------------------------------------
    app.include_router(routes_auth.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(routes_targets.router, prefix="/api/v1/targets", tags=["targets"])
    app.include_router(routes_scans.router, prefix="/api/v1/scans", tags=["scans"])
    app.include_router(routes_reports.router, prefix="/api/v1/reports", tags=["reports"])

    register_exception_handlers(app)

    # -------------------------------------------------------------------
    # ✅ FRONTEND / UI ROUTES
    # -------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard_page(request: Request) -> Any:
        # Pass APP_NAME so base.html has a title
        return templates.TemplateResponse("dashboard.html", {
            "request": request, 
            "APP_NAME": "AUDIT_PRO"
        })

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Any:
        return templates.TemplateResponse("auth/login.html", {
            "request": request, 
            "APP_NAME": "AUDIT_PRO"
        })

    @app.get("/register", response_class=HTMLResponse)
    async def register_page(request: Request) -> Any:
        return templates.TemplateResponse("auth/register.html", {
            "request": request, 
            "APP_NAME": "AUDIT_PRO"
        })

    @app.get("/health", tags=["internal"])
    async def healthcheck(db=Depends(get_db)) -> Dict[str, str]:
        return {"status": "ok"}

    return app

app = create_app()