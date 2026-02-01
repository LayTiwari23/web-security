from __future__ import annotations
import os
from typing import Any, Dict

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
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

    # ✅ Centralized Branding (matches sidebar and templates)
    APP_NAME = "WebSec Audit"

    app = FastAPI(
        title=APP_NAME,
        description="Scan web targets for common security misconfigurations.",
        version="1.0.0",
        debug=settings.DEBUG,
    )

    # -------------------------------------------------------------------
    # ✅ PROTOCOL MIDDLEWARE (Ensures HTTPS detection behind proxies)
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
    # ✅ PATH CONFIGURATION (Absolute paths for Docker reliability)
    # -------------------------------------------------------------------
    current_file_path = os.path.abspath(__file__)
    # Navigate from src/app/main.py to the project root
    src_dir = os.path.dirname(os.path.dirname(current_file_path)) 
    
    templates_dir = os.path.join(src_dir, "app", "templates")
    static_path = os.path.join(src_dir, "static")

    # Mount static assets (CSS, JS, Images)
    if os.path.exists(static_path):
        app.mount("/static", StaticFiles(directory=static_path), name="static")

    # Initialize Jinja2 Templates
    templates = Jinja2Templates(directory=templates_dir)
    app.state.templates = templates

    # -------------------------------------------------------------------
    # ✅ REGISTER ROUTERS
    # These prefixes determine the action URL in your HTML forms.
    # -------------------------------------------------------------------
    app.include_router(routes_auth.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(routes_targets.router, prefix="/api/v1/targets", tags=["targets"])
    app.include_router(routes_scans.router, prefix="/api/v1/scans", tags=["scans"])
    app.include_router(routes_reports.router, prefix="/api/v1/reports", tags=["reports"])

    register_exception_handlers(app)

    # -------------------------------------------------------------------
    # ✅ UI ROUTES (Aligning with sidebar and branding)
    # -------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def root_redirect():
        """Redirect root traffic to the centralized login gateway."""
        return RedirectResponse(url="/api/v1/auth/login")

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard_page(request: Request) -> Any:
        """Render the main security dashboard."""
        return templates.TemplateResponse("dashboard.html", {
            "request": request, 
            "APP_NAME": APP_NAME
        })

    # Note: Login/Register pages are served from routes_auth.py via prefix
    # Accessible at: /api/v1/auth/login and /api/v1/auth/register

    @app.get("/health", tags=["internal"])
    async def healthcheck(db=Depends(get_db)) -> Dict[str, str]:
        """Health check endpoint for container orchestration."""
        return {"status": "ok"}

    return app

app = create_app()