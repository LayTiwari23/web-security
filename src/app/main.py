# src/app/main.py

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ✅ UPDATED IMPORTS (Absolute Paths)
from src.app.config import get_settings
from src.core.logging_config import setup_logging
from src.core.exceptions import register_exception_handlers
from src.db.session import get_db

# ✅ UPDATED API IMPORTS
# Assumes 'api' folder is inside 'src/app'. 
# If 'api' is directly in 'src', change this to 'from src.api.v1 import ...'
from src.api.v1 import (
    routes_auth,
    routes_targets,
    routes_scans,
    routes_reports,
)

# -------------------------------------------------------------------
# App factory
# -------------------------------------------------------------------

def create_app() -> FastAPI:
    settings = get_settings()
    setup_logging()

    app = FastAPI(
        title="Web Security Compliance Checker",
        description="Scan web targets for common security misconfigurations.",
        version="1.0.0",
        debug=settings.DEBUG,
    )

    # Mount static files
    # We use resolve().parents[1] to go up two levels (from app/main.py -> src/app -> src) 
    # if your static folder is in src/static. 
    # If static is inside src/app/static, keeping .parent is fine.
    # Let's stick to your current logic but ensure folder exists.
    static_dir = Path(__file__).resolve().parent / "static"
    
    # Check if directory exists to avoid errors
    if not static_dir.exists():
        static_dir.mkdir(parents=True, exist_ok=True)
        
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Templates
    templates_dir = Path(__file__).resolve().parent / "templates"
    templates = Jinja2Templates(directory=str(templates_dir))

    # Store templates in app.state for reuse
    app.state.templates = templates

    # Routers (API)
    app.include_router(
        routes_auth.router,
        prefix="/api/v1/auth",
        tags=["auth"],
    )
    app.include_router(
        routes_targets.router,
        prefix="/api/v1/targets",
        tags=["targets"],
    )
    app.include_router(
        routes_scans.router,
        prefix="/api/v1/scans",
        tags=["scans"],
    )
    app.include_router(
        routes_reports.router,
        prefix="/api/v1/reports",
        tags=["reports"],
    )

    # Exception handlers
    register_exception_handlers(app)

    # -------------------------------------------------------------------
    # Simple server-rendered pages
    # -------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Any:
        """Landing page or redirect to dashboard/login."""
        return templates.TemplateResponse("dashboard.html", {"request": request})

    # Example dependency usage on a page if you need DB access:
    @app.get("/health", tags=["internal"])
    async def healthcheck(db=Depends(get_db)) -> Dict[str, str]:
        # optionally do a simple DB query here
        return {"status": "ok"}

    return app

app = create_app()