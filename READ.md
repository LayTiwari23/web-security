# Web Security Compliance Checker

A small web app and API built with FastAPI and Celery to scan web applications for common security misconfigurations (HTTP headers, TLS, cookies, etc.), track scan jobs, and generate downloadable PDF reports.

## Features

- User registration & login (JWT-based API + cookie-based HTML UI)
- Manage scan targets (URLs)
- Start asynchronous security scans using Celery workers
- Store detailed findings per scan (headers, TLS, cookies, etc.)
- Generate and download PDF reports for completed scans
- Simple server-rendered HTML interface (Jinja2) + JSON API
- Dockerized stack (FastAPI/Celery, PostgreSQL, Redis, optional Nginx)

---

## Project Structure

```text
web-security-compliance-checker/
├─ docker/
│  ├─ api.Dockerfile              # FastAPI + Celery image
│  ├─ nginx.Dockerfile            # Optional: Nginx reverse proxy
│
├─ compose/
│  ├─ docker-compose.dev.yml      # Local dev stack
│  ├─ docker-compose.prod.yml     # Prod-like stack (optional)
│
├─ alembic/                       # DB migrations
│  ├─ env.py
│  ├─ script.py.mako
│  ├─ versions/
│     ├─ xxxx_initial_tables.py
│     ├─ xxxx_add_pdf_reports.py
│
├─ src/
│  └─ app/
│     ├─ main.py                  # FastAPI app entrypoint (includes routers, middleware)
│     ├─ config.py                # Load Settings instance for whole app
│
│     ├─ core/
│     │  ├─ settings.py           # Pydantic BaseSettings (DB URL, Redis URL, secrets)
│     │  ├─ security.py           # JWT creation/verification, password hashing
│     │  ├─ exceptions.py         # Global exception handlers, custom errors
│     │  ├─ logging_config.py     # Logging configuration
│     │  ├─ rate_limit.py         # (optional) rate limiting helper using Redis
│
│     ├─ db/
│     │  ├─ base.py               # Base = declarative_base(), import all models here
│     │  ├─ session.py            # SessionLocal, get_db dependency
│     │  └─ models/               # SQLAlchemy models split by domain
│     │     ├─ user.py            # User model
│     │     ├─ target.py          # Target model
│     │     ├─ scan.py            # ScanJob + Finding models
│     │     ├─ pdf_report.py      # PdfReport model
│
│     ├─ api/
│     │  ├─ deps.py               # Common dependencies (get_current_user, etc.)
│     │  └─ v1/
│     │     ├─ routes_auth.py     # /auth/login, /auth/register, /auth/logout
│     │     ├─ routes_targets.py  # /targets (list/create/delete)
│     │     ├─ routes_scans.py    # /scans (start scan, view status, view findings)
│     │     ├─ routes_reports.py  # /reports (list/download/delete PDF reports)
│
│     ├─ services/
│     │  ├─ auth_service.py       # Register user, authenticate, token handling
│     │  ├─ scan_service.py       # Create scan jobs, aggregate results
│     │  ├─ report_service.py     # List/delete reports, ownership checks
│     │  ├─ pdf_service.py        # Generate PDF file for given scan_id + user_id
│     │  └─ security_checks/      # Logic adapted from GitHub project
│     │     ├─ __init__.py        # run_all_checks(url) orchestrator
│     │     ├─ headers.py         # HTTP security headers checks
│     │     ├─ tls.py             # TLS/SSL configuration checks
│     │     ├─ cookies.py         # Cookie security flags checks
│     │     ├─ ...                # any other checks you port over
│
│     ├─ workers/
│     │  ├─ celery_app.py         # Celery instance & configuration
│     │  └─ tasks_scans.py        # Celery tasks:
│     │                           #  - run_security_scan(scan_id)
│     │                           #  - generate_pdf_report(scan_id)
│
│     ├─ templates/               # Jinja2 templates for server-side rendered UI
│     │  ├─ base.html             # Main layout, nav, common blocks
│     │  ├─ auth/
│     │  │  ├─ login.html         # Login form (email/password)
│     │  │  └─ register.html      # Registration form
│     │  ├─ dashboard.html        # Simple dashboard after login
│     │  ├─ targets/
│     │  │  └─ list.html          # List/create targets UI
│     │  ├─ scans/
│     │  │  ├─ list.html          # List user scans
│     │  │  └─ detail.html        # Scan detail + findings + link to report
│     │  └─ reports/
│     │     └─ list.html          # List all PDF reports for user
│
│     ├─ static/                  # Static files (very simple styling)
│     │  ├─ css/
│     │  │  └─ main.css           # Basic CSS
│     │  └─ js/
│     │     └─ main.js            # Optional, minimal JS
│
│     └─ utils/                   # Small helpers (optional)
│        ├─ hashing.py            # maybe reuse or alias core.security password utils
│        ├─ pagination.py         # if you add paging
│        └─ misc.py
│
├─ tests/
│  ├─ test_auth.py                # Registration/login tests
│  ├─ test_targets.py             # Targets CRUD tests
│  ├─ test_scans.py               # Scan creation & task tests
│  ├─ test_reports.py             # PDF listing/download/delete tests
│  └─ ...                         # more as needed
│
├─ .env.example                   # Example environment variables
├─ requirements.txt               # Python dependencies
├─ README.md
└─ Makefile / tasks.py (optional) # Helper commands (run tests, format, etc.)