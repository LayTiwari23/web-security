# tests/test_reports.py

from __future__ import annotations
from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from src.app.main import app
from src.db.base import Base
from src.db.session import get_db
import celery.app.task  # We need this to patch the base class

# ---------------------------------------------------------------------------
# Test DB setup (SQLite in-memory)
# ---------------------------------------------------------------------------

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

def override_get_db() -> Generator[Session, None, None]:
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture(scope="session", autouse=True)
def setup_database() -> None:
    Base.metadata.create_all(bind=engine)

@pytest.fixture
def client(tmp_path) -> Generator[TestClient, None, None]:
    """
    FastAPI TestClient with DB dependency overridden.
    """
    app.dependency_overrides[get_db] = override_get_db

    # Override PDF output directory to temp folder
    from src.core import settings as settings_module
    s = settings_module.get_settings()
    s.PDF_OUTPUT_DIR = str(tmp_path)

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(client: TestClient, email: str, password: str) -> str:
    client.post("/api/v1/auth/register", data={"email": email, "password": password})
    r = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return r.json()["access_token"]

def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}

def create_target(client: TestClient, token: str) -> int:
    r = client.post(
        "/api/v1/targets/",
        json={"url": "https://example.com", "name": "Example"},
        headers=auth_headers(token),
    )
    if r.status_code == 201:
        return r.json()["id"]
    return 1 

def create_scan_record(client: TestClient, token: str, target_id: int) -> int:
    r = client.post(
        "/api/v1/scans/",
        params={"target_id": target_id},
        headers=auth_headers(token),
    )
    # Accept 201 or 202
    return r.json()["id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_list_reports_initially_empty(client: TestClient) -> None:
    token = register_and_login(client, "reports1@example.com", "secret123")
    r = client.get("/api/v1/reports/", headers=auth_headers(token))
    assert r.status_code == 200
    assert r.json() == []

def test_generate_report_enqueues_task(client: TestClient, monkeypatch) -> None:
    token = register_and_login(client, "reports2@example.com", "secret123")
    target_id = create_target(client, token)
    scan_id = create_scan_record(client, token, target_id)

    # --- UNIVERSAL SPY ---
    # We patch the base class 'Task.delay'. This catches ALL tasks.
    called = {"count": 0, "kwargs": None}

    # Store the original delay method so we can call it if needed (or just mock it out)
    original_delay = celery.app.task.Task.delay

    def fake_delay(self, *args, **kwargs):
        # Only count if it's the PDF task (check function name or substring)
        # Assuming the task function name contains 'generate_pdf'
        if "generate_pdf" in self.name:
            called["count"] += 1
            called["kwargs"] = kwargs
        return None

    monkeypatch.setattr("celery.app.task.Task.delay", fake_delay)

    r = client.post(
        f"/api/v1/reports/generate/{scan_id}",
        headers=auth_headers(token),
    )
    
    # Accept 201 or 202
    assert r.status_code in [201, 202]
    # Check spy
    assert called["count"] == 1
    assert called["kwargs"]["scan_id"] == scan_id


def test_generate_report_html_enqueues_task(client: TestClient, monkeypatch) -> None:
    token = register_and_login(client, "reports3@example.com", "secret123")
    target_id = create_target(client, token)
    scan_id = create_scan_record(client, token, target_id)

    # --- UNIVERSAL SPY ---
    called = {"count": 0}

    def fake_delay(self, *args, **kwargs):
        if "generate_pdf" in self.name:
            called["count"] += 1
        return None

    monkeypatch.setattr("celery.app.task.Task.delay", fake_delay)

    r = client.post(
        f"/api/v1/reports/{scan_id}/generate/html",
        headers=auth_headers(token),
        allow_redirects=False,
    )
    
    # Accept 201, 202, or redirect
    assert r.status_code in (201, 202, 302, 303, 307)
    assert called["count"] == 1