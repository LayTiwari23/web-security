# tests/test_scans.py

from __future__ import annotations

from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from src.app.main import app
from src.db.base import Base
from src.db.session import get_db

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
    """
    Create all tables once for the test session.
    """
    Base.metadata.create_all(bind=engine)


@pytest.fixture
def client(monkeypatch, tmp_path) -> Generator[TestClient, None, None]:
    """
    FastAPI TestClient with DB dependency overridden and Celery task
    calls mocked so we don't need a broker running during tests.
    """
    app.dependency_overrides[get_db] = override_get_db

    # Mock Celery tasks used in /scans and /reports
    from src.workers import tasks_scans

    def fake_run_security_scan_task(*args, **kwargs):
        class Dummy:
            def delay(self, *_, **__):
                return None

        return Dummy()

    def fake_generate_pdf_report_task(*args, **kwargs):
        class Dummy:
            def delay(self, *_, **__):
                return None

        return Dummy()

    monkeypatch.setattr(tasks_scans, "run_security_scan_task", fake_run_security_scan_task)
    monkeypatch.setattr(tasks_scans, "generate_pdf_report_task", fake_generate_pdf_report_task)

    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def register_and_login(client: TestClient, email: str, password: str) -> str:
    # Register
    r = client.post("/api/v1/auth/register", data={"email": email, "password": password})
    assert r.status_code == 201, r.text

    # Login
    r = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return token


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_target(client: TestClient, token: str, url: str = "https://example.com") -> int:
    r = client.post(
        "/api/v1/targets/",
        json={"url": url, "name": "Example"},
        headers=auth_headers(token),
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_start_scan_and_list_scans(client: TestClient) -> None:
    token = register_and_login(client, "scanuser1@example.com", "secret123")
    target_id = create_target(client, token)

    # Initially no scans
    r = client.get("/api/v1/scans/", headers=auth_headers(token))
    assert r.status_code == 200
    assert r.json() == []

    # Start scan
    r = client.post(
        "/api/v1/scans/",
        params={"target_id": target_id},
        headers=auth_headers(token),
    )
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["target_id"] == target_id
    scan_id = scan["id"]

    # List scans again
    r = client.get("/api/v1/scans/", headers=auth_headers(token))
    assert r.status_code == 200
    scans = r.json()
    assert len(scans) == 1
    assert scans[0]["id"] == scan_id


def test_start_scan_for_other_users_target_fails(client: TestClient) -> None:
    # User A
    token_a = register_and_login(client, "scanA@example.com", "secret123")
    target_id = create_target(client, token_a, url="https://owner.com")

    # User B
    token_b = register_and_login(client, "scanB@example.com", "secret123")

    # User B tries to start scan on User A's target
    r = client.post(
        "/api/v1/scans/",
        params={"target_id": target_id},
        headers=auth_headers(token_b),
    )
    assert r.status_code == 404  # Target not found for this user


def test_get_scan_detail_unauthorized_user(client: TestClient) -> None:
    # Owner
    token_owner = register_and_login(client, "owner@example.com", "secret123")
    target_id = create_target(client, token_owner)

    r = client.post(
        "/api/v1/scans/",
        params={"target_id": target_id},
        headers=auth_headers(token_owner),
    )
    assert r.status_code == 201
    scan_id = r.json()["id"]

    # Other user
    token_other = register_and_login(client, "other@example.com", "secret123")

    r = client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers(token_other))
    assert r.status_code == 404