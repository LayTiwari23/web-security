# tests/test_targets.py

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
    FastAPI TestClient with DB dependency overridden.
    """
    app.dependency_overrides[get_db] = override_get_db
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_create_and_list_targets(client: TestClient) -> None:
    token = register_and_login(client, "targets1@example.com", "secret123")

    # Initially no targets
    r = client.get("/api/v1/targets/", headers=auth_headers(token))
    assert r.status_code == 200
    assert r.json() == []

    # Create target
    payload = {"url": "https://example.com", "name": "Example"}
    r = client.post("/api/v1/targets/", json=payload, headers=auth_headers(token))
    assert r.status_code == 201, r.text
    data = r.json()
    # Check if the URL matches, allowing for a trailing slash
    assert data["url"].rstrip("/") == payload["url"].rstrip("/")
    assert data["name"] == payload["name"]
    target_id = data["id"]

    # List targets again
    r = client.get("/api/v1/targets/", headers=auth_headers(token))
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1
    assert items[0]["id"] == target_id


def test_delete_target(client: TestClient) -> None:
    token = register_and_login(client, "targets2@example.com", "secret123")

    # Create target
    payload = {"url": "https://delete-me.com", "name": "To delete"}
    r = client.post("/api/v1/targets/", json=payload, headers=auth_headers(token))
    assert r.status_code == 201
    target_id = r.json()["id"]

    # Delete it
    r = client.delete(f"/api/v1/targets/{target_id}", headers=auth_headers(token))
    assert r.status_code == 204

    # Ensure it's gone
    r = client.get("/api/v1/targets/", headers=auth_headers(token))
    assert r.status_code == 200
    items = r.json()
    assert all(t["id"] != target_id for t in items)


def test_cannot_delete_other_users_target(client: TestClient) -> None:
    # User A
    token_a = register_and_login(client, "userA@example.com", "secret123")
    r = client.post(
        "/api/v1/targets/",
        json={"url": "https://owner.com", "name": "Owner target"},
        headers=auth_headers(token_a),
    )
    assert r.status_code == 201
    target_id = r.json()["id"]

    # User B
    token_b = register_and_login(client, "userB@example.com", "secret123")

    # User B tries to delete User A's target
    r = client.delete(f"/api/v1/targets/{target_id}", headers=auth_headers(token_b))
    assert r.status_code == 404  # not found for this user