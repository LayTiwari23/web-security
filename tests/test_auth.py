# tests/test_auth.py
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
    """Create all tables once for the test session."""
    Base.metadata.create_all(bind=engine)

@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """FastAPI TestClient with DB dependency overridden."""
    app.dependency_overrides[get_db] = override_get_db
    # ✅ FIX: Defined 'c' inside the with block before yielding
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def register_user(client: TestClient, email: str, password: str) -> None:
    resp = client.post(
        "/api/v1/auth/register",
        data={"email": email, "password": password},
    )
    # Allow 201 (Created) or 400 (if already exists during debug)
    if resp.status_code != 201 and resp.json().get("detail") != "Email already registered":
        assert resp.status_code == 201, resp.text

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_register_user_success(client: TestClient) -> None:
    email = "user1@example.com"
    password = "secret123"
    resp = client.post(
        "/api/v1/auth/register",
        data={"email": email, "password": password},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["email"] == email
    assert "id" in data

def test_register_user_duplicate_email(client: TestClient) -> None:
    email = "dup@example.com"
    password = "secret123"
    register_user(client, email, password)
    resp = client.post(
        "/api/v1/auth/register",
        data={"email": email, "password": password},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["detail"] == "Email already registered"

def test_login_success(client: TestClient) -> None:
    email = "login@example.com"
    password = "secret123"
    register_user(client, email, password)
    resp = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_credentials(client: TestClient) -> None:
    email = "badlogin@example.com"
    password = "secret123"
    register_user(client, email, password)
    resp = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": "wrongpassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["detail"] == "Incorrect email or password"