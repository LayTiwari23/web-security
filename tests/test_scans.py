import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from src.db.base import Base
from src.workers.tasks_scans import evaluate_compliance

# ✅ FIX: Force SQLite for local tests to avoid connection errors
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool, # ✅ Keeps the tables alive for the whole test
)

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Triggers the registry we fixed in Step 1."""
    from src.db import models 
    Base.metadata.create_all(bind=engine)

def test_compliance_decision_logic():
    """Verifies the 28-item logic works without needing a real DB."""
    class MockF:
        def __init__(self, name): self.name = name

    findings = [MockF("SSLv3 Protocol is enabled")]
    results = evaluate_compliance(findings)
    assert results["16"]["status"] == "N"