import pytest
import sys
import os
import psycopg2
from urllib.parse import urlparse

# 1. Setup path
sys.path.append(os.getcwd())

# 2. THE "DISCONNECT" FIX (Monkeypatch)
# This fixture runs automatically for every test.
# It finds the "delay" function (which sends tasks to Redis)
# and replaces it with a fake function that does absolutely nothing.
@pytest.fixture(autouse=True)
def mock_celery_tasks(monkeypatch):
    """
    Prevents any connection attempts to Redis/RabbitMQ.
    """
    # Define a fake function that just prints a message and returns None
    def fake_delay(*args, **kwargs):
        print("   [Mock] Task 'sent' successfully (Intercepted by test!)")
        return None

    # Replace the real .delay() method with our fake one
    monkeypatch.setattr("celery.app.task.Task.delay", fake_delay)


# 3. Database Auto-Cleaner (Standard)
@pytest.fixture(scope="session", autouse=True)
def clean_database_automatically():
    """
    Wipes the database before tests start.
    """
    # Hardcoded to your local Postgres settings
    db_url = "postgresql://postgres:postgres@127.0.0.1:5432/websec_db"
    
    try:
        result = urlparse(db_url)
        conn = psycopg2.connect(
            dbname=result.path[1:],
            user=result.username,
            password=result.password,
            host=result.hostname,
            port=result.port
        )
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE users, targets, scans, findings, pdf_reports RESTART IDENTITY CASCADE;")
        conn.close()
        print("\n✨ Database wiped clean! Ready for tests. ✨")
    except Exception:
        pass