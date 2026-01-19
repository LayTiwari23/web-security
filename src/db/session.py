# src/db/session.py

from __future__ import annotations
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from src.core.settings import get_settings

settings = get_settings()

# --------------------------------------------------------------------------
# ✅ THE FIX: 
# 1. We use 'settings.DATABASE_URL' (because we know it definitely exists).
# 2. We wrap it in 'str()' to turn the fancy URL object into plain text.
# --------------------------------------------------------------------------
engine = create_engine(str(settings.DATABASE_URL), pool_pre_ping=True)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a SQLAlchemy Session.
    Closes the session after the request is done.
    """
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()