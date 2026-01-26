from __future__ import annotations
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from src.core.settings import settings

# ✅ THE FIX: Production-grade connection pooling
engine = create_engine(
    str(settings.DATABASE_URL),
    pool_size=10,        # Number of permanent connections
    max_overflow=20,     # Extra connections during high traffic
    pool_pre_ping=True,  # Automatically tests/recovers connections
    pool_recycle=3600    # Resets connections every hour to prevent timeouts
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

def get_db() -> Generator[Session, None, None]:
    """Provides a thread-safe database session."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()