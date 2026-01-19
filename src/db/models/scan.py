# src/app/db/models/scan.py

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from src.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_id = Column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # e.g. "pending", "running", "completed", "failed"
    status = Column(String(length=50), nullable=False, default="pending")

    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    # Optional: store summary/metadata
    summary = Column(Text, nullable=True)
    extra_data = Column(JSON, nullable=True)

    # Relationships
    user = relationship("User", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    pdf_reports = relationship(
        "PdfReport",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Scan id={self.id} status={self.status!r}>"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # e.g. 'headers', 'tls', 'cookies', etc.
    check_type = Column(String(length=100), nullable=False)
    name = Column(String(length=255), nullable=False)

    # e.g. 'low', 'medium', 'high', 'critical'
    severity = Column(String(length=50), nullable=False)

    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)

    # Any extra data you want to store for debugging / details
    raw_data = Column(JSON, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Finding id={self.id} severity={self.severity!r}>"