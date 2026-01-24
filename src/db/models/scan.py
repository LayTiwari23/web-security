# src/db/models/scan.py
from __future__ import annotations
from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from src.db.base import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(length=50), nullable=False, default="pending")
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    summary = Column(Text, nullable=True)
    extra_data = Column(JSON, nullable=True)

    # ✅ Using string references to avoid initialization order issues
    user = relationship("User", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    
    # 1-to-1 relationship for the report record
    report = relationship(
        "PdfReport",
        back_populates="scan",
        cascade="all, delete-orphan",
        uselist=False
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} status={self.status!r}>"

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    check_type = Column(String(length=100), nullable=False)
    name = Column(String(length=255), nullable=False)
    severity = Column(String(length=50), nullable=False)
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="findings")