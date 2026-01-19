# src/app/db/models/pdf_report.py

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from src.db.base import Base


class PdfReport(Base):
    __tablename__ = "pdf_reports"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id = Column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Path to the generated PDF file (relative or absolute)
    file_path = Column(String(length=1024), nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    # Relationships
    user = relationship("User", back_populates="pdf_reports")
    scan = relationship("Scan", back_populates="pdf_reports")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PdfReport id={self.id} scan_id={self.scan_id}>"