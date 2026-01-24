# src/db/models/pdf_report.py

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
    
    # ✅ unique=True ensures each scan has exactly one report (1-to-1)
    scan_id = Column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        unique=True, 
    )

    # Path to the generated PDF file inside the shared Docker volume [/app/pdf_reports]
    file_path = Column(String(length=1024), nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    # Relationships
    # user uses plural because a user can have many PDF records
    user = relationship("User", back_populates="pdf_reports")
    
    # ✅ FIXED: Points back to 'report' attribute in your updated Scan model
    scan = relationship("Scan", back_populates="report")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PdfReport id={self.id} scan_id={self.scan_id}>"