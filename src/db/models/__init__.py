# src/db/models/__init__.py
from src.db.base import Base
from src.db.models.user import User
from src.db.models.scan import Scan, Finding
from src.db.models.target import Target
from src.db.models.pdf_report import PdfReport

# This makes importing easier for other files
__all__ = ["Base", "User", "Scan", "Finding", "Target", "PdfReport"]