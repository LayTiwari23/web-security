from src.db.base import Base
from src.db.models.user import User
from src.db.models.target import Target
from src.db.models.scan import Scan, Finding
from src.db.models.pdf_report import PdfReport # ✅ Points to your actual filename

# This registry allows the 'setup_database' fixture to find everything
__all__ = ["Base", "User", "Target", "Scan", "Finding", "PdfReport"]