# src/core/settings.py

from __future__ import annotations

from functools import lru_cache
from typing import Any, List, Optional

# Updated imports for Pydantic V2 compatibility
from pydantic import AnyHttpUrl, PostgresDsn, RedisDsn, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # -------------------------------------------------
    # Core app
    # -------------------------------------------------
    APP_NAME: str = "Web Security Compliance Checker"
    DEBUG: bool = False
    APP_ENV: str = "development"  # development / production / test

    # -------------------------------------------------
    # Security / Auth
    # -------------------------------------------------
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    ALGORITHM: str = "HS256"

    # -------------------------------------------------
    # Database
    # -------------------------------------------------
    DATABASE_URL: PostgresDsn = "postgresql+psycopg2://websec_user:websec_pass@db:5432/websec_db"

    # ✅ THE FIX: Create a bridge between the two names
    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        return str(self.DATABASE_URL)

    # -------------------------------------------------
    # Redis / Celery
    # -------------------------------------------------
    REDIS_URL: RedisDsn = "redis://redis:6379/0"
    CELERY_BROKER_URL: RedisDsn = "redis://redis:6379/1"
    CELERY_RESULT_BACKEND: RedisDsn = "redis://redis:6379/2"

    # Optional: rate limiting via Redis
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # -------------------------------------------------
    # CORS
    # -------------------------------------------------
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Any) -> List[AnyHttpUrl]:
        """
        Allow CORS origins to be provided as a comma-separated string or list.
        """
        if isinstance(v, str) and not v.startswith("["):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        if isinstance(v, (list, tuple)):
            return list(v)
        return []

    # -------------------------------------------------
    # PDF / Reports
    # -------------------------------------------------
    PDF_OUTPUT_DIR: str = "pdf_reports"

    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()