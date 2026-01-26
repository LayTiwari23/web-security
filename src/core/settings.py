from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, List, Union

from pydantic import AnyHttpUrl, AnyUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 1 day
    ALGORITHM: str = "HS256"

    # -------------------------------------------------
    # Database
    # -------------------------------------------------
    # Using AnyUrl | str allows your local tests to use 'sqlite:///:memory:' 
    # while production uses 'postgresql://'.
    DATABASE_URL: AnyUrl | str = "postgresql://websec_user:websec_pass@localhost:5432/websec_db"

    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        """Helper to ensure the URL is always returned as a string for SQLAlchemy."""
        return str(self.DATABASE_URL)

    # -------------------------------------------------
    # Redis / Celery
    # -------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # Rate limiting configuration
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # -------------------------------------------------
    # CORS
    # -------------------------------------------------
    # In Pydantic V2, AnyHttpUrl is strict; we use a field_validator to handle 
    # strings or lists from the environment.
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> List[AnyHttpUrl]:
        """
        Migrated from @validator to @field_validator (Pydantic V2 style).
        Handles comma-separated strings or JSON lists from .env.
        """
        if isinstance(v, str) and not v.startswith("["):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        if isinstance(v, str) and v.startswith("["):
            return json.loads(v)
        if isinstance(v, (list, tuple)):
            return list(v)
        return []

    # -------------------------------------------------
    # PDF / Reports
    # -------------------------------------------------
    PDF_OUTPUT_DIR: str = "pdf_reports"

    # -------------------------------------------------
    # Configuration Logic
    # -------------------------------------------------
    # SettingsConfigDict replaces the old 'class Config'.
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Global instance for use throughout the application
settings = get_settings()