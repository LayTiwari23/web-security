# src/app/core/logging_config.py

from __future__ import annotations

import logging
import logging.config
from typing import Any, Dict

from .settings import get_settings


def get_logging_config() -> Dict[str, Any]:
    settings = get_settings()
    log_level = "DEBUG" if settings.DEBUG else "INFO"

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            },
            "uvicorn": {
                "format": "%(levelname)s %(asctime)s [%(name)s] %(message)s",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "standard",
                "level": log_level,
            },
            "uvicorn": {
                "class": "logging.StreamHandler",
                "formatter": "uvicorn",
                "level": log_level,
            },
        },
        "loggers": {
            "": {  # root logger
                "handlers": ["console"],
                "level": log_level,
            },
            "uvicorn": {
                "handlers": ["uvicorn"],
                "level": log_level,
                "propagate": False,
            },
            "uvicorn.error": {
                "handlers": ["uvicorn"],
                "level": log_level,
                "propagate": False,
            },
            "uvicorn.access": {
                "handlers": ["uvicorn"],
                "level": log_level,
                "propagate": False,
            },
            "celery": {
                "handlers": ["console"],
                "level": log_level,
                "propagate": False,
            },
            "sqlalchemy.engine": {
                # set to INFO/DEBUG if you want query logging
                "handlers": ["console"],
                "level": "WARNING",
                "propagate": False,
            },
        },
    }


def setup_logging() -> None:
    """
    Apply logging configuration. Call once at startup.
    """
    config = get_logging_config()
    logging.config.dictConfig(config)