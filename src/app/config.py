# src/app/config.py

from functools import lru_cache

from src.core.settings import Settings


@lru_cache
def get_settings() -> Settings:
    """
    Return a cached Settings instance.

    Using lru_cache ensures we only parse environment variables once and
    reuse the same Settings object across the app.
    """
    return Settings()