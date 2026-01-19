# src/app/utils/misc.py

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse


def utc_now() -> datetime:
    """
    Return current UTC time as naive datetime (or adapt to timezone-aware
    if you prefer). Handy for consistent timestamps.
    """
    return datetime.utcnow()


def normalize_url(url: str) -> str:
    """
    Basic URL normalizer:
      - ensures scheme is present (defaults to https)
      - lowercases scheme and hostname
    """
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or "").lower()

    normalized = parsed._replace(scheme=scheme, netloc=netloc).geturl()
    return normalized


def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    """
    Try to convert a value to int; return default on failure.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default