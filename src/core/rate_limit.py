# src/app/core/rate_limit.py

from __future__ import annotations

import time
from typing import Callable

import redis  # type: ignore
from fastapi import HTTPException, Request, status

from .settings import get_settings

settings = get_settings()


def get_redis_client() -> redis.Redis:
    return redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)


def rate_limit(
    key_prefix: str,
    max_requests: int | None = None,
    window_seconds: int | None = None,
) -> Callable:
    """
    Simple Redis-based rate limiter.

    Usage:
        @router.get("/endpoint")
        @rate_limit("endpoint", max_requests=100, window_seconds=60)
        async def endpoint(...):
            ...
    """
    if max_requests is None:
        max_requests = settings.RATE_LIMIT_REQUESTS
    if window_seconds is None:
        window_seconds = settings.RATE_LIMIT_WINDOW_SECONDS

    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            if not settings.RATE_LIMIT_ENABLED:
                return await func(*args, **kwargs)

            # Try to get Request from args/kwargs
            request: Request | None = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if request is None:
                request = kwargs.get("request")

            # Fallback to remote address if no user info
            identifier = "anonymous"
            if request is not None:
                # If you later add auth, you could use request.user.id, etc.
                client_host = request.client.host if request.client else "unknown"
                identifier = client_host

            key = f"rl:{key_prefix}:{identifier}"
            now = int(time.time())

            r = get_redis_client()
            with r.pipeline() as pipe:
                # Remove old entries from sorted set
                pipe.zremrangebyscore(key, 0, now - window_seconds)
                # Add current request timestamp
                pipe.zadd(key, {str(now): now})
                # Get current count
                pipe.zcard(key)
                # Set TTL on key
                pipe.expire(key, window_seconds)
                _, _, count, _ = pipe.execute()

            if count > max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests, slow down.",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator