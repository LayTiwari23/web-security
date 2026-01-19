# src/app/api/deps.py

from __future__ import annotations

from typing import Generator, Optional

# Added Request to imports
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from src.core.security import get_user_id_from_token
from src.db.session import get_db
from src.db.models.user import User

# 1. auto_error=False allows us to check cookies if the header is missing
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_db_session() -> Generator[Session, None, None]:
    """
    Simple alias so API layer can depend on `get_db_session`
    instead of importing from db.session directly.
    """
    yield from get_db()


# 2. New Helper: Tries Header first, then Cookie
def get_token_from_request(
    request: Request,
    token_header: Optional[str] = Depends(oauth2_scheme)
) -> str:
    # A. Check the Header (Standard API Clients)
    if token_header:
        return token_header

    # B. Check the Cookie (Browser / Localhost)
    cookie_token = request.cookies.get("access_token")
    
    if cookie_token:
        # We stored it as "Bearer <token>", so we must strip the prefix
        if cookie_token.startswith("Bearer "):
            return cookie_token[7:]  # Remove "Bearer "
        return cookie_token

    # C. If found in neither, fail
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )


def get_current_user(
    db: Session = Depends(get_db_session),
    # 3. Use our new smart helper instead of the dumb oauth2_scheme
    token: str = Depends(get_token_from_request),
) -> User:
    """
    Resolve the currently authenticated user from a Bearer token
    (found in either Header or Cookie).
    """
    user_id = get_user_id_from_token(token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive or missing user",
        )

    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Alias/helper if you later want to differentiate between
    authenticated vs. active users.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )
    return current_user


def get_current_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Restrict endpoint to superusers.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
    return current_user