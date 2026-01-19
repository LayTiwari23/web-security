# src/app/services/auth_service.py

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from src.core.security import hash_password, verify_password
from src.db.models.user import User


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def create_user(db: Session, email: str, password: str) -> User:
    """
    Create a new user with hashed password.
    """
    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        is_active=True,
        is_superuser=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    """
    Return user if credentials are valid, otherwise None.
    """
    user = get_user_by_email(db, email=email.lower())
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    return user