# src/app/utils/pagination.py

from __future__ import annotations

from math import ceil
from typing import Generic, Iterable, List, Optional, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """
    Simple pagination response model.
    """
    items: List[T]
    total: int
    page: int
    size: int
    pages: int


def paginate_list(
    items: Iterable[T],
    page: int = 1,
    size: int = 20,
) -> Page[T]:
    """
    Paginate a plain Python iterable (e.g. list of ORM objects).

    In real endpoints, you will usually paginate at the DB level
    using .offset().limit() instead of this helper.
    """
    page = max(page, 1)
    size = max(size, 1)

    items_list = list(items)
    total = len(items_list)
    pages = max(ceil(total / size), 1)

    start = (page - 1) * size
    end = start + size
    paged_items = items_list[start:end]

    return Page[T](
        items=paged_items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


def apply_sqlalchemy_pagination(query, page: int = 1, size: int = 20):
    """
    Helper for SQLAlchemy queries.

    Returns (items, total) where:
      - items is the list for the requested page
      - total is the total count before pagination

    Example:
        items, total = apply_sqlalchemy_pagination(
            db.query(User).filter(...),
            page=page,
            size=size,
        )
    """
    page = max(page, 1)
    size = max(size, 1)

    total = query.order_by(None).count()
    items = query.offset((page - 1) * size).limit(size).all()
    return items, total