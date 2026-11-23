"""Helpers shared by route modules: pagination and safe sorting."""

import math

from sqlalchemy import asc, desc, func, select
from sqlalchemy.orm import Query, Session

from app.core.errors import AppError


def paginate(query: Query, page: int, page_size: int, transform=None) -> dict:
    total = query.order_by(None).count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    if transform:
        items = [transform(i) for i in items]
    return {"items": items, "total": total, "page": page, "page_size": page_size,
            "pages": max(1, math.ceil(total / page_size))}


def apply_sort(query: Query, model, sort: str | None, order: str, allowed: set[str], default: str) -> Query:
    """Sort only by whitelisted columns, so user input never becomes raw SQL."""
    field = sort or default
    if field not in allowed:
        raise AppError(f"Cannot sort by '{field}'. Allowed: {', '.join(sorted(allowed))}", 422, "validation_error")
    column = getattr(model, field)
    direction = desc if order == "desc" else asc
    return query.order_by(direction(column).nulls_last(), direction(model.id))


def count(db: Session, stmt) -> int:
    return db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
