"""Cursor pagination (api-surface.md §1): list endpoints use `cursor`/
`limit`, never an unbounded list. Every list-endpoint entity in this schema
keys its primary key column `id` (a UUID), so `paginate` orders and seeks on
that column rather than taking a caller-supplied sort key — one mechanism
for every future list route (`/users`, `/tickets`, `/audit-log`, ...) to
reuse rather than reinventing per route.
"""

import base64
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class Page[T]:
    items: list[T]
    next_cursor: str | None


def _encode_cursor(pk: Any) -> str:
    return base64.urlsafe_b64encode(str(pk).encode()).decode()


def _decode_cursor(cursor: str) -> str:
    return base64.urlsafe_b64decode(cursor.encode()).decode()


def paginate[T](db: Session, query: Select[tuple[T]], *, cursor: str | None, limit: int) -> Page[T]:
    entity = query.column_descriptions[0]["entity"]
    pk_column = entity.id
    stmt = query.order_by(pk_column)
    if cursor is not None:
        stmt = stmt.where(pk_column > _decode_cursor(cursor))
    rows = list(db.execute(stmt.limit(limit + 1)).scalars().all())
    has_more = len(rows) > limit
    items = rows[:limit]
    next_cursor = _encode_cursor(items[-1].id) if has_more and items else None  # type: ignore[attr-defined]
    return Page(items=items, next_cursor=next_cursor)
