"""RFC 9457 Problem Details and the small set of §1 conventions built on top
of it (api-surface.md §1): the denial split (`forbidden`/`not_found`), the
single 429 + Retry-After shape (`too_many_requests`), and the
`Idempotency-Key` dependency — validated and echoed, format and length only,
because replay safety comes from each route's own natural business key
rather than a replay store.
"""

import re
from collections.abc import Sequence
from http import HTTPStatus
from typing import Annotated, NoReturn, TypedDict

from fastapi import Header
from starlette.requests import Request
from starlette.responses import JSONResponse

from gameframework.api.middleware import REQUEST_ID_HEADER, get_request_id

PROBLEM_CONTENT_TYPE = "application/problem+json"

_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._~-]{1,255}$")


class FieldError(TypedDict):
    field: str
    message: str


class ProblemError(Exception):
    """Raised anywhere in a route, rendered by `problem_error_handler`. The
    machine-readable `code` is the contract; `detail` is English prose, not
    the contract (ADR-0017, api-surface.md §1).
    """

    def __init__(
        self,
        status: int,
        code: str,
        detail: str | None = None,
        fields: Sequence[FieldError] | None = None,
    ) -> None:
        super().__init__(detail or code)
        self.status = status
        self.code = code
        self.detail = detail
        self.fields = fields


class RateLimitError(ProblemError):
    """The single `429` + `Retry-After` shape fixed here rather than
    invented per route (api-surface.md §1)."""

    def __init__(
        self, retry_after: int, code: str = "rate_limited", detail: str | None = None
    ) -> None:
        super().__init__(status=429, code=code, detail=detail)
        self.retry_after = retry_after


def forbidden(code: str, detail: str | None = None) -> NoReturn:
    """A role that may not call this route at all (api-surface.md §1)."""
    raise ProblemError(status=403, code=code, detail=detail)


def not_found(code: str, detail: str | None = None) -> NoReturn:
    """Non-disclosure only: an object outside the session's scope, or a
    staff target for a gameadmin (api-surface.md §1)."""
    raise ProblemError(status=404, code=code, detail=detail)


def too_many_requests(
    retry_after: int, code: str = "rate_limited", detail: str | None = None
) -> NoReturn:
    raise RateLimitError(retry_after=retry_after, code=code, detail=detail)


async def problem_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, ProblemError)
    request_id = get_request_id() or ""
    body: dict[str, object] = {
        "type": "about:blank",
        "title": HTTPStatus(exc.status).phrase,
        "status": exc.status,
        "code": exc.code,
        "request_id": request_id,
    }
    if exc.detail is not None:
        body["detail"] = exc.detail
    if exc.fields is not None:
        body["fields"] = list(exc.fields)
    headers = {REQUEST_ID_HEADER: request_id}
    if isinstance(exc, RateLimitError):
        headers["Retry-After"] = str(exc.retry_after)
    return JSONResponse(
        status_code=exc.status, content=body, media_type=PROBLEM_CONTENT_TYPE, headers=headers
    )


async def idempotency_key(
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> str | None:
    if idempotency_key is None:
        return None
    if not _IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key):
        raise ProblemError(
            status=422,
            code="idempotency_key_invalid",
            detail="Idempotency-Key must be 1-255 characters from [A-Za-z0-9._~-]",
        )
    return idempotency_key
