"""RFC 9457 Problem Details and the small set of §1 conventions built on top
of it (api-surface.md §1): the denial split (`forbidden`/`not_found`), the
single 429 + Retry-After shape (`too_many_requests`), and the
`Idempotency-Key` dependency — validated and echoed, format and length only,
because replay safety comes from each route's own natural business key
rather than a replay store.
"""

import logging
import re
from collections.abc import Mapping, Sequence
from http import HTTPStatus
from typing import Annotated, NoReturn, TypedDict

from fastapi import Header
from fastapi.exception_handlers import http_exception_handler as default_http_exception_handler
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from gameframework.api.middleware import REQUEST_ID_HEADER, get_request_id, request_id_from_scope

PROBLEM_CONTENT_TYPE = "application/problem+json"

_logger = logging.getLogger(__name__)

_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._~-]{1,255}$")

# RFC 9457 fixes the meaning of these five members; an extension carrying
# one of their names would silently replace it when merged into the body
# (api-surface.md §1) — `status: "paused"` where a client expects the
# integer `409` is worse than no extension at all. Guarded once, here,
# rather than left to the discipline of each route that adds a member.
_RESERVED_PROBLEM_MEMBERS = frozenset({"type", "title", "status", "detail", "instance"})


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
        extensions: dict[str, object] | None = None,
    ) -> None:
        super().__init__(detail or code)
        self.status = status
        self.code = code
        self.detail = detail
        self.fields = fields
        self.extensions = extensions


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


def _problem_response(
    *,
    status: int,
    code: str,
    request_id: str,
    detail: str | None = None,
    fields: Sequence[FieldError] | None = None,
    extensions: Mapping[str, object] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    """The one place a problem body is built (api-surface.md §1), whether a
    route raised the error or the framework did.
    """
    body: dict[str, object] = {
        "type": "about:blank",
        "title": HTTPStatus(status).phrase,
        "status": status,
        "code": code,
        "request_id": request_id,
    }
    if detail is not None:
        body["detail"] = detail
    if fields is not None:
        body["fields"] = list(fields)
    if extensions is not None:
        collisions = _RESERVED_PROBLEM_MEMBERS & extensions.keys()
        if collisions:
            # Unconditional, not `assert`: this enforces a contract rather
            # than documenting an invariant, and `python -O`/`PYTHONOPTIMIZE`
            # strip `assert` statements — which would silently restore the
            # `body.update()` overwrite this guard exists to prevent, in the
            # one place api-surface.md §1 tells every route it need not
            # check for itself (Working Agreement standard).
            raise AssertionError(
                f"ProblemError extensions collide with reserved Problem Details "
                f"member(s) {sorted(collisions)} (api-surface.md §1) — rename "
                f"at the raise site"
            )
        body.update(extensions)
    return JSONResponse(
        status_code=status,
        content=body,
        media_type=PROBLEM_CONTENT_TYPE,
        headers={REQUEST_ID_HEADER: request_id, **(headers or {})},
    )


async def problem_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, ProblemError)
    headers = {"Retry-After": str(exc.retry_after)} if isinstance(exc, RateLimitError) else None
    return _problem_response(
        status=exc.status,
        code=exc.code,
        request_id=get_request_id() or "",
        detail=exc.detail,
        fields=exc.fields,
        extensions=exc.extensions,
        headers=headers,
    )


async def request_validation_handler(request: Request, exc: Exception) -> JSONResponse:
    """A request the framework's own validation refuses, before any route
    logic runs (api-surface.md §1): `request_invalid`, one `fields` entry
    per offending location. Only the message is serialized — pydantic's
    `input` would echo the submitted value back, and a rejected body can be
    a password.

    A route's own `422` (`idempotency_key_invalid`, `participation_not_found`)
    is a `ProblemError` and never reaches this handler, so `request_invalid`
    does not replace a named code.
    """
    assert isinstance(exc, RequestValidationError)
    fields = [
        FieldError(field=".".join(str(part) for part in error["loc"]), message=error["msg"])
        for error in exc.errors()
    ]
    return _problem_response(
        status=422,
        code="request_invalid",
        request_id=request_id_from_scope(request.scope),
        fields=fields,
    )


_ROUTING_CODES = {404: "route_not_found", 405: "method_not_allowed"}


async def http_exception_handler(request: Request, exc: Exception) -> Response:
    """The `HTTPException`s the framework itself raises (api-surface.md §1).
    No app code raises one, so every one reaching this handler is the
    framework's:

    - `404` / `405` come from routing: no route serves the path
      (`route_not_found`) or the route does not serve the method
      (`method_not_allowed`, with the `Allow` header the router set).
    - `400` comes from a body the framework cannot parse — FastAPI for its
      own body handling, Starlette's `request.form()` for a malformed
      multipart body, as the two upload routes read theirs. That is
      `request_invalid` with the status kept at `400` and a single
      `fields` entry, `body`, carrying the parser's message and none of
      what was submitted.

    Any other status is left to the framework's default.
    """
    assert isinstance(exc, StarletteHTTPException)
    request_id = request_id_from_scope(request.scope)
    if exc.status_code == 400:
        return _problem_response(
            status=400,
            code="request_invalid",
            request_id=request_id,
            fields=[FieldError(field="body", message=str(exc.detail))],
            headers=exc.headers,
        )
    code = _ROUTING_CODES.get(exc.status_code)
    if code is None:
        return await default_http_exception_handler(request, exc)
    return _problem_response(
        status=exc.status_code, code=code, request_id=request_id, headers=exc.headers
    )


async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """An unhandled exception (api-surface.md §1): `internal_error`, its text
    logged with the request id and never serialized.

    This runs in Starlette's outermost `ServerErrorMiddleware`, outside
    `RequestIdMiddleware` and after that middleware has reset its context
    variable — so the id comes from the scope, and `X-Request-Id` is set
    here because the middleware's own send wrapper is not in this path.
    """
    request_id = request_id_from_scope(request.scope)
    _logger.error("unhandled exception (request_id=%s)", request_id, exc_info=exc)
    return _problem_response(status=500, code="internal_error", request_id=request_id)


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
