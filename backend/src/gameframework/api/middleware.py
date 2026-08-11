"""X-Request-Id (api-surface.md §1): accepts an inbound id or mints a UUID,
sets it on the response and on a ContextVar so `errors.py`'s exception
handler can echo it into the Problem Details body.

Pure ASGI rather than `BaseHTTPMiddleware`: this runs in the same task as
the rest of the request, so the ContextVar set here is visible everywhere
downstream, including inside the exception handler, with no task-boundary
surprises to reason about.
"""

import uuid
from contextvars import ContextVar

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_HEADER = "X-Request-Id"

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    return _request_id.get()


class RequestIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = MutableHeaders(scope=scope)
        request_id = headers.get(REQUEST_ID_HEADER.lower()) or str(uuid.uuid4())
        token = _request_id.set(request_id)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                response_headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            _request_id.reset(token)
