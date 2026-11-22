"""The error contract where no route raised the error (api-surface.md §1,
M2-Task-Plan.md Task 2 Step 6): a request the framework's own validation
refuses (`request_invalid`, `422`) or whose body it cannot parse
(`request_invalid`, `400`), a path no route serves (`route_not_found`), a
method the route does not serve (`method_not_allowed`) and an unhandled
exception (`internal_error`) answer the same RFC 9457 body as a
`ProblemError` does — stable `code`, the request id in body and header.

Every case drives a real route and registers none of its own, except the
fall-through for a status outside `400`, `404` and `405`: no real route can
raise one, so that case calls the handler directly.
"""

import asyncio
import json
import logging
import uuid

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from gameframework.api.errors import http_exception_handler
from gameframework.api.middleware import get_request_id
from gameframework.db.models.identity import Role
from gameframework.main import app
from gameframework.services.passwords import hash_password

from ..conftest import make_user

ADMIN_PASSWORD = "Admin-Passw0rd!"


def _login_as_admin(client: TestClient, db_session: Session) -> None:
    admin = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(ADMIN_PASSWORD),
    )
    response = client.post(
        "/api/v1/auth/login", json={"username": admin.username, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200


def _assert_problem(
    response: Response, *, status: int, code: str, request_id: str
) -> dict[str, object]:
    """The shape every case shares: status, `code`, Problem Details media
    type, and the one request id in the body and in `X-Request-Id`. The
    caller supplies the id it sent, so "the same value" is asserted against
    the request's own id rather than against whatever happened to be
    minted — an empty or stale id satisfies a body-equals-header check
    just as well.
    """
    assert response.status_code == status
    try:
        body = response.json()
    except ValueError:
        body = None
    assert isinstance(body, dict), f"body is not a JSON document: {response.text!r}"
    assert body.get("code") == code
    assert response.headers["content-type"].startswith("application/problem+json")
    assert body["status"] == status
    assert body["request_id"] == request_id
    assert response.headers.get("X-Request-Id") == request_id
    return body


# --------------------------------------------------------------------------
# request_invalid — the framework's own validation
# --------------------------------------------------------------------------


def test_body_missing_a_required_field_is_request_invalid(
    client: TestClient, db_session: Session
) -> None:
    """`POST /users` declares `initial_password` required (users.py,
    `CreateStaffRequest`). The caller is an authenticated admin so the
    refusal is the validation and not the session: dependencies resolve
    before a body error is raised, so an unauthenticated caller would be
    answered `401` instead.
    """
    _login_as_admin(client, db_session)
    request_id = str(uuid.uuid4())

    response = client.post(
        "/api/v1/users",
        json={"username": "new-gameadmin", "role": "gameadmin"},
        headers={"X-Request-Id": request_id},
    )

    body = _assert_problem(response, status=422, code="request_invalid", request_id=request_id)
    fields = body["fields"]
    assert isinstance(fields, list)
    assert any("initial_password" in entry["field"] for entry in fields)


def test_malformed_uuid_in_a_path_is_request_invalid(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    request_id = str(uuid.uuid4())

    response = client.get("/api/v1/users/not-a-uuid", headers={"X-Request-Id": request_id})

    body = _assert_problem(response, status=422, code="request_invalid", request_id=request_id)
    fields = body["fields"]
    assert isinstance(fields, list)
    assert any("user_id" in entry["field"] for entry in fields)
    # The refused value is not echoed back: a rejected body can be a password.
    assert "not-a-uuid" not in response.text


def test_body_the_framework_cannot_parse_is_request_invalid_with_status_400(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §1: `request_invalid` is "`422`, or `400` for a body
    that cannot be parsed", with the location `body` alone. A multipart
    request without a boundary is refused by the parser inside
    `request.form()`, which `POST /event-definitions/import` (admin-only)
    calls for its upload — so the framework, not the route, raises the
    `400`. What the client submitted is not echoed back.
    """
    _login_as_admin(client, db_session)
    request_id = str(uuid.uuid4())
    submitted = f"submitted-{uuid.uuid4().hex}"

    response = client.post(
        "/api/v1/event-definitions/import",
        content=submitted.encode(),
        headers={"Content-Type": "multipart/form-data", "X-Request-Id": request_id},
    )

    body = _assert_problem(response, status=400, code="request_invalid", request_id=request_id)
    fields = body["fields"]
    assert isinstance(fields, list)
    assert len(fields) == 1
    assert fields[0]["field"] == "body"
    assert fields[0]["message"]
    assert submitted not in response.text


# --------------------------------------------------------------------------
# route_not_found — and distinct from object_not_found
# --------------------------------------------------------------------------


def test_unknown_path_under_api_v1_is_route_not_found(client: TestClient) -> None:
    request_id = str(uuid.uuid4())

    response = client.get("/api/v1/no-such-route", headers={"X-Request-Id": request_id})

    _assert_problem(response, status=404, code="route_not_found", request_id=request_id)


def test_object_outside_scope_on_a_real_route_stays_object_not_found(
    client: TestClient, db_session: Session
) -> None:
    """The other half of "distinguishable": `GET /users/{id}` exists, so an
    id it cannot find is the non-disclosure answer, `object_not_found`,
    never `route_not_found`. This case passes today by design — a route's
    own `ProblemError` already carries its code — and is here to keep a
    handler for unknown paths from being widened to every `404`.
    """
    _login_as_admin(client, db_session)
    request_id = str(uuid.uuid4())

    response = client.get(f"/api/v1/users/{uuid.uuid4()}", headers={"X-Request-Id": request_id})

    _assert_problem(response, status=404, code="object_not_found", request_id=request_id)


# --------------------------------------------------------------------------
# method_not_allowed
# --------------------------------------------------------------------------


def test_method_a_route_does_not_serve_is_method_not_allowed(client: TestClient) -> None:
    """`/info` serves `GET` only; `POST` is not served. Routing answers
    before any dependency runs, so no session is needed. The `Allow` header
    the framework sets must survive the handler. A path with a single route
    on purpose: where several routes share a path (`GET` and `POST` on
    `/users`), the framework reports the first partial match's methods
    alone, so the header's value there would not say what "intact" is.
    """
    request_id = str(uuid.uuid4())

    response = client.post("/api/v1/info", headers={"X-Request-Id": request_id})

    _assert_problem(response, status=405, code="method_not_allowed", request_id=request_id)
    assert response.headers.get("Allow") == "GET"


# --------------------------------------------------------------------------
# any other HTTPException status — left to the framework
# --------------------------------------------------------------------------


def test_http_exception_outside_400_404_405_keeps_the_framework_default() -> None:
    """No real route can reach this branch, so the handler is called
    directly. `400`, `404` and `405` are the framework refusals the contract
    names; any other status must come out exactly as the framework renders
    it — its `detail` body, its headers — with no `code` invented for it.
    """
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    exc = StarletteHTTPException(
        status_code=403, detail="framework detail", headers={"X-Kept": "1"}
    )

    response = asyncio.run(http_exception_handler(request, exc))

    assert response.status_code == 403
    assert json.loads(bytes(response.body)) == {"detail": "framework detail"}
    assert response.headers.get("X-Kept") == "1"
    assert not response.headers["content-type"].startswith("application/problem+json")


# --------------------------------------------------------------------------
# internal_error — an unhandled exception
# --------------------------------------------------------------------------


def _get_users_made_to_raise(
    client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    *,
    headers: dict[str, str],
) -> tuple[Response, str, list[str | None]]:
    """`GET /users` made to raise from inside `paginate`, after the session
    check has passed. The shared `client` re-raises server exceptions into
    the test, and it is Task 1a's to leave alone, so the request goes
    through a `TestClient` of its own built with
    `raise_server_exceptions=False`, carrying the admin's cookies over from
    `client` (whose fixture also keeps the `get_session` override and the
    lifespan in place).

    Returns the response, the sentinel the exception carried, and the
    request id the route saw on `get_request_id()` when it raised — the id
    the middleware minted or accepted, which the `500` must then carry.
    """
    _login_as_admin(client, db_session)
    sentinel = f"sentinel-{uuid.uuid4().hex}"
    seen_by_route: list[str | None] = []

    def raising_paginate(*args: object, **kwargs: object) -> None:
        seen_by_route.append(get_request_id())
        raise RuntimeError(sentinel)

    monkeypatch.setattr("gameframework.api.users.paginate", raising_paginate)

    with TestClient(
        app,
        base_url="https://app.event.example.com",
        client=("127.0.0.1", 50000),
        raise_server_exceptions=False,
    ) as own_client:
        for cookie in client.cookies.jar:
            own_client.cookies.jar.set_cookie(cookie)
        response = own_client.get("/api/v1/users", headers=headers)
    return response, sentinel, seen_by_route


def test_unhandled_exception_is_internal_error_and_never_serialized(
    client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The header is asserted on the `500` as deliberately as the body: the
    `500` is answered outside `RequestIdMiddleware`, after it has reset its
    context variable.
    """
    request_id = str(uuid.uuid4())

    response, sentinel, _ = _get_users_made_to_raise(
        client, db_session, monkeypatch, headers={"X-Request-Id": request_id}
    )

    _assert_problem(response, status=500, code="internal_error", request_id=request_id)
    assert sentinel not in response.text
    assert sentinel not in str(response.headers)


def test_unhandled_exception_carries_the_minted_request_id(
    client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No `X-Request-Id` is sent, so the middleware mints the id. An inbound
    id also sits in the request headers, where a handler reading them would
    find it; a minted one lives on the middleware's context variable alone
    unless something puts it on the request scope, and that variable is
    reset by the time the `500` is answered. The id the route recorded
    while it ran is the one the response must carry — and the one the
    handler's own log record names, with the exception attached, because the
    text that is kept out of the response is kept in the log (api-surface.md
    §1: "logged with the request id").
    """
    response, sentinel, seen_by_route = _get_users_made_to_raise(
        client, db_session, monkeypatch, headers={}
    )

    assert len(seen_by_route) == 1
    minted = seen_by_route[0]
    assert minted is not None
    uuid.UUID(minted)  # minted by the middleware, not supplied by the test
    _assert_problem(response, status=500, code="internal_error", request_id=minted)
    assert sentinel not in response.text
    assert sentinel not in str(response.headers)

    logged = [
        record
        for record in caplog.records
        if record.name == "gameframework.api.errors" and record.levelno == logging.ERROR
    ]
    assert len(logged) == 1
    assert minted in logged[0].getMessage()
    assert logged[0].exc_info is not None
    assert str(logged[0].exc_info[1]) == sentinel
