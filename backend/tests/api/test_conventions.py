"""The api-surface.md §1 conventions every later endpoint inherits: Problem
Details error bodies, the X-Request-Id echo, the CORS origin rule, the
403/404 denial split, the single 429 + Retry-After shape, the
Idempotency-Key dependency, cursor pagination, and the audit writer's
installation-scope PII guard (data-model.md §3.23) — the one rule in this
task no CHECK constraint can express, so it gets its own test rather than
riding along with the scope/event_run_id CHECK Task 1a already proves.

The routes under `/api/v1/_test/...` exist only to give the conventions
something to attach to — Task 2 ships no business routes of its own (that is
Task 3 onward). They are registered by the `conventions_router` fixture and
torn down after each test, the same "temporary diagnostic route" approach
Task 1a used to prove the `client` fixture's dependency override.
"""

import uuid
from collections.abc import Iterator

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.api.errors import (
    ProblemError,
    forbidden,
    idempotency_key,
    not_found,
    too_many_requests,
)
from gameframework.api.pagination import paginate
from gameframework.config import get_settings
from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.infrastructure import Job
from gameframework.main import app
from gameframework.services.audit import AuditDetailsError, write_audit

from ..conftest import make_event_run, make_job

_router = APIRouter(prefix="/api/v1/_test")


@_router.get("/problem")
def route_problem() -> None:
    raise ProblemError(400, "test_problem", detail="something went wrong")


@_router.get("/forbidden")
def route_forbidden() -> None:
    forbidden("role_denied")


@_router.get("/not-found")
def route_not_found() -> None:
    not_found("object_not_found")


@_router.get("/rate-limited")
def route_rate_limited() -> None:
    too_many_requests(retry_after=30)


@_router.post("/idempotent")
def route_idempotent(key: str | None = Depends(idempotency_key)) -> dict[str, str | None]:
    return {"idempotency_key": key}


@pytest.fixture()
def conventions_router() -> Iterator[None]:
    app.include_router(_router)
    try:
        yield
    finally:
        app.router.routes = [
            route
            for route in app.router.routes
            if not getattr(route, "path", "").startswith("/api/v1/_test")
        ]


# --------------------------------------------------------------------------
# Problem Details + X-Request-Id
# --------------------------------------------------------------------------


def test_problem_error_returns_problem_json_with_code(
    client: TestClient, conventions_router: None
) -> None:
    response = client.get("/api/v1/_test/problem")
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["code"] == "test_problem"
    assert body["detail"] == "something went wrong"


def test_response_carries_x_request_id(client: TestClient, conventions_router: None) -> None:
    response = client.get("/api/v1/_test/problem")
    assert response.headers["X-Request-Id"]
    assert response.json()["request_id"] == response.headers["X-Request-Id"]


def test_inbound_request_id_is_echoed(client: TestClient, conventions_router: None) -> None:
    inbound = str(uuid.uuid4())
    response = client.get("/api/v1/_test/problem", headers={"X-Request-Id": inbound})
    assert response.headers["X-Request-Id"] == inbound
    assert response.json()["request_id"] == inbound


def test_healthy_response_also_carries_x_request_id(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.headers["X-Request-Id"]


# --------------------------------------------------------------------------
# Denial split: 403 (role) vs 404 (non-disclosure)
# --------------------------------------------------------------------------


def test_role_denied_route_answers_403(client: TestClient, conventions_router: None) -> None:
    response = client.get("/api/v1/_test/forbidden")
    assert response.status_code == 403
    assert response.json()["code"] == "role_denied"


def test_out_of_scope_object_answers_404(client: TestClient, conventions_router: None) -> None:
    response = client.get("/api/v1/_test/not-found")
    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


# --------------------------------------------------------------------------
# 429 + Retry-After
# --------------------------------------------------------------------------


def test_rate_limited_carries_retry_after(client: TestClient, conventions_router: None) -> None:
    response = client.get("/api/v1/_test/rate-limited")
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "30"


# --------------------------------------------------------------------------
# Idempotency-Key: format/length validated and echoed, no replay store
# --------------------------------------------------------------------------


def test_malformed_idempotency_key_refused_422(
    client: TestClient, conventions_router: None
) -> None:
    response = client.post(
        "/api/v1/_test/idempotent", headers={"Idempotency-Key": "bad key with spaces!"}
    )
    assert response.status_code == 422


def test_well_formed_idempotency_key_echoed(client: TestClient, conventions_router: None) -> None:
    key = "abc-123_def.456"
    response = client.post("/api/v1/_test/idempotent", headers={"Idempotency-Key": key})
    assert response.status_code == 200
    assert response.json()["idempotency_key"] == key


def test_absent_idempotency_key_is_accepted(client: TestClient, conventions_router: None) -> None:
    response = client.post("/api/v1/_test/idempotent")
    assert response.status_code == 200
    assert response.json()["idempotency_key"] is None


# --------------------------------------------------------------------------
# CORS: single configured origin, never reflected, never wildcarded
# --------------------------------------------------------------------------


def test_disallowed_origin_gets_no_cors_header(client: TestClient) -> None:
    response = client.get("/api/v1/health", headers={"Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in response.headers


def test_configured_origin_gets_exactly_itself_never_wildcard(client: TestClient) -> None:
    origin = get_settings().frontend_origin
    response = client.get("/api/v1/health", headers={"Origin": origin})
    assert response.headers["access-control-allow-origin"] == origin
    assert response.headers["access-control-allow-origin"] != "*"


# --------------------------------------------------------------------------
# Cursor pagination
# --------------------------------------------------------------------------


def test_paginate_pages_in_id_order_with_next_cursor(db_session: Session) -> None:
    jobs = sorted((make_job(db_session) for _ in range(3)), key=lambda job: job.id)

    first_page = paginate(db_session, select(Job), cursor=None, limit=2)
    assert [item.id for item in first_page.items] == [jobs[0].id, jobs[1].id]
    assert first_page.next_cursor is not None

    second_page = paginate(db_session, select(Job), cursor=first_page.next_cursor, limit=2)
    assert [item.id for item in second_page.items] == [jobs[2].id]
    assert second_page.next_cursor is None


# --------------------------------------------------------------------------
# Audit writer: installation-scope rows must not carry participant PII in
# `details` — data-model.md §3.23, enforced by the writer because no CHECK
# constraint can express it. The scope <=> event_run_id CHECK itself is
# already proven in tests/db/test_constraints.py and is not retested here.
# --------------------------------------------------------------------------


def test_write_audit_refuses_participant_pii_in_installation_scope_details(
    db_session: Session,
) -> None:
    with pytest.raises(AuditDetailsError):
        write_audit(
            db_session,
            actor_user_id=None,
            scope=AuditScope.installation,
            event_run_id=None,
            action="initial_admin_created",
            target_type="user",
            target_id=uuid.uuid4(),
            details={"username": "admin"},
        )


def test_write_audit_allows_installation_scope_details_without_pii(
    db_session: Session,
) -> None:
    entry = write_audit(
        db_session,
        actor_user_id=None,
        scope=AuditScope.installation,
        event_run_id=None,
        action="initial_admin_created",
        target_type="user",
        target_id=uuid.uuid4(),
        details={"note": "framework-minted"},
    )
    assert entry.details == {"note": "framework-minted"}


def test_write_audit_allows_participant_pii_shaped_keys_in_participant_scope(
    db_session: Session,
) -> None:
    """The guard is installation-scope only: `details` on a `participant`
    row may legitimately need a field also named e.g. `username` (this is
    not the field the PII inventory means to gate — participant-scope rows
    are destroyed with their run, data-model.md §3.23), so the writer must
    not reject it.
    """
    run = make_event_run(db_session)
    entry = write_audit(
        db_session,
        actor_user_id=None,
        scope=AuditScope.participant,
        event_run_id=run.id,
        action="force_solve",
        target_type="team_challenge",
        target_id=uuid.uuid4(),
        details={"reason": "stuck team", "username": "not actually gated here"},
    )
    assert entry.details["username"] == "not actually gated here"
