"""M2-Task-Plan.md Task 18 Step 3 (api-surface.md §2.17, the sensitive-
field rule at the foot of the table): "responses never carry another
user's `username`/`display_name`/`email` to non-staff except where a
feature requires it... Every staff route that reads or changes another
person's data appears in the audit log per the ✅ column."

Reuses Step 2's own scenarios (`tests.authz.test_generated.SCENARIOS`)
rather than building a second set of fixtures for the same routes — a
route's response shape does not change between "is this call allowed"
and "does this response leak PII." Local `_login`/`_make_actor` are
small, standalone copies rather than imports from `test_generated.py`:
conftest.py's own module docstring is explicit that test modules do not
import helpers from one another (only from conftest.py), so an unrelated
suite's change cannot silently break this one.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from gameframework.db.models.identity import Role, User
from gameframework.services.passwords import hash_password

from ..conftest import make_user
from .matrix import MATRIX, MatrixRow, RouteContext
from .test_generated import SCENARIOS

_FORBIDDEN_KEYS = frozenset({"username", "display_name", "email"})

ACTIVE_ROWS = [row for row in MATRIX if row.skip_milestone is None]
_NON_STAFF_REACHABLE_ROWS = [row for row in ACTIVE_ROWS if Role.player in row.roles]


def _login(client: TestClient, user: User, password: str) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": password}
    )
    assert response.status_code == 200, response.text


def _make_actor(db: Session, role: Role) -> tuple[User, str]:
    username = f"{role.value}-{uuid.uuid4().hex[:8]}"
    password = username if role is Role.player else f"Fixture-{uuid.uuid4().hex[:8]}!"
    user = make_user(
        db,
        username=username,
        role=role,
        must_change_password=False,
        password_hash=hash_password(password),
    )
    return user, password


def _call(client: TestClient, row: MatrixRow, context: RouteContext) -> httpx.Response:
    """Standalone copy of `test_generated.py`'s own helper — small enough
    that duplicating it here is cheaper than importing a private name
    across test modules (conftest.py's own rule: helpers live in one
    place, and that place is conftest.py, not another test file)."""
    path, body = row.route.build(context)
    headers = {"If-Match": str(context.revision)} if context.revision is not None else None
    return client.request(  # type: ignore[arg-type]
        row.route.method, f"/api/v1{path}", json=body, headers=headers
    )


def _find_forbidden_keys(value: object, path: str = "") -> list[str]:
    """Recursively walks a JSON-decoded response body for any of
    `_FORBIDDEN_KEYS` at any nesting depth — a structural scan against
    the actual body shape, not a check against today's known route list,
    so a field nested inside a future aggregate response is caught the
    same way a top-level one is."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, sub in value.items():
            here = f"{path}.{key}" if path else key
            if key in _FORBIDDEN_KEYS:
                found.append(here)
            found.extend(_find_forbidden_keys(sub, here))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_find_forbidden_keys(item, f"{path}[{index}]"))
    return found


def test_scanner_detects_pii_in_a_known_leaking_body() -> None:
    """Proof the scanner is not toothless (Working-Agreement: "an
    implementation ignoring the condition entirely passes") before it is
    trusted against real responses below — nested, not only top-level."""
    leaking = {"id": "x", "username": "alice", "nested": {"display_name": "Alice A"}}

    found = _find_forbidden_keys(leaking)

    assert set(found) == {"username", "nested.display_name"}


@pytest.mark.parametrize(
    "row", _NON_STAFF_REACHABLE_ROWS, ids=[row.name for row in _NON_STAFF_REACHABLE_ROWS]
)
def test_no_pii_served_to_non_staff(
    row: MatrixRow, client: TestClient, db_session: Session
) -> None:
    scenario = SCENARIOS[row.name](db_session)
    actor, password = scenario.allowed[Role.player]
    _login(client, actor, password)

    response = _call(client, row, scenario.context)

    assert response.status_code < 300, response.text
    leaked = _find_forbidden_keys(response.json())
    assert leaked == [], f"{row.name} response carries PII key(s): {leaked}"


def test_export_is_the_named_exception_and_does_carry_pii(
    client: TestClient, db_session: Session
) -> None:
    """The one deliberate, audited opening (api-surface.md §2.4/§2.17):
    admin-only, and it *does* serve `username`/`display_name`/`email` —
    proven directly so the negative claim above is read against a real
    positive case, not an accidental absence of one."""
    target, _pw = _make_actor(db_session, Role.player)
    admin, admin_pw = _make_actor(db_session, Role.admin)
    _login(client, admin, admin_pw)

    response = client.get(f"/api/v1/users/{target.id}/export")

    assert response.status_code == 200, response.text
    leaked = set(_find_forbidden_keys(response.json()))
    assert {"username", "display_name", "email"} <= leaked


def test_users_erase_is_the_second_named_exception_but_its_own_response_carries_no_pii(
    client: TestClient, db_session: Session
) -> None:
    """`DELETE /users/{id}` follows the export as the other named admin-
    only opening (api-surface.md §2.17) — but the opening is the *access*
    the role gate grants, not this route's own payload, which is `{}`."""
    target, _pw = _make_actor(db_session, Role.player)
    admin, admin_pw = _make_actor(db_session, Role.admin)
    _login(client, admin, admin_pw)

    response = client.delete(f"/api/v1/users/{target.id}")

    assert response.status_code == 200, response.text
    assert _find_forbidden_keys(response.json()) == []
