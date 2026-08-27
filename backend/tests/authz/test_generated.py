"""Generated from `tests.authz.matrix.MATRIX` (M2-Task-Plan.md Task 18
Step 2; api-surface.md §2.17, §1's denial split). Four assertions per
active row, and the first two are different outcomes that must never be
conflated (api-surface.md §1): each allowed role passes; each disallowed
role is refused `403 role_denied`; an object-scope violation is refused
`404 object_not_found`, never data; a lifecycle gate refuses outside its
accepted states; an audited action leaves its `audit_log` row.

Scenario building is per-row (`SCENARIOS`, keyed by `MatrixRow.name`) —
`matrix.py` stays a pure §2.17 transcription, the fixture mechanics a
real request needs live here, alongside the rest of the generator.

**"captain" is a derived sub-role, not a stored one** (`user.role`
carries no `captain` value — `deps.resolve_captaincy`). Two rows'
§2.17 Roles column names `captain` rather than bare `player`
(`teams_rename`, `auth_otp_issue`): a `Role.player` caller who captains
no team is refused the same `403 role_denied` a wrong stored role would
be, even though `Role.player` sits in `MatrixRow.roles` (it is the
*candidate* role, not an unconditional pass). `test_non_captain_player_refused_role_denied`
binds that case directly, alongside — not instead of —
`test_disallowed_role_refused`, which covers stored-role mismatches.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from gameframework.config import get_settings
from gameframework.db.models.authoring import DefinitionStatus, EventDefinition
from gameframework.db.models.feedback import AuditLog
from gameframework.db.models.identity import Role, User
from gameframework.db.models.play import TeamChallengeState
from gameframework.db.models.runs import EventRun, RunStatus
from gameframework.services.challenges import NoParticipationError, start_challenge
from gameframework.services.definitions import DEFAULT_CONTRACT_RANGE
from gameframework.services.passwords import hash_password
from gameframework.services.preflight import compute_config_hash

from ..conftest import (
    make_blocked_address,
    make_challenge,
    make_event_definition,
    make_event_run,
    make_installed_artifact,
    make_participation,
    make_team,
    make_team_challenge,
    make_user,
)
from .matrix import MATRIX, MatrixRow, RouteContext

ACTIVE_ROWS = [row for row in MATRIX if row.skip_milestone is None]
ALL_ROLES = (Role.admin, Role.gameadmin, Role.player)


# ---------------------------------------------------------------------------
# shared fixture helpers
# ---------------------------------------------------------------------------


def _login(client: TestClient, user: User, password: str) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": password}
    )
    assert response.status_code == 200, response.text


def _make_actor(db: Session, role: Role, **overrides: object) -> tuple[User, str]:
    """A logged-in-able user of `role`. Players authenticate on
    username-as-password (api-surface.md §2.2's initial-password rule);
    `must_change_password=False` so a directly-inserted fixture row reads
    as already activated, the same convention `tests/challenges/
    test_start.py`'s `_setup_team_in_run` uses — this is a fixture
    convenience, not a claim about the real activation flow, which
    Task 4's own suite covers."""
    username = f"{role.value}-{uuid.uuid4().hex[:8]}"
    password = username if role is Role.player else f"Fixture-{uuid.uuid4().hex[:8]}!"
    user = make_user(
        db,
        username=username,
        role=role,
        must_change_password=False,
        password_hash=hash_password(password),
        **overrides,
    )
    return user, password


def _excluded_status(
    allowed: frozenset[RunStatus | DefinitionStatus],
) -> RunStatus | DefinitionStatus:
    """The first member of `allowed`'s own enum class that `allowed`
    itself does not accept — deterministic over each enum's declared
    order, so the same gate always gets the same negative case. Generic
    over `RunStatus` and `DefinitionStatus`: both are `StrEnum`s and every
    lifecycle-gated row's `allowed` set is drawn from exactly one of them,
    so the member type of any element names the enum to search."""
    enum_cls: type[RunStatus] | type[DefinitionStatus] = type(next(iter(allowed)))
    return next(status for status in enum_cls if status not in allowed)


def _audit_count(db: Session, actor_id: uuid.UUID) -> int:
    return db.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.actor_user_id == actor_id)
    ).scalar_one()


def _call(client: TestClient, row: MatrixRow, context: RouteContext) -> httpx.Response:
    path, body = row.route.build(context)
    headers = {"If-Match": str(context.revision)} if context.revision is not None else None
    return client.request(  # type: ignore[arg-type]
        row.route.method, f"/api/v1{path}", json=body, headers=headers
    )


# ---------------------------------------------------------------------------
# per-row scenarios
# ---------------------------------------------------------------------------


@dataclass
class RowScenario:
    context: RouteContext
    allowed: dict[Role, tuple[User, str]]
    run: EventRun | None = None
    """Set whenever `row.lifecycle` is a `RunStatus` set — mutated to
    `_excluded_status(row.lifecycle)` for the lifecycle-gate test."""
    definition: EventDefinition | None = None
    """Set whenever `row.lifecycle` is a `DefinitionStatus` set instead —
    the definitions rows' equivalent of `run` above. A row sets exactly
    one of the two, never both."""
    scope_violation: tuple[User, str, RouteContext] | None = None
    extra_role_denied: list[tuple[User, str]] = field(default_factory=list)
    """Actors who hold an allowed *stored* role but are refused anyway —
    the "captain" cases (see module docstring)."""


def _make_publishable_draft(db: Session, *, minigame_id: str) -> tuple[EventDefinition, int]:
    """A `draft` definition with exactly one challenge pinned to a
    matching installed artifact — the minimal document `validate_
    definition` accepts, built directly against the ORM rows `apply_patch`/
    `publish` read (`existing_challenges_document`) rather than through an
    HTTP `PATCH`, mirroring `tests/definitions/test_lifecycle.py`'s own
    `_create_publishable_draft` at the row level. Returns the definition
    and its revision (`1`, for the caller's `If-Match`) — a whole-document
    re-validation runs on *any* field-touching `PATCH`
    (`_apply_draft_document_fields`), draft or published, so a definition
    with zero challenges 422s on `challenges: [] should be non-empty`
    (confirmed by mutation, Step 2 report) even for a `story`-only edit.
    """
    digest = "sha256:" + uuid.uuid4().hex + uuid.uuid4().hex
    # conftest.py's `make_event_definition`/`make_challenge` defaults
    # (`contract_version="1.0"`, `minigame_version_range=">=1.0.0"`) are
    # not valid document ranges — `>=A.B,<C.D` — because no other suite's
    # fixture round-trips them through `existing_challenges_document`/
    # `validate_definition` the way `publish`/a content-touching `PATCH`
    # does; every other consumer of these two factories only ever reads
    # the ORM columns directly. Confirmed by running this scenario
    # unmodified first (Step 2 report): `contract`/`minigame/version`
    # both failed schema validation on the stock defaults.
    definition = make_event_definition(
        db, status=DefinitionStatus.draft, contract_version=DEFAULT_CONTRACT_RANGE
    )
    make_challenge(
        db,
        definition=definition,
        minigame_id=minigame_id,
        minigame_version="1.0.0",
        minigame_version_range=">=1.0,<2.0",
        minigame_image_digest=digest,
        hint_cap=100,
    )
    make_installed_artifact(
        db,
        artifact_id=minigame_id,
        version="1.0.0",
        manifest={"id": minigame_id, "version": "1.0.0"},
        image_digest=digest,
    )
    return definition, definition.revision


def _scenario_teams_rename(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.running)
    captain_a, captain_a_pw = _make_actor(db, Role.player)
    team_a = make_team(db, run=run, captain=captain_a)
    make_participation(db, user=captain_a, run=run, team_id=team_a.id)
    non_captain, non_captain_pw = _make_actor(db, Role.player)
    make_participation(db, user=non_captain, run=run, team_id=team_a.id)
    team_b = make_team(db, run=run)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(team_id=team_a.id),
        allowed={
            Role.player: (captain_a, captain_a_pw),
            Role.admin: (admin, admin_pw),
            Role.gameadmin: (gameadmin, gameadmin_pw),
        },
        run=run,
        scope_violation=(captain_a, captain_a_pw, RouteContext(team_id=team_b.id)),
        extra_role_denied=[(non_captain, non_captain_pw)],
    )


def _scenario_teams_create(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.created)
    participation = make_participation(db, run=run)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(run_id=run.id, user_id=participation.user_id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        run=run,
        scope_violation=(
            admin,
            admin_pw,
            RouteContext(run_id=uuid.uuid4(), user_id=participation.user_id),
        ),
    )


def _scenario_teams_set_members(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.created)
    team = make_team(db, run=run)
    participation = make_participation(db, run=run)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(team_id=team.id, user_id=participation.user_id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        run=run,
        scope_violation=(
            admin,
            admin_pw,
            RouteContext(team_id=uuid.uuid4(), user_id=participation.user_id),
        ),
    )


def _scenario_participants_import(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.created)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(run_id=run.id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        run=run,
        scope_violation=(admin, admin_pw, RouteContext(run_id=uuid.uuid4())),
    )


def _scenario_participants_create_one(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.created)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(run_id=run.id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        run=run,
        scope_violation=(admin, admin_pw, RouteContext(run_id=uuid.uuid4())),
    )


def _scenario_teams_set_captain(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.running)
    team = make_team(db, run=run)
    new_captain, _pw = _make_actor(db, Role.player)
    make_participation(db, user=new_captain, run=run, team_id=team.id)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(team_id=team.id, user_id=new_captain.id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        run=run,
        scope_violation=(
            admin,
            admin_pw,
            RouteContext(team_id=uuid.uuid4(), user_id=new_captain.id),
        ),
    )


def _scenario_auth_otp_issue(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.running)
    captain_a, captain_a_pw = _make_actor(db, Role.player)
    team_a = make_team(db, run=run, captain=captain_a)
    make_participation(db, user=captain_a, run=run, team_id=team_a.id)
    target_a, _pw = _make_actor(db, Role.player)
    make_participation(db, user=target_a, run=run, team_id=team_a.id)
    team_b = make_team(db, run=run)
    target_b, _pw2 = _make_actor(db, Role.player)
    make_participation(db, user=target_b, run=run, team_id=team_b.id)
    non_captain, non_captain_pw = _make_actor(db, Role.player)
    make_participation(db, user=non_captain, run=run, team_id=team_a.id)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(user_id=target_a.id),
        allowed={
            Role.player: (captain_a, captain_a_pw),
            Role.admin: (admin, admin_pw),
            Role.gameadmin: (gameadmin, gameadmin_pw),
        },
        scope_violation=(captain_a, captain_a_pw, RouteContext(user_id=target_b.id)),
        extra_role_denied=[(non_captain, non_captain_pw)],
    )


def _scenario_me_language(db: Session) -> RowScenario:
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    player, player_pw = _make_actor(db, Role.player)
    return RowScenario(
        context=RouteContext(),
        allowed={
            Role.admin: (admin, admin_pw),
            Role.gameadmin: (gameadmin, gameadmin_pw),
            Role.player: (player, player_pw),
        },
    )


def _scenario_challenges_start(db: Session) -> RowScenario:
    definition = make_event_definition(db)
    run = make_event_run(db, definition=definition, status=RunStatus.running)
    player, player_pw = _make_actor(db, Role.player)
    team = make_team(db, run=run)
    make_participation(db, user=player, run=run, team_id=team.id)
    challenge = make_challenge(db, definition=definition)
    make_team_challenge(db, team, challenge, state=TeamChallengeState.startable)
    return RowScenario(
        context=RouteContext(challenge_id=challenge.id),
        allowed={Role.player: (player, player_pw)},
        run=run,
    )


def _scenario_users_export(db: Session) -> RowScenario:
    target, _pw = _make_actor(db, Role.player)
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(
        context=RouteContext(user_id=target.id),
        allowed={Role.admin: (admin, admin_pw)},
        scope_violation=(admin, admin_pw, RouteContext(user_id=uuid.uuid4())),
    )


def _scenario_users_erase(db: Session) -> RowScenario:
    target, _pw = _make_actor(db, Role.player)
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(
        context=RouteContext(user_id=target.id),
        allowed={Role.admin: (admin, admin_pw)},
        scope_violation=(admin, admin_pw, RouteContext(user_id=uuid.uuid4())),
    )


def _scenario_security_blocked_addresses_list(db: Session) -> RowScenario:
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
    )


def _scenario_security_blocked_addresses_release(db: Session) -> RowScenario:
    blocked = make_blocked_address(db)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(blocked_id=blocked.id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        scope_violation=(admin, admin_pw, RouteContext(blocked_id=uuid.uuid4())),
    )


def _scenario_runs_preflight(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.created)
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(
        context=RouteContext(run_id=run.id),
        allowed={Role.admin: (admin, admin_pw)},
        run=run,
        scope_violation=(admin, admin_pw, RouteContext(run_id=uuid.uuid4())),
    )


def _scenario_definitions_list(db: Session) -> RowScenario:
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
    )


def _scenario_definitions_create(db: Session) -> RowScenario:
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(context=RouteContext(), allowed={Role.admin: (admin, admin_pw)})


def _scenario_definitions_read(db: Session) -> RowScenario:
    definition = make_event_definition(db)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(definition_id=definition.id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        scope_violation=(admin, admin_pw, RouteContext(definition_id=uuid.uuid4())),
    )


def _scenario_definitions_patch(db: Session) -> RowScenario:
    definition, revision = _make_publishable_draft(db, minigame_id=f"mini-{uuid.uuid4().hex[:8]}")
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(definition_id=definition.id, revision=revision),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        definition=definition,
        scope_violation=(
            admin,
            admin_pw,
            RouteContext(definition_id=uuid.uuid4(), revision=revision),
        ),
    )


def _scenario_definitions_publish(db: Session) -> RowScenario:
    definition, _revision = _make_publishable_draft(db, minigame_id=f"mini-{uuid.uuid4().hex[:8]}")
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(
        context=RouteContext(definition_id=definition.id),
        allowed={Role.admin: (admin, admin_pw)},
        definition=definition,
        scope_violation=(admin, admin_pw, RouteContext(definition_id=uuid.uuid4())),
    )


def _scenario_definitions_unpublish(db: Session) -> RowScenario:
    definition = make_event_definition(db, status=DefinitionStatus.published)
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(
        context=RouteContext(definition_id=definition.id),
        allowed={Role.admin: (admin, admin_pw)},
        definition=definition,
        scope_violation=(admin, admin_pw, RouteContext(definition_id=uuid.uuid4())),
    )


def _scenario_definitions_archive(db: Session) -> RowScenario:
    definition = make_event_definition(db, status=DefinitionStatus.published)
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(
        context=RouteContext(definition_id=definition.id),
        allowed={Role.admin: (admin, admin_pw)},
        definition=definition,
        scope_violation=(admin, admin_pw, RouteContext(definition_id=uuid.uuid4())),
    )


def _scenario_definitions_unarchive(db: Session) -> RowScenario:
    definition = make_event_definition(db, status=DefinitionStatus.archived)
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(
        context=RouteContext(definition_id=definition.id),
        allowed={Role.admin: (admin, admin_pw)},
        definition=definition,
        scope_violation=(admin, admin_pw, RouteContext(definition_id=uuid.uuid4())),
    )


def _scenario_definitions_clone(db: Session) -> RowScenario:
    definition = make_event_definition(db)
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(
        context=RouteContext(definition_id=definition.id),
        allowed={Role.admin: (admin, admin_pw)},
        scope_violation=(admin, admin_pw, RouteContext(definition_id=uuid.uuid4())),
    )


def _scenario_definitions_dry_run(db: Session) -> RowScenario:
    definition = make_event_definition(db)
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(
        context=RouteContext(definition_id=definition.id),
        allowed={Role.admin: (admin, admin_pw)},
        scope_violation=(admin, admin_pw, RouteContext(definition_id=uuid.uuid4())),
    )


def _scenario_runs_start(db: Session) -> RowScenario:
    definition = make_event_definition(db, status=DefinitionStatus.published)
    run = make_event_run(db, definition=definition, status=RunStatus.created)
    team = make_team(db, run=run)
    make_participation(db, run=run, team_id=team.id)
    settings = get_settings()
    run.preflight_config_hash = compute_config_hash(db, run, settings)
    run.preflight_passed_at = datetime.now(UTC)
    db.commit()
    admin, admin_pw = _make_actor(db, Role.admin)
    return RowScenario(
        context=RouteContext(run_id=run.id),
        allowed={Role.admin: (admin, admin_pw)},
        run=run,
        scope_violation=(admin, admin_pw, RouteContext(run_id=uuid.uuid4())),
    )


def _scenario_runs_pause(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.running)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(run_id=run.id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        run=run,
        scope_violation=(admin, admin_pw, RouteContext(run_id=uuid.uuid4())),
    )


def _scenario_runs_resume(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.paused, paused_at=datetime.now(UTC))
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(run_id=run.id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        run=run,
        scope_violation=(admin, admin_pw, RouteContext(run_id=uuid.uuid4())),
    )


def _scenario_runs_finish(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.running)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(run_id=run.id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        run=run,
        scope_violation=(admin, admin_pw, RouteContext(run_id=uuid.uuid4())),
    )


def _scenario_runs_patch(db: Session) -> RowScenario:
    run = make_event_run(db, status=RunStatus.running)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(run_id=run.id),
        allowed={Role.admin: (admin, admin_pw), Role.gameadmin: (gameadmin, gameadmin_pw)},
        run=run,
        scope_violation=(admin, admin_pw, RouteContext(run_id=uuid.uuid4())),
    )


def _scenario_event_read(db: Session) -> RowScenario:
    definition = make_event_definition(db)
    run = make_event_run(db, definition=definition, status=RunStatus.running)
    player, player_pw = _make_actor(db, Role.player)
    team = make_team(db, run=run)
    make_participation(db, user=player, run=run, team_id=team.id)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(),
        allowed={
            Role.player: (player, player_pw),
            Role.admin: (admin, admin_pw),
            Role.gameadmin: (gameadmin, gameadmin_pw),
        },
    )


def _scenario_challenges_list(db: Session) -> RowScenario:
    definition = make_event_definition(db)
    run = make_event_run(db, definition=definition, status=RunStatus.running)
    player, player_pw = _make_actor(db, Role.player)
    team = make_team(db, run=run)
    make_participation(db, user=player, run=run, team_id=team.id)
    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(),
        allowed={
            Role.player: (player, player_pw),
            Role.admin: (admin, admin_pw),
            Role.gameadmin: (gameadmin, gameadmin_pw),
        },
    )


def _scenario_challenges_read(db: Session) -> RowScenario:
    definition_a = make_event_definition(db)
    run_a = make_event_run(db, definition=definition_a, status=RunStatus.running)
    player, player_pw = _make_actor(db, Role.player)
    team_a = make_team(db, run=run_a)
    make_participation(db, user=player, run=run_a, team_id=team_a.id)
    challenge_a = make_challenge(db, definition=definition_a)

    definition_b = make_event_definition(db)
    challenge_b = make_challenge(db, definition=definition_b)

    admin, admin_pw = _make_actor(db, Role.admin)
    gameadmin, gameadmin_pw = _make_actor(db, Role.gameadmin)
    return RowScenario(
        context=RouteContext(challenge_id=challenge_a.id),
        allowed={
            Role.player: (player, player_pw),
            Role.admin: (admin, admin_pw),
            Role.gameadmin: (gameadmin, gameadmin_pw),
        },
        scope_violation=(player, player_pw, RouteContext(challenge_id=challenge_b.id)),
    )


SCENARIOS = {
    "teams_rename": _scenario_teams_rename,
    "teams_create": _scenario_teams_create,
    "teams_set_members": _scenario_teams_set_members,
    "participants_import": _scenario_participants_import,
    "participants_create_one": _scenario_participants_create_one,
    "teams_set_captain": _scenario_teams_set_captain,
    "auth_otp_issue": _scenario_auth_otp_issue,
    "me_language": _scenario_me_language,
    "challenges_start": _scenario_challenges_start,
    "users_export": _scenario_users_export,
    "users_erase": _scenario_users_erase,
    "security_blocked_addresses_list": _scenario_security_blocked_addresses_list,
    "security_blocked_addresses_release": _scenario_security_blocked_addresses_release,
    "runs_preflight": _scenario_runs_preflight,
    "definitions_list": _scenario_definitions_list,
    "definitions_create": _scenario_definitions_create,
    "definitions_read": _scenario_definitions_read,
    "definitions_patch": _scenario_definitions_patch,
    "definitions_publish": _scenario_definitions_publish,
    "definitions_unpublish": _scenario_definitions_unpublish,
    "definitions_archive": _scenario_definitions_archive,
    "definitions_unarchive": _scenario_definitions_unarchive,
    "definitions_clone": _scenario_definitions_clone,
    "definitions_dry_run": _scenario_definitions_dry_run,
    "runs_start": _scenario_runs_start,
    "runs_pause": _scenario_runs_pause,
    "runs_resume": _scenario_runs_resume,
    "runs_finish": _scenario_runs_finish,
    "runs_patch": _scenario_runs_patch,
    "event_read": _scenario_event_read,
    "challenges_list": _scenario_challenges_list,
    "challenges_read": _scenario_challenges_read,
}

assert set(SCENARIOS) == {row.name for row in ACTIVE_ROWS}, (
    "every active row needs exactly one scenario builder — see the module "
    "docstring; a name mismatch here means matrix.py and this file disagree"
)
# A row silently emptied of roles (`roles=()`) would drop out of
# `_ALLOWED_PARAMS` below with nothing to say so — zero parametrized cases
# is a vacuous pass, not a red one. Caught here, at collection, rather
# than left to be noticed by a coverage count nobody is watching.
assert all(row.roles for row in ACTIVE_ROWS), (
    "an active row with an empty roles tuple generates no allowed-role "
    "case for itself and would vacuously pass — every §2.17 row names at "
    "least one role"
)


# ---------------------------------------------------------------------------
# 1. each allowed role passes
# ---------------------------------------------------------------------------

_ALLOWED_PARAMS = [(row, role) for row in ACTIVE_ROWS for role in row.roles]


@pytest.mark.parametrize(
    "row,role",
    _ALLOWED_PARAMS,
    ids=[f"{row.name}:{role.value}" for row, role in _ALLOWED_PARAMS],
)
def test_allowed_role_succeeds(
    row: MatrixRow, role: Role, client: TestClient, db_session: Session
) -> None:
    scenario = SCENARIOS[row.name](db_session)
    actor, password = scenario.allowed[role]
    _login(client, actor, password)

    response = _call(client, row, scenario.context)

    assert response.status_code < 300, response.text


# ---------------------------------------------------------------------------
# 2. each disallowed role is refused 403 role_denied
# ---------------------------------------------------------------------------

_DISALLOWED_PARAMS = [
    (row, role) for row in ACTIVE_ROWS for role in ALL_ROLES if role not in row.roles
]


@pytest.mark.parametrize(
    "row,role",
    _DISALLOWED_PARAMS,
    ids=[f"{row.name}:{role.value}" for row, role in _DISALLOWED_PARAMS],
)
def test_disallowed_role_refused(
    row: MatrixRow, role: Role, client: TestClient, db_session: Session
) -> None:
    scenario = SCENARIOS[row.name](db_session)
    actor, password = _make_actor(db_session, role)
    _login(client, actor, password)

    response = _call(client, row, scenario.context)

    assert response.status_code == 403, response.text
    assert response.json()["code"] == "role_denied"


_EXTRA_ROLE_DENIED_ROWS = [
    row for row in ACTIVE_ROWS if row.name in {"teams_rename", "auth_otp_issue"}
]


@pytest.mark.parametrize(
    "row", _EXTRA_ROLE_DENIED_ROWS, ids=[r.name for r in _EXTRA_ROLE_DENIED_ROWS]
)
def test_non_captain_player_refused_role_denied(
    row: MatrixRow, client: TestClient, db_session: Session
) -> None:
    """§2.17's Roles column names `captain`, not `player`, for these two
    rows — a `Role.player` caller holding no captaincy is refused
    `role_denied` exactly as a wrong stored role would be (deps.py's
    `_ensure_own_team_or_staff`, `api/security.py`'s OTP handler)."""
    scenario = SCENARIOS[row.name](db_session)
    actor, password = scenario.extra_role_denied[0]
    _login(client, actor, password)

    response = _call(client, row, scenario.context)

    assert response.status_code == 403, response.text
    assert response.json()["code"] == "role_denied"


# ---------------------------------------------------------------------------
# 3. an object-scope violation is refused 404 object_not_found, never data
# ---------------------------------------------------------------------------

_SCOPE_VIOLATION_ROWS = [row for row in ACTIVE_ROWS if row.scoped_id_field is not None]


@pytest.mark.parametrize(
    "row", _SCOPE_VIOLATION_ROWS, ids=[row.name for row in _SCOPE_VIOLATION_ROWS]
)
def test_object_scope_violation_refused(
    row: MatrixRow, client: TestClient, db_session: Session
) -> None:
    scenario = SCENARIOS[row.name](db_session)
    assert scenario.scope_violation is not None, (
        f"{row.name} declares scoped_id_field but no scenario.scope_violation "
        "— fix the scenario builder"
    )
    actor, password, wrong_context = scenario.scope_violation
    _login(client, actor, password)

    response = _call(client, row, wrong_context)

    assert response.status_code == 404, response.text
    assert response.json()["code"] == "object_not_found"


# ---------------------------------------------------------------------------
# 4. a lifecycle gate refuses outside its accepted states
# ---------------------------------------------------------------------------

_LIFECYCLE_ROWS = [
    row for row in ACTIVE_ROWS if row.lifecycle is not None and not row.lifecycle_refusal_untested
]


@pytest.mark.parametrize("row", _LIFECYCLE_ROWS, ids=[row.name for row in _LIFECYCLE_ROWS])
def test_lifecycle_gate_refused_outside_accepted_states(
    row: MatrixRow, client: TestClient, db_session: Session
) -> None:
    scenario = SCENARIOS[row.name](db_session)
    assert row.lifecycle is not None
    stateful = scenario.run or scenario.definition
    assert stateful is not None, f"{row.name} has a lifecycle gate but no scenario.run/definition"
    actor, password = next(iter(scenario.allowed.values()))
    _login(client, actor, password)
    stateful.status = _excluded_status(row.lifecycle)  # type: ignore[assignment]
    db_session.commit()

    response = _call(client, row, scenario.context)

    # api-surface.md §1: the lifecycle refusal must not be confused with
    # either denial shape — a role/scope check answering for a status
    # mismatch would leak which one governs the route.
    assert response.status_code not in (200, 201, 403, 404), response.text
    assert response.status_code >= 400, response.text


# ---------------------------------------------------------------------------
# 5. an audited action leaves its audit_log row
# ---------------------------------------------------------------------------

_AUDITED_ROWS = [row for row in ACTIVE_ROWS if row.audited]


@pytest.mark.parametrize("row", _AUDITED_ROWS, ids=[row.name for row in _AUDITED_ROWS])
def test_audited_action_writes_audit_log(
    row: MatrixRow, client: TestClient, db_session: Session
) -> None:
    scenario = SCENARIOS[row.name](db_session)
    actor, password = next(iter(scenario.allowed.values()))
    _login(client, actor, password)
    before = _audit_count(db_session, actor.id)

    response = _call(client, row, scenario.context)

    assert response.status_code < 300, response.text
    after = _audit_count(db_session, actor.id)
    assert after > before, "no audit_log row was written for this actor"


# ---------------------------------------------------------------------------
# Targeted regression: `challenges_start`'s role gate is unbound without
# this (M2-Task-Plan.md Task 18). `current_session(Role.player)` refuses
# staff before `start_challenge` is ever called, so nothing above reaches
# this path through the HTTP client — it is only reachable by weakening
# that role gate, which is exactly the scenario a service-level test can
# bind without needing to mutate route code to prove it. Confirmed by
# reproducing the mutation directly: widening the role gate to admit
# `Role.admin`/`Role.gameadmin` made `test_disallowed_role_refused
# [challenges_start:admin]` and `[challenges_start:gameadmin]` error out
# with an unhandled `sqlalchemy.exc.NoResultFound` rather than fail
# cleanly on `assert response.status_code == 403` — a crash, not a
# 403, is exactly what a role column alone cannot catch.
# ---------------------------------------------------------------------------


def test_start_challenge_with_no_participation_raises_no_participation_error(
    db_session: Session,
) -> None:
    """The service-level backstop `services/challenges.py`'s
    `start_challenge` now raises for a caller holding no participation in
    `run` at all, rather than crashing `.scalar_one()` on an empty result
    — staff, or any future caller shape a role check fails to keep out.
    `api/challenges.py` converts this to `403 role_denied`."""
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    staff, _pw = _make_actor(db_session, Role.admin)
    challenge = make_challenge(db_session, definition=definition)

    with pytest.raises(NoParticipationError):
        start_challenge(db_session, run, staff, challenge)
