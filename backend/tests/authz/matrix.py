"""Authorization matrix, transcribed from api-surface.md §2.17 — the
normative source. **Authorization tests are generated from this file**
(§2.17's own words, M2-Task-Plan.md Task 18): `test_generated.py`
parametrizes over `MATRIX`. If this file and §2.17 ever disagree, §2.17
is right and this file is the bug — fix the row, not the document.

**Excluded on purpose.** §2.17 itself excludes `GET /auth/session`,
`GET /auth/csrf` and `POST /auth/password`: those three carry no object
scope and no lifecycle gate. What governs them is the session's
`restricted` flag (api-surface.md §2.2), and a row here would generate a
test against the wrong rule (ADR-0007, data-model.md §3.2). Do not add
them, however tempting the "every auth route needs a row" instinct is.

**The four prose-lifecycle groups §2.17 did not determine on its own
were reported before being encoded, and are resolved now** (Step 1
report and Daniel's ruling on it; M2-Task-Plan.md Task 18; AGENTS.md
"Report, do not resolve" — none was guessed into a row before this):

- Definition authoring (§2.17 line 395, "per §2.6 status rules") —
  decomposed into the eleven `definitions_*` rows below, per-action gates
  read from §2.6 with one exception Daniel ruled rather than transcribed:
  `PATCH` refusing on `archived` is not stated in §2.6's prose (it *is*
  already the code's own behavior, `services/definitions.py::apply_patch`
  line 424) — cited `"§2.6 + assistant ruling, Task 18"` rather than a
  bare §2.6 line, and Daniel is adding the sentence to §2.6 itself so the
  two do not stay out of step. `POST .../import` is reported, not
  encoded: it needs a multipart upload or a real HTTPS fetch, neither of
  which this generator's JSON-body `Route.build` can drive.
- Run lifecycle (§2.17 line 396, "per run status") — `start`/`pause`/
  `resume`/`finish` decomposed into the `runs_*` rows below, confirmed
  against §2.6 line 32. `keep`/`legal-hold`/`destroy` stay `lifecycle=
  None  # TBD — M6`: §2.6 describes what each does without stating an
  accepted status set, and Daniel ruled that undetermined rather than
  invented. `export` is the one exception — §2.6 line 37 states its gate
  outright ("still served after the run is `destroyed`") — cited as such,
  not `# TBD`.
- `PATCH /runs/{id}` (§2.17 line 397, "until `destroyed`") — encoded as
  `{created, running, paused, finished}`, but `lifecycle_refusal_
  untested=True`: no M2 route can ever produce a `destroyed` run, so the
  refusal half is bound only once M6's `destroy` route exists (recorded
  in Backlog.md). The accepted half is bound now.
- `GET /leaderboard`, `GET /event`, `GET /challenges*` (§2.17 line 398)
  — split three ways. `GET /event` and `GET /challenges` carry no path id
  (`ObjectScope.OWN_RUN`, no violation case); `GET /challenges/{id}` does
  — `api/challenges.py::_get_challenge_for_run` already answers
  `404 object_not_found` for a challenge from another run's definition,
  a real case this file was wrong to claim didn't exist. `GET
  /leaderboard` is M5 (not built — Implementation-Plan.md §M5), in the
  skip block. "Visibility-filtered serialization" is a *content* rule
  (which fields are served), not an access rule Task 18's refusal-focused
  generator has any business encoding — Step 3 and M5's own suite own
  that half.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto

from gameframework.db.models.authoring import DefinitionStatus
from gameframework.db.models.identity import Role
from gameframework.db.models.runs import RunStatus


class ObjectScope(Enum):
    """api-surface.md §1: the object-scope axis the Roles column never
    answers. `SELF` and `OWN_TEAM` are resolved from the live session
    (§2.17's own enforcement rule); `OWN_RUN` is the same idea one level
    up — the caller's own resolved current run (`services.runs.
    resolve_current_run`), which staff hold too via its installation-wide
    branch, so it is not `ANY` in the staff-bypass sense; `ANY` is staff
    scope proper, where the only possible negative case is a nonexistent
    id, never a cross-tenant one. Daniel's ruling on §2.17 line 398: this
    is a *content* rule ("visibility-filtered serialization") layered on
    top of an access rule that already is one of these three — `OWN_RUN`
    is the access half, and Task 18 generates only that half. Which
    fields get filtered for which caller is Step 3's concern
    (`test_sensitive_fields.py`) and M5's own visibility suite, not this
    file.
    """

    SELF = auto()
    OWN_TEAM = auto()
    OWN_RUN = auto()
    ANY = auto()


@dataclass(frozen=True)
class RouteContext:
    """The ids a route factory may need to address its path or body,
    once `test_generated.py` (Step 2) has built the underlying rows
    through conftest.py's `make_*` factories. Not every field is set for
    every row — only what that row's `Route.build` reads. `scoped_id`
    doubles as the id the generator substitutes with a same-shaped id
    from a *different* team/run to build the object-scope-violation case
    (`scoped_id_field` on `MatrixRow` names which `RouteContext` field
    that is); rows with no addressable object (`self` scope, or a list
    route) leave it `None` and generate no such case. `revision` is the
    one non-id field here: `PATCH /event-definitions/{id}`'s mandatory
    `If-Match` header (api-surface.md §1) needs a value from outside the
    path/body, and adding one optional field is cheaper than a second
    return shape on every other row's `Route.build`.
    """

    team_id: uuid.UUID | None = None
    run_id: uuid.UUID | None = None
    challenge_id: uuid.UUID | None = None
    user_id: uuid.UUID | None = None
    blocked_id: uuid.UUID | None = None
    definition_id: uuid.UUID | None = None
    revision: int | None = None


@dataclass(frozen=True)
class Route:
    """How to address the route once `RouteContext`'s ids exist. `build`
    returns `(path, json_body)` — `json_body` is `None` for a route with
    no request body (a bare `GET`/`DELETE`), a `dict` for every JSON-object
    body, and a `list` for `participants_import`'s bare JSON array
    (`POST /runs/{id}/users/import` accepts one or the other by
    `Content-Type`, api/participants.py; this row always sends the list
    form).
    """

    method: str
    build: Callable[[RouteContext], tuple[str, dict[str, object] | list[object] | None]]


@dataclass(frozen=True)
class MatrixRow:
    """One line of api-surface.md §2.17."""

    name: str
    citation: str
    route: Route
    roles: tuple[Role, ...]
    scope: ObjectScope
    scoped_id_field: str | None
    """Name of the `RouteContext` field the object-scope-violation case
    substitutes (e.g. `"team_id"`), or `None` where no such case exists —
    `scope is ObjectScope.SELF`, or a list route with no target id at all.
    `ObjectScope.ANY` rows may still name one: the negative case there is
    "this id does not exist," not "this id belongs to someone else."
    """
    lifecycle: frozenset[RunStatus | DefinitionStatus] | None
    """`event_run.status` (or, for the definitions rows, `event_
    definition.status`) values the action is accepted in, or `None` for
    §2.17's "any" — no gate at all."""
    audited: bool
    skip_milestone: str | None = None
    """`None` for a row active in M2. Otherwise the milestone that ships
    the route (`"M3"`, `"M5"`, `"M6"`) — `test_generated.py` skips it and
    that milestone's own Task 18-equivalent step unskips rather than
    re-derives (M2-Task-Plan.md Task 18)."""
    lifecycle_refusal_untested: bool = False
    """`PATCH /runs/{id}`'s one true exception: accepted in `{created,
    running, paused, finished}`, refused only at `destroyed` — but no
    route in M2 can ever produce a `destroyed` run (`POST /runs/{id}/
    destroy` is M6), so the refusal half is a claim with no live path
    behind it. Daniel's ruling: bind the accepted half only here; the
    refusal is Backlog's until M6's `destroy` route exists. `True` skips
    this row in the lifecycle-refusal test only — the allowed-role,
    disallowed-role, scope and audit tests still run over it."""


# ---------------------------------------------------------------------------
# Active in M2 — api-surface.md §2.17, lines 378-394.
# ---------------------------------------------------------------------------

MATRIX: list[MatrixRow] = [
    MatrixRow(
        name="teams_rename",
        citation="api-surface.md §2.17 line 378",
        route=Route("PATCH", lambda ctx: (f"/teams/{ctx.team_id}", {"name": "Renamed"})),
        roles=(Role.player, Role.admin, Role.gameadmin),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field="team_id",
        lifecycle=frozenset(
            {RunStatus.created, RunStatus.running, RunStatus.paused, RunStatus.finished}
        ),
        audited=False,
    ),
    MatrixRow(
        name="teams_create",
        citation="api-surface.md §2.17 line 379",
        route=Route(
            "POST",
            lambda ctx: (
                f"/runs/{ctx.run_id}/teams",
                {
                    "name": "New Team",
                    "member_user_ids": [str(ctx.user_id)],
                    "captain_user_id": str(ctx.user_id),
                },
            ),
        ),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=frozenset({RunStatus.created}),
        audited=True,
    ),
    MatrixRow(
        name="teams_set_members",
        citation="api-surface.md §2.17 line 379",
        route=Route(
            "PUT",
            lambda ctx: (
                f"/teams/{ctx.team_id}/members",
                {"member_user_ids": [str(ctx.user_id)]},
            ),
        ),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="team_id",
        lifecycle=frozenset({RunStatus.created}),
        audited=True,
    ),
    MatrixRow(
        name="participants_import",
        citation="api-surface.md §2.17 line 379",
        route=Route(
            "POST",
            lambda ctx: (
                f"/runs/{ctx.run_id}/users/import",
                [{"username": f"import-{uuid.uuid4().hex[:8]}", "name": "Imported"}],
            ),
        ),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=frozenset({RunStatus.created}),
        audited=True,
    ),
    MatrixRow(
        name="participants_create_one",
        citation="api-surface.md §2.17 line 379",
        route=Route(
            "POST",
            lambda ctx: (
                f"/runs/{ctx.run_id}/users",
                {"username": f"single-{uuid.uuid4().hex[:8]}", "name": "Single"},
            ),
        ),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=frozenset({RunStatus.created}),
        audited=True,
    ),
    MatrixRow(
        name="teams_set_captain",
        citation="api-surface.md §2.17 line 380",
        route=Route(
            "PUT",
            lambda ctx: (f"/teams/{ctx.team_id}/captain", {"captain_user_id": str(ctx.user_id)}),
        ),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="team_id",
        lifecycle=frozenset(
            {RunStatus.created, RunStatus.running, RunStatus.paused, RunStatus.finished}
        ),
        audited=True,
    ),
    MatrixRow(
        name="auth_otp_issue",
        citation="api-surface.md §2.17 line 381",
        route=Route("POST", lambda ctx: ("/auth/otp", {"user_id": str(ctx.user_id)})),
        roles=(Role.player, Role.admin, Role.gameadmin),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field="user_id",
        lifecycle=None,
        audited=True,
    ),
    MatrixRow(
        name="me_language",
        citation="api-surface.md §2.17 line 382",
        route=Route("PUT", lambda ctx: ("/me/language", {"preferred_language": "de"})),
        roles=(Role.player, Role.admin, Role.gameadmin),
        scope=ObjectScope.SELF,
        scoped_id_field=None,
        lifecycle=None,
        audited=False,
    ),
    MatrixRow(
        name="challenges_start",
        citation="api-surface.md §2.17 line 387",
        route=Route("POST", lambda ctx: (f"/challenges/{ctx.challenge_id}/start", None)),
        roles=(Role.player,),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field=None,
        # `own team` is resolved from the caller's own current-run
        # participation inside services.challenges.start_challenge — no
        # team id ever appears in this route's path or body, so there is
        # no cross-tenant id to substitute (unlike teams_rename or
        # auth_otp_issue, whose scoped id names a target the caller does
        # not control). Flagged in the Step 1 report rather than assumed.
        lifecycle=frozenset({RunStatus.running}),
        audited=False,
    ),
    MatrixRow(
        name="users_export",
        citation="api-surface.md §2.17 line 390",
        route=Route("GET", lambda ctx: (f"/users/{ctx.user_id}/export", None)),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="user_id",
        lifecycle=None,
        audited=True,
    ),
    MatrixRow(
        name="users_erase",
        citation="api-surface.md §2.17 line 390",
        route=Route("DELETE", lambda ctx: (f"/users/{ctx.user_id}", None)),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="user_id",
        lifecycle=None,
        audited=True,
    ),
    MatrixRow(
        name="security_blocked_addresses_list",
        citation="api-surface.md §2.17 line 391",
        route=Route("GET", lambda ctx: ("/security/blocked-addresses", None)),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field=None,
        lifecycle=None,
        # §2.17's audit column reads "✅ (the release)" — the list read is
        # deliberately not audited; only the DELETE below is.
        audited=False,
    ),
    MatrixRow(
        name="security_blocked_addresses_release",
        citation="api-surface.md §2.17 line 391",
        route=Route("DELETE", lambda ctx: (f"/security/blocked-addresses/{ctx.blocked_id}", None)),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="blocked_id",
        lifecycle=None,
        audited=True,
    ),
    MatrixRow(
        name="runs_preflight",
        citation="api-surface.md §2.17 line 394",
        route=Route("POST", lambda ctx: (f"/runs/{ctx.run_id}/preflight", None)),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=frozenset({RunStatus.created}),
        audited=False,
    ),
    # -----------------------------------------------------------------
    # Definition authoring (§2.17 line 395, "per §2.6 status rules") —
    # decomposed per Daniel's ruling on the Step 1 report. `POST
    # /event-definitions/import` is left out: it needs either a multipart
    # file upload or a real HTTPS fetch, neither of which this generator's
    # JSON-body `Route.build` shape can drive — reported rather than
    # force-fit. `GET .../export-yaml` does not exist yet in M2 (checked
    # against the actual route table, not §2.6's prose) and moves to the
    # M5 skip block below.
    # -----------------------------------------------------------------
    MatrixRow(
        name="definitions_list",
        citation="api-surface.md §2.6 (Definitions table)",
        route=Route("GET", lambda ctx: ("/event-definitions", None)),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field=None,
        lifecycle=None,
        audited=False,
    ),
    MatrixRow(
        name="definitions_create",
        citation="api-surface.md §2.6 (Definitions table)",
        route=Route("POST", lambda ctx: ("/event-definitions", None)),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field=None,
        lifecycle=None,
        audited=False,
    ),
    MatrixRow(
        name="definitions_read",
        citation="api-surface.md §2.6 (Definitions table)",
        route=Route("GET", lambda ctx: (f"/event-definitions/{ctx.definition_id}", None)),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="definition_id",
        lifecycle=None,
        audited=False,
    ),
    MatrixRow(
        name="definitions_patch",
        citation="api-surface.md §2.6 + assistant ruling, Task 18",
        route=Route(
            "PATCH", lambda ctx: (f"/event-definitions/{ctx.definition_id}", {"story": {"en": "x"}})
        ),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="definition_id",
        lifecycle=frozenset({DefinitionStatus.draft, DefinitionStatus.published}),
        audited=False,
    ),
    MatrixRow(
        name="definitions_publish",
        citation="api-surface.md §2.6 line 19",
        route=Route("POST", lambda ctx: (f"/event-definitions/{ctx.definition_id}/publish", None)),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="definition_id",
        lifecycle=frozenset({DefinitionStatus.draft}),
        audited=True,
    ),
    MatrixRow(
        name="definitions_unpublish",
        citation="api-surface.md §2.6 line 19",
        route=Route(
            "POST", lambda ctx: (f"/event-definitions/{ctx.definition_id}/unpublish", None)
        ),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="definition_id",
        lifecycle=frozenset({DefinitionStatus.published}),
        audited=True,
    ),
    MatrixRow(
        name="definitions_archive",
        citation="api-surface.md §2.6 line 19",
        route=Route("POST", lambda ctx: (f"/event-definitions/{ctx.definition_id}/archive", None)),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="definition_id",
        lifecycle=frozenset({DefinitionStatus.draft, DefinitionStatus.published}),
        audited=True,
    ),
    MatrixRow(
        name="definitions_unarchive",
        citation="api-surface.md §2.6 line 20",
        route=Route(
            "POST", lambda ctx: (f"/event-definitions/{ctx.definition_id}/unarchive", None)
        ),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="definition_id",
        lifecycle=frozenset({DefinitionStatus.archived}),
        audited=True,
    ),
    MatrixRow(
        name="definitions_clone",
        citation="api-surface.md §2.6 (Definitions table)",
        route=Route("POST", lambda ctx: (f"/event-definitions/{ctx.definition_id}/clone", None)),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="definition_id",
        lifecycle=None,
        audited=False,
    ),
    MatrixRow(
        name="definitions_dry_run",
        citation="api-surface.md §2.6 line 23",
        route=Route("POST", lambda ctx: (f"/event-definitions/{ctx.definition_id}/dry-run", None)),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="definition_id",
        # §2.6 line 23: static validation only, writes nothing, reports
        # errors at 200 rather than refusing — no status condition, and
        # inventing one would be exactly the fixture-resolution Daniel's
        # ruling names as wrong.
        lifecycle=None,
        audited=False,
    ),
    # -----------------------------------------------------------------
    # Run lifecycle (§2.17 line 396, "per run status") — the M2-active
    # sub-actions of POST /runs/{id}/transition, per Daniel's ruling.
    # `start`'s "no current successful preflight" 409 is a precondition,
    # not a status gate, and is not what the lifecycle test below drives.
    # keep/legal-hold/destroy/export stay in the M6 skip block.
    # -----------------------------------------------------------------
    MatrixRow(
        name="runs_start",
        citation="api-surface.md §2.6 line 32",
        route=Route("POST", lambda ctx: (f"/runs/{ctx.run_id}/transition", {"action": "start"})),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=frozenset({RunStatus.created}),
        audited=True,
    ),
    MatrixRow(
        name="runs_pause",
        citation="api-surface.md §2.6 line 32",
        route=Route("POST", lambda ctx: (f"/runs/{ctx.run_id}/transition", {"action": "pause"})),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=frozenset({RunStatus.running}),
        audited=True,
    ),
    MatrixRow(
        name="runs_resume",
        citation="api-surface.md §2.6 line 32",
        route=Route("POST", lambda ctx: (f"/runs/{ctx.run_id}/transition", {"action": "resume"})),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=frozenset({RunStatus.paused}),
        audited=True,
    ),
    MatrixRow(
        name="runs_finish",
        citation="api-surface.md §2.6 line 32",
        route=Route("POST", lambda ctx: (f"/runs/{ctx.run_id}/transition", {"action": "finish"})),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=frozenset({RunStatus.running, RunStatus.paused}),
        audited=True,
    ),
    MatrixRow(
        name="runs_patch",
        citation="api-surface.md §2.17 line 397",
        route=Route("PATCH", lambda ctx: (f"/runs/{ctx.run_id}", {"otp_lifetime_minutes": 10})),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=frozenset(
            {RunStatus.created, RunStatus.running, RunStatus.paused, RunStatus.finished}
        ),
        audited=True,
        lifecycle_refusal_untested=True,
    ),
    # -----------------------------------------------------------------
    # §2.17 line 398 split per Daniel's ruling: the two visibility-
    # filtered reads with no path id are `roles=all`/no scope case;
    # `GET /challenges/{id}` carries a real one, already implemented
    # (`api/challenges.py::_get_challenge_for_run`). `GET /leaderboard`
    # is M5 (Implementation-Plan.md §M5), in the skip block below.
    # -----------------------------------------------------------------
    MatrixRow(
        name="event_read",
        citation="api-surface.md §2.17 line 398 (§2.6)",
        route=Route("GET", lambda ctx: ("/event", None)),
        roles=(Role.admin, Role.gameadmin, Role.player),
        scope=ObjectScope.OWN_RUN,
        scoped_id_field=None,
        lifecycle=None,
        audited=False,
    ),
    MatrixRow(
        name="challenges_list",
        citation="api-surface.md §2.17 line 398 (§2.7)",
        route=Route("GET", lambda ctx: ("/challenges", None)),
        roles=(Role.admin, Role.gameadmin, Role.player),
        scope=ObjectScope.OWN_RUN,
        scoped_id_field=None,
        lifecycle=None,
        audited=False,
    ),
    MatrixRow(
        name="challenges_read",
        citation="api-surface.md §2.17 line 398 (§2.7)",
        route=Route("GET", lambda ctx: (f"/challenges/{ctx.challenge_id}", None)),
        roles=(Role.admin, Role.gameadmin, Role.player),
        scope=ObjectScope.OWN_RUN,
        scoped_id_field="challenge_id",
        lifecycle=None,
        audited=False,
    ),
    # -----------------------------------------------------------------
    # M3+ — present and skipped, per §2.17's own milestone assignments
    # cross-checked against Implementation-Plan.md's per-milestone
    # checklists (M2-Task-Plan.md Task 18: "marked with their milestone
    # and skipped, so the file is already the complete matrix and later
    # milestones unskip rather than re-derive").
    # -----------------------------------------------------------------
    MatrixRow(
        name="rewards_read",
        citation="api-surface.md §2.17 line 386 (§2.7)",
        route=Route("GET", lambda ctx: ("/me/team/rewards", None)),
        roles=(Role.player,),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field=None,
        lifecycle=frozenset({RunStatus.running, RunStatus.paused}),
        audited=False,
        skip_milestone="M3",  # Implementation-Plan.md §M3, "team loot read path"
    ),
    MatrixRow(
        name="challenges_flag",
        citation="api-surface.md §2.17 line 388 (§2.7)",
        route=Route(
            "POST", lambda ctx: (f"/challenges/{ctx.challenge_id}/flag", {"flag": "placeholder"})
        ),
        roles=(Role.player,),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field=None,
        lifecycle=frozenset({RunStatus.running}),
        audited=True,
        skip_milestone="M3",  # Implementation-Plan.md §M3
    ),
    MatrixRow(
        name="tickets_list",
        citation="api-surface.md §2.17 line 383 (§2.10)",
        route=Route("GET", lambda ctx: ("/tickets", None)),
        roles=(Role.player, Role.admin, Role.gameadmin),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field=None,
        lifecycle=None,
        audited=False,
        skip_milestone="M5",  # Implementation-Plan.md §M5 item 1, "support tickets"
    ),
    MatrixRow(
        name="tickets_create",
        citation="api-surface.md §2.17 line 383 (§2.10)",
        route=Route("POST", lambda ctx: ("/tickets", {"subject": "Help", "body": "..."})),
        roles=(Role.player,),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field=None,
        lifecycle=None,
        audited=False,
        skip_milestone="M5",
    ),
    MatrixRow(
        name="tickets_messages_list",
        citation="api-surface.md §2.17 line 383 (§2.10)",
        route=Route("GET", lambda ctx: (f"/tickets/{ctx.team_id}/messages", None)),
        roles=(Role.player, Role.admin, Role.gameadmin),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field="team_id",
        lifecycle=None,
        audited=False,
        skip_milestone="M5",
    ),
    MatrixRow(
        name="tickets_messages_post",
        citation="api-surface.md §2.17 line 383 (§2.10)",
        route=Route("POST", lambda ctx: (f"/tickets/{ctx.team_id}/messages", {"body": "reply"})),
        roles=(Role.player, Role.admin, Role.gameadmin),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field="team_id",
        lifecycle=None,
        audited=False,
        skip_milestone="M5",
    ),
    MatrixRow(
        name="chat_messages",
        citation="api-surface.md §2.17 line 384 (§2.10)",
        route=Route("GET", lambda ctx: ("/chat/messages", None)),
        roles=(Role.player,),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field=None,
        lifecycle=None,
        audited=False,
        # §2.17's own line also names "chat over `/ws`" — `GET /ws` is
        # §1's one non-REST surface (a WebSocket handshake, not a status
        # code) and does not fit this generator's request/response shape
        # at all; it needs its own assertion vocabulary, which is M5's to
        # design alongside the WS layer itself, not this row's to guess.
        skip_milestone="M5",  # Implementation-Plan.md §M5 item 1, WebSocket layer
    ),
    MatrixRow(
        name="gamemaster_threads_read",
        citation="api-surface.md §2.17 line 385 (§2.11)",
        route=Route("GET", lambda ctx: (f"/gamemaster/threads/{ctx.challenge_id}", None)),
        roles=(Role.player,),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field=None,
        # §2.17: "running/paused (send...); history readable after" — send
        # and read genuinely differ (below), history stays readable once
        # `finished` too; left `None` ("any") is an over-approximation for
        # the read half specifically, flagged rather than asserted.
        lifecycle=None,
        audited=False,
        skip_milestone="M5",  # Implementation-Plan.md §M5 item 2, AI gamemaster
    ),
    MatrixRow(
        name="gamemaster_threads_send",
        citation="api-surface.md §2.17 line 385 (§2.11)",
        route=Route(
            "POST",
            lambda ctx: (f"/gamemaster/threads/{ctx.challenge_id}/messages", {"body": "hint?"}),
        ),
        roles=(Role.player,),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field=None,
        lifecycle=frozenset({RunStatus.running, RunStatus.paused}),
        audited=False,
        skip_milestone="M5",
    ),
    MatrixRow(
        name="ratings_submit",
        citation="api-surface.md §2.17 line 389 (§2.13)",
        route=Route("POST", lambda ctx: ("/ratings", {"minigame_id": "demo", "stars": 5})),
        roles=(Role.player,),
        scope=ObjectScope.OWN_TEAM,
        scoped_id_field=None,
        lifecycle=frozenset({RunStatus.finished}),
        audited=False,
        skip_milestone="M5",  # Implementation-Plan.md §M5 item 9, captain rating
    ),
    MatrixRow(
        name="challenges_force_solve",
        citation="api-surface.md §2.17 line 392 (§2.7)",
        route=Route(
            "POST",
            lambda ctx: (
                f"/challenges/{ctx.challenge_id}/teams/{ctx.team_id}/solve",
                {"reason": "broken minigame"},
            ),
        ),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="team_id",
        lifecycle=frozenset({RunStatus.running, RunStatus.paused}),
        audited=True,
        skip_milestone="M5",  # Implementation-Plan.md §M5, force-solve/cancel/adjustments
    ),
    MatrixRow(
        name="challenges_cancel",
        citation="api-surface.md §2.17 line 392 (§2.7)",
        route=Route(
            "POST",
            lambda ctx: (
                f"/challenges/{ctx.challenge_id}/teams/{ctx.team_id}/cancel",
                {"reason": "broken minigame"},
            ),
        ),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="team_id",
        lifecycle=frozenset({RunStatus.running, RunStatus.paused}),
        audited=True,
        skip_milestone="M5",
    ),
    MatrixRow(
        name="score_adjustments_create",
        citation="api-surface.md §2.17 line 392 (§2.12)",
        route=Route(
            "POST",
            lambda ctx: (
                f"/teams/{ctx.team_id}/score-adjustments",
                {"points_delta": 5, "reason": "correction"},
            ),
        ),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="team_id",
        lifecycle=frozenset({RunStatus.running, RunStatus.paused}),
        audited=True,
        skip_milestone="M5",
    ),
    MatrixRow(
        name="score_adjustments_list",
        citation="api-surface.md §2.17 line 392 (§2.12)",
        route=Route("GET", lambda ctx: (f"/teams/{ctx.team_id}/score-adjustments", None)),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="team_id",
        lifecycle=frozenset({RunStatus.running, RunStatus.paused}),
        audited=False,
        skip_milestone="M5",
    ),
    MatrixRow(
        name="minigames_port_override",
        citation="api-surface.md §2.17 line 393 (§2.8)",
        route=Route(
            "POST",
            lambda ctx: (
                "/minigames/demo/ports/22/override",
                {"host_port": 9100, "reason": "port conflict"},
            ),
        ),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field=None,
        lifecycle=frozenset({RunStatus.created}),
        audited=True,
        skip_milestone="M3",  # Implementation-Plan.md §M3, port/resources overrides
    ),
    MatrixRow(
        name="minigames_resources_override",
        citation="api-surface.md §2.17 line 393 (§2.8)",
        route=Route(
            "POST",
            lambda ctx: (
                "/minigames/demo/resources-override",
                {"pids": 512, "reason": "solo run sizing"},
            ),
        ),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field=None,
        lifecycle=frozenset({RunStatus.created}),
        audited=True,
        skip_milestone="M3",
    ),
    # `lifecycle=None` on the four rows below is a placeholder, not a
    # reading of "any" — none of §2.6's prose for `keep`/`legal-hold`/
    # `destroy`/`export` states an explicit status gate the way `start`'s
    # or `pause`'s does, and M6 (ADR-0019) is where that gets resolved
    # against the implementation. Present now so M6's own Task 18-
    # equivalent does not have to rediscover these four routes or their
    # roles/audit column from §2.17 again; the gate itself is theirs to
    # fill in, same as this task is filling in M2's.
    MatrixRow(
        name="runs_keep",
        citation="api-surface.md §2.17 line 396 (§2.6)",
        route=Route("POST", lambda ctx: (f"/runs/{ctx.run_id}/keep", None)),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=None,  # TBD — M6
        audited=True,
        skip_milestone="M6",  # Implementation-Plan.md §M6, GDPR grace-period timer
    ),
    MatrixRow(
        name="runs_legal_hold",
        citation="api-surface.md §2.17 line 396 (§2.6)",
        route=Route(
            "POST", lambda ctx: (f"/runs/{ctx.run_id}/legal-hold", {"reason": "pending inquiry"})
        ),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=None,  # TBD — M6
        audited=True,
        skip_milestone="M6",
    ),
    MatrixRow(
        name="runs_destroy",
        citation="api-surface.md §2.17 line 396 (§2.6)",
        route=Route("POST", lambda ctx: (f"/runs/{ctx.run_id}/destroy", {"export": True})),
        roles=(Role.admin,),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        lifecycle=None,  # TBD — M6
        audited=True,
        skip_milestone="M6",
    ),
    MatrixRow(
        name="runs_export",
        citation="api-surface.md §2.6 line 37",
        route=Route("GET", lambda ctx: (f"/runs/{ctx.run_id}/export", None)),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="run_id",
        # The one row in this group where "any" is stated, not a
        # placeholder: §2.6 line 37 says outright that this route is
        # "still served after the run is `destroyed`" — the opposite
        # gate from `PATCH /runs/{id}`'s "until destroyed" next door.
        lifecycle=None,
        audited=False,
        skip_milestone="M6",
    ),
    MatrixRow(
        name="definitions_export_yaml",
        citation="api-surface.md §2.6 (Definitions table)",
        route=Route(
            "GET", lambda ctx: (f"/event-definitions/{ctx.definition_id}/export-yaml", None)
        ),
        roles=(Role.admin, Role.gameadmin),
        scope=ObjectScope.ANY,
        scoped_id_field="definition_id",
        lifecycle=None,
        audited=False,
        # §2.6: "M5 editor roundtrip" — not implemented, checked against the route table
        skip_milestone="M5",
    ),
    MatrixRow(
        name="leaderboard_read",
        citation="api-surface.md §2.17 line 398 (§2.12)",
        route=Route("GET", lambda ctx: ("/leaderboard", None)),
        roles=(Role.admin, Role.gameadmin, Role.player),
        scope=ObjectScope.OWN_RUN,
        scoped_id_field=None,
        lifecycle=None,
        audited=False,
        skip_milestone="M5",  # Implementation-Plan.md §M5, "leaderboard live"
    ),
]
