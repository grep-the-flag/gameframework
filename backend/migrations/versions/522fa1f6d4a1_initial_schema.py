"""initial_schema

Revision ID: 522fa1f6d4a1
Revises:
Create Date: 2026-08-10 17:37:04.879741

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "522fa1f6d4a1"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Every PostgreSQL enum type is managed explicitly (create_type=False on each
# column use below) so that downgrade leaves nothing behind: dropping a table
# does not drop the enum types its columns referenced. postgresql.ENUM (not
# the generic sa.Enum) is required here — create_type=False on a generic
# sa.Enum is not honored by op.create_table's DDL compilation.
event_definition_status = postgresql.ENUM(
    "draft", "published", "archived", name="event_definition_status", create_type=False
)
unlock_mode = postgresql.ENUM("manual", "guided", name="unlock_mode", create_type=False)
scoring_mode = postgresql.ENUM("casual", "challenge", name="scoring_mode", create_type=False)
participation_mode = postgresql.ENUM("teams", "solo", name="participation_mode", create_type=False)
installed_artifact_type = postgresql.ENUM(
    "minigame", "event", "theme", "language", name="installed_artifact_type", create_type=False
)
job_state = postgresql.ENUM(
    "pending", "leased", "succeeded", "failed", "dead", name="job_state", create_type=False
)
user_role = postgresql.ENUM("admin", "gameadmin", "player", name="user_role", create_type=False)
event_run_status = postgresql.ENUM(
    "created",
    "running",
    "paused",
    "finished",
    "destroyed",
    name="event_run_status",
    create_type=False,
)
event_run_export_state = postgresql.ENUM(
    "pending",
    "succeeded",
    "failed_retrying",
    "skipped",
    name="event_run_export_state",
    create_type=False,
)
audit_log_scope = postgresql.ENUM(
    "participant", "installation", name="audit_log_scope", create_type=False
)
challenge_dependency_source = postgresql.ENUM(
    "explicit", "reward", name="challenge_dependency_source", create_type=False
)
minigame_instance_solve_mode = postgresql.ENUM(
    "flag", "callback", name="minigame_instance_solve_mode", create_type=False
)
minigame_instance_health = postgresql.ENUM(
    "unknown", "healthy", "unhealthy", name="minigame_instance_health", create_type=False
)
reward_definition_type = postgresql.ENUM(
    "ssh_keypair", "password", "token", "ssl_cert", name="reward_definition_type", create_type=False
)
minigame_port_source = postgresql.ENUM(
    "allocated", "override", name="minigame_port_source", create_type=False
)
score_entry_type = postgresql.ENUM(
    "challenge_award",
    "hint_charge",
    "hint_refund",
    "admin_adjustment",
    "penalty",
    name="score_entry_type",
    create_type=False,
)
score_entry_source = postgresql.ENUM(
    "system", "admin", name="score_entry_source", create_type=False
)
team_challenge_state = postgresql.ENUM(
    "locked",
    "startable",
    "provisioning",
    "active",
    "solved",
    "provision_failed",
    name="team_challenge_state",
    create_type=False,
)
ticket_status = postgresql.ENUM(
    "open", "in_progress", "closed", name="ticket_status", create_type=False
)
ai_message_role = postgresql.ENUM("user", "assistant", name="ai_message_role", create_type=False)

ALL_ENUMS = [
    event_definition_status,
    unlock_mode,
    scoring_mode,
    participation_mode,
    installed_artifact_type,
    job_state,
    user_role,
    event_run_status,
    event_run_export_state,
    audit_log_scope,
    challenge_dependency_source,
    minigame_instance_solve_mode,
    minigame_instance_health,
    reward_definition_type,
    minigame_port_source,
    score_entry_type,
    score_entry_source,
    team_challenge_state,
    ticket_status,
    ai_message_role,
]


def upgrade() -> None:
    bind = op.get_bind()
    for enum_type in ALL_ENUMS:
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "event_definition",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("source_version", sa.String(), nullable=False),
        sa.Column("name", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("story", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", event_definition_status, nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("unlock_mode", unlock_mode, nullable=False),
        sa.Column("scoring_mode", scoring_mode, nullable=False),
        sa.Column("participation_mode", participation_mode, server_default="teams", nullable=False),
        sa.Column("grace_period_days", sa.Integer(), server_default="7", nullable=False),
        sa.Column("theme_ref", sa.String(), nullable=True),
        sa.Column("language_default", sa.String(), nullable=False),
        sa.Column("contract_version", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("gamemaster_enabled", sa.Boolean(), nullable=False),
        sa.Column("privacy_notice_md", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "installed_artifact",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("type", installed_artifact_type, nullable=False),
        sa.Column("artifact_id", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False),
        sa.Column("manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("image_digest", sa.String(), nullable=True),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column(
            "installed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("type", "artifact_id", "version"),
    )
    op.create_table(
        "job",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_type", sa.String(), nullable=False),
        sa.Column("business_key", sa.String(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("state", job_state, nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_owner", sa.String(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_job_business_key_non_terminal",
        "job",
        ["job_type", "business_key"],
        unique=True,
        postgresql_where=sa.text("state IN ('pending', 'leased')"),
    )
    op.create_table(
        "outbox_event",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("topic", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "user",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("display_name", sa.String(), nullable=True),
        sa.Column("email", sa.String(), nullable=True),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("role", user_role, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("otp_hash", sa.String(), nullable=True),
        sa.Column("otp_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("otp_consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("preferred_language", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "blocked_address",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("address", postgresql.INET(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["released_by_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("address"),
    )
    op.create_table(
        "challenge",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_definition_id", sa.Uuid(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("order_num", sa.Integer(), nullable=False),
        sa.Column("title", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("text", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("minigame_id", sa.String(), nullable=False),
        sa.Column("minigame_version_range", sa.String(), nullable=False),
        sa.Column("minigame_version", sa.String(), nullable=False),
        sa.Column("minigame_image_digest", sa.String(), nullable=False),
        sa.Column("minigame_host_label", sa.String(), nullable=False),
        sa.Column("points", sa.Integer(), nullable=False),
        sa.Column("hint_cost", sa.Integer(), nullable=False),
        sa.Column("hint_cap", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["event_definition_id"],
            ["event_definition.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_definition_id", "minigame_host_label"),
        sa.UniqueConstraint("event_definition_id", "order_num"),
        sa.UniqueConstraint("event_definition_id", "slug"),
    )
    op.create_table(
        "event_run",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_definition_id", sa.Uuid(), nullable=False),
        sa.Column("definition_revision", sa.Integer(), nullable=False),
        sa.Column("preflight_passed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("preflight_config_hash", sa.String(), nullable=True),
        sa.Column("status", event_run_status, nullable=False),
        sa.Column("scheduled_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scheduled_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("unlock_mode", unlock_mode, nullable=False),
        sa.Column("scoring_mode", scoring_mode, nullable=False),
        sa.Column("participation_mode", participation_mode, nullable=False),
        sa.Column("theme_ref", sa.String(), nullable=True),
        sa.Column("gamemaster_enabled", sa.Boolean(), nullable=False),
        sa.Column("gamemaster_provider", sa.String(), nullable=True),
        sa.Column("gamemaster_endpoint", sa.String(), nullable=True),
        sa.Column("language_default", sa.String(), nullable=False),
        sa.Column("grace_period_days", sa.Integer(), nullable=False),
        sa.Column("otp_lifetime_minutes", sa.Integer(), server_default="5", nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("grace_deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("export_state", event_run_export_state, nullable=False),
        sa.Column("export_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("hard_deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("legal_hold", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("legal_hold_reason", sa.String(), nullable=True),
        sa.Column("destroyed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["event_definition_id"], ["event_definition.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_event_run_single_active",
        "event_run",
        [sa.literal_column("(true)")],
        unique=True,
        postgresql_where=sa.text("status IN ('running', 'paused')"),
    )
    op.create_table(
        "session",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("restricted", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("scope", audit_log_scope, nullable=False),
        sa.Column("event_run_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target_type", sa.String(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(scope = 'participant') = (event_run_id IS NOT NULL)",
            name="ck_audit_log_scope_event_run",
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["event_run_id"],
            ["event_run.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "challenge_dependency",
        sa.Column("challenge_id", sa.Uuid(), nullable=False),
        sa.Column("depends_on_id", sa.Uuid(), nullable=False),
        sa.Column("source", challenge_dependency_source, nullable=False),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenge.id"],
        ),
        sa.ForeignKeyConstraint(
            ["depends_on_id"],
            ["challenge.id"],
        ),
        sa.PrimaryKeyConstraint("challenge_id", "depends_on_id"),
    )
    op.create_table(
        "minigame_instance",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_run_id", sa.Uuid(), nullable=False),
        sa.Column("minigame_id", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=True),
        sa.Column("solve_mode", minigame_instance_solve_mode, nullable=False),
        sa.Column("image_ref", sa.String(), nullable=False),
        sa.Column("image_digest", sa.String(), nullable=False),
        sa.Column("resources_override", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("container_ref", sa.String(), nullable=True),
        sa.Column("health", minigame_instance_health, nullable=False),
        sa.Column("last_health_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["event_run_id"],
            ["event_run.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_run_id", "hostname"),
        sa.UniqueConstraint("event_run_id", "minigame_id"),
    )
    op.create_table(
        "reward_definition",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("producer_challenge_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("type", reward_definition_type, nullable=False),
        sa.ForeignKeyConstraint(
            ["producer_challenge_id"],
            ["challenge.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "team",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_run_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("handle", sa.String(), nullable=False),
        sa.Column("captain_user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["captain_user_id"],
            ["user.id"],
        ),
        sa.ForeignKeyConstraint(
            ["event_run_id"],
            ["event_run.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_run_id", "handle"),
        sa.UniqueConstraint("id", "event_run_id", name="uq_team_id_event_run_id"),
    )
    op.create_table(
        "ai_conversation",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenge.id"],
        ),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["team.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("team_id", "challenge_id"),
    )
    op.create_table(
        "chat_message",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("author_user_id", sa.Uuid(), nullable=True),
        sa.Column("body", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["author_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["team.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "event_participation",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("event_run_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=True),
        sa.Column("handle", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["event_run_id"],
            ["event_run.id"],
        ),
        sa.ForeignKeyConstraint(
            ["team_id", "event_run_id"],
            ["team.id", "team.event_run_id"],
            name="fk_event_participation_team",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_run_id", "handle"),
        sa.UniqueConstraint("user_id", "event_run_id"),
    )
    op.create_table(
        "minigame_port",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("minigame_instance_id", sa.Uuid(), nullable=False),
        sa.Column("container_port", sa.Integer(), nullable=False),
        sa.Column("host_port", sa.Integer(), nullable=False),
        sa.Column("source", minigame_port_source, nullable=False),
        sa.Column("override_reason", sa.String(), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(source = 'override') = (override_reason IS NOT NULL)",
            name="ck_minigame_port_override_reason",
        ),
        sa.CheckConstraint(
            "container_port BETWEEN 1 AND 65535", name="ck_minigame_port_container_port_range"
        ),
        sa.CheckConstraint(
            "host_port BETWEEN 1 AND 65535", name="ck_minigame_port_host_port_range"
        ),
        sa.ForeignKeyConstraint(
            ["minigame_instance_id"], ["minigame_instance.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("minigame_instance_id", "container_port"),
    )
    op.create_index(
        "uq_minigame_port_live_host_port",
        "minigame_port",
        ["host_port"],
        unique=True,
        postgresql_where=sa.text("released_at IS NULL"),
    )
    op.create_table(
        "rating",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_run_id", sa.Uuid(), nullable=False),
        sa.Column("minigame_id", sa.String(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("stars", sa.Integer(), nullable=False),
        sa.Column("comment", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("stars BETWEEN 1 AND 5", name="ck_rating_stars_range"),
        sa.ForeignKeyConstraint(
            ["event_run_id"],
            ["event_run.id"],
        ),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["team.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_run_id", "minigame_id", "team_id"),
    )
    op.create_table(
        "reward_consumption",
        sa.Column("reward_definition_id", sa.Uuid(), nullable=False),
        sa.Column("consumer_challenge_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["consumer_challenge_id"],
            ["challenge.id"],
        ),
        sa.ForeignKeyConstraint(
            ["reward_definition_id"],
            ["reward_definition.id"],
        ),
        sa.PrimaryKeyConstraint("reward_definition_id", "consumer_challenge_id"),
    )
    op.create_table(
        "score_entry",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_run_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_id", sa.Uuid(), nullable=True),
        sa.Column("entry_type", score_entry_type, nullable=False),
        sa.Column("points_delta", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("source", score_entry_source, nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("idempotency_key", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenge.id"],
        ),
        sa.ForeignKeyConstraint(
            ["event_run_id"],
            ["event_run.id"],
        ),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["team.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    op.create_table(
        "team_challenge",
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_id", sa.Uuid(), nullable=False),
        sa.Column("state", team_challenge_state, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("solved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("solved_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("provision_attempts", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenge.id"],
        ),
        sa.ForeignKeyConstraint(["solved_by_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["team.id"],
        ),
        sa.PrimaryKeyConstraint("team_id", "challenge_id"),
    )
    op.create_index(
        "uq_team_challenge_active_per_team",
        "team_challenge",
        ["team_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('provisioning', 'active')"),
    )
    op.create_table(
        "ticket",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("opened_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("status", ticket_status, nullable=False),
        sa.Column("assigned_to_user_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["assigned_to_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["opened_by_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["team.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "vault_entry",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_run_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("reward_definition_id", sa.Uuid(), nullable=False),
        sa.Column("encrypted_value", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["event_run_id"],
            ["event_run.id"],
        ),
        sa.ForeignKeyConstraint(
            ["reward_definition_id"],
            ["reward_definition.id"],
        ),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["team.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("team_id", "reward_definition_id"),
    )
    op.create_table(
        "ai_message",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("conversation_id", sa.Uuid(), nullable=False),
        sa.Column("role", ai_message_role, nullable=False),
        sa.Column("content", sa.String(), nullable=False),
        sa.Column("hint_cost_charged", sa.Integer(), nullable=False),
        sa.Column("author_user_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["author_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["conversation_id"],
            ["ai_conversation.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ticket_message",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ticket_id", sa.Uuid(), nullable=False),
        sa.Column("author_user_id", sa.Uuid(), nullable=True),
        sa.Column("body", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["author_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["ticket_id"],
            ["ticket.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("ticket_message")
    op.drop_table("ai_message")
    op.drop_table("vault_entry")
    op.drop_table("ticket")
    op.drop_index(
        "uq_team_challenge_active_per_team",
        table_name="team_challenge",
        postgresql_where=sa.text("state IN ('provisioning', 'active')"),
    )
    op.drop_table("team_challenge")
    op.drop_table("score_entry")
    op.drop_table("reward_consumption")
    op.drop_table("rating")
    op.drop_index(
        "uq_minigame_port_live_host_port",
        table_name="minigame_port",
        postgresql_where=sa.text("released_at IS NULL"),
    )
    op.drop_table("minigame_port")
    op.drop_table("event_participation")
    op.drop_table("chat_message")
    op.drop_table("ai_conversation")
    op.drop_table("team")
    op.drop_table("reward_definition")
    op.drop_table("minigame_instance")
    op.drop_table("challenge_dependency")
    op.drop_table("audit_log")
    op.drop_table("session")
    op.drop_index(
        "uq_event_run_single_active",
        table_name="event_run",
        postgresql_where=sa.text("status IN ('running', 'paused')"),
    )
    op.drop_table("event_run")
    op.drop_table("challenge")
    op.drop_table("blocked_address")
    op.drop_table("user")
    op.drop_index(
        "uq_job_business_key_non_terminal",
        table_name="job",
        postgresql_where=sa.text("state IN ('pending', 'leased')"),
    )
    op.drop_table("job")
    op.drop_table("installed_artifact")
    op.drop_table("event_definition")
    op.drop_table("outbox_event")

    bind = op.get_bind()
    for enum_type in ALL_ENUMS:
        enum_type.drop(bind, checkfirst=True)
