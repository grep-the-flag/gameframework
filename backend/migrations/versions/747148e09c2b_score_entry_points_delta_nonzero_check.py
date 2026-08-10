"""score_entry_points_delta_nonzero_check

Revision ID: 747148e09c2b
Revises: 522fa1f6d4a1
Create Date: 2026-08-10 21:42:41.609619

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "747148e09c2b"
down_revision: str | None = "522fa1f6d4a1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_score_entry_points_delta_nonzero", "score_entry", "points_delta != 0"
    )


def downgrade() -> None:
    op.drop_constraint("ck_score_entry_points_delta_nonzero", "score_entry", type_="check")
