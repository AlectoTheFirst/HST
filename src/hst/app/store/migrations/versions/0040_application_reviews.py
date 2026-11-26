"""application_reviews: the review flags of the Business Applications

A row is one flag of one application. `state` is `open` or `closed`. An
application has at most 1 open flag (`uq_application_reviews_open`).
`opened_by` is NULL for a flag that a saved revision opened. `revision` is the
newest revision of the application when the flag opened. `application_id`
holds the id of an `application` record of `assessment_records`. It has no
foreign key.
`opened_by` and `closed_by` are ON DELETE SET NULL.

Revision ID: 0040
Revises: 0039
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None

TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "application_reviews",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("application_id", sa.Text, nullable=False),
        sa.Column("state", sa.Text, nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("opened_at", TS, nullable=False),
        sa.Column("opened_by", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("closed_at", TS, nullable=True),
        sa.Column("closed_by", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.CheckConstraint("state IN ('open', 'closed')", name="ck_application_reviews_state"),
        sa.CheckConstraint("revision > 0", name="ck_application_reviews_revision"),
    )
    op.create_index("ix_application_reviews_opened", "application_reviews", ["application_id", "opened_at"])
    op.create_index(
        "uq_application_reviews_open",
        "application_reviews",
        ["application_id"],
        unique=True,
        postgresql_where=sa.text("state = 'open'"),
    )


def downgrade() -> None:
    op.drop_index("uq_application_reviews_open", table_name="application_reviews")
    op.drop_index("ix_application_reviews_opened", table_name="application_reviews")
    op.drop_table("application_reviews")
