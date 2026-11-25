"""changes, change_intents: the change entity

A change is a planned operation stated as a list of typed intents against a pinned
snapshot.

`snapshot_cts` is a `collection_ts` from `/api/snapshots`.

`change_intents.kind` is the name of an entry of the change intent catalog.
`params` is the payload of that entry. `position` is the order of display and
evaluation.

Revision ID: 0014
Revises: 0013
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "changes",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("snapshot_cts", sa.BigInteger, nullable=True),
        sa.Column("status", sa.Text, nullable=False, server_default="draft"),
        sa.Column(
            "created_by",
            sa.Integer,
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('draft', 'simulated', 'closed')", name="ck_changes_status"),
    )
    op.create_table(
        "change_intents",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "change_id",
            sa.Integer,
            sa.ForeignKey("changes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("position", sa.Integer, nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("params", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.UniqueConstraint("change_id", "position", name="uq_change_intents_change_position"),
    )
    op.create_index("ix_change_intents_change", "change_intents", ["change_id"])


def downgrade() -> None:
    op.drop_index("ix_change_intents_change", table_name="change_intents")
    op.drop_table("change_intents")
    op.drop_table("changes")
