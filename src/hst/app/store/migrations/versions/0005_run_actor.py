"""runs.triggered_by: the user who started a collection

A run that no user started has NULL in `triggered_by`.

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("triggered_by", sa.Integer, nullable=True))
    op.create_foreign_key(
        "runs_triggered_by_fkey", "runs", "users", ["triggered_by"], ["id"], ondelete="SET NULL"
    )


def downgrade() -> None:
    op.drop_constraint("runs_triggered_by_fkey", "runs", type_="foreignkey")
    op.drop_column("runs", "triggered_by")
