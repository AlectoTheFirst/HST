"""Immutable assessment documents and isolated analysis queue.

Revision ID: 0023
Revises: 0022
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assessment_records",
        sa.Column("kind", sa.Text, primary_key=True),
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("revision", sa.Integer, primary_key=True),
        sa.Column("document", JSONB, nullable=False),
        sa.CheckConstraint("revision > 0", name="assessment_positive_revision"),
    )
    op.create_index("assessment_records_document", "assessment_records", ["document"], postgresql_using="gin")

    op.create_index(
        "assessment_records_queue",
        "assessment_records",
        ["kind", sa.text("(document ->> 'state')"), sa.text("(document ->> 'created_at')")],
    )


def downgrade() -> None:
    op.drop_index("assessment_records_queue", table_name="assessment_records")
    op.drop_index("assessment_records_document", table_name="assessment_records")
    op.drop_table("assessment_records")
