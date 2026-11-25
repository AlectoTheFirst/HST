"""Drop the standalone device groups.

Revision ID: 0020
Revises: 0019

A source row of a group-kind collector is the group (collectors/base.py
`Collector.KIND`), and `site_members` is the one per-device assignment.

The migration drops the membership rows and writes none of them to
`site_members`.
"""

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("device_group_members")
    op.drop_table("device_groups")


def downgrade() -> None:
    # The downgrade creates the tables empty.
    op.create_table(
        "device_groups",
        sa.Column("name", sa.Text, primary_key=True),
        sa.Column("site", sa.Text, sa.ForeignKey("sites.code", ondelete="RESTRICT")),
    )
    op.create_table(
        "device_group_members",
        sa.Column("device_uid", sa.Text, primary_key=True),
        sa.Column(
            "group_name", sa.Text, sa.ForeignKey("device_groups.name", ondelete="CASCADE"), nullable=False
        ),
    )
