"""sites and device assignment

Revision ID: 0004
Revises: 0003

`site_members.device_uid` is the uid of a device in Neo4j.
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sites",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("code", sa.Text, nullable=False, unique=True),
        sa.Column("name", sa.Text, nullable=False, server_default=""),
        sa.Column("location", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_table(
        "site_members",
        # The primary key gives a device one site.
        sa.Column("device_uid", sa.Text, primary_key=True),
        sa.Column("site_id", sa.Integer, sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "assigned_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
    )
    op.create_index("ix_site_members_site", "site_members", ["site_id"])


def downgrade() -> None:
    op.drop_index("ix_site_members_site", table_name="site_members")
    op.drop_table("site_members")
    op.drop_table("sites")
