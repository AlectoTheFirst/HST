"""Device groups. A device belongs to at most one group."""

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
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


def downgrade() -> None:
    op.drop_table("device_group_members")
    op.drop_table("device_groups")
