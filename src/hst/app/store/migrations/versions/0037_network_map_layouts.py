"""network_map_layouts and network_map_views: the stored layouts and views of the network map

All users share the rows of both tables.

`network_map_layouts` holds, per drawn scope (`site/<code>`), the positions
that a person moved, keyed by device uid. A stored position replaces the
position of the planner for that uid. `network_map_views` holds named views. A
view holds the open site, the line kinds and the camera. Both tables have a
revision, and a write states the revision that it read. `updated_by` and
`owner_id` are ON DELETE SET NULL.

Revision ID: 0037
Revises: 0036
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None

TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "network_map_layouts",
        sa.Column("scope", sa.Text, primary_key=True),
        sa.Column("positions", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("updated_by", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint("revision > 0", name="ck_network_map_layouts_revision"),
    )
    op.create_table(
        "network_map_views",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("state", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("owner_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.UniqueConstraint("name", name="uq_network_map_views_name"),
        sa.CheckConstraint("revision > 0", name="ck_network_map_views_revision"),
    )


def downgrade() -> None:
    op.drop_table("network_map_views")
    op.drop_table("network_map_layouts")
