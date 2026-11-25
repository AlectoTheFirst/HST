"""Locations an orchestrator reports, and the site each is bound to.

Revision ID: 0021
Revises: 0020

An orchestrator manages devices at many sites. It reports the place of each
device as a stable id and a display name. An operator binds the id to a Site. A
device at an unbound location is unplaced and gets no LOCATED_IN edge.

A location name is not matched to a Site name.
"""

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "target_devices",
        sa.Column("location_id", sa.Text, nullable=False, server_default=""),
    )
    op.create_table(
        "reported_locations",
        sa.Column("source", sa.Text, sa.ForeignKey("sources.name", ondelete="CASCADE"), primary_key=True),
        sa.Column("location_id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False, server_default=""),
        sa.Column("site", sa.Text, sa.ForeignKey("sites.code", ondelete="RESTRICT")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("reported_locations")
    op.drop_column("target_devices", "location_id")
