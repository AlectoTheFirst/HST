"""device_status.last_graph_sha, last_graph_at and last_graph_fetch_at: the graph change key

`last_raw_sha` compares payloads. A Cisco or VyOS payload differs on every
fetch in uptimes, counters, timers and route ages.

`last_graph_sha` holds the digest of the batch that the last normalized payload
of the device produced (`collectors/base.py graph_sha`). It is bound to the
normalization revision and the placement generation, as `last_raw_sha` is. A
payload whose batch has the same digest writes to the graph only the objects
that another source or device also writes. Its raw file and side tables are
written, and its other graph objects come forward from the parent run.
`last_graph_at` is the time at which that batch was last written. The forced
full load (`COLLECT_FULL_INTERVAL_S`) is measured against it.
`last_graph_fetch_at` is the fetch time of the payload whose batch was last
compared with the graph. A device run applies a parked payload only when it
was fetched after that time.

`last_graph_sha` defaults to an empty string and the 2 times to NULL. A device
with an empty digest writes its graph at the next load and records the digest.

Revision ID: 0031
Revises: 0030
"""

import sqlalchemy as sa
from alembic import op

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "device_status",
        sa.Column("last_graph_sha", sa.Text, nullable=False, server_default=""),
    )
    op.add_column(
        "device_status",
        sa.Column("last_graph_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "device_status",
        sa.Column("last_graph_fetch_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("device_status", "last_graph_fetch_at")
    op.drop_column("device_status", "last_graph_at")
    op.drop_column("device_status", "last_graph_sha")
