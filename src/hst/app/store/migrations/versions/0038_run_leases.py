"""run_leases: the graph runs that a reader holds open

A trace pinned to a historical run reads the graph in many statements. The
scheduled prune deletes a run in many commits, under a lock that no reader
takes. A reader takes a lease on the run before its first statement and
releases the lease after its last one. The prune keeps every run with an
unexpired lease. A lease has an expiry, and the lease of a reader that dies
ends at that time.

Revision ID: 0038
Revises: 0037
"""

import sqlalchemy as sa
from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_leases",
        sa.Column("lease_token", sa.String(48), primary_key=True),
        sa.Column("snapshot_key", sa.BigInteger, nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
    )
    op.create_index("ix_run_leases_expiry", "run_leases", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_run_leases_expiry", table_name="run_leases")
    op.drop_table("run_leases")
