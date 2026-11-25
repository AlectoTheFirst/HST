"""runs.snapshot_key: the snapshot a run published

`finish_run` writes `snapshot_key` from the `collection_ts` that the collection
published. A cycle, a run of one source and a device run set it. The key is
NULL for a run that published nothing. The reasoner trigger, a run that failed
before the switchover and a device run that found nothing parked publish
nothing.

The column is text, as the id that `/api/snapshots` reports for the same value.

The migration writes no key to the existing rows.

Revision ID: 0015
Revises: 0014
"""

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("snapshot_key", sa.Text, nullable=True))


def downgrade() -> None:
    op.drop_column("runs", "snapshot_key")
