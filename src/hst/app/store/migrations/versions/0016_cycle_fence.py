"""cycle_fence_seq: the publication fence for the cycle lock

`cycle_lock` excludes 2 holders at one time. A holder whose lock connection
dies keeps running on its worker thread while the next holder writes.

Each acquisition of the lock draws one value of the sequence and passes it to
the graph. The cycle pointer stores the fence of its last move and refuses a
lower one (core/cycle.py `set_pointer`). A later acquisition draws a greater
value in every process.

A pointer without a fence compares below every fence, and the first
publication with a fence overwrites it.

Revision ID: 0016
Revises: 0015
"""

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

SEQUENCE = "cycle_fence_seq"


def upgrade() -> None:
    op.execute(sa.schema.CreateSequence(sa.Sequence(SEQUENCE)))


def downgrade() -> None:
    op.execute(sa.schema.DropSequence(sa.Sequence(SEQUENCE)))
