"""Remove the automatic reassessment flag from saved assessment definitions.

A publication marks an assessment as needing reassessment, and the operator
queues the evaluation. The definition model forbids unknown keys, and the
migration removes `auto_reassess` from every stored definition.

Revision ID: 0026
Revises: 0025
"""

from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "UPDATE assessment_records "
        "SET document = document #- '{definition,auto_reassess}' "
        "WHERE kind = 'assessment' "
        "AND jsonb_exists(document -> 'definition', 'auto_reassess')"
    )


def downgrade() -> None:
    # The downgrade sets the flag to true, its default.
    op.execute(
        "UPDATE assessment_records "
        "SET document = jsonb_set(document, '{definition,auto_reassess}', 'true'::jsonb) "
        "WHERE kind = 'assessment' AND jsonb_exists(document, 'definition')"
    )
