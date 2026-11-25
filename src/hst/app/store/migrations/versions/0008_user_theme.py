"""users.theme: the UI palette preference of the account

The UI follows the OS when `theme` is NULL.

Revision ID: 0008
Revises: 0007
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("theme", sa.Text, nullable=True))


def downgrade() -> None:
    op.drop_column("users", "theme")
