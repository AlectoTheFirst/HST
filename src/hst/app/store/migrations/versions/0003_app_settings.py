"""app settings (AI agent provider config)

Revision ID: 0003
Revises: 0002

`secrets` is sealed by app/crypto.py.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("key", sa.Text, primary_key=True),
        sa.Column("value", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("secrets", sa.LargeBinary, nullable=False, server_default=sa.text("''::bytea")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("app_settings")
