"""Transactional compiled-analysis artifact index.

Revision ID: 0024
Revises: 0023
"""

import sqlalchemy as sa
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analysis_cache_artifacts",
        sa.Column("cache_key", sa.String(64), primary_key=True),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("encrypted_bytes", sa.BigInteger, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pinned", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.CheckConstraint("encrypted_bytes > 0", name="analysis_cache_positive_bytes"),
        sa.CheckConstraint("lease_count >= 0", name="analysis_cache_nonnegative_leases"),
    )
    op.create_index(
        "analysis_cache_lru", "analysis_cache_artifacts", ["pinned", "lease_count", "accessed_at"]
    )


def downgrade() -> None:
    op.drop_index("analysis_cache_lru", table_name="analysis_cache_artifacts")
    op.drop_table("analysis_cache_artifacts")
