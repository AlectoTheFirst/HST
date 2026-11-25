"""jobs: the queue of the scheduler

The job `maintenance.purge_job_history` deletes the completed rows older than
JOB_HISTORY_RETENTION_DAYS.

Revision ID: 0011
Revises: 0010
"""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "jobs",
        sa.Column("id", sa.Integer, primary_key=True),
        # 'maintenance.prune_graph', 'maintenance.purge_sessions', ...
        sa.Column("kind", sa.Text, nullable=False),
        # A maintenance job has NULL in `source` and `device`. A collection job
        # sets them.
        sa.Column("source", sa.Text, nullable=True),
        sa.Column("device", sa.Text, nullable=True),
        # 'queued' | 'running' | 'ok' | 'error' | 'dead'
        sa.Column("state", sa.Text, nullable=False, server_default="queued"),
        sa.Column("priority", sa.Integer, nullable=False, server_default="0"),
        sa.Column("attempt", sa.Integer, nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer, nullable=False, server_default="1"),
        # `not_before` holds the due time of the schedule or the retry time of the backoff.
        sa.Column("not_before", sa.TIMESTAMP(timezone=True), nullable=False),
        # `lease_expires_at` is the end of the lease of a claim. An executor extends
        # it while it works, and a claim past it is requeued. It is NULL when the
        # row is not running.
        sa.Column("lease_expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("claimed_by", sa.Text, nullable=True),
        sa.Column("enqueued_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        # `detail` is text for an operator and can hold the text of an exception.
        # No unauthenticated caller reads it, and a job body writes no credential
        # to it.
        sa.Column("detail", sa.Text, nullable=True),
        sa.Column("triggered_by", sa.Text, nullable=False, server_default=""),
    )
    op.create_index(
        "one_pending_per_kind",
        "jobs",
        ["kind", sa.text("coalesce(source, '')"), sa.text("coalesce(device, '')")],
        unique=True,
        postgresql_where=sa.text("state IN ('queued', 'running')"),
    )
    op.create_index(
        "jobs_ready",
        "jobs",
        ["priority", "not_before"],
        postgresql_where=sa.text("state = 'queued'"),
    )
    # the history purge deletes by completion age
    op.create_index("ix_jobs_finished_at", "jobs", ["finished_at"])


def downgrade() -> None:
    op.drop_index("ix_jobs_finished_at", table_name="jobs")
    op.drop_index("jobs_ready", table_name="jobs")
    op.drop_index("one_pending_per_kind", table_name="jobs")
    op.drop_table("jobs")
