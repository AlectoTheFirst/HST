"""ai_events, ai_prompt_versions, cypher_events.origin and cypher_events.ai_step_id

`ai_events` holds the metadata of the AI surfaces. It has one row per turn
event, provider round or tool call, with the provider, the requested model, the
served model, the token counts, the latency and an outcome. It holds no
question, answer, argument or result text. `user_id` is ON DELETE SET NULL, as
in `cypher_events`. The conversation, message and step ids have no foreign key,
and an event stays when its conversation is purged.

`ai_prompt_versions` stores the static prompt text once per hash. A stored
prompt hash identifies the prompt text of an answer.

`cypher_events.origin` is the surface that ran a query (`web`, `mcp`, `rest`).
`cypher_events.ai_step_id` is the tool call that ran it. Both are nullable, and
the migration fills neither.

Revision ID: 0032
Revises: 0031
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_prompt_versions",
        sa.Column("hash", sa.Text, primary_key=True),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    )
    op.create_table(
        "ai_events",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("origin", sa.Text, nullable=False),
        sa.Column("surface", sa.Text, nullable=True),
        sa.Column("event", sa.Text, nullable=False),
        sa.Column("conversation_id", UUID(as_uuid=False), nullable=True),
        sa.Column("message_id", UUID(as_uuid=False), nullable=True),
        sa.Column("step_id", UUID(as_uuid=False), nullable=True),
        sa.Column("provider", sa.Text, nullable=True),
        sa.Column("model_requested", sa.Text, nullable=True),
        sa.Column("model_served", sa.Text, nullable=True),
        sa.Column("prompt_hash", sa.Text, nullable=True),
        sa.Column("tool", sa.Text, nullable=True),
        sa.Column("tool_version", sa.Integer, nullable=True),
        sa.Column("snapshot", sa.Text, nullable=True),
        sa.Column("latency_ms", sa.Integer, nullable=True),
        sa.Column("tokens_in", sa.Integer, nullable=True),
        sa.Column("tokens_out", sa.Integer, nullable=True),
        sa.Column("outcome", sa.Text, nullable=False),
        sa.Column("error_class", sa.Text, nullable=True),
        sa.Column("detail", JSONB, nullable=True),
    )
    op.create_index("ix_ai_events_at", "ai_events", ["at"])
    op.create_index("ix_ai_events_user_at", "ai_events", ["user_id", "at"])
    op.add_column("cypher_events", sa.Column("origin", sa.Text, nullable=True))
    op.add_column("cypher_events", sa.Column("ai_step_id", UUID(as_uuid=False), nullable=True))


def downgrade() -> None:
    op.drop_column("cypher_events", "ai_step_id")
    op.drop_column("cypher_events", "origin")
    op.drop_index("ix_ai_events_user_at", table_name="ai_events")
    op.drop_index("ix_ai_events_at", table_name="ai_events")
    op.drop_table("ai_events")
    op.drop_table("ai_prompt_versions")
