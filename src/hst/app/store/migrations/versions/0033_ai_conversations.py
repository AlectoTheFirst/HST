"""ai_conversations, ai_messages, ai_steps and ai_links

The tables are the conversation store of the AI surfaces. A conversation
belongs to one user and is deleted with that user (ON DELETE CASCADE).
Messages, steps and links are deleted with their conversation. An assistant
message also holds the state of its turn in a status, a lease and a cancel
flag. A client polls the id of the assistant message, from any process and
after a restart.

`ai_conversations.step_count` is the last step label issued. A step takes the
next value. A label is unique within a conversation and is not reused after
compaction.

`ai_links.ref_id` holds the id of a row in another table and has no foreign key.
`assessment_records` is keyed by (kind, id, revision) and is insert-only.

Revision ID: 0033
Revises: 0032
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_conversations",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("surface", sa.Text, nullable=False),
        sa.Column("ephemeral", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("title", sa.Text, nullable=False, server_default=""),
        sa.Column("snapshot_id", sa.Text, nullable=True),
        sa.Column("pin_mode", sa.Text, nullable=False, server_default="follow"),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("summary_through", sa.Integer, nullable=False, server_default="0"),
        sa.Column("message_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("step_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_message_at", sa.TIMESTAMP(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_ai_conversations_user_last", "ai_conversations", ["user_id", sa.text("last_message_at DESC")]
    )
    op.create_index("ix_ai_conversations_last", "ai_conversations", ["last_message_at"])
    op.create_table(
        "ai_messages",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "conversation_id",
            UUID(as_uuid=False),
            sa.ForeignKey("ai_conversations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("content", sa.Text, nullable=False, server_default=""),
        sa.Column("context", JSONB, nullable=True),
        sa.Column("envelope", JSONB, nullable=True),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("snapshot_id", sa.Text, nullable=True),
        sa.Column("provider", sa.Text, nullable=True),
        sa.Column("model_requested", sa.Text, nullable=True),
        sa.Column("model_served", sa.Text, nullable=True),
        sa.Column("prompt_hash", sa.Text, sa.ForeignKey("ai_prompt_versions.hash"), nullable=True),
        sa.Column("usage", JSONB, nullable=True),
        sa.Column("lease_owner", sa.Text, nullable=True),
        sa.Column("lease_expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("cancel_requested", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.UniqueConstraint("conversation_id", "seq", name="uq_ai_messages_conversation_seq"),
    )
    op.create_index(
        "ix_ai_messages_active",
        "ai_messages",
        ["status"],
        postgresql_where=sa.text("status IN ('pending', 'running')"),
    )
    op.create_table(
        "ai_steps",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "conversation_id",
            UUID(as_uuid=False),
            sa.ForeignKey("ai_conversations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "message_id",
            UUID(as_uuid=False),
            sa.ForeignKey("ai_messages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("label", sa.Integer, nullable=False),
        sa.Column("tool", sa.Text, nullable=False),
        sa.Column("tool_version", sa.Integer, nullable=False),
        sa.Column("arguments", JSONB, nullable=False),
        sa.Column("is_error", sa.Boolean, nullable=False),
        sa.Column("result", sa.Text, nullable=True),
        sa.Column("result_sha256", sa.Text, nullable=False),
        sa.Column("result_chars", sa.Integer, nullable=False),
        sa.Column("result_summary", sa.Text, nullable=True),
        sa.Column("provenance", JSONB, nullable=True),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("elapsed_ms", sa.Integer, nullable=False),
        sa.Column("compacted_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.UniqueConstraint("conversation_id", "label", name="uq_ai_steps_conversation_label"),
    )
    op.create_index("ix_ai_steps_message", "ai_steps", ["message_id"])
    op.create_table(
        "ai_links",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "conversation_id",
            UUID(as_uuid=False),
            sa.ForeignKey("ai_conversations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "message_id",
            UUID(as_uuid=False),
            sa.ForeignKey("ai_messages.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "step_id",
            UUID(as_uuid=False),
            sa.ForeignKey("ai_steps.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("ref_id", sa.Text, nullable=False),
        sa.Column("ref_revision", sa.Integer, nullable=True),
        sa.Column("direction", sa.Text, nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    )
    op.create_index("ix_ai_links_ref", "ai_links", ["kind", "ref_id"])


def downgrade() -> None:
    op.drop_index("ix_ai_links_ref", table_name="ai_links")
    op.drop_table("ai_links")
    op.drop_index("ix_ai_steps_message", table_name="ai_steps")
    op.drop_table("ai_steps")
    op.drop_index("ix_ai_messages_active", table_name="ai_messages")
    op.drop_table("ai_messages")
    op.drop_index("ix_ai_conversations_last", table_name="ai_conversations")
    op.drop_index("ix_ai_conversations_user_last", table_name="ai_conversations")
    op.drop_table("ai_conversations")
