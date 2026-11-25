"""device_identity: the registry of device uids

A device uid is minted one time from the short hostname of the device. The
table keeps the uid under the identifiers that the collectors see. One row is
one identifier. `kind` is `serial` or `ref`, and `value` is the slugged serial
or `<source>:<ref>`. A uid has one row per identifier, and a stack has one row
per member serial.

`hostname` is the hostname at the mint, and `last_hostname` is the hostname
seen last. The identity report compares them. `first_run_id` is the run that
wrote the row. It has no foreign key, and the row stays when the run is
deleted.

The uid index uses text_pattern_ops. The mint finds `dev:<name>` and its
suffixed forms with `LIKE 'dev:<name>-%'` under any database collation.

`device_identity_meta` holds one row with the column `generation`. The rename
command increments it, and every collector hashes it into its change hash. A
rename loads every device again at the next run.

Revision ID: 0035
Revises: 0034
"""

import sqlalchemy as sa
from alembic import op

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_identity",
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("uid", sa.Text, nullable=False),
        sa.Column("hostname", sa.Text, nullable=True),
        sa.Column("last_hostname", sa.Text, nullable=True),
        sa.Column("first_run_id", sa.BigInteger, nullable=True),
        sa.PrimaryKeyConstraint("kind", "value", name="pk_device_identity"),
        sa.CheckConstraint("kind IN ('serial', 'ref')", name="ck_device_identity_kind"),
    )
    op.create_index(
        "ix_device_identity_uid", "device_identity", ["uid"], postgresql_ops={"uid": "text_pattern_ops"}
    )
    op.create_table(
        "device_identity_meta",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=False),
        sa.Column("generation", sa.Integer, nullable=False, server_default="0"),
        sa.CheckConstraint("id = 1", name="ck_device_identity_meta_one_row"),
    )
    op.execute("INSERT INTO device_identity_meta (id, generation) VALUES (1, 0)")


def downgrade() -> None:
    op.drop_table("device_identity_meta")
    op.drop_index("ix_device_identity_uid", table_name="device_identity")
    op.drop_table("device_identity")
