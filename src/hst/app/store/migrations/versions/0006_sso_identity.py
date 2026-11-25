"""SSO schema: auth providers, identities, group mappings, auth state

Revision ID: 0006
Revises: 0005

The tables of federated login:

- `auth_providers` holds one row per configured OIDC or SAML identity
  provider. `secrets` is sealed by app/crypto.py.
- `identities` holds one row per external account, linked to one local user at
  one provider.
- `group_mappings` holds the rules from a group to a role per provider. Every
  SSO login applies them.
- `auth_state` holds the server-side one-time rows of the OIDC state, nonce and
  PKCE verifier, of the SAML request ids and of the SAML assertion replay
  cache. `consume_auth_state` deletes a row when it reads it.
  `purge_expired_auth_state` deletes the expired rows.

`users.password_hash` is nullable. An account with NULL has no password
authentication, as every SSO-provisioned account. `users.role_source` is
'local' for a role that an admin assigned and 'mapped' for a role from the
group mappings. The default is 'local'.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("users", "password_hash", existing_type=sa.Text, nullable=True)
    op.add_column(
        "users", sa.Column("role_source", sa.Text, nullable=False, server_default=sa.text("'local'"))
    )

    op.create_table(
        "auth_providers",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("config", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("secrets", sa.LargeBinary, nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    )
    op.create_table(
        "identities",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "provider_id",
            sa.Integer,
            sa.ForeignKey("auth_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("subject", sa.Text, nullable=False),
        sa.Column("email", sa.Text, nullable=False, server_default=""),
        sa.Column("last_login_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.UniqueConstraint("provider_id", "subject", name="uq_identities_provider_subject"),
    )
    op.create_table(
        "group_mappings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "provider_id",
            sa.Integer,
            sa.ForeignKey("auth_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("group_name", sa.Text, nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.UniqueConstraint("provider_id", "group_name", name="uq_group_mappings_provider_group"),
    )
    op.create_table(
        "auth_state",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column(
            "provider_id",
            sa.Integer,
            sa.ForeignKey("auth_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("payload", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("auth_state")
    op.drop_table("group_mappings")
    op.drop_table("identities")
    op.drop_table("auth_providers")
    op.drop_column("users", "role_source")
    op.alter_column("users", "password_hash", existing_type=sa.Text, nullable=False)
