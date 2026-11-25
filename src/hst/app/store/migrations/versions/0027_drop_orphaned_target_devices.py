"""Remove the observations of hosts that already left their fleet.

Revision ID: 0027
Revises: 0026

The migration deletes the `target_devices` and `device_status` rows of a host
that has no row in the fleet of its source. `replace_devices` deletes these
rows together with the fleet row.

The migration changes only a source with a fleet. A controller and a group
collected through its own `config.host` have no fleet rows.
"""

from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "DELETE FROM target_devices t "
        "WHERE EXISTS (SELECT 1 FROM devices d WHERE d.source = t.source) "
        "AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.source = t.source AND d.host = t.host)"
    )
    op.execute(
        "DELETE FROM device_status t "
        "WHERE EXISTS (SELECT 1 FROM devices d WHERE d.source = t.source) "
        "AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.source = t.source AND d.host = t.host)"
    )


def downgrade() -> None:
    # The next collection run records the current observations.
    pass
