"""geo_places: the offline place table behind the site address lookup

Revision ID: 0030
Revises: 0029

The table holds one row per postal code and place from the GeoNames postal
code dump (download.geonames.org/export/zip, CC BY 4.0). `hst geo-places load`
replaces the whole table, and the app only reads it. The lookup is a prefix
search. Both search columns have a text_pattern_ops index. `LIKE 'x%'` uses
the index under any database collation.

`name_key` is the place name in lower case and without accents. The search key
"munchen" finds "München".
"""

import sqlalchemy as sa
from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "geo_places",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("country_code", sa.Text, nullable=False),
        sa.Column("postal_code", sa.Text, nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("admin1", sa.Text, nullable=False, server_default=""),
        sa.Column("admin2", sa.Text, nullable=False, server_default=""),
        sa.Column("lat", sa.Float, nullable=False),
        sa.Column("lon", sa.Float, nullable=False),
        sa.Column("name_key", sa.Text, nullable=False),
    )
    op.create_index(
        "ix_geo_places_name_key", "geo_places", ["name_key"], postgresql_ops={"name_key": "text_pattern_ops"}
    )
    op.create_index(
        "ix_geo_places_postal_code",
        "geo_places",
        ["postal_code"],
        postgresql_ops={"postal_code": "text_pattern_ops"},
    )


def downgrade() -> None:
    op.drop_index("ix_geo_places_postal_code", table_name="geo_places")
    op.drop_index("ix_geo_places_name_key", table_name="geo_places")
    op.drop_table("geo_places")
