"""Migration 0028 against a disposable Postgres."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

pytestmark = pytest.mark.pg
DSN = os.environ.get("HST_TEST_PG_DSN")
if not DSN:
    pytest.skip("HST_TEST_PG_DSN not set", allow_module_level=True)

import sqlalchemy as sa  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.util.exc import CommandError  # noqa: E402
from sqlalchemy import create_engine, inspect  # noqa: E402

from hst.app.inventory import contracts  # noqa: E402
from hst.app.inventory import tables as t  # noqa: E402
from hst.app.store import pg as pgmod  # noqa: E402
from hst.app.store.pg import metadata, upgrade_to_head  # noqa: E402

SYNC_DSN = DSN.replace("+asyncpg", "+psycopg")
NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


def _cfg() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(pgmod.__file__).parent / "migrations"))
    cfg.set_main_option("sqlalchemy.url", DSN.replace("%", "%%"))
    return cfg


@pytest.fixture
def at_head():
    upgrade_to_head(DSN)
    engine = create_engine(SYNC_DSN)
    with engine.begin() as conn:
        for table in reversed(metadata.sorted_tables):
            conn.execute(table.delete())
        conn.execute(sa.text("INSERT INTO inventory_state (id, updated_at) VALUES (1, now())"))
    yield engine
    engine.dispose()
    upgrade_to_head(DSN)


def _checks(insp, table: str) -> dict[str, str]:
    return {c["name"]: c["sqltext"] for c in insp.get_check_constraints(table)}


def _fks(insp, table: str) -> dict[tuple[str, ...], dict]:
    return {tuple(f["constrained_columns"]): f for f in insp.get_foreign_keys(table)}


def _indexes(insp, table: str) -> dict[str, dict]:
    return {i["name"]: i for i in insp.get_indexes(table)}


def test_every_inventory_table_and_added_column_exists_and_matches_metadata(at_head):
    insp = inspect(at_head)
    present = set(insp.get_table_names())
    assert {x.name for x in t.INVENTORY_TABLES} <= present
    for table, column in t.LEGACY_ADDITIONS:
        assert column in {c["name"] for c in insp.get_columns(table)}, (table, column)
    try:
        command.check(_cfg())
    except CommandError as exc:
        pytest.fail(f"0028 and tables.py disagree: {exc}")


def test_check_constraints_carry_the_contract_vocabularies(at_head):
    insp = inspect(at_head)
    expectations = {
        ("inventory_devices", "ck_inventory_devices_lifecycle"): contracts.Lifecycle,
        ("inventory_devices", "ck_inventory_devices_collection_state"): contracts.CollectionState,
        ("inventory_devices", "ck_inventory_devices_placement_state"): contracts.PlacementState,
        ("inventory_targets", "ck_inventory_targets_kind"): contracts.TargetKind,
        ("inventory_observations", "ck_inventory_observations_state"): contracts.ObservationState,
        ("inventory_observations", "ck_inventory_observations_authority"): contracts.Authority,
        ("inventory_placements", "ck_inventory_placements_mode"): contracts.PlacementMode,
        ("inventory_placements", "ck_inventory_placements_origin"): contracts.PlacementOrigin,
        ("inventory_publications", "ck_inventory_publications_state"): contracts.PublicationState,
        ("inventory_outbox", "ck_inventory_outbox_kind"): contracts.OutboxKind,
        ("inventory_outbox", "ck_inventory_outbox_state"): contracts.OutboxState,
        ("inventory_state", "ck_inventory_state_activation"): contracts.ActivationState,
        ("inventory_operation_previews", "ck_inventory_operation_previews_op"): contracts.PreviewOperation,
    }
    for (table, name), enum in expectations.items():
        checks = _checks(insp, table)
        assert name in checks, (table, name, sorted(checks))
        for member in enum:
            assert f"'{member.value}'" in checks[name], (name, member)
        # and nothing the enum does not know about
        quoted = (
            {q.strip("'") for q in checks[name].split("(")[1].rstrip(")").split(", ")}
            if "IN (" in checks[name]
            else None
        )
        if quoted is not None:
            assert quoted == {m.value for m in enum}, (name, quoted)
    assert "ck_inventory_placements_assigned_site" in _checks(insp, "inventory_placements")
    assert "ck_collection_profile_versions_credential_pair" in _checks(insp, "collection_profile_versions")
    assert "ck_inventory_state_singleton" in _checks(insp, "inventory_state")
    for table in (
        "inventory_devices",
        "inventory_targets",
        "inventory_placements",
        "collection_profiles",
        "collection_credentials",
        "inventory_saved_views",
        "inventory_routing_groups",
    ):
        assert any(n.endswith("_revision") for n in _checks(insp, table)), table


def test_unique_constraints_and_partial_indexes(at_head):
    insp = inspect(at_head)
    uniques = lambda table: {tuple(u["column_names"]) for u in insp.get_unique_constraints(table)}  # noqa: E731
    assert ("graph_uid",) in uniques("inventory_devices")
    assert ("legacy_device_id",) in uniques("inventory_targets")
    assert ("owner_id", "name") in uniques("inventory_saved_views")
    assert ("actor_id", "idempotency_key") in uniques("inventory_operation_results")
    assert ("dedup_key",) in uniques("inventory_outbox")
    assert ("display_name",) in uniques("collection_profiles")
    assert ("display_name",) in uniques("collection_credentials")
    assert ("display_name",) in uniques("inventory_routing_groups")
    assert ("handle",) in uniques("reported_locations")
    active = _indexes(insp, "inventory_targets")["uq_inventory_targets_active"]
    assert active["unique"] is True and active["column_names"] == ["source_key", "host"]
    assert "archived_at IS NULL" in active["dialect_options"]["postgresql_where"]
    pk = insp.get_pk_constraint("inventory_observations")["constrained_columns"]
    assert pk == ["target_id", "device_id"]
    assert insp.get_pk_constraint("collection_profile_versions")["constrained_columns"] == [
        "profile_id",
        "revision",
    ]
    assert insp.get_pk_constraint("collection_credential_versions")["constrained_columns"] == [
        "credential_id",
        "revision",
    ]
    assert insp.get_pk_constraint("inventory_routing_members")["constrained_columns"] == [
        "group_id",
        "context_uid",
    ]


def test_list_filter_sort_and_event_indexes_exist(at_head):
    insp = inspect(at_head)
    devices = _indexes(insp, "inventory_devices")
    for name in (
        "ix_inventory_devices_hostname",
        "ix_inventory_devices_graph_uid",
        "ix_inventory_devices_management_address",
        "ix_inventory_devices_platform",
        "ix_inventory_devices_site",
        "ix_inventory_devices_lifecycle",
        "ix_inventory_devices_collection_state",
        "ix_inventory_devices_placement_state",
        "ix_inventory_devices_last_success",
    ):
        assert name in devices, name
    # The three search columns carry case-insensitive expression indexes.
    for name, column in (
        ("ix_inventory_devices_hostname", "hostname"),
        ("ix_inventory_devices_graph_uid", "graph_uid"),
        ("ix_inventory_devices_management_address", "management_address"),
    ):
        assert f"lower({column})" in " ".join(str(e) for e in devices[name].get("expressions", [])), name
    events = _indexes(insp, "inventory_events")
    assert events["ix_inventory_events_entity"]["column_names"] == ["entity_type", "entity_id", "id"]
    assert "ix_inventory_events_at" in events
    assert "ix_inventory_outbox_ready" in _indexes(insp, "inventory_outbox")
    assert "ix_inventory_operation_previews_expiry" in _indexes(insp, "inventory_operation_previews")
    assert "ix_inventory_observations_device" in _indexes(insp, "inventory_observations")
    assert "ix_inventory_targets_source" in _indexes(insp, "inventory_targets")


def test_foreign_keys_carry_the_archive_semantics(at_head):
    insp = inspect(at_head)

    def rule(table, cols):
        return (_fks(insp, table)[cols]["options"].get("ondelete") or "NO ACTION").upper()

    assert rule("inventory_targets", ("source_id",)) == "SET NULL"
    assert rule("inventory_targets", ("legacy_device_id",)) == "SET NULL"
    assert rule("inventory_targets", ("onboarding_site_id",)) == "SET NULL"
    assert rule("inventory_targets", ("profile_id",)) == "RESTRICT"
    assert rule("inventory_observations", ("target_id",)) == "RESTRICT"
    assert rule("inventory_observations", ("device_id",)) == "RESTRICT"
    assert rule("inventory_observations", ("reported_location_handle",)) == "SET NULL"
    assert rule("inventory_placements", ("device_id",)) == "RESTRICT"
    assert rule("inventory_placements", ("site_id",)) == "RESTRICT"
    assert rule("inventory_devices", ("resolved_site_id",)) == "SET NULL"
    assert rule("inventory_events", ("actor_id",)) == "SET NULL"
    assert rule("sources", ("default_profile_id",)) == "SET NULL"
    assert rule("inventory_staged_targets", ("snapshot_key",)) == "CASCADE"
    assert rule("inventory_staged_observations", ("snapshot_key",)) == "CASCADE"
    assert rule("inventory_preview_impacts", ("token",)) == "CASCADE"
    assert rule("collection_profile_versions", ("profile_id",)) == "RESTRICT"
    composite = _fks(insp, "collection_profile_versions")[("credential_id", "credential_revision")]
    assert composite["referred_table"] == "collection_credential_versions"
    assert composite["referred_columns"] == ["credential_id", "revision"]
    # No FK from any inventory table cascades a source or target deletion into
    # a device, a placement or an event.
    for table in ("inventory_devices", "inventory_placements", "inventory_events"):
        for fk in insp.get_foreign_keys(table):
            assert fk["referred_table"] not in ("sources", "inventory_targets", "devices"), (table, fk)


def test_migration_seeds_the_inactive_singleton_state():
    engine = create_engine(SYNC_DSN)
    try:
        command.downgrade(_cfg(), "0027")
        command.upgrade(_cfg(), "head")
        with engine.connect() as conn:
            row = conn.execute(sa.text("SELECT * FROM inventory_state")).mappings().one()
    finally:
        engine.dispose()
    assert row["id"] == 1 and row["resolver_version"] == 1 and row["activation_state"] == "inactive"
    assert row["intent_generation"] == 1 and row["read_model_snapshot_key"] is None


def test_archive_on_delete_semantics_with_real_deletes(at_head):
    engine = at_head
    with engine.begin() as conn:
        sid = conn.execute(
            sa.text(
                "INSERT INTO sources (name, type, created_at, updated_at) "
                "VALUES ('lab', 'vyos', :n, :n) RETURNING id"
            ),
            {"n": NOW},
        ).scalar_one()
        uid = conn.execute(
            sa.text(
                "INSERT INTO users (username, role, created_at) VALUES ('ada', 'admin', :n) RETURNING id"
            ),
            {"n": NOW},
        ).scalar_one()
        did = conn.execute(
            sa.text(
                "INSERT INTO devices (source, host, created_at, updated_at) "
                "VALUES ('lab', 'r1', :n, :n) RETURNING id"
            ),
            {"n": NOW},
        ).scalar_one()
        site_id = conn.execute(
            sa.text("INSERT INTO sites (code, created_at, updated_at) VALUES ('fra', :n, :n) RETURNING id"),
            {"n": NOW},
        ).scalar_one()
        conn.execute(
            sa.text(
                "INSERT INTO reported_locations (source, location_id, name, site, updated_at) "
                "VALUES ('lab', 'loc-1', 'Frankfurt', 'fra', :n)"
            ),
            {"n": NOW},
        )
        handle = conn.execute(sa.text("SELECT handle FROM reported_locations")).scalar_one()
        assert isinstance(handle, uuid.UUID)
        pid, tid, dev = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        conn.execute(
            t.collection_profiles.insert().values(
                id=pid, display_name="p", collector_type="vyos", created_at=NOW, updated_at=NOW
            )
        )
        conn.execute(
            t.collection_profile_versions.insert().values(
                profile_id=pid, revision=1, settings={}, created_at=NOW
            )
        )
        conn.execute(
            t.inventory_targets.insert().values(
                id=tid,
                source_id=sid,
                source_key="lab",
                host="r1",
                kind="direct",
                legacy_device_id=did,
                profile_id=pid,
                onboarding_site_id=site_id,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        conn.execute(
            t.inventory_devices.insert().values(
                id=dev,
                graph_uid="dev:x",
                first_seen=NOW,
                last_seen=NOW,
                updated_at=NOW,
                resolved_site_id=site_id,
            )
        )
        conn.execute(
            t.inventory_observations.insert().values(
                target_id=tid, device_id=dev, reported_location_handle=handle, updated_at=NOW
            )
        )
        conn.execute(
            t.inventory_placements.insert().values(
                device_id=dev, mode="assigned", site_id=site_id, actor_id=uid, updated_at=NOW
            )
        )
        conn.execute(
            t.inventory_events.insert().values(
                entity_type="device", entity_id=str(dev), actor_id=uid, action="place", at=NOW
            )
        )
        conn.execute(
            sa.text("UPDATE sources SET default_profile_id = :p WHERE id = :s"), {"p": pid, "s": sid}
        )

    with pytest.raises(sa.exc.IntegrityError), engine.begin() as conn:
        conn.execute(t.collection_profiles.delete().where(t.collection_profiles.c.id == pid))
    # A site with an assigned placement cannot be deleted underneath the intent.
    with pytest.raises(sa.exc.IntegrityError), engine.begin() as conn:
        conn.execute(sa.text("DELETE FROM sites WHERE id = :s"), {"s": site_id})
    # A device with observations or a placement is never deleted by a cascade.
    with pytest.raises(sa.exc.IntegrityError), engine.begin() as conn:
        conn.execute(t.inventory_devices.delete().where(t.inventory_devices.c.id == dev))

    with engine.begin() as conn:
        conn.execute(sa.text("DELETE FROM devices WHERE id = :d"), {"d": did})
        conn.execute(sa.text("DELETE FROM users WHERE id = :u"), {"u": uid})  # actor gone
        conn.execute(sa.text("DELETE FROM sources WHERE id = :s"), {"s": sid})
    with engine.connect() as conn:
        target = conn.execute(t.inventory_targets.select()).mappings().one()
        assert target["source_id"] is None and target["source_key"] == "lab"
        assert target["legacy_device_id"] is None and target["profile_id"] == pid
        assert conn.execute(sa.select(sa.func.count()).select_from(t.inventory_devices)).scalar_one() == 1
        obs = conn.execute(t.inventory_observations.select()).mappings().one()
        assert obs["reported_location_handle"] is None  # location cascaded with its source; claim retained
        placement = conn.execute(t.inventory_placements.select()).mappings().one()
        assert placement["site_id"] == site_id and placement["actor_id"] is None
        event = conn.execute(t.inventory_events.select()).mappings().one()
        assert event["actor_id"] is None and event["entity_id"] == str(dev)


def test_downgrade_removes_exactly_the_revision_and_keeps_the_0027_rows(at_head):
    engine = at_head
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO sources (name, type, display_name, created_at, updated_at) "
                "VALUES ('keep', 'vyos', 'Keep', :n, :n)"
            ),
            {"n": NOW},
        )
        conn.execute(
            sa.text("INSERT INTO sites (code, created_at, updated_at) VALUES ('ams', :n, :n)"), {"n": NOW}
        )
        conn.execute(
            sa.text(
                "INSERT INTO reported_locations (source, location_id, updated_at) VALUES ('keep', 'l1', :n)"
            ),
            {"n": NOW},
        )
    command.downgrade(_cfg(), "0027")
    insp = inspect(engine)
    present = set(insp.get_table_names())
    assert not ({x.name for x in t.INVENTORY_TABLES} & present)
    for table, column in t.LEGACY_ADDITIONS:
        assert column not in {c["name"] for c in insp.get_columns(table)}, (table, column)
    assert {
        "sources",
        "devices",
        "device_status",
        "target_devices",
        "reported_locations",
        "site_members",
        "sites",
    } <= present
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT name FROM sources")).scalar_one() == "keep"
        assert conn.execute(sa.text("SELECT code FROM sites")).scalar_one() == "ams"
        assert conn.execute(sa.text("SELECT location_id FROM reported_locations")).scalar_one() == "l1"
        assert conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one() == "0027"
    command.upgrade(_cfg(), "head")
    with engine.connect() as conn:
        assert (
            conn.execute(sa.text("SELECT count(DISTINCT handle) FROM reported_locations")).scalar_one() == 1
        )
        assert conn.execute(sa.text("SELECT display_name FROM sources")).scalar_one() == ""
        assert conn.execute(sa.text("SELECT revision FROM sites")).scalar_one() == 1
