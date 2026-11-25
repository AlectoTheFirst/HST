"""Activated legacy site APIs share inventory intent and revision semantics."""

from __future__ import annotations

import httpx
import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.inventory_rig import device, fake_rig

from hst.app.crypto import generate_key
from hst.app.inventory import inventory_routes
from hst.app.main import create_app
from hst.app.security import hash_password
from hst.core import Settings


@pytest.fixture
async def rig():
    r = fake_rig()
    await r.store.create_user("operator", hash_password(PASSWORD), "operator")
    await r.store.create_user("viewer", hash_password(PASSWORD), "viewer")
    await r.seed_source("direct", "vyos", config={"site_code": "fra", "routing_scope": "legacy"})
    await r.seed_source("ctrl", "velocloud")
    await r.seed_site("fra", "Frankfurt")
    await r.seed_site("ams", "Amsterdam")
    await r.seed_location("ctrl", "site/1", "Reported location", site="fra")
    await r.target("direct", "router", onboarding_site="fra")
    await r.run(
        "1000",
        {
            ("direct", "router"): ("complete", [device("dev:direct", "router")]),
            ("ctrl", ""): (
                "complete",
                [device("dev:controller", "edge", location=("site/1", "Reported location"))],
            ),
        },
    )
    await r.store.update_site("fra", params={"routing_scope": "frozen", "lat": 50.0, "lon": 8.0})
    async with r.repo.transaction() as tx:
        await tx.activate(resolver_version=2, schema_version=1, backfill_version=2, now=r.clock())
    return r


@pytest.fixture
async def client(rig):
    app = create_app(
        settings=Settings(_env_file=None, hst_secret_key=generate_key()),
        store=rig.store,
        register_inventory=False,
    )
    app.state.inventory_context = rig.ctx
    inventory_routes.register(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "operator")
        yield client


async def test_direct_legacy_assignment_uses_inventory_and_null_restores_auto(client, rig):
    response = await client.post("/api/sites/assign", json={"device_uid": "dev:direct", "site": "ams"})
    assert response.status_code == 200, response.text
    async with rig.repo.transaction() as tx:
        row = await tx.get_device_by_graph_uid("dev:direct")
        placement = await tx.get_placement(row.id)
        assert placement.mode == "assigned" and placement.site_id == rig.site_ids["ams"]
        assert row.resolved_site_id == rig.site_ids["ams"]
        before_revision = placement.revision
    response = await client.post("/api/sites/assign", json={"device_uid": "dev:direct", "site": None})
    assert response.status_code == 200
    async with rig.repo.transaction() as tx:
        placement = await tx.get_placement(row.id)
        assert placement.mode == "auto" and placement.site_id is None
        assert placement.revision == before_revision + 1
        row = await tx.get_device(row.id)
        assert row.resolved_site_id is None  # No live inheritance from source.site_code.
    assert (await rig.store.get_source("direct")).config["routing_scope"] == "legacy"


async def test_legacy_location_binding_recomputes_inventory_and_bumps_revision(client, rig):
    async with rig.repo.transaction() as tx:
        before = (await tx.list_locations("ctrl"))[0]
    response = await client.patch("/api/locations/ctrl/site/1", json={"site": "ams"})
    assert response.status_code == 200, response.text
    async with rig.repo.transaction() as tx:
        loc = await tx.get_location(before.handle)
        row = await tx.get_device_by_graph_uid("dev:controller")
        assert loc.site == "ams" and loc.revision == before.revision + 1
        assert row.resolved_site_id == rig.site_ids["ams"]
        assert row.latest_snapshot_key == "1000"
    listed = (await client.get("/api/locations")).json()["locations"]
    assert next(loc for loc in listed if loc["location_id"] == "site/1")["site"] == "ams"
    sites = (await client.get("/api/sites")).json()["sites"]
    assert next(site for site in sites if site["code"] == "ams")["device_count"] == 1


async def test_delete_releases_assigned_auto_and_onboarding_without_changing_frozen_sources(client, rig):
    response = await client.delete("/api/sites/fra")
    assert response.status_code == 200, response.text
    assert response.json()["groups"] == []
    assert response.json()["devices"] == ["dev:direct"]
    assert response.json()["locations"] == [{"source": "ctrl", "location_id": "site/1"}]
    async with rig.repo.transaction() as tx:
        direct = await tx.get_device_by_graph_uid("dev:direct")
        controller = await tx.get_device_by_graph_uid("dev:controller")
        placement = await tx.get_placement(direct.id)
        assert placement.mode == "unplaced" and placement.site_id is None
        assert direct.resolved_site_id is None and controller.resolved_site_id is None
        assert (await tx.get_active_target("direct", "router")).onboarding_site_id is None
        assert (await tx.list_locations("ctrl"))[0].site is None
        assert direct.latest_snapshot_key == controller.latest_snapshot_key == "1000"
    assert await rig.store.get_site("fra") is None
    assert (await rig.store.get_source("direct")).config == {"site_code": "fra", "routing_scope": "legacy"}


async def test_legacy_site_patch_accepts_unchanged_frozen_routing_and_updates_geography(client, rig):
    response = await client.patch(
        "/api/sites/fra", json={"name": "New name", "params": {"routing_scope": "frozen", "lat": 51.0}}
    )
    assert response.status_code == 200, response.text
    assert response.json()["params"] == {"routing_scope": "frozen", "lat": 51.0, "lon": 8.0}
    assert response.json()["name"] == "New name"
    async with rig.repo.transaction() as tx:
        row = next(s for s in await rig.ctx.site_rows(tx).list() if s.code == "fra")
        assert row.revision == 2
    response = await client.patch(
        "/api/sites/fra", json={"name": "Forbidden", "params": {"routing_scope": "new"}}
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "normalization_migrated"
    assert response.json()["references"] == ["site:fra"]
    assert (await rig.store.get_site("fra")).name == "New name"
    response = await client.patch("/api/sites/fra", json={"params": None})
    assert response.status_code == 409


async def test_invalid_coordinates_leave_name_and_revision_unchanged(client, rig):
    response = await client.patch("/api/sites/fra", json={"name": "Bad", "params": {"lat": None}})
    assert response.status_code == 422, response.text
    async with rig.repo.transaction() as tx:
        row = next(s for s in await rig.ctx.site_rows(tx).list() if s.code == "fra")
        assert row.name == "Frankfurt" and row.revision == 1


async def test_active_legacy_create_rejects_routing_defaults_and_creates_revisioned_geography(client, rig):
    response = await client.post("/api/sites", json={"code": "new", "params": {"routing_scope": "new"}})
    assert response.status_code == 409
    response = await client.post(
        "/api/sites", json={"code": "new", "name": "New", "params": {"lat": 10, "lon": 20}}
    )
    assert response.status_code == 201, response.text
    assert response.json()["params"] == {"lat": 10, "lon": 20}
    async with rig.repo.transaction() as tx:
        row = next(s for s in await rig.ctx.site_rows(tx).list() if s.code == "new")
        assert row.revision == 1


async def test_active_legacy_create_refuses_a_code_that_is_the_same_site_as_another(client, rig):
    """`NEW` beside `new` is one graph Site under two codes."""
    assert (await client.post("/api/sites", json={"code": "new"})).status_code == 201
    response = await client.post("/api/sites", json={"code": "NEW"})
    assert response.status_code == 409
    assert "folds onto 'new'" in response.text
    async with rig.repo.transaction() as tx:
        assert [s.code for s in await rig.ctx.site_rows(tx).list() if s.code.lower() == "new"] == ["new"]


async def test_active_legacy_site_writes_preserve_permission_boundary(client):
    await login(client, "viewer")
    for method, path, body in [
        ("POST", "/api/sites/assign", {"device_uid": "dev:direct", "site": "ams"}),
        ("PATCH", "/api/locations/ctrl/site/1", {"site": "ams"}),
        ("DELETE", "/api/sites/fra", None),
    ]:
        response = await client.request(method, path, json=body)
        assert response.status_code == 403


@pytest.mark.pg
async def test_postgres_site_revision_compare_and_swap_rejects_concurrent_writer():
    """Force both requests to read revision one before either can update it."""
    import asyncio

    from tests.app.inventory_rig import DSN, NOW, reset_pg

    from hst.app.inventory.observations import PgSiteRows
    from hst.app.inventory.repository import StaleRevision

    if not DSN:
        pytest.skip("HST_TEST_PG_DSN not set")
    store = await reset_pg()
    try:
        site = await store.create_site("race", "Before", "")
        barrier = asyncio.Barrier(2)

        class ConcurrentRead:
            def __init__(self, connection):
                self.connection = connection
                self.waited = False

            async def execute(self, statement):
                result = await self.connection.execute(statement)
                if statement.is_select and not self.waited:
                    self.waited = True
                    await asyncio.wait_for(barrier.wait(), timeout=5)
                return result

        async def edit(name):
            async with store.inventory().transaction() as tx:
                rows = PgSiteRows(ConcurrentRead(tx.connection))
                return await rows.update(site.id, expected_revision=1, now=NOW, name=name)

        results = await asyncio.gather(edit("A"), edit("B"), return_exceptions=True)
        assert sum(isinstance(result, StaleRevision) for result in results) == 1
        assert sum(not isinstance(result, Exception) for result in results) == 1
        stale = next(result for result in results if isinstance(result, StaleRevision))
        assert stale.current_revision == 2
        async with store.inventory().transaction() as tx:
            rows = await PgSiteRows(tx.connection).list()
            assert rows[0].revision == 2
    finally:
        await store.dispose()


@pytest.mark.pg
async def test_postgres_legacy_store_mutations_share_active_inventory_primitives():
    from tests.app.inventory_rig import DSN, pg_rig

    from hst.app.inventory.legacy import NormalizationMigrated

    if not DSN:
        pytest.skip("HST_TEST_PG_DSN not set")
    r = await pg_rig()
    try:
        await r.seed_source("direct", "vyos", config={"site_code": "fra"})
        await r.seed_source("ctrl", "velocloud")
        await r.seed_site("fra", "Frankfurt")
        await r.seed_site("ams", "Amsterdam")
        await r.seed_location("ctrl", "loc", "Reported", site="fra")
        await r.target("direct", "router", onboarding_site="fra")
        await r.run(
            "1000",
            {
                ("direct", "router"): ("complete", [device("dev:direct")]),
                ("ctrl", ""): ("complete", [device("dev:ctrl", location=("loc", "Reported"))]),
            },
        )
        async with r.repo.transaction() as tx:
            await tx.activate(resolver_version=2, schema_version=1, backfill_version=2, now=r.clock())
        await r.store.update_site("fra", name="Updated geography", params={"lat": 10, "lon": 20})
        with pytest.raises(NormalizationMigrated):
            await r.store.update_site("fra", params={"routing_scope": "new"})
        await r.store.assign_device("dev:direct", "ams")
        await r.store.bind_location("ctrl", "loc", "ams")
        async with r.repo.transaction() as tx:
            direct = await tx.get_device_by_graph_uid("dev:direct")
            controller = await tx.get_device_by_graph_uid("dev:ctrl")
            assert direct.resolved_site_id == controller.resolved_site_id == r.site_ids["ams"]
        released = await r.store.delete_site("ams")
        assert released.devices == ["dev:direct"]
        assert released.locations == [("ctrl", "loc")]
        async with r.repo.transaction() as tx:
            assert (await tx.get_placement(direct.id)).mode == "unplaced"
            assert (await tx.get_location((await tx.list_locations("ctrl"))[0].handle)).site is None
            assert (await tx.get_device(controller.id)).resolved_site_id is None
    finally:
        await r.store.dispose()
