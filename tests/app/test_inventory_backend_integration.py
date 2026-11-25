from types import SimpleNamespace

from tests.app.inventory_rig import fake_rig

from hst.app import runs_exec
from hst.app.inventory import collection
from hst.app.inventory.contracts import PublicationState
from hst.app.inventory.normalization import freeze_legacy_normalization
from hst.core import Settings


async def test_execution_stages_real_service_before_publication(monkeypatch):
    rig = fake_rig()
    await rig.seed_source("vco", "velocloud")
    row = await rig.store.get_source("vco")
    collector = SimpleNamespace(
        config=SimpleNamespace(host=""),
        last_device_uids=["dev:edge"],
        last_device_locations={"dev:edge": ("branch", "Branch")},
        last_device_facts={
            "dev:edge": {"hostname": "edge", "platform": "velocloud", "management_address": "192.0.2.1"}
        },
    )
    prepared = [runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(None, collector, None)])]
    capture = runs_exec.ExecutionCapture(collection.ExecutionContext(resolver_version=2, activated=True))
    monkeypatch.setattr(collection, "_observation_service", rig.service)
    await runs_exec._stage_results(
        rig.store,
        capture,
        100,
        prepared,
        [runs_exec.DeviceOutcome("vco", "", True)],
        publish=False,
    )
    assert await rig.device_by_uid("dev:edge") is None
    async with rig.repo.transaction() as tx:
        assert (await tx.get_publication("100")).state == PublicationState.STAGED.value
    await rig.service.compose_placements("100")
    await runs_exec._publish_inventory(rig.store, capture, 100)
    device = await rig.device_by_uid("dev:edge")
    assert device is not None
    assert (device.hostname, device.platform, device.management_address) == ("edge", "velocloud", "192.0.2.1")
    observations = await rig.observations("dev:edge")
    assert len(observations) == 1
    assert observations[0].reported_location_handle is not None


async def test_reconcile_does_not_promote_unpublished_staging(monkeypatch):
    rig = fake_rig()
    async with rig.repo.transaction() as tx:
        await tx.activate(resolver_version=2, schema_version=1, backfill_version=1, now=rig.clock())
        await tx.stage_publication("200", parent_snapshot_key=None, now=rig.clock())
    monkeypatch.setattr(collection, "_observation_service", rig.service)
    await collection.reconcile_on_startup(rig.store)
    async with rig.repo.transaction() as tx:
        assert (await tx.get_publication("200")).state == PublicationState.STAGED.value


async def test_execution_consumes_structured_legacy_freeze():
    rig = fake_rig()
    await rig.seed_source("adc", "netscaler", config={"site_code": "old", "l3dom": "pinned"})
    row = await rig.store.get_source("adc")
    settings = Settings(_env_file=None)
    frozen = freeze_legacy_normalization(row, {}, settings)
    inventory = SimpleNamespace(frozen_normalization=frozen.as_dict())
    values = collection.frozen_normalization_values(row, inventory, settings)["values"]
    assert values["routing_scope"] == frozen.routing_scope.value
    assert values["l3dom"] == "pinned"
    assert values["site_code"] == "old"


async def test_one_dispatcher_serves_connection_inventory_and_routing_operations(monkeypatch):
    import httpx
    from fastapi import FastAPI
    from tests.app.inventory_rig import device
    from tests.app.test_inventory_collection import settings_for

    from hst.app.auth import current_user
    from hst.app.inventory import connection_routes, inventory_routes, routing_routes

    rig = fake_rig()
    await rig.seed_source("lab", "vyos")
    await rig.run("100", {("lab", "r1"): ("complete", [device("dev:r1")])})
    user = await rig.store.create_user("operator", "unused", "admin")
    app = FastAPI()
    app.state.store = rig.store
    app.state.settings = settings_for()
    app.state.inventory_context = rig.ctx
    app.dependency_overrides[current_user] = lambda: user
    connection_routes.register(app)
    inventory_routes.register(app, operations=False)
    routing_routes.register(app, operations=False)
    monkeypatch.setattr(connection_routes, "_now", rig.clock)
    from hst.app.inventory.routing import BatchGraphReader, RoutingService

    routing_service = RoutingService(rig.repo, BatchGraphReader({}), clock=rig.clock)
    monkeypatch.setattr(routing_routes, "service", lambda request: routing_service)
    paths = app.openapi()["paths"]
    assert set(paths["/api/inventory/operations/preview"]) == {"post"}
    assert set(paths["/api/inventory/operations/apply"]) == {"post"}
    inventory_device = await rig.device_by_uid("dev:r1")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/inventory/operations/preview",
            json={
                "operation": "archive_devices",
                "selection": {"ids": [str(inventory_device.id)]},
                "change": {},
            },
        )
        assert response.status_code == 200, response.text
        body = {"token": response.json()["token"], "idempotency_key": "archive-device"}
        response = await client.post("/api/inventory/operations/apply", json=body)
        assert response.status_code == 200, response.text
        replay = await client.post("/api/inventory/operations/apply", json=body)
        assert replay.status_code == 200, replay.text
        assert replay.json()["status"] == "reused"
        group = await client.post("/api/inventory/routing-groups", json={"display_name": "WAN"})
        assert group.status_code == 201, group.text
        group_id = group.json()["id"]
        response = await client.post(
            "/api/inventory/operations/preview",
            json={
                "operation": "edit_routing_members",
                "selection": {"ids": [group_id]},
                "change": {"group_id": group_id, "remove_context_uids": ["vrf:old"]},
            },
        )
        assert response.status_code == 200, response.text
        body = {"token": response.json()["token"], "idempotency_key": "routing-members"}
        response = await client.post("/api/inventory/operations/apply", json=body)
        assert response.status_code == 200, response.text
        assert (await client.post("/api/inventory/operations/apply", json=body)).json()["status"] == "reused"
