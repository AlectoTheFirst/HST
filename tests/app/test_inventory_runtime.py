"""Production route registration, activation gates and resolver compatibility."""

from datetime import UTC, datetime

import httpx
import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.inventory_rig import fake_rig

from hst.app.crypto import generate_key
from hst.app.inventory.runtime import compatible
from hst.app.main import create_app
from hst.app.security import hash_password
from hst.core import Settings


@pytest.fixture
async def configured():
    rig = fake_rig()
    await rig.store.create_user("vera", hash_password(PASSWORD), "viewer")
    await rig.store.create_user("ada", hash_password(PASSWORD), "admin")
    app = create_app(Settings(_env_file=None, hst_secret_key=generate_key()), store=rig.store)
    app.state.inventory_context = rig.ctx
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test", headers={"X-HST-CSRF": "1"}
    ) as client:
        yield rig, app, client


async def test_inventory_routes_are_registered_once(configured):
    _, app, _ = configured
    paths = app.openapi()["paths"]
    routes = [(method.upper(), path) for path, methods in paths.items() for method in methods]
    operation_ids = [operation["operationId"] for methods in paths.values() for operation in methods.values()]
    assert len(operation_ids) == len(set(operation_ids))
    assert ("POST", "/api/inventory/operations/preview") in routes
    assert ("GET", "/api/inventory/devices/{device_id}/routing") in routes


async def test_inactive_inventory_is_inspectable_but_not_mutable(configured):
    _, _, client = configured
    await login(client, "ada")
    state = await client.get("/api/inventory/state")
    assert state.status_code == 200
    assert state.json()["activation_state"] == "inactive"
    assert (await client.get("/api/inventory/devices")).status_code == 503
    assert (
        await client.post("/api/inventory/sites", json={"code": "fra", "name": "Frankfurt"})
    ).status_code == 503


async def test_active_inventory_preserves_viewer_permissions(configured):
    rig, _, client = configured
    async with rig.repo.transaction() as tx:
        await tx.activate(resolver_version=2, schema_version=1, backfill_version=1, now=rig.clock())
    await login(client, "vera")
    assert (await client.get("/api/inventory/devices")).status_code == 200
    assert (await client.get("/api/inventory/connections")).status_code == 403
    assert (await client.get("/api/inventory/credentials")).status_code == 403
    assert (
        await client.post("/api/inventory/sites", json={"code": "fra", "name": "Frankfurt"})
    ).status_code == 403


async def test_newer_resolver_refuses_readiness_and_inventory(configured):
    rig, _, client = configured
    async with rig.repo.transaction() as tx:
        await tx.activate(resolver_version=3, schema_version=1, backfill_version=1, now=datetime.now(UTC))
    assert not await compatible(rig.store)
    await login(client, "ada")
    assert (await client.get("/api/readyz")).status_code == 503
    assert (await client.get("/api/inventory/devices")).status_code == 503
