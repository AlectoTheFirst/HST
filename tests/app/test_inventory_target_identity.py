"""Collector identity overrides must never leak across a connection's targets."""

import os
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from tests.app.conftest import login
from tests.app.inventory_fakes import FakeInventoryTx
from tests.app.test_inventory_collection import activate, make_client, make_store, settings_for

from hst.app.inventory.connection_routes import API_PREFIX


@pytest.fixture
def identity_store(monkeypatch):
    original = FakeInventoryTx.create_target

    async def create(self, *, endpoint_config=None, **kwargs):
        target = await original(self, **kwargs)
        target = replace(target, endpoint_config=endpoint_config or {})
        self.t.targets[target.id] = target
        return target

    monkeypatch.setattr(FakeInventoryTx, "create_target", create)


async def test_target_replacement_keeps_identity_local(tmp_path, identity_store):
    store = await make_store()
    await activate(store)
    async with make_client(store, settings_for(tmp_path)) as client:
        await login(client, "ada")
        response = await client.post(
            f"{API_PREFIX}/connections",
            json={
                "name": "gateways",
                "collector_type": "checkpoint_gateway",
                "enabled": False,
                "config": {"management_source": "manager"},
            },
        )
        assert response.status_code == 201, response.text
        connection = response.json()
        targets = []
        for index in range(2):
            response = await client.post(
                f"{API_PREFIX}/targets",
                json={
                    "connection_id": connection["id"],
                    "host": f"gateway-{index}",
                    "endpoint_config": {"appliance_uid": f"appliance-{index}"},
                },
            )
            assert response.status_code == 201, response.text
            targets.append(response.json())
        before = dict((await store.get_source("gateways")).config)
        response = await client.post(
            f"{API_PREFIX}/operations/preview",
            json={
                "operation": "replace_target",
                "selection": {"ids": [targets[0]["id"]]},
                "change": {"endpoint_config": {"appliance_uid": "replacement"}},
            },
        )
        assert response.status_code == 200, response.text
        response = await client.post(
            f"{API_PREFIX}/operations/apply",
            json={
                "token": response.json()["token"],
                "idempotency_key": "replace-first",
            },
        )
        assert response.status_code == 200, response.text
        assert (await store.get_source("gateways")).config == before
        response = await client.get(f"{API_PREFIX}/targets", params={"connection_id": connection["id"]})
        assert response.status_code == 200, response.text
        by_host = {target["host"]: target for target in response.json()}
        assert by_host["gateway-0"]["endpoint_config"] == {"appliance_uid": "replacement"}
        assert by_host["gateway-1"]["endpoint_config"] == {"appliance_uid": "appliance-1"}


@pytest.mark.parametrize(
    "settings", [{"host": "other"}, {"host_key": "pin"}, {"auth": {"password": "secret"}}]
)
async def test_target_identity_rejects_address_pins_and_credentials(tmp_path, settings):
    store = await make_store()
    await activate(store)
    async with make_client(store, settings_for(tmp_path)) as client:
        await login(client, "ada")
        response = await client.post(
            f"{API_PREFIX}/connections", json={"name": "fleet", "collector_type": "vyos"}
        )
        assert response.status_code == 201
        response = await client.post(
            f"{API_PREFIX}/targets",
            json={
                "connection_id": response.json()["id"],
                "host": "one",
                "endpoint_config": settings,
            },
        )
        assert response.status_code == 422
        assert not await store.list_devices("fleet")


@pytest.mark.pg
@pytest.mark.skipif(not os.environ.get("HST_TEST_PG_DSN"), reason="HST_TEST_PG_DSN not set")
async def test_target_identity_roundtrips_in_postgres():
    from tests.app.inventory_rig import reset_pg

    store = await reset_pg()
    try:
        source = await store.create_source("identity-roundtrip", "checkpoint_gateway", {}, b"")
        async with store.inventory().transaction() as tx:
            target = await tx.create_target(
                source_id=source.id,
                source_key=source.name,
                host="gateway",
                kind="direct",
                now=datetime.now(UTC),
                endpoint_config={"appliance_uid": "one"},
            )
        async with store.inventory().transaction() as tx:
            found = await tx.get_target(target.id)
            assert found is not None
            assert found.endpoint_config == {"appliance_uid": "one"}
        assert (await store.get_source(source.name)).config == {}
    finally:
        await store.dispose()
