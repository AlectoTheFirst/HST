"""VCO jump access resolves from profiles with secrets kept in credentials."""

from tests.app.conftest import login
from tests.app.test_inventory_collection import (
    activate,
    make_client,
    make_store,
    seed_credential,
    settings_for,
)
from tests.app.test_inventory_profiles import _connection

from hst.app.inventory.connection_routes import _resolve_target
from hst.collectors.velocloud import VeloCloudConfig


async def test_vco_jump_profile_reaches_execution_with_sealed_credentials(tmp_path):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    secrets = {"auth.key": "vco-api-secret", "jump_host.auth.password": "bastion-secret"}
    credential = await seed_credential(store, settings, secrets)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        response = await client.post(
            "/api/inventory/profiles",
            json={
                "display_name": "VCO through bastion",
                "collector_type": "velocloud",
                "credential_id": str(credential.id),
                "settings": {
                    "auth": {"method": "api_key"},
                    "jump_host": {
                        "host": "bastion.example",
                        "port": 2222,
                        "host_key": "ssh-ed25519 test-pin",
                        "auth": {"method": "password", "username": "jump-user"},
                    },
                },
            },
        )
        assert response.status_code == 201, response.text
        profile = response.json()
        connection = await _connection(
            client,
            name="vco",
            collector_type="velocloud",
            profile_id=profile["id"],
            config={"url": "https://vco.example", "orchestrator_release": "6.4.0"},
        )
        targets = (
            await client.get("/api/inventory/targets", params={"connection_id": connection["id"]})
        ).json()
        response = await client.get(f"/api/inventory/targets/{targets[0]['id']}/effective")
        assert response.status_code == 200, response.text
        assert response.json()["values"]["jump_host.host"] == "bastion.example"
        assert response.json()["origins"]["jump_host.host"] == "profile"
        assert all(secret not in response.text for secret in secrets.values())
        assert all(secret not in str(profile) for secret in secrets.values())
        metadata = (await client.get("/api/inventory/field-metadata")).json()
        fields = next(row["fields"] for row in metadata if row["collector_type"] == "velocloud")
        assert next(f for f in fields if f["path"] == "jump_host.host")["category"] == "profile"
        assert next(f for f in fields if f["path"] == "jump_host.auth.password")["secret"]

    from hst.app.crypto import dek

    async with store.inventory().transaction() as tx:
        row = await store.get_source("vco")
        [target] = await tx.list_targets(row.id)
        resolved, _, _ = await _resolve_target(store, settings, tx, target, key=dek(settings))
    config = VeloCloudConfig.model_validate(resolved.payload)
    assert config.auth.key.get_secret_value() == secrets["auth.key"]
    assert config.jump_host.host == "bastion.example"
    assert config.jump_host.auth.password.get_secret_value() == secrets["jump_host.auth.password"]
