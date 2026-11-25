"""A VCO profile needs its API token and jump key in the selected credential."""

import pytest
from tests.app.conftest import login
from tests.app.test_inventory_collection import make_client, make_store, seed_credential, settings_for


@pytest.mark.parametrize("missing", [None, "auth.key", "jump_host.auth.private_key"])
async def test_vco_private_key_profile_uses_one_complete_credential(tmp_path, missing):
    store = await make_store()
    settings = settings_for(tmp_path)
    secrets = {"auth.key": "vco-token", "jump_host.auth.private_key": "ssh-key-material"}
    if missing:
        secrets.pop(missing)
    credential = await seed_credential(store, settings, secrets)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        response = await client.post(
            "/api/inventory/profiles",
            json={
                "display_name": "VCO jump access",
                "collector_type": "velocloud",
                "credential_id": str(credential.id),
                "settings": {
                    "auth": {"method": "api_key"},
                    "jump_host": {
                        "host": "bastion.example",
                        "host_key": "ssh-ed25519 test-pin",
                        "auth": {"method": "private_key", "username": "jump-user"},
                    },
                },
            },
        )
    if missing:
        assert response.status_code == 422
        assert f"({missing})" in response.json()["error"]
        assert "the profile needs one credential with every required secret" in response.json()["error"]
    else:
        assert response.status_code == 201, response.text
    assert all(value not in response.text for value in secrets.values())
