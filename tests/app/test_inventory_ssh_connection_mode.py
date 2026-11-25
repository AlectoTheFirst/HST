"""The SSH connection mode is a profile setting resolved for execution."""

import pytest
from tests.app.conftest import login
from tests.app.test_inventory_collection import activate, make_client, make_store, settings_for
from tests.app.test_inventory_profiles import _connection, _target

from hst import collectors


@pytest.mark.parametrize("collector_type", ["iosxe", "nxos", "iosxr", "vyos", "checkpoint_gateway"])
async def test_profile_connection_mode_roundtrip_and_effective_config(tmp_path, collector_type):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    api = "/api/inventory"
    async with make_client(store, settings) as client:
        await login(client, "ada")
        response = await client.post(
            f"{api}/profiles",
            json={
                "display_name": "Single command SSH",
                "collector_type": collector_type,
                "settings": {
                    "auth": {"method": "agent", "username": "collector"},
                    "fresh_connection_per_command": True,
                    **(
                        {"expert_shell_account": "collector"}
                        if collector_type == "checkpoint_gateway"
                        else {}
                    ),
                },
            },
        )
        assert response.status_code == 201, response.text
        profile = response.json()
        saved = (await client.get(f"{api}/profiles/{profile['id']}")).json()
        assert saved["settings"]["fresh_connection_per_command"] is True
        connection = await _connection(
            client,
            collector_type=collector_type,
            profile_id=profile["id"],
            config={"estate": "lab", "management_source": "management"}
            if collector_type == "checkpoint_gateway"
            else {},
        )
        target = await _target(client, connection["id"], "router")
        response = await client.get(f"{api}/targets/{target['id']}/effective")
        assert response.status_code == 200, response.text
        effective = response.json()
        assert effective["values"]["fresh_connection_per_command"] is True
        assert effective["origins"]["fresh_connection_per_command"] == "profile"

        metadata = (await client.get(f"{api}/field-metadata")).json()
        row = next(row for row in metadata if row["collector_type"] == collector_type)
        field = next(f for f in row["fields"] if f["path"] == "fresh_connection_per_command")
        assert field["category"] == "profile"
        assert field["label"] == "Fresh SSH connection per command"
        schema = collectors.REGISTRY[collector_type].ConfigModel.model_json_schema()
        assert schema["properties"][field["path"]]["type"] == "boolean"
        assert schema["properties"][field["path"]]["default"] is False
