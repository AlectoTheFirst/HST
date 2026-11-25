"""VCO onboarding needs no source-wide carrier classification."""

from tests.app.conftest import login
from tests.app.test_inventory_collection import make_client, make_store, settings_for

from hst.app.inventory.collection import frozen_normalization_values, validate_connection_config
from hst.collectors.velocloud import VeloCloudConfig


async def test_vco_onboarding_excludes_carrier_hints():
    store = await make_store()
    async with make_client(store) as client:
        await login(client, "otto")
        response = await client.get("/api/inventory/field-metadata")
        assert response.status_code == 200
        metadata = next(row for row in response.json() if row["collector_type"] == "velocloud")
        editable = {
            field["path"]
            for field in metadata["fields"]
            if field["category"] in {"connection", "target", "profile", "credential"}
        }
        assert {"url", "enterprise_logical_ids", "orchestrator_release", "auth.key"} <= editable
        assert not {"provider_name", "private_carriers"} & editable

    config = validate_connection_config(
        "velocloud", {"url": "https://vco.example", "orchestrator_release": "6.4.0"}
    )
    validated = VeloCloudConfig(**config, auth={"key": "test-key"})
    assert validated.enterprise_ids == []  # Discover all accessible enterprises.
    assert validated.private_carrier_names == set()


async def test_stored_vco_carrier_hints_are_kept_as_frozen_normalization_values():
    store = await make_store()
    hints = {"provider_name": "Existing Provider", "private_carriers": "Existing ISP"}
    row = await store.create_source("vco", "velocloud", hints, b"")
    frozen = frozen_normalization_values(row, None, settings_for())
    assert {key: frozen["values"][key] for key in hints} == hints
