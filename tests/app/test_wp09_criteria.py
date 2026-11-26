"""WP-09 "Done when": a revision saved by the visual editor exports and imports
again without losing a supported field."""

from __future__ import annotations

import copy

import pytest
import yaml
from tests.app.conftest import login
from tests.app.release_scenarios_rig import (
    CHECKOUT_ID,
    CHECKOUT_YAML,
    Inventory,
    ScenarioStore,
    api_interface,
    commit_yaml,
    install,
)


@pytest.fixture
def store():
    return ScenarioStore()


def _editor_definition(current: dict) -> dict:
    """The definition as `ApplicationEditor` sends it. The added group, member
    and connection have generated ids. The added connection has an empty
    `header_constraints` and an empty `parts` list in its member condition."""
    definition = copy.deepcopy(current)
    definition["name"] = "Checkout (edited)"
    definition["owner"] = "payments"
    definition["groups"].append(
        {"id": "group-5", "name": "Monitoring", "members": [{"id": "member-1", "address": "198.51.100.99"}]}
    )
    definition["connections"].append(
        {
            "id": "connection-4",
            "name": "Monitoring to API",
            "source": "group-5",
            "destination": "api",
            "protocol": "tcp",
            "destination_ports": [9100],
            "success": "forward",
            "destination_condition": {"kind": "member", "member": "api-primary", "parts": []},
            "header_constraints": {},
        }
    )
    definition["services"][0]["connection_ids"].append("connection-4")
    database = next(item for item in definition["connections"] if item["id"] == "api-to-database")
    database["destination_ports"] = [5433]
    return definition


async def test_an_editor_saved_revision_exports_and_imports_again_as_the_same_revision(
    client, store, monkeypatch
):
    install(monkeypatch, Inventory("4000", {"4000": api_interface("10.20.0.10")}))
    await login(client, "otto")
    assert (await commit_yaml(client, CHECKOUT_YAML)).status_code == 201
    current = (await client.get(f"/api/business-applications/{CHECKOUT_ID}")).json()["application"]

    edited = _editor_definition(current["definition"])
    saved = await client.put(
        f"/api/business-applications/{CHECKOUT_ID}",
        json={"definition": edited, "expected_revision": 1, "source": "editor"},
    )
    assert saved.status_code == 200, saved.text
    saved = saved.json()
    assert saved["revision"] == 2
    assert saved["origin"]["source"] == "editor"

    exported = await client.get(f"/api/business-applications/{CHECKOUT_ID}/export?revision=2")
    assert exported.status_code == 200, exported.text
    assert exported.headers["x-hst-application-revision"] == "2"
    document = yaml.safe_load(exported.text)
    assert document == saved["definition"]
    # the advanced fields of the Checkout example
    connections = {item["id"]: item for item in document["connections"]}
    assert connections["clients-to-frontend"]["mtu"] == {
        "mode": "packet",
        "ip_packet_bytes": 1500,
        "ipv4_df": True,
    }
    assert connections["clients-to-frontend"]["source_context"] == {"vrf": "vrf:branch"}
    assert connections["frontend-to-api"]["destination_condition"]["kind"] == "threshold"
    assert connections["api-to-database"]["destination_ports"] == [5433]
    assert connections["connection-4"]["source"] == "group-5"
    assert document["services"][0]["component_roles"] == [{"group_id": "frontend", "role": "endpoint"}]

    for mode in ("merge", "replace"):
        preview = await client.post(
            "/api/business-applications/import/preview", json={"yaml": exported.text, "mode": mode}
        )
        assert preview.status_code == 200, preview.text
        assert preview.json()["no_op"] is True
        assert preview.json()["result_digest"] == saved["digest"]
        assert preview.json()["definition"] == saved["definition"]

    again = await commit_yaml(client, exported.text, mode="replace")
    assert again.status_code == 201, again.text
    assert again.json()["revision"] == 2
    assert again.json()["digest"] == saved["digest"]
    history = (await client.get(f"/api/business-applications/{CHECKOUT_ID}/history")).json()
    assert [item["revision"] for item in history["revisions"]] == [2, 1]
